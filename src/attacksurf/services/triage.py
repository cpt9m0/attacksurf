"""AI triage (ADR 0029): which findings a scan sends, the jobs that send them, and where the
judgments go.

`run_triage`, `run_triage_batch`, `finish_triage` and `fail_triage` are the `ai.*` job use
cases and commit; the other public functions are building blocks and don't. Every query is
scoped by `org_id`.
"""

from collections import defaultdict
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from datetime import UTC, datetime
from uuid import UUID

import structlog
from pydantic import ValidationError
from sqlalchemy import func
from sqlalchemy.orm import Session

from attacksurf.ai.factory import build_provider
from attacksurf.ai.schemas import MAX_FINDINGS_PER_BATCH, FindingTriage, StoredTriage
from attacksurf.ai.triage import (
    EVIDENCE_ITEMS_PER_FINDING,
    TRIAGE_PROMPT_VERSION,
    TRIAGE_PURPOSE,
    TriageBatch,
    TriageEvidence,
    TriageFinding,
    match_results,
    triage_batch,
    triage_cache_key,
)
from attacksurf.config import Settings
from attacksurf.domain.findings import ACTIVE_STATUSES, SEVERITY_RANK, Severity
from attacksurf.domain.jobs import JobNotFound, JobTask, PipelineQueue
from attacksurf.domain.llm import LLMConfig, LLMError, LLMUnavailable
from attacksurf.domain.net import DnsResolver
from attacksurf.domain.scans import JobStatus
from attacksurf.infra.db.models import Asset, Evidence, Finding, FindingObservation, Job
from attacksurf.infra.db.tenancy import get_scoped, scoped
from attacksurf.services import jobs, org_settings
from attacksurf.services.llm_usage import record_llm_usage
from attacksurf.services.scans import load_job_scan, root_is_active

log = structlog.get_logger(__name__)

# The jobs of one run, after the `triage` coordinator that `finalize_scan` queues.
COORDINATOR_STAGE = "triage"
BATCH_STAGE = "triage_batch"
DONE_STAGE = "triage_done"
FAILURE_STAGE = "triage_failure"
# AI work, not scan work: the scan's own progress leaves these out.
TRIAGE_STAGES = (COORDINATOR_STAGE, BATCH_STAGE, DONE_STAGE, FAILURE_STAGE)


@dataclass(frozen=True)
class AssetTriage:
    """One asset's batch for one call, with what storing its judgments needs."""

    asset_id: UUID
    batch: TriageBatch
    finding_ids: Mapping[str, UUID]  # batch ref -> finding
    cache_keys: Mapping[str, str]  # batch ref -> the cache key its judgment answers


def run_triage(
    session: Session,
    queue: PipelineQueue,
    org_id: UUID,
    job_id: UUID,
    settings: Settings,
    *,
    resolver: DnsResolver | None = None,
) -> None:
    """The `ai.triage` job: gate, then one `ai.triage_batch` job per asset with work.

    The batch jobs run in parallel and `ai.triage_done` follows them; if a batch crashes,
    `ai.triage_failed` runs instead. A redelivered coordinator reuses its job rows.
    """
    config = org_settings.enforce_triage_budget(
        session, org_id, job_id, settings, resolver=resolver
    )
    if config is None:
        return
    _, scan = load_job_scan(session, org_id, job_id)  # the scan lock: one run plans at a time
    if not root_is_active(session, org_id, scan):
        session.rollback()
        jobs.mark_job_skipped(session, org_id, job_id, "The domain was archived.")
        return
    scan_id = scan.id
    asset_ids = assets_to_triage(
        session, org_id, scan_id, model=config.model, include_info=settings.llm_triage_include_info
    )
    if not asset_ids:
        session.rollback()
        return
    header = tuple(
        _job_task(
            session,
            org_id,
            scan_id,
            stage=BATCH_STAGE,
            task_name="ai.triage_batch",
            asset_id=asset_id,
        )
        for asset_id in asset_ids
    )
    tail = (_job_task(session, org_id, scan_id, stage=DONE_STAGE, task_name="ai.triage_done"),)
    error = _job_task(session, org_id, scan_id, stage=FAILURE_STAGE, task_name="ai.triage_failed")
    jobs.enqueue_workflow(session, queue, header, tail, error)


def run_triage_batch(
    session: Session,
    org_id: UUID,
    job_id: UUID,
    settings: Settings,
    *,
    retry_allowed: bool,
    resolver: DnsResolver | None = None,
    now: datetime | None = None,
) -> None:
    """The `ai.triage_batch` job: one LLM call for one asset's findings.

    Like a scanner job it records its own failures, so the run goes on for the other assets; it
    raises only `LLMUnavailable`, and only while Celery may still retry.
    """
    config = org_settings.enforce_triage_budget(
        session, org_id, job_id, settings, resolver=resolver
    )
    if config is None:
        return
    job = get_scoped(session, Job, job_id, org_id)
    if job is None or job.scan_id is None or job.asset_id is None:
        raise JobNotFound(str(job_id))
    planned = build_asset_batch(
        session,
        org_id,
        job.scan_id,
        job.asset_id,
        model=config.model,
        include_info=settings.llm_triage_include_info,
    )
    session.rollback()  # no transaction stays open during a call that can take minutes
    if planned is None:
        return  # nothing left: a redelivery after success, or another run got there first
    try:
        result = triage_batch(build_provider(config), planned.batch)
    except LLMError as exc:
        record_llm_usage(session, org_id, config, purpose=TRIAGE_PURPOSE, outcome=exc)
        session.commit()  # tokens a failed call spent still count against the budget
        if isinstance(exc, LLMUnavailable) and retry_allowed:
            raise
        jobs.mark_job_failed(session, org_id, job_id, exc)
        log.warning(
            "triage batch failed",
            org_id=str(org_id),
            job_id=str(job_id),
            error=jobs.describe_error(exc),
        )
        return
    record_llm_usage(session, org_id, config, purpose=TRIAGE_PURPOSE, outcome=result)
    store_triage(
        session,
        org_id,
        planned,
        match_results(planned.batch, result.parsed),
        config=config,
        triaged_at=now or datetime.now(UTC),
    )
    session.commit()


def finish_triage(session: Session, org_id: UUID, job_id: UUID) -> None:
    """The `ai.triage_done` job: every batch of the run ended, so its failure job goes unused."""
    scan_id = _scan_of(session, org_id, job_id)
    _close_queued(session, org_id, scan_id, (FAILURE_STAGE,), JobStatus.SKIPPED, error=None)
    session.commit()


def fail_triage(session: Session, org_id: UUID, job_id: UUID) -> None:
    """The `ai.triage_failed` job: a batch crashed, so close the run's queued jobs.

    The scan completed before triage started and is never touched.
    """
    scan_id = _scan_of(session, org_id, job_id)
    _close_queued(
        session,
        org_id,
        scan_id,
        (BATCH_STAGE, DONE_STAGE),
        JobStatus.FAILED,
        error="AI triage stopped after an unexpected error.",
    )
    session.commit()


def assets_to_triage(
    session: Session, org_id: UUID, scan_id: UUID, *, model: str, include_info: bool
) -> list[UUID]:
    """Assets with at least one finding this scan observed and `model` hasn't judged yet."""
    findings = _untriaged(session, org_id, scan_id, model=model, include_info=include_info)
    return sorted({finding.asset_id for finding in findings})


def build_asset_batch(
    session: Session,
    org_id: UUID,
    scan_id: UUID,
    asset_id: UUID,
    *,
    model: str,
    include_info: bool,
) -> AssetTriage | None:
    """The asset's most severe untriaged findings, at most `MAX_FINDINGS_PER_BATCH`, or None.

    One call per asset per scan keeps every job inside Celery's time limit; findings past the
    cap are sent by a later scan, when the ones judged now are cache hits (ADR 0029).
    """
    findings = _untriaged(
        session, org_id, scan_id, model=model, include_info=include_info, asset_id=asset_id
    )[:MAX_FINDINGS_PER_BATCH]
    asset = get_scoped(session, Asset, asset_id, org_id)
    if not findings or asset is None:
        return None
    evidence = _latest_evidence(session, org_id, [finding.id for finding in findings])
    refs = [f"F{index}" for index in range(1, len(findings) + 1)]
    batch = TriageBatch(
        asset_value=asset.value,
        asset_type=asset.type,
        findings=tuple(
            TriageFinding(
                ref=ref,
                rule_id=finding.rule_id,
                title=finding.title,
                description=finding.description,
                severity=finding.severity,
                confidence=finding.confidence,
                location=finding.location,
                evidence=evidence.get(finding.id, ()),
            )
            for ref, finding in zip(refs, findings, strict=True)
        ),
    )
    return AssetTriage(
        asset_id=asset_id,
        batch=batch,
        finding_ids={ref: finding.id for ref, finding in zip(refs, findings, strict=True)},
        cache_keys={
            ref: _cache_key(finding, model) for ref, finding in zip(refs, findings, strict=True)
        },
    )


def store_triage(
    session: Session,
    org_id: UUID,
    planned: AssetTriage,
    judgments: Mapping[str, FindingTriage],
    *,
    config: LLMConfig,
    triaged_at: datetime,
) -> int:
    """Write each judgment to its finding's `ai_triage`; returns how many were written.

    Building block: doesn't commit. Only `ai_triage` changes: the AI never touches a finding's
    status, severity or confidence (AGENTS.md rule 7). Refs outside the batch are ignored.
    """
    written = 0
    for ref, judgment in judgments.items():
        finding_id = planned.finding_ids.get(ref)
        finding = None if finding_id is None else get_scoped(session, Finding, finding_id, org_id)
        if finding is None:
            continue
        finding.ai_triage = StoredTriage.from_judgment(
            judgment,
            prompt_version=TRIAGE_PROMPT_VERSION,
            config=config,
            cache_key=planned.cache_keys[ref],
            triaged_at=triaged_at,
        ).model_dump(mode="json")
        written += 1
    return written


def stored_triage(finding: Finding) -> StoredTriage | None:
    """The finding's stored judgment, or None when it has none or it doesn't validate."""
    if finding.ai_triage is None:
        return None
    try:
        return StoredTriage.model_validate(finding.ai_triage)
    except ValidationError:
        return None


def _job_task(
    session: Session,
    org_id: UUID,
    scan_id: UUID,
    *,
    stage: str,
    task_name: str,
    asset_id: UUID | None = None,
) -> JobTask:
    # The scan lock is held: a redelivered coordinator finds and reuses the same rows.
    row = session.scalars(
        scoped(Job, org_id).where(
            Job.scan_id == scan_id, Job.stage == stage, Job.asset_id == asset_id
        )
    ).one_or_none()
    if row is None:
        row = jobs.record_job(
            session, org_id=org_id, scan_id=scan_id, stage=stage, asset_id=asset_id
        )
    return JobTask(task_name, org_id, row.id)


def _scan_of(session: Session, org_id: UUID, job_id: UUID) -> UUID:
    job = get_scoped(session, Job, job_id, org_id)
    if job is None or job.scan_id is None:
        raise JobNotFound(str(job_id))
    return job.scan_id


def _close_queued(
    session: Session,
    org_id: UUID,
    scan_id: UUID,
    stages: tuple[str, ...],
    status: JobStatus,
    *,
    error: str | None,
) -> None:
    for row in session.scalars(
        scoped(Job, org_id).where(
            Job.scan_id == scan_id, Job.stage.in_(stages), Job.status == JobStatus.QUEUED
        )
    ):
        row.status = status
        row.error = error
        row.finished_at = func.now()


def _untriaged(
    session: Session,
    org_id: UUID,
    scan_id: UUID,
    *,
    model: str,
    include_info: bool,
    asset_id: UUID | None = None,
) -> list[Finding]:
    # "This scan observed it" is its observation row, never `Finding.last_seen_scan_id`, which
    # overlapping scans move (ADR 0027).
    query = (
        scoped(Finding, org_id)
        .join(
            FindingObservation,
            (FindingObservation.finding_id == Finding.id)
            & (FindingObservation.org_id == Finding.org_id),
        )
        .where(FindingObservation.scan_id == scan_id, Finding.status.in_(ACTIVE_STATUSES))
    )
    if not include_info:
        query = query.where(Finding.severity != Severity.INFO)
    if asset_id is not None:
        query = query.where(Finding.asset_id == asset_id)
    findings = [finding for finding in session.scalars(query) if not _is_current(finding, model)]
    return sorted(
        findings,
        key=lambda finding: (finding.asset_id, -SEVERITY_RANK[finding.severity], finding.id),
    )


def _is_current(finding: Finding, model: str) -> bool:
    stored = stored_triage(finding)
    return stored is not None and stored.cache_key == _cache_key(finding, model)


def _cache_key(finding: Finding, model: str) -> str:
    return triage_cache_key(
        TRIAGE_PROMPT_VERSION, model, finding.fingerprint, finding.evidence_digest
    )


def _latest_evidence(
    session: Session, org_id: UUID, finding_ids: Sequence[UUID]
) -> dict[UUID, tuple[TriageEvidence, ...]]:
    rows = session.scalars(
        scoped(Evidence, org_id)
        .where(Evidence.finding_id.in_(finding_ids))
        .order_by(Evidence.finding_id, Evidence.captured_at.desc(), Evidence.id.desc())
    )
    grouped: defaultdict[UUID, list[TriageEvidence]] = defaultdict(list)
    for row in rows:
        if len(grouped[row.finding_id]) < EVIDENCE_ITEMS_PER_FINDING:
            grouped[row.finding_id].append(TriageEvidence(row.kind, row.data))
    return {finding_id: tuple(items) for finding_id, items in grouped.items()}
