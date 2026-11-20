"""AI exposure summary (ADR 0030): assemble scan context, run one LLM call, and store it.

`run_summary` is the `ai.summarize` job use case and commits; `build_summary_input` and
`store_summary` are building blocks and don't. Every query is scoped by `org_id`.
"""

from collections.abc import Collection
from datetime import UTC, datetime
from uuid import UUID

import structlog
from pydantic import ValidationError
from sqlalchemy.orm import Session

from attacksurf.ai.factory import build_provider
from attacksurf.ai.schemas import StoredSummary, TriagePriority
from attacksurf.ai.summary import (
    MAX_SUMMARY_ASSETS,
    MAX_SUMMARY_DIFF_ASSETS,
    MAX_SUMMARY_FINDINGS,
    SUMMARY_PROMPT_VERSION,
    SUMMARY_PURPOSE,
    SummaryAsset,
    SummaryAssetChanges,
    SummaryDiff,
    SummaryFinding,
    SummaryFindingTriage,
    SummaryInput,
    SummarySeverityCounts,
    ValidatedSummary,
    summarize,
    validate_summary,
)
from attacksurf.config import Settings
from attacksurf.domain.findings import ACTIVE_STATUSES, SEVERITY_RANK
from attacksurf.domain.jobs import JobNotFound
from attacksurf.domain.llm import LLMConfig, LLMError, LLMUnavailable
from attacksurf.domain.net import DnsResolver
from attacksurf.domain.scans import ScanNotFound
from attacksurf.infra.db.models import Asset, Finding, FindingObservation, Job, Scan
from attacksurf.infra.db.tenancy import get_scoped, scoped
from attacksurf.services import jobs, org_settings, scan_views
from attacksurf.services.llm_usage import record_llm_usage
from attacksurf.services.scans import root_is_active
from attacksurf.services.triage import stored_triage, triage_is_stale

log = structlog.get_logger(__name__)

# Owned by AI exposure summaries (ADR 0030): reserve if manual tagging is added later.
NOTABLE_TAG = "notable"
_PRIORITY_ORDER = {priority: index for index, priority in enumerate(TriagePriority)}


def run_summary(
    session: Session,
    org_id: UUID,
    job_id: UUID,
    settings: Settings,
    *,
    retry_allowed: bool,
    resolver: DnsResolver | None = None,
    now: datetime | None = None,
) -> None:
    """The `ai.summarize` job: one LLM call to summarize the scan's exposure (ADR 0030).

    Never touches the scan's status or its triage results. A redelivery after a summary is
    already stored returns without calling the LLM. `LLMUnavailable` raises while retries remain;
    every other `LLMError` fails only this job. Usage is committed on both success and failure.
    """
    job = get_scoped(session, Job, job_id, org_id)
    if job is None or job.scan_id is None:
        raise JobNotFound(str(job_id))
    scan = get_scoped(session, Scan, job.scan_id, org_id)
    if scan is None:
        raise JobNotFound(str(job_id))
    if stored_summary(scan) is not None:
        session.rollback()
        return
    if not root_is_active(session, org_id, scan):
        session.rollback()
        jobs.mark_job_skipped(session, org_id, job_id, "The domain was archived.")
        return
    scan_id = scan.id
    root_asset_id = scan.root_asset_id
    config = org_settings.enforce_triage_budget(
        session, org_id, job_id, settings, resolver=resolver
    )
    if config is None:
        return
    summary_input = build_summary_input(session, org_id, scan_id)
    session.rollback()  # no transaction stays open during a call that can take minutes
    try:
        result = summarize(build_provider(config), summary_input)
    except LLMError as exc:
        record_llm_usage(session, org_id, config, purpose=SUMMARY_PURPOSE, outcome=exc)
        session.commit()  # tokens a failed call spent still count against the budget
        if isinstance(exc, LLMUnavailable) and retry_allowed:
            raise
        jobs.mark_job_failed(session, org_id, job_id, exc)
        log.warning(
            "exposure summary failed",
            org_id=str(org_id),
            job_id=str(job_id),
            error=jobs.describe_error(exc),
        )
        return
    validated = validate_summary(summary_input, result.parsed)
    record_llm_usage(session, org_id, config, purpose=SUMMARY_PURPOSE, outcome=result)
    store_summary(
        session,
        org_id,
        scan_id,
        validated,
        config=config,
        generated_at=now or datetime.now(UTC),
    )
    apply_notable_tags(
        session,
        org_id,
        root_asset_id,
        [item.asset_id for item in validated.notable_assets],
    )
    session.commit()


def build_summary_input(session: Session, org_id: UUID, scan_id: UUID) -> SummaryInput:
    """Assemble the bounded, tenant-scoped input for `scan_id` (no raw evidence).

    Building block: read-only, doesn't commit. Raises `ScanNotFound` for missing or foreign scans.
    """
    scan = get_scoped(session, Scan, scan_id, org_id)
    if scan is None:
        raise ScanNotFound(str(scan_id))
    root = get_scoped(session, Asset, scan.root_asset_id, org_id)
    root_domain = root.value if root is not None else ""
    changes = _to_summary_diff(scan_views.parse_diff(scan.stats))
    findings = _select_findings(session, org_id, scan_id)
    assets = _select_assets(session, org_id, scan.root_asset_id)
    return SummaryInput(
        root_domain=root_domain,
        changes=changes,
        findings=findings,
        assets=assets,
    )


def store_summary(
    session: Session,
    org_id: UUID,
    scan_id: UUID,
    validated: ValidatedSummary,
    *,
    config: LLMConfig,
    generated_at: datetime,
) -> StoredSummary:
    """Persist `validated` onto `Scan.ai_summary`. Building block: doesn't commit."""
    scan = get_scoped(session, Scan, scan_id, org_id)
    if scan is None:
        raise ScanNotFound(str(scan_id))
    record = validated.to_stored(
        prompt_version=SUMMARY_PROMPT_VERSION,
        config=config,
        generated_at=generated_at,
    )
    scan.ai_summary = record.model_dump(mode="json")
    return record


def stored_summary(scan: Scan) -> StoredSummary | None:
    """The scan's stored exposure summary, or None when absent or invalid."""
    if scan.ai_summary is None:
        return None
    try:
        return StoredSummary.model_validate(scan.ai_summary)
    except ValidationError:
        return None


def apply_notable_tags(
    session: Session,
    org_id: UUID,
    root_asset_id: UUID,
    notable_asset_ids: Collection[UUID],
) -> None:
    """Sync the `notable` tag on assets under `root_asset_id` to match `notable_asset_ids`.

    Building block: doesn't commit. Adds `notable` to flagged active assets under the scan's
    root and removes it from that root's other assets. Never touches any other tag value,
    another root's assets, or another organization's assets (ADR 0030).
    """
    flagged = set(notable_asset_ids)
    assets = session.scalars(
        scoped(Asset, org_id).where(
            (Asset.id == root_asset_id) | (Asset.parent_id == root_asset_id)
        )
    ).all()
    for asset in assets:
        current = list(asset.tags or ())
        has_tag = NOTABLE_TAG in current
        should_have = asset.id in flagged and asset.is_active
        if should_have and not has_tag:
            asset.tags = [*current, NOTABLE_TAG]
        elif not should_have and has_tag:
            asset.tags = [tag for tag in current if tag != NOTABLE_TAG]


def _select_findings(session: Session, org_id: UUID, scan_id: UUID) -> tuple[SummaryFinding, ...]:
    rows = session.execute(
        scoped(Finding, org_id)
        .add_columns(Asset.value)
        .join(
            FindingObservation,
            (FindingObservation.finding_id == Finding.id)
            & (FindingObservation.org_id == Finding.org_id),
        )
        .join(Asset, (Asset.id == Finding.asset_id) & (Asset.org_id == Finding.org_id))
        .where(FindingObservation.scan_id == scan_id, Finding.status.in_(ACTIVE_STATUSES))
    ).all()

    candidates: list[tuple[Finding, str, SummaryFindingTriage | None]] = []
    for finding, asset_value in rows:
        triage = stored_triage(finding)
        current_triage: SummaryFindingTriage | None = None
        if triage is not None and not triage_is_stale(finding, triage):
            current_triage = SummaryFindingTriage(
                priority=triage.priority,
                adjusted_severity=triage.adjusted_severity,
                false_positive_likelihood=triage.false_positive_likelihood,
                rationale=triage.rationale,
            )
        candidates.append((finding, asset_value, current_triage))

    candidates.sort(key=_finding_sort_key)
    selected = candidates[:MAX_SUMMARY_FINDINGS]
    return tuple(
        SummaryFinding(
            ref=f"F{index}",
            finding_id=finding.id,
            rule_id=finding.rule_id,
            title=finding.title,
            severity=finding.severity,
            asset_name=asset_value,
            triage=current_triage,
        )
        for index, (finding, asset_value, current_triage) in enumerate(selected, start=1)
    )


def _finding_sort_key(
    item: tuple[Finding, str, SummaryFindingTriage | None],
) -> tuple[int, int, int, int, str, UUID]:
    finding, _, triage = item
    if triage is not None:
        return (
            0,
            _PRIORITY_ORDER[triage.priority],
            -SEVERITY_RANK[triage.adjusted_severity],
            -SEVERITY_RANK[finding.severity],
            finding.title,
            finding.id,
        )
    return (
        1,
        len(_PRIORITY_ORDER),
        -SEVERITY_RANK[finding.severity],
        -SEVERITY_RANK[finding.severity],
        finding.title,
        finding.id,
    )


def _select_assets(session: Session, org_id: UUID, root_asset_id: UUID) -> tuple[SummaryAsset, ...]:
    rows = session.scalars(
        scoped(Asset, org_id)
        .where(
            Asset.is_active.is_(True),
            (Asset.id == root_asset_id) | (Asset.parent_id == root_asset_id),
        )
        .order_by(Asset.value, Asset.type, Asset.id)
        .limit(MAX_SUMMARY_ASSETS)
    ).all()
    return tuple(
        SummaryAsset(
            ref=f"A{index}",
            asset_id=asset.id,
            name=asset.value,
            asset_type=asset.type,
        )
        for index, asset in enumerate(rows, start=1)
    )


def _to_summary_diff(diff: scan_views.DiffSummary | None) -> SummaryDiff | None:
    if diff is None:
        return None
    return SummaryDiff(
        new_findings=_to_severity_counts(diff.new_findings),
        fixed_findings=_to_severity_counts(diff.fixed_findings),
        regressed_findings=_to_severity_counts(diff.regressed_findings),
        total_findings=_to_severity_counts(diff.total_findings),
        new_assets=_to_asset_changes(diff.new_assets),
        disappeared_assets=_to_asset_changes(diff.disappeared_assets),
    )


def _to_severity_counts(bucket: scan_views.SeverityBucket) -> SummarySeverityCounts:
    return SummarySeverityCounts(
        total=bucket.total,
        by_severity=tuple((sev, count) for sev, count in bucket.by_severity if count > 0),
    )


def _to_asset_changes(bucket: scan_views.DiffAssetBucket) -> SummaryAssetChanges:
    return SummaryAssetChanges(
        total=bucket.total,
        names=tuple(asset.value for asset in bucket.assets[:MAX_SUMMARY_DIFF_ASSETS]),
    )
