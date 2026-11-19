"""AI triage (ADR 0029): which findings a scan sends, and where the judgments go.

The functions here are building blocks and don't commit; the `ai.*` job use cases that compose
them do. Every query is scoped by `org_id`.
"""

from collections import defaultdict
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from datetime import datetime
from uuid import UUID

from pydantic import ValidationError
from sqlalchemy.orm import Session

from attacksurf.ai.schemas import MAX_FINDINGS_PER_BATCH, FindingTriage, StoredTriage
from attacksurf.ai.triage import (
    EVIDENCE_ITEMS_PER_FINDING,
    TRIAGE_PROMPT_VERSION,
    TriageBatch,
    TriageEvidence,
    TriageFinding,
    triage_cache_key,
)
from attacksurf.domain.findings import ACTIVE_STATUSES, SEVERITY_RANK, Severity
from attacksurf.domain.llm import LLMConfig
from attacksurf.infra.db.models import Asset, Evidence, Finding, FindingObservation
from attacksurf.infra.db.tenancy import get_scoped, scoped


@dataclass(frozen=True)
class AssetTriage:
    """One asset's batch for one call, with what storing its judgments needs."""

    asset_id: UUID
    batch: TriageBatch
    finding_ids: Mapping[str, UUID]  # batch ref -> finding
    cache_keys: Mapping[str, str]  # batch ref -> the cache key its judgment answers


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
