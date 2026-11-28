"""What the UI shows about a scan's AI exposure summary (ADR 0030). Read-only and tenant-scoped."""

from collections.abc import Sequence
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from enum import StrEnum
from uuid import UUID

from sqlalchemy import func
from sqlalchemy.orm import Session

from attacksurf.ai.schemas import MIN_CHAIN_FINDINGS, StoredSummary
from attacksurf.domain.assets import AssetType
from attacksurf.domain.findings import Severity
from attacksurf.domain.scans import JobStatus, ScanNotFound, ScanStatus
from attacksurf.infra.db.models import Asset, Finding, Job, Scan
from attacksurf.infra.db.tenancy import get_scoped, scoped
from attacksurf.services.summary import stored_summary
from attacksurf.services.triage import (
    BATCH_STAGE,
    COORDINATOR_STAGE,
    DONE_STAGE,
    SUMMARY_STAGE,
    TRIAGE_STAGES,
)

SUMMARY_START_GRACE = timedelta(minutes=1)
MAX_DASHBOARD_SUMMARIES = 8
MAX_DASHBOARD_RISKS = 3
_UNFINISHED = (JobStatus.QUEUED, JobStatus.RUNNING)
_ACTIVE_SCAN = (ScanStatus.QUEUED, ScanStatus.RUNNING)


class SummaryState(StrEnum):
    # Scan is still running, or just completed and its AI jobs haven't appeared yet.
    AWAITING_SCAN = "awaiting_scan"
    # Scan ended without a summary (failed, cancelled, or predates summaries).
    NOT_STARTED = "not_started"
    # Triage is running, or `ai.summarize` is queued.
    PENDING = "pending"
    # `ai.summarize` is currently running.
    RUNNING = "running"
    SKIPPED = "skipped"
    FAILED = "failed"
    DONE = "done"


@dataclass(frozen=True)
class SummaryRiskView:
    finding_id: UUID
    title: str
    severity: Severity
    asset_value: str
    why: str


@dataclass(frozen=True)
class SummaryNotableAssetView:
    asset_id: UUID
    value: str
    asset_type: AssetType
    reason: str


@dataclass(frozen=True)
class SummaryChainFindingView:
    finding_id: UUID
    title: str
    severity: Severity


@dataclass(frozen=True)
class SummaryRiskChainView:
    title: str
    findings: tuple[SummaryChainFindingView, ...]
    asset_id: UUID | None
    asset_value: str | None
    why: str


@dataclass(frozen=True)
class ScanSummaryView:
    state: SummaryState
    notice: str | None
    summary: StoredSummary | None
    key_risks: tuple[SummaryRiskView, ...]
    notable_assets: tuple[SummaryNotableAssetView, ...]
    risk_chains: tuple[SummaryRiskChainView, ...] = ()

    @property
    def active(self) -> bool:
        """Whether the page should keep polling."""
        return self.state in (
            SummaryState.AWAITING_SCAN,
            SummaryState.PENDING,
            SummaryState.RUNNING,
        )


@dataclass(frozen=True)
class RootSummaryCard:
    root_id: UUID
    root_value: str
    scan_id: UUID
    summary: StoredSummary
    top_risks: tuple[SummaryRiskView, ...]
    notable_count: int


def get_scan_summary(
    session: Session, org_id: UUID, scan_id: UUID, *, now: datetime | None = None
) -> ScanSummaryView:
    """The scan's exposure summary card state and resolved links. Raises `ScanNotFound`."""
    scan = get_scoped(session, Scan, scan_id, org_id)
    if scan is None:
        raise ScanNotFound(str(scan_id))
    stored = stored_summary(scan)
    if stored is not None:
        risks = _resolve_risks(session, org_id, stored)
        assets = _resolve_assets(session, org_id, stored)
        chains = _resolve_risk_chains(session, org_id, stored)
        return ScanSummaryView(
            state=SummaryState.DONE,
            notice=None,
            summary=stored,
            key_risks=risks,
            notable_assets=assets,
            risk_chains=chains,
        )
    run = session.scalars(
        scoped(Job, org_id)
        .where(Job.scan_id == scan_id, Job.stage.in_(TRIAGE_STAGES))
        .order_by(Job.created_at, Job.id)
    ).all()
    state, notice = _summary_state(run, scan, now or datetime.now(UTC))
    return ScanSummaryView(
        state=state,
        notice=notice,
        summary=None,
        key_risks=(),
        notable_assets=(),
    )


def list_latest_root_summaries(session: Session, org_id: UUID) -> tuple[RootSummaryCard, ...]:
    """Latest AI exposure summary per active root domain for the dashboard (top 3 risks each)."""
    latest = (
        scoped(Scan, org_id)
        .where(Scan.status == ScanStatus.COMPLETED, Scan.ai_summary.is_not(None))
        .with_only_columns(
            Scan.root_asset_id,
            Scan.id.label("scan_id"),
            Scan.created_at.label("scan_at"),
            func.row_number()
            .over(
                partition_by=Scan.root_asset_id,
                order_by=(Scan.created_at.desc(), Scan.id.desc()),
            )
            .label("rank"),
        )
        .subquery()
    )
    rows = session.execute(
        scoped(Asset, org_id)
        .add_columns(Scan)
        .join(latest, (latest.c.root_asset_id == Asset.id) & (latest.c.rank == 1))
        .join(Scan, (Scan.id == latest.c.scan_id) & (Scan.org_id == org_id))
        .where(
            Asset.type == AssetType.DOMAIN,
            Asset.parent_id.is_(None),
            Asset.is_active.is_(True),
        )
        .order_by(latest.c.scan_at.desc(), Asset.value)
        .limit(MAX_DASHBOARD_SUMMARIES)
    ).all()

    parsed: list[tuple[Asset, Scan, StoredSummary]] = []
    all_finding_ids: set[UUID] = set()
    for root, scan in rows:
        stored = stored_summary(scan)
        if stored is None:
            continue
        parsed.append((root, scan, stored))
        for risk in stored.key_risks[:MAX_DASHBOARD_RISKS]:
            all_finding_ids.add(risk.finding_id)

    findings_by_id = _load_findings(session, org_id, all_finding_ids)
    cards: list[RootSummaryCard] = []
    for root, scan, stored in parsed:
        top_risks = tuple(
            SummaryRiskView(
                finding_id=risk.finding_id,
                title=title,
                severity=severity,
                asset_value=asset_value,
                why=risk.why,
            )
            for risk in stored.key_risks[:MAX_DASHBOARD_RISKS]
            if (resolved := findings_by_id.get(risk.finding_id)) is not None
            for title, severity, asset_value in (resolved,)
        )
        cards.append(
            RootSummaryCard(
                root_id=root.id,
                root_value=root.value,
                scan_id=scan.id,
                summary=stored,
                top_risks=top_risks,
                notable_count=len(stored.notable_assets),
            )
        )
    return tuple(cards)


def _summary_state(
    run: Sequence[Job], scan: Scan, now: datetime
) -> tuple[SummaryState, str | None]:
    summary_jobs = [job for job in run if job.stage == SUMMARY_STAGE]
    if summary_jobs:
        return _summary_job_outcome(summary_jobs[-1])
    return _pre_summary_state(run, scan, now)


def _summary_job_outcome(latest: Job) -> tuple[SummaryState, str | None]:
    outcomes = {
        JobStatus.QUEUED: (SummaryState.PENDING, None),
        JobStatus.RUNNING: (SummaryState.RUNNING, None),
        JobStatus.SKIPPED: (SummaryState.SKIPPED, latest.error),
        JobStatus.FAILED: (SummaryState.FAILED, "AI exposure summary could not run."),
    }
    return outcomes.get(latest.status, (SummaryState.NOT_STARTED, None))


def _pre_summary_state(
    run: Sequence[Job], scan: Scan, now: datetime
) -> tuple[SummaryState, str | None]:
    coordinator = _coordinator(run)
    if coordinator is None:
        state = (
            SummaryState.AWAITING_SCAN
            if _scan_may_still_start(scan, now)
            else SummaryState.NOT_STARTED
        )
        return state, None
    if coordinator.status in _UNFINISHED:
        return SummaryState.PENDING, None
    if coordinator.status is JobStatus.SKIPPED:
        return SummaryState.SKIPPED, coordinator.error
    if coordinator.status is not JobStatus.COMPLETED:
        return SummaryState.FAILED, "AI exposure summary could not run."
    return _post_coordinator_state(run, coordinator, now)


def _post_coordinator_state(
    run: Sequence[Job], coordinator: Job, now: datetime
) -> tuple[SummaryState, str | None]:
    batches = [job for job in run if job.stage == BATCH_STAGE]
    done_jobs = [job for job in run if job.stage == DONE_STAGE]
    if any(job.status in _UNFINISHED for job in (*batches, *done_jobs)):
        return SummaryState.PENDING, None
    if any(job.status is JobStatus.FAILED for job in done_jobs):
        return SummaryState.FAILED, "AI exposure summary could not run."
    # Triage just finished (either via `triage_done` or nothing-new `triage`): allow a short
    # grace window for `_queue_summary` to commit the `summary` job row.
    finisher = done_jobs[-1] if done_jobs else coordinator
    if finisher.finished_at is not None and now - finisher.finished_at <= SUMMARY_START_GRACE:
        return SummaryState.PENDING, None
    return SummaryState.NOT_STARTED, None


def _scan_may_still_start(scan: Scan, now: datetime) -> bool:
    if scan.status in _ACTIVE_SCAN:
        return True
    return (
        scan.status is ScanStatus.COMPLETED
        and scan.finished_at is not None
        and now - scan.finished_at <= SUMMARY_START_GRACE
    )


def _coordinator(run: Sequence[Job]) -> Job | None:
    coordinators = [job for job in run if job.stage == COORDINATOR_STAGE]
    unfinished = [job for job in coordinators if job.status in _UNFINISHED]
    if unfinished:
        return unfinished[-1]
    return coordinators[-1] if coordinators else None


def _resolve_risks(
    session: Session, org_id: UUID, stored: StoredSummary
) -> tuple[SummaryRiskView, ...]:
    ids = {risk.finding_id for risk in stored.key_risks}
    findings = _load_findings(session, org_id, ids)
    return tuple(
        SummaryRiskView(
            finding_id=risk.finding_id,
            title=title,
            severity=severity,
            asset_value=asset_value,
            why=risk.why,
        )
        for risk in stored.key_risks
        if (resolved := findings.get(risk.finding_id)) is not None
        for title, severity, asset_value in (resolved,)
    )


def _load_findings(
    session: Session, org_id: UUID, finding_ids: set[UUID]
) -> dict[UUID, tuple[str, Severity, str]]:
    if not finding_ids:
        return {}
    rows = session.execute(
        scoped(Finding, org_id)
        .add_columns(Asset.value)
        .join(Asset, (Asset.id == Finding.asset_id) & (Asset.org_id == Finding.org_id))
        .where(Finding.id.in_(finding_ids))
    ).all()
    return {
        finding.id: (finding.title, finding.severity, asset_value) for finding, asset_value in rows
    }


def _resolve_assets(
    session: Session, org_id: UUID, stored: StoredSummary
) -> tuple[SummaryNotableAssetView, ...]:
    ids = {item.asset_id for item in stored.notable_assets}
    if not ids:
        return ()
    rows = session.scalars(scoped(Asset, org_id).where(Asset.id.in_(ids))).all()
    by_id = {asset.id: asset for asset in rows}
    return tuple(
        SummaryNotableAssetView(
            asset_id=item.asset_id,
            value=asset.value,
            asset_type=asset.type,
            reason=item.reason,
        )
        for item in stored.notable_assets
        if (asset := by_id.get(item.asset_id)) is not None
    )


def _resolve_risk_chains(
    session: Session, org_id: UUID, stored: StoredSummary
) -> tuple[SummaryRiskChainView, ...]:
    if not stored.risk_chains:
        return ()
    finding_ids = {fid for chain in stored.risk_chains for fid in chain.finding_ids}
    findings = _load_findings(session, org_id, finding_ids)
    asset_ids = {chain.asset_id for chain in stored.risk_chains if chain.asset_id is not None}
    assets_by_id = (
        {
            asset.id: asset
            for asset in session.scalars(scoped(Asset, org_id).where(Asset.id.in_(asset_ids)))
        }
        if asset_ids
        else {}
    )
    resolved_chains: list[SummaryRiskChainView] = []
    for chain in stored.risk_chains:
        chain_findings = tuple(
            SummaryChainFindingView(finding_id=fid, title=title, severity=severity)
            for fid in chain.finding_ids
            if (loaded := findings.get(fid)) is not None
            for title, severity, _ in (loaded,)
        )
        if len(chain_findings) < MIN_CHAIN_FINDINGS:
            continue
        asset = assets_by_id.get(chain.asset_id) if chain.asset_id is not None else None
        resolved_chains.append(
            SummaryRiskChainView(
                title=chain.title,
                findings=chain_findings,
                asset_id=asset.id if asset is not None else None,
                asset_value=asset.value if asset is not None else None,
                why=chain.why,
            )
        )
    return tuple(resolved_chains)
