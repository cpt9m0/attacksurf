"""What the UI shows about a scan's AI triage (ADR 0029). Read-only and tenant-scoped."""

from collections.abc import Sequence
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from enum import StrEnum
from uuid import UUID

from sqlalchemy.orm import Session

from attacksurf.ai.schemas import StoredTriage, TriagePriority
from attacksurf.domain.findings import SEVERITY_RANK, Severity
from attacksurf.domain.scans import JobStatus, ScanNotFound, ScanStatus
from attacksurf.infra.db.models import Asset, Finding, FindingObservation, Job, Scan
from attacksurf.infra.db.tenancy import get_scoped, scoped
from attacksurf.services.jobs import FINISHED
from attacksurf.services.triage import (
    BATCH_STAGE,
    COORDINATOR_STAGE,
    DONE_STAGE,
    TRIAGE_STAGES,
    stored_triage,
)

TRIAGE_ROW_LIMIT = 100
TRIAGE_START_GRACE = timedelta(minutes=1)
_UNFINISHED = (JobStatus.QUEUED, JobStatus.RUNNING)
_ACTIVE_SCAN = (ScanStatus.QUEUED, ScanStatus.RUNNING)
_PRIORITY_ORDER = {priority: index for index, priority in enumerate(TriagePriority)}


class TriageState(StrEnum):
    # The scan is still running, or completed moments ago and its triage job is about to appear.
    AWAITING_SCAN = "awaiting_scan"
    # The scan ended without triage: it failed, was cancelled, or predates AI triage.
    NOT_STARTED = "not_started"
    PENDING = "pending"
    RUNNING = "running"
    SKIPPED = "skipped"
    FAILED = "failed"
    DONE = "done"


@dataclass(frozen=True)
class TriageRow:
    finding_id: UUID
    title: str
    asset_value: str
    location: str
    severity: Severity  # the scanner's, shown beside the AI's
    triage: StoredTriage


@dataclass(frozen=True)
class ScanTriage:
    state: TriageState
    notice: str | None  # why it was skipped or failed, or what a finished run left out
    batches_done: int
    batches_total: int
    rows: tuple[TriageRow, ...]  # at most TRIAGE_ROW_LIMIT, most urgent first
    total: int

    @property
    def active(self) -> bool:
        """Whether the page should keep polling."""
        return self.state in (TriageState.AWAITING_SCAN, TriageState.PENDING, TriageState.RUNNING)


def get_scan_triage(
    session: Session, org_id: UUID, scan_id: UUID, *, now: datetime | None = None
) -> ScanTriage:
    """The scan's triage run and its findings' judgments. Raises `ScanNotFound`."""
    scan = get_scoped(session, Scan, scan_id, org_id)
    if scan is None:
        raise ScanNotFound(str(scan_id))
    run = session.scalars(
        scoped(Job, org_id)
        .where(Job.scan_id == scan_id, Job.stage.in_(TRIAGE_STAGES))
        .order_by(Job.created_at, Job.id)
    ).all()
    rows = _judged_rows(session, org_id, scan_id)
    state, notice, done, total = _run_state(run, scan, now or datetime.now(UTC))
    return ScanTriage(
        state=state,
        notice=notice,
        batches_done=done,
        batches_total=total,
        rows=tuple(rows[:TRIAGE_ROW_LIMIT]),
        total=len(rows),
    )


def _run_state(
    run: Sequence[Job], scan: Scan, now: datetime
) -> tuple[TriageState, str | None, int, int]:
    coordinator = _coordinator(run)
    if coordinator is None:
        waiting = _triage_may_still_start(scan, now)
        return (TriageState.AWAITING_SCAN if waiting else TriageState.NOT_STARTED), None, 0, 0
    if coordinator.status is not JobStatus.COMPLETED:
        state, notice = _coordinator_outcome(coordinator)
        return state, notice, 0, 0
    return _batches_state(run)


def _triage_may_still_start(scan: Scan, now: datetime) -> bool:
    # An active scan queues triage when it completes. `finalize_scan` commits the completion
    # before it creates the triage job, so a just-completed scan gets a short grace too; past
    # it, no job means none is coming (the broker refused it, or the scan predates triage).
    if scan.status in _ACTIVE_SCAN:
        return True
    return (
        scan.status is ScanStatus.COMPLETED
        and scan.finished_at is not None
        and now - scan.finished_at <= TRIAGE_START_GRACE
    )


def _coordinator_outcome(coordinator: Job) -> tuple[TriageState, str | None]:
    if coordinator.status in _UNFINISHED:
        return TriageState.PENDING, None
    if coordinator.status is JobStatus.SKIPPED:
        return TriageState.SKIPPED, coordinator.error
    # The stored error is a class name at best: say what happened, not why.
    return TriageState.FAILED, "AI triage could not run."


def _batches_state(run: Sequence[Job]) -> tuple[TriageState, str | None, int, int]:
    batches = [job for job in run if job.stage == BATCH_STAGE]
    done_jobs = [job for job in run if job.stage == DONE_STAGE]
    finished = sum(job.status in FINISHED for job in batches)
    if finished < len(batches) or any(job.status in _UNFINISHED for job in done_jobs):
        return TriageState.RUNNING, None, finished, len(batches)
    failed_tail = next((job for job in done_jobs if job.status is JobStatus.FAILED), None)
    if failed_tail is not None:
        return TriageState.FAILED, failed_tail.error, finished, len(batches)
    missed = sum(job.status is not JobStatus.COMPLETED for job in batches)
    notice = f"{missed} of {len(batches)} assets were not triaged this time." if missed else None
    return TriageState.DONE, notice, finished, len(batches)


def _coordinator(run: Sequence[Job]) -> Job | None:
    # Scans queued before ADR 0029 also carry the old chain's completed `triage` stage: an
    # unfinished coordinator is always the current one, otherwise the latest is.
    coordinators = [job for job in run if job.stage == COORDINATOR_STAGE]
    unfinished = [job for job in coordinators if job.status in _UNFINISHED]
    if unfinished:
        return unfinished[-1]
    return coordinators[-1] if coordinators else None


def _judged_rows(session: Session, org_id: UUID, scan_id: UUID) -> list[TriageRow]:
    # The judgments of the findings this scan observed (ADR 0027: its observation rows).
    results = session.execute(
        scoped(Finding, org_id)
        .add_columns(Asset.value)
        .join(
            FindingObservation,
            (FindingObservation.finding_id == Finding.id)
            & (FindingObservation.org_id == Finding.org_id),
        )
        .join(Asset, (Asset.id == Finding.asset_id) & (Asset.org_id == Finding.org_id))
        .where(FindingObservation.scan_id == scan_id, Finding.ai_triage.is_not(None))
    ).all()
    rows = [
        TriageRow(
            finding_id=finding.id,
            title=finding.title,
            asset_value=asset_value,
            location=finding.location,
            severity=finding.severity,
            triage=triage,
        )
        for finding, asset_value in results
        if (triage := stored_triage(finding)) is not None
    ]
    return sorted(
        rows,
        key=lambda row: (
            _PRIORITY_ORDER[row.triage.priority],
            -SEVERITY_RANK[row.triage.adjusted_severity],
            row.title,
            row.finding_id,
        ),
    )
