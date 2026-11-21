"""Scan use cases and pipeline planning. Celery canvas stays behind PipelineQueue."""

from collections.abc import Mapping, Sequence
from datetime import timedelta
from uuid import UUID

import structlog
from sqlalchemy import func, select, update
from sqlalchemy.orm import Session
from sqlalchemy.sql.elements import ColumnElement

from attacksurf.domain.assets import AssetNotFound, AssetType
from attacksurf.domain.events import EventDispatcher, ScanCompleted
from attacksurf.domain.jobs import JobNotFound, JobTask, PipelineQueue, TaskQueue
from attacksurf.domain.scanners import ScanProfile
from attacksurf.domain.scans import (
    JobStatus,
    ScanAlreadyActive,
    ScanError,
    ScanNotFound,
    ScanRateLimited,
    ScanStatus,
    ScanTrigger,
)
from attacksurf.infra.db.models import Asset, Job, Org, Scan
from attacksurf.infra.db.tenancy import get_scoped, scoped
from attacksurf.scanners.registry import ScannerRegistry
from attacksurf.services import jobs, notifications
from attacksurf.services.audit import audit

log = structlog.get_logger(__name__)

TERMINAL = {ScanStatus.COMPLETED, ScanStatus.FAILED, ScanStatus.CANCELLED}
_ACTIVE = (ScanStatus.QUEUED, ScanStatus.RUNNING)
_UNFINISHED_JOBS = (JobStatus.QUEUED, JobStatus.RUNNING)


def start_scan(
    session: Session,
    queue: TaskQueue,
    *,
    org_id: UUID,
    root_asset_id: UUID,
    profile: str,
    registry: ScannerRegistry,
    profiles: Mapping[str, ScanProfile],
    triggered_by: ScanTrigger = ScanTrigger.USER,
    actor_id: UUID | None = None,
    max_starts_per_hour: int | None = None,
) -> Scan:
    """Queue a scan of a root domain and commit. Raises `ScanError` for bad requests.

    The root row is locked, so two concurrent starts for the same root serialize: the
    second sees the first's committed scan and gets `ScanAlreadyActive` instead of a
    duplicate. The lock is only ever taken on the root here; archiving locks the root's
    scans first and the root second, so the two wait in one direction and never deadlock
    (ADR 0021). `max_starts_per_hour` caps starts of this profile in the trailing hour
    (all statuses: even a failed start consumed a worker slot); None means no quota.
    The quota count and the insert are serialised on the org row: concurrent starts for
    different roots lock different asset rows and could otherwise both read a below-limit
    count and both insert (same pattern as the artifact quota, `services.artifacts`).
    """
    selected = profiles.get(profile)
    if selected is None:
        raise ScanError("Unknown scan profile.")
    registry.validate(selected)
    if not selected.discover and not selected.checks:
        raise ScanError("profile has no scanners")
    root = session.scalars(
        scoped(Asset, org_id).where(Asset.id == root_asset_id).with_for_update(),
        execution_options={"populate_existing": True},  # a committed archive must not be missed
    ).one_or_none()
    if root is None or root.parent_id is not None or not root.is_active:
        raise AssetNotFound("Root asset not found.")
    if root.type != AssetType.DOMAIN:
        raise ScanError("only domain root scans are supported")
    active = session.scalars(
        scoped(Scan, org_id).where(
            Scan.root_asset_id == root.id,
            Scan.status.in_(_ACTIVE),
        )
    ).one_or_none()
    if active is not None:
        raise ScanAlreadyActive(active.id)
    if max_starts_per_hour is not None:
        # Serialise the org's starts (see docstring): the lock is held until the
        # transaction commits in `create_job` below.
        session.execute(select(Org.id).where(Org.id == org_id).with_for_update())
        recent = (
            session.scalar(
                scoped(Scan, org_id)
                .where(
                    Scan.profile == profile,
                    Scan.created_at > func.now() - timedelta(hours=1),
                )
                .with_only_columns(func.count())
            )
            or 0
        )
        if recent >= max_starts_per_hour:
            raise ScanRateLimited("Too many scans started recently. Try again later.")
    scan = Scan(
        org_id=org_id,
        root_asset_id=root.id,
        profile=profile,
        status=ScanStatus.QUEUED,
        triggered_by=triggered_by,
    )
    session.add(scan)
    session.flush()
    scan_id = scan.id
    audit(
        session,
        org_id,
        "scan.started",
        actor_id=actor_id,
        target_type="scan",
        target_id=str(scan_id),
    )
    try:
        jobs.create_job(
            session,
            queue,
            org_id=org_id,
            scan_id=scan_id,
            stage="discover",
            task_name="passive.discover",
        )
    except Exception:
        fail_scan(session, org_id, scan_id)
        raise
    return scan


def cancel_scan(
    session: Session, org_id: UUID, scan_id: UUID, *, actor_id: UUID | None = None
) -> Scan:
    """Cancel a queued/running scan and its unfinished jobs, and commit (ADR 0021).

    Database-only, like archiving: already-queued tasks run once and drop their output when
    they see the terminal scan, so nothing is revoked in Celery. Cancelling a finished scan
    changes nothing. Raises `ScanNotFound` for a missing or another org's scan.
    """
    scan = session.scalars(
        scoped(Scan, org_id).where(Scan.id == scan_id).with_for_update(),
        execution_options={"populate_existing": True},
    ).one_or_none()
    if scan is None:
        raise ScanNotFound(str(scan_id))
    if scan.status in TERMINAL:
        return scan
    cancel_scan_rows(session, org_id, (scan.id,), job_error="Scan cancelled.")
    audit(
        session,
        org_id,
        "scan.cancelled",
        actor_id=actor_id,
        target_type="scan",
        target_id=str(scan.id),
        details={"reason": "user_requested"},
    )
    session.commit()
    return scan


def cancel_scan_rows(
    session: Session, org_id: UUID, scan_ids: Sequence[UUID], *, job_error: str
) -> Sequence[UUID]:
    """Mark queued/running scans cancelled with their unfinished jobs, without committing.

    Shares its single statement with `cancel_root_scans` (archiving): only the scan filter,
    the job error text and the audit reason differ.
    """
    return _cancel_matching(session, org_id, Scan.id.in_(scan_ids), job_error=job_error)


def cancel_root_scans(
    session: Session, org_id: UUID, root_id: UUID, *, job_error: str
) -> Sequence[UUID]:
    """Cancel the root's queued/running scans and their unfinished jobs, without committing.

    One atomic statement: a scan committed between a separate select and the update would
    otherwise be missed. Rows are locked scan-then-job, the order `run_check` and
    `TrackedTask` use, so a cancellation and a worker finishing a job can't deadlock.
    `clock_timestamp()` is the real time of each update: `now()` is when this transaction
    began, which can precede a worker's `started_at` committed in between, and the schema
    requires `finished_at >= started_at` (ADR 0021).
    """
    return _cancel_matching(session, org_id, Scan.root_asset_id == root_id, job_error=job_error)


def _cancel_matching(
    session: Session, org_id: UUID, scan_filter: ColumnElement[bool], *, job_error: str
) -> Sequence[UUID]:
    cancelled = session.scalars(
        update(Scan)
        .where(
            Scan.org_id == org_id,
            scan_filter,
            Scan.status.in_(_ACTIVE),
        )
        .values(
            status=ScanStatus.CANCELLED,
            started_at=func.coalesce(Scan.started_at, func.clock_timestamp()),
            finished_at=func.clock_timestamp(),
        )
        .returning(Scan.id),
        execution_options={"synchronize_session": "fetch"},
    ).all()
    if not cancelled:
        return []
    session.execute(
        update(Job)
        .where(
            Job.org_id == org_id,
            Job.scan_id.in_(cancelled),
            Job.status.in_(_UNFINISHED_JOBS),
        )
        .values(
            status=JobStatus.CANCELLED,
            error=job_error,
            finished_at=func.greatest(Job.started_at, func.clock_timestamp()),
        ),
        execution_options={"synchronize_session": "fetch"},
    )
    return cancelled


def dispatch_stage(
    session: Session,
    queue: PipelineQueue,
    org_id: UUID,
    job_id: UUID,
    *,
    registry: ScannerRegistry,
    profiles: Mapping[str, ScanProfile],
) -> None:
    job, scan = load_job_scan(session, org_id, job_id)
    if scan.status in TERMINAL or not root_is_active(session, org_id, scan):
        _abandon_stage(session, org_id, job)
        session.commit()
        return
    if scan.started_at is None:
        scan.started_at = func.now()
    scan.status = ScanStatus.RUNNING
    profile = profiles[scan.profile]
    registry.validate(profile)
    discovery = job.stage == "discover"
    names = profile.discover if discovery else profile.checks
    targets = session.scalars(
        scoped(Asset, org_id)
        .where(
            Asset.is_active.is_(True),
            (Asset.id == scan.root_asset_id)
            if discovery
            else ((Asset.id == scan.root_asset_id) | (Asset.parent_id == scan.root_asset_id)),
        )
        .order_by(Asset.id)
    ).all()
    header = tuple(
        _task(
            session,
            scan,
            "discovery" if discovery else "check",
            f"{scanner.queue}.scan",
            scanner=name,
            asset_id=asset.id,
        )
        for name in names
        for scanner in (registry.get(name),)
        for asset in targets
        if asset.type in scanner.asset_types
    )
    # AI triage is not scan work: `finalize_scan` queues it once the scan is complete.
    stages = ("checks",) if discovery else ("persist", "diff", "finalize")
    tail = tuple(_task(session, scan, stage, f"passive.{stage}") for stage in stages)
    error = _task(session, scan, "failure", "passive.fail_scan")
    scan_id = scan.id
    try:
        jobs.enqueue_workflow(session, queue, header, tail, error)
    except Exception:
        fail_scan(session, org_id, scan_id)
        raise


def _task(
    session: Session,
    scan: Scan,
    stage: str,
    task_name: str,
    *,
    scanner: str | None = None,
    asset_id: UUID | None = None,
) -> JobTask:
    # dispatch_stage holds the scan lock: retries reuse rows instead of making new jobs.
    row = session.scalars(
        scoped(Job, scan.org_id).where(
            Job.scan_id == scan.id,
            Job.stage == stage,
            Job.scanner == scanner,
            Job.asset_id == asset_id,
        )
    ).one_or_none()
    if row is None:
        row = jobs.record_job(
            session,
            org_id=scan.org_id,
            scan_id=scan.id,
            stage=stage,
            scanner=scanner,
            asset_id=asset_id,
        )
    return JobTask(task_name, scan.org_id, row.id)


def root_is_active(session: Session, org_id: UUID, scan: Scan) -> bool:
    """Fresh read: an archive may have committed after this task loaded the scan.

    A cancelled scan normally shows its own status; checking the root too means a scan whose
    cancellation somehow missed still can't fan out or complete against an archived root.
    """
    root = session.scalars(
        scoped(Asset, org_id).where(Asset.id == scan.root_asset_id),
        execution_options={"populate_existing": True},
    ).one_or_none()
    return root is not None and root.is_active


def _abandon_stage(session: Session, org_id: UUID, job: Job) -> None:
    """A stage that must not run. Skip its job, and cancel a scan whose cancellation was missed.

    The root is archived or the scan is already terminal (ADR 0021). Cancelling here keeps a scan
    the archive missed from staying `queued` forever; committing the skip ends the stage, so
    `finalize` can complete. Queued work of the batch is left to `finalize`, which skips and
    closes anything still queued when the chord delivers it.
    """
    scan = session.scalars(
        scoped(Scan, org_id).where(Scan.id == job.scan_id).with_for_update(),
        execution_options={"populate_existing": True},
    ).one()
    if scan.status not in TERMINAL:
        scan.status = ScanStatus.CANCELLED
        scan.started_at = func.coalesce(scan.started_at, func.clock_timestamp())
        scan.finished_at = func.clock_timestamp()
    job.status = JobStatus.SKIPPED
    job.error = "Scan is no longer running."
    job.finished_at = func.now()


def load_job_scan(session: Session, org_id: UUID, job_id: UUID) -> tuple[Job, Scan]:
    """Tenant-scoped building block: lock the scan in the caller's transaction, no commit."""
    job = get_scoped(session, Job, job_id, org_id)
    if job is None:
        raise JobNotFound(str(job_id))
    scan = session.scalars(
        scoped(Scan, org_id).where(Scan.id == job.scan_id).with_for_update(),
        execution_options={"populate_existing": True},
    ).one()
    return job, scan


def finalize_scan(
    session: Session, queue: TaskQueue, org_id: UUID, job_id: UUID, events: EventDispatcher
) -> None:
    """Complete the scan, then queue its AI triage job (ADR 0029).

    Triage starts only after the completion committed, so nothing it does can change the scan.
    A broker failure fails just the triage job (`create_job` records it) and is logged here.
    """
    _, scan = load_job_scan(session, org_id, job_id)
    if scan.status in TERMINAL or not root_is_active(session, org_id, scan):
        session.rollback()
        return
    pending = session.scalars(
        scoped(Job, org_id).where(
            Job.scan_id == scan.id,
            # `triage` stays for chains published before ADR 0029; that stage now completes
            # at once, ahead of `finalize`.
            Job.stage.in_(("discovery", "check", "persist", "diff", "triage")),
            Job.status.in_((JobStatus.QUEUED, JobStatus.RUNNING)),
        )
    ).all()
    if pending:
        raise ValueError("cannot finalize pending work")
    scan.status = ScanStatus.COMPLETED
    scan.finished_at = func.now()
    for unused in session.scalars(
        scoped(Job, org_id).where(
            Job.scan_id == scan.id,
            Job.stage == "failure",
            Job.status == JobStatus.QUEUED,
        )
    ):
        unused.status = JobStatus.SKIPPED
        unused.finished_at = func.now()
    event = ScanCompleted(org_id, scan.id)
    audit(session, org_id, "scan.completed", target_type="scan", target_id=str(scan.id))
    session.commit()
    events.publish(event)
    try:
        jobs.create_job(
            session,
            queue,
            org_id=org_id,
            scan_id=event.scan_id,
            stage="triage",
            task_name="ai.triage",
        )
    except Exception as exc:
        # The scan is already complete; nothing about triage may fail the `finalize` task.
        log.warning(
            "triage not queued",
            org_id=str(org_id),
            scan_id=str(event.scan_id),
            error=jobs.describe_error(exc),
        )
        notifications.queue_scan_notification(session, queue, org_id, event.scan_id)


def fail_scan(session: Session, org_id: UUID, scan_id: UUID) -> None:
    scan = session.scalars(
        scoped(Scan, org_id).where(Scan.id == scan_id).with_for_update(),
        execution_options={"populate_existing": True},
    ).one_or_none()
    if scan is not None and scan.status not in TERMINAL:
        scan.status = ScanStatus.FAILED
        if scan.started_at is None:
            scan.started_at = func.now()
        scan.finished_at = func.now()
        for pending in session.scalars(
            scoped(Job, org_id).where(
                Job.scan_id == scan.id,
                Job.status == JobStatus.QUEUED,
                Job.stage != "failure",
            )
        ):
            pending.status = JobStatus.CANCELLED
            pending.error = "Scan pipeline failed."
            pending.finished_at = func.now()
        audit(session, org_id, "scan.failed", target_type="scan", target_id=str(scan.id))
    session.commit()


def fail_job_scan(session: Session, org_id: UUID, job_id: UUID) -> None:
    """Fail a scan after a pipeline task error, including errors before canvas publication."""
    job = get_scoped(session, Job, job_id, org_id)
    if job is not None and job.scan_id is not None:  # jobs outside a scan have no scan to fail
        fail_scan(session, org_id, job.scan_id)
