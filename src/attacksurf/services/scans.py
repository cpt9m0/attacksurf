"""Scan use cases and pipeline planning. Celery canvas stays behind PipelineQueue."""

from collections.abc import Mapping
from uuid import UUID

from sqlalchemy import func
from sqlalchemy.orm import Session

from attacksurf.domain.assets import AssetNotFound, AssetType
from attacksurf.domain.events import EventDispatcher, ScanCompleted
from attacksurf.domain.jobs import JobNotFound, JobTask, PipelineQueue, TaskQueue
from attacksurf.domain.scanners import ScanProfile
from attacksurf.domain.scans import JobStatus, ScanError, ScanStatus, ScanTrigger
from attacksurf.infra.db.models import Asset, Job, Scan
from attacksurf.infra.db.tenancy import get_scoped, scoped
from attacksurf.scanners.registry import ScannerRegistry
from attacksurf.services import jobs
from attacksurf.services.audit import audit

TERMINAL = {ScanStatus.COMPLETED, ScanStatus.FAILED, ScanStatus.CANCELLED}


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
) -> Scan:
    selected = profiles.get(profile)
    if selected is None:
        raise ScanError("Unknown scan profile.")
    registry.validate(selected)
    if not selected.discover and not selected.checks:
        raise ScanError("profile has no scanners")
    root = get_scoped(session, Asset, root_asset_id, org_id)
    if root is None or root.parent_id is not None or not root.is_active:
        raise AssetNotFound("Root asset not found.")
    if root.type != AssetType.DOMAIN:
        raise ScanError("only domain root scans are supported")
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
    audit(session, org_id, "scan.started", target_type="scan", target_id=str(scan_id))
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
    if scan.status in TERMINAL:
        session.rollback()
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
    stages = ("checks",) if discovery else ("persist", "diff", "triage", "finalize")
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


def finalize_scan(session: Session, org_id: UUID, job_id: UUID, events: EventDispatcher) -> None:
    _, scan = load_job_scan(session, org_id, job_id)
    if scan.status in TERMINAL:
        session.rollback()
        return
    pending = session.scalars(
        scoped(Job, org_id).where(
            Job.scan_id == scan.id,
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
    if job is not None:
        fail_scan(session, org_id, job.scan_id)
