"""Job lifecycle: create + enqueue, and the state changes `workers.base.TrackedTask` records.

Each function is one use case and commits. Timestamps come from the database clock, so
`finished_at >= started_at` holds even when a retry runs on a worker with a skewed clock.
"""

from uuid import UUID

import structlog
from sqlalchemy import func
from sqlalchemy.orm import Session

from attacksurf.domain.jobs import JobNotFound, TaskQueue
from attacksurf.domain.scans import JobStatus
from attacksurf.infra.db.models import Job
from attacksurf.infra.db.tenancy import scoped

MAX_ERROR_LENGTH = 2000
FINISHED = frozenset(
    {JobStatus.COMPLETED, JobStatus.FAILED, JobStatus.CANCELLED, JobStatus.SKIPPED}
)

log = structlog.get_logger(__name__)


def create_job(
    session: Session,
    queue: TaskQueue,
    *,
    org_id: UUID,
    scan_id: UUID,
    stage: str,
    task_name: str,
    scanner: str | None = None,
    asset_id: UUID | None = None,
) -> Job:
    """Add a queued job and send its task. Commits first: a worker must find the row."""
    job = Job(
        org_id=org_id,
        scan_id=scan_id,
        stage=stage,
        scanner=scanner,
        asset_id=asset_id,
        status=JobStatus.QUEUED,
    )
    session.add(job)
    session.flush()
    job_id = job.id  # read before commit: no reload query between commit and enqueue
    session.commit()
    try:
        queue.enqueue(task_name, org_id=org_id, job_id=job_id)
    except Exception as exc:
        # Broker down: without this the job would show as queued forever.
        mark_job_failed(session, org_id, job_id, exc)
        raise
    return job


def mark_job_running(
    session: Session, org_id: UUID, job_id: UUID, celery_task_id: str | None
) -> Job | None:
    """Start an attempt. None if the job already finished (a redelivered task): skip it."""
    job = _lock(session, org_id, job_id)
    if job.status in FINISHED:
        session.rollback()
        return None
    # RUNNING again is fine: the worker died mid-task and the broker redelivered it.
    job.status = JobStatus.RUNNING
    job.attempts += 1
    job.celery_task_id = celery_task_id
    if job.started_at is None:
        job.started_at = func.now()
    session.commit()
    return job


def mark_job_completed(session: Session, org_id: UUID, job_id: UUID) -> None:
    _finish(session, org_id, job_id, JobStatus.COMPLETED, error=None)


def mark_job_failed(session: Session, org_id: UUID, job_id: UUID, exc: BaseException) -> None:
    _finish(session, org_id, job_id, JobStatus.FAILED, error=describe_error(exc))


def mark_job_retrying(session: Session, org_id: UUID, job_id: UUID, exc: BaseException) -> None:
    job = _lock(session, org_id, job_id)
    if job.status in FINISHED:
        session.rollback()
        return
    job.status = JobStatus.QUEUED
    job.error = describe_error(exc)
    session.commit()


def describe_error(exc: BaseException) -> str:
    """Exception type + message, capped. Full tracebacks go to the logs only."""
    message = str(exc)
    text = f"{type(exc).__name__}: {message}" if message else type(exc).__name__
    return text[:MAX_ERROR_LENGTH]


def _finish(
    session: Session, org_id: UUID, job_id: UUID, status: JobStatus, *, error: str | None
) -> None:
    job = _lock(session, org_id, job_id)
    if job.status in FINISHED:
        # e.g. cancelled while running: the cancellation wins.
        log.info("job already finished", job_status=job.status, ignored_status=status)
        session.rollback()
        return
    job.status = status
    job.error = error
    job.finished_at = func.now()
    session.commit()


def _lock(session: Session, org_id: UUID, job_id: UUID) -> Job:
    # Row lock: a redelivered duplicate can't interleave its state changes with ours.
    job = session.scalars(
        scoped(Job, org_id).where(Job.id == job_id).with_for_update()
    ).one_or_none()
    if job is None:
        raise JobNotFound(str(job_id))
    return job
