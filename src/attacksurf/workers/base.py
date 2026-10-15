"""`TrackedTask`: Celery base class that mirrors a task's lifecycle onto its `Job` row.

Every tracked task takes the keyword arguments `org_id` and `job_id` (strings, JSON-safe).
"""

from typing import Any
from uuid import UUID

import structlog
from celery import Task
from sqlalchemy.orm import Session

from attacksurf.domain.jobs import JobNotFound, TransientJobError
from attacksurf.services import jobs
from attacksurf.workers import runtime

log = structlog.get_logger(__name__)


class TrackedTask(Task):
    autoretry_for = (TransientJobError,)
    max_retries = 3
    retry_backoff = True  # 1s, 2s, 4s, ... capped below, with jitter
    retry_backoff_max = 600
    retry_jitter = True
    soft_time_limit = 300  # SoftTimeLimitExceeded inside the task -> job failed
    time_limit = 330

    def __call__(self, *args: Any, **kwargs: Any) -> Any:
        ids = _job_ids(kwargs)
        if ids is None:
            raise ValueError("tracked tasks need org_id and job_id keyword arguments (UUIDs)")
        org_id, job_id = ids
        structlog.contextvars.clear_contextvars()
        structlog.contextvars.bind_contextvars(
            org_id=str(org_id), job_id=str(job_id), task=self.name, task_id=self.request.id
        )
        try:
            with self._session() as session:
                job = jobs.mark_job_running(session, org_id, job_id, self.request.id)
                if job is None:
                    log.info("job already finished, skipping redelivered task")
                    return None
                structlog.contextvars.bind_contextvars(scan_id=str(job.scan_id))
            log.info("job started")
            result = super().__call__(*args, **kwargs)
            with self._session() as session:
                jobs.mark_job_completed(session, org_id, job_id)
            log.info("job completed")
            return result
        finally:
            structlog.contextvars.clear_contextvars()

    def on_retry(self, exc: Exception, task_id: str, args: Any, kwargs: Any, einfo: Any) -> None:
        self._record(kwargs, exc, retrying=True)

    def on_failure(self, exc: Exception, task_id: str, args: Any, kwargs: Any, einfo: Any) -> None:
        self._record(kwargs, exc, retrying=False)

    def _record(self, kwargs: dict[str, Any], exc: Exception, *, retrying: bool) -> None:
        ids = _job_ids(kwargs)
        if ids is None:
            log.error("task without valid job ids failed", task=self.name, error=type(exc).__name__)
            return
        org_id, job_id = ids
        log.warning(
            "job retrying" if retrying else "job failed",
            org_id=str(org_id),
            job_id=str(job_id),
            task=self.name,
            exc_info=exc,
        )
        try:
            with self._session() as session:
                if retrying:
                    jobs.mark_job_retrying(session, org_id, job_id, exc)
                else:
                    jobs.mark_job_failed(session, org_id, job_id, exc)
        except JobNotFound:
            log.error("job row missing", org_id=str(org_id), job_id=str(job_id))

    @staticmethod
    def _session() -> Session:
        return runtime.session_factory()()


def _job_ids(kwargs: dict[str, Any]) -> tuple[UUID, UUID] | None:
    try:
        return UUID(str(kwargs["org_id"])), UUID(str(kwargs["job_id"]))
    except (KeyError, ValueError):
        return None
