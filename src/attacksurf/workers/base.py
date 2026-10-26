"""`TrackedTask`: Celery base class that mirrors a task's lifecycle onto its `Job` row.

Every tracked task takes the keyword arguments `org_id` and `job_id` (strings, JSON-safe).
"""

import traceback
from typing import Any
from uuid import UUID

import structlog
from celery import Task
from sqlalchemy.exc import InterfaceError, OperationalError
from sqlalchemy.orm import Session

from attacksurf.domain.jobs import JobNotFound, TransientJobError
from attacksurf.services import jobs
from attacksurf.workers import runtime

log = structlog.get_logger(__name__)

# The database itself is briefly unreachable (restart, failover, network blip).
DB_UNAVAILABLE = (OperationalError, InterfaceError)
# Celery retries plus one redelivery after a lost worker; beyond that the task is poison.
EXTRA_DELIVERIES = 2


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
            try:
                with self._session() as session:
                    job = jobs.mark_job_running(
                        session,
                        org_id,
                        job_id,
                        self.request.id,
                        max_attempts=(self.max_retries or 0) + EXTRA_DELIVERIES,
                    )
                    if job is None:
                        log.info("job finished or out of attempts, not running it")
                        return None
                    structlog.contextvars.bind_contextvars(scan_id=str(job.scan_id))
            except DB_UNAVAILABLE as exc:
                # Outside `run`, so Celery's autoretry doesn't apply: without this the message
                # is acked and the job stays `queued` forever.
                raise self.retry(exc=exc, countdown=self._backoff()) from exc
            log.info("job started")
            result = super().__call__(*args, **kwargs)
            try:
                with self._session() as session:
                    jobs.mark_job_completed(session, org_id, job_id)
            except DB_UNAVAILABLE as exc:
                raise self.retry(
                    exc=exc, countdown=self._backoff()
                ) from exc  # tasks are idempotent
            log.info("job completed")
            return result
        finally:
            structlog.contextvars.clear_contextvars()

    def on_retry(self, exc: Exception, task_id: str, args: Any, kwargs: Any, einfo: Any) -> None:
        self._record(kwargs, exc, retrying=True)

    def on_failure(self, exc: Exception, task_id: str, args: Any, kwargs: Any, einfo: Any) -> None:
        self._record(kwargs, exc, retrying=False)

    def _record(self, kwargs: dict[str, Any], exc: BaseException, *, retrying: bool) -> None:
        ids = _job_ids(kwargs)
        # No exc_info: a traceback ends with the exception's message, which can hold tokens or
        # scan evidence. Log the frames and the sanitized error instead.
        log.warning(
            "job retrying" if retrying else "job failed",
            task=self.name,
            org_id=str(ids[0]) if ids else None,
            job_id=str(ids[1]) if ids else None,
            error=jobs.describe_error(exc),
            stack="".join(traceback.format_tb(exc.__traceback__)),
        )
        if ids is None:
            return
        org_id, job_id = ids
        try:
            with self._session() as session:
                if retrying:
                    jobs.mark_job_retrying(session, org_id, job_id, exc)
                else:
                    jobs.mark_job_failed(session, org_id, job_id, exc)
        except JobNotFound:
            log.error("job row missing", org_id=str(org_id), job_id=str(job_id))
        except DB_UNAVAILABLE as db_exc:
            log.error("could not record job state", error=jobs.describe_error(db_exc))

    def _backoff(self) -> int:
        return min(2**self.request.retries, self.retry_backoff_max)

    @staticmethod
    def _session() -> Session:
        return runtime.session_factory()()


def _job_ids(kwargs: dict[str, Any]) -> tuple[UUID, UUID] | None:
    try:
        return UUID(str(kwargs["org_id"])), UUID(str(kwargs["job_id"]))
    except (KeyError, ValueError):
        return None
