"""Thin pipeline entry points. Redis receives IDs/None, never ScanOutput/evidence."""

from typing import Any
from uuid import UUID

import structlog
from celery.exceptions import Retry

from attacksurf.domain.rules import RULES
from attacksurf.domain.scanners import ScannerError
from attacksurf.infra.events import dispatcher
from attacksurf.infra.queue import CeleryTaskQueue
from attacksurf.scanners.profiles import PROFILES
from attacksurf.scanners.registry import registry
from attacksurf.services import jobs, scans
from attacksurf.services.scanner_jobs import run_check
from attacksurf.workers import runtime
from attacksurf.workers.app import app
from attacksurf.workers.base import TrackedTask


class PipelineTask(TrackedTask):
    ignore_result = False  # required for Redis chords, including failed/skipped scanner receipts

    def __call__(self, *args: Any, **kwargs: Any) -> Any:
        try:
            return super().__call__(*args, **kwargs)
        except Retry as exc:
            # The backend stores retry exceptions too (e.g. a DB URL in a driver error).
            safe = ScannerError(jobs.describe_error(exc.exc)) if exc.exc is not None else None
            raise Retry(
                exc=safe,
                when=exc.when,
                is_eager=getattr(exc, "is_eager", False),
                sig=getattr(exc, "sig", None),
            ) from None
        except Exception as exc:
            # ChordError embeds repr(exception), so sanitize before Celery sees the failure.
            raise ScannerError(jobs.describe_error(exc)) from None

    def on_failure(self, exc: Exception, task_id: str, args: Any, kwargs: Any, einfo: Any) -> None:
        super().on_failure(exc, task_id, args, kwargs, einfo)
        try:
            with self._session() as session:
                scans.fail_job_scan(session, UUID(kwargs["org_id"]), UUID(kwargs["job_id"]))
        except Exception as failure:
            structlog.get_logger(__name__).error(
                "could not fail scan", error=jobs.describe_error(failure)
            )


@app.task(base=PipelineTask, name="passive.discover")
def discover(*, org_id: str, job_id: str) -> None:
    _dispatch(org_id, job_id)


@app.task(base=PipelineTask, name="passive.checks")
def checks(*, org_id: str, job_id: str) -> None:
    _dispatch(org_id, job_id)


def _dispatch(org_id: str, job_id: str) -> None:
    with runtime.session_factory()() as session:
        scans.dispatch_stage(
            session,
            CeleryTaskQueue(app),
            UUID(org_id),
            UUID(job_id),
            registry=registry,
            profiles=PROFILES,
        )


@app.task(bind=True, base=PipelineTask, name="passive.scan")
def scan(self: PipelineTask, *, org_id: str, job_id: str) -> None:
    with runtime.session_factory()() as session:
        run_check(
            session,
            UUID(org_id),
            UUID(job_id),
            registry=registry,
            gate=runtime.scanner_gate(),
            events=dispatcher,
            catalog=RULES,
            retry_allowed=self.request.retries < (self.max_retries or 0),
        )


@app.task(base=PipelineTask, name="passive.persist")
def persist(*, org_id: str, job_id: str) -> None:
    """Barrier: outputs were committed by scanner jobs before their chord receipts."""


@app.task(base=PipelineTask, name="passive.diff")
def diff(*, org_id: str, job_id: str) -> None:
    """Lifecycle diff/stats belong to #20; never infer fixes from absent/failed results."""


@app.task(base=PipelineTask, name="passive.triage")
def triage(*, org_id: str, job_id: str) -> None:
    """AI triage belongs to #25; no provider calls in this issue."""


@app.task(base=PipelineTask, name="passive.finalize")
def finalize(*, org_id: str, job_id: str) -> None:
    with runtime.session_factory()() as session:
        scans.finalize_scan(session, UUID(org_id), UUID(job_id), dispatcher)


@app.task(base=PipelineTask, name="passive.fail_scan")
def fail_scan(*, org_id: str, job_id: str) -> None:
    with runtime.session_factory()() as session:
        scans.fail_job_scan(session, UUID(org_id), UUID(job_id))
