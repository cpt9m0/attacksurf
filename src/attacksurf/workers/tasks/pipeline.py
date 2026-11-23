"""Thin pipeline entry points. Redis receives IDs/None, never ScanOutput/evidence."""

from typing import Any
from uuid import UUID

import structlog

from attacksurf.domain.rules import RULES
from attacksurf.domain.scanners import ScannerError
from attacksurf.infra.events import dispatcher
from attacksurf.infra.queue import CeleryTaskQueue
from attacksurf.scanners.profiles import WORKER_PROFILES
from attacksurf.scanners.registry import registry
from attacksurf.services import jobs, scan_diff, scans
from attacksurf.services.scanner_jobs import run_check
from attacksurf.workers import runtime
from attacksurf.workers.app import app
from attacksurf.workers.base import ChordTask


class PipelineTask(ChordTask):
    """A scan pipeline stage: a failure that escapes it fails the scan."""

    sanitized_error = ScannerError

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
            profiles=WORKER_PROFILES,
        )


@app.task(bind=True, base=PipelineTask, name="passive.scan", mark_completed=False)
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
            profiles=WORKER_PROFILES,
        )


@app.task(base=PipelineTask, name="passive.persist")
def persist(*, org_id: str, job_id: str) -> None:
    """Barrier: outputs were committed by scanner jobs before their chord receipts."""


@app.task(base=PipelineTask, name="passive.diff")
def diff(*, org_id: str, job_id: str) -> None:
    """Finding lifecycle and scan stats (ADR 0027); never infer fixes from absent results."""
    with runtime.session_factory()() as session:
        scan_diff.diff_scan(session, UUID(org_id), UUID(job_id), dispatcher)


@app.task(base=PipelineTask, name="passive.triage")
def triage(*, org_id: str, job_id: str) -> None:
    """No-op kept for one release: chains published before ADR 0029 still name this stage.

    Triage now runs after the scan as `ai.triage`; completing this job lets `finalize` run.
    Delete it once no chain from before that release can still be queued.
    """


@app.task(base=PipelineTask, name="passive.finalize")
def finalize(*, org_id: str, job_id: str) -> None:
    with runtime.session_factory()() as session:
        scans.finalize_scan(session, CeleryTaskQueue(app), UUID(org_id), UUID(job_id), dispatcher)


@app.task(base=PipelineTask, name="passive.fail_scan")
def fail_scan(*, org_id: str, job_id: str) -> None:
    with runtime.session_factory()() as session:
        scans.fail_job_scan(session, UUID(org_id), UUID(job_id))
