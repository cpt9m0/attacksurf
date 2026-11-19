"""Housekeeping tasks."""

from datetime import UTC, datetime

import structlog

from attacksurf.infra.queue import CeleryTaskQueue
from attacksurf.scanners.registry import registry
from attacksurf.services import artifacts, scan_schedules
from attacksurf.workers import runtime
from attacksurf.workers.app import app
from attacksurf.workers.base import TrackedTask

log = structlog.get_logger(__name__)


@app.task(base=TrackedTask, name="passive.ping")
def ping(*, org_id: str, job_id: str) -> None:
    """Does nothing: proves a worker picks up a job and records its lifecycle."""
    log.info("pong")


@app.task(name="passive.purge_expired_artifacts")
def purge_expired_artifacts() -> None:
    """Beat entry point: delete artifacts past retention and stale staged plaintext (#85).

    System-wide (no tenant, no job row), so it isn't a `TrackedTask`. It runs even with no
    encryption key configured: deleting needs none.
    """
    with runtime.session_factory()() as session:
        purged = artifacts.purge_expired(session, runtime.artifact_store(), now=datetime.now(UTC))
    log.info("artifact purge ran", artifacts=purged)


@app.task(name="passive.enqueue_due_scans")
def enqueue_due_scans() -> None:
    """Beat entry point: start scans whose root is due (#27).

    System-wide like the purge, but each started scan keeps its normal tracked jobs. Errors
    are logged by type only and re-raised with a sanitized message, so broker or driver
    details never reach Celery's result backend.
    """
    try:
        with runtime.session_factory()() as session:
            count = scan_schedules.enqueue_due_scans(
                session,
                CeleryTaskQueue(app),
                now=datetime.now(UTC),
                registry=registry,
                max_starts_per_hour=runtime.settings().scan_max_starts_per_hour,
            )
    except Exception as exc:
        log.error("scan schedule tick failed", error=type(exc).__name__)
        raise RuntimeError("Scan schedule tick failed.") from None
    if count:
        log.info("scheduled scans queued", count=count)
