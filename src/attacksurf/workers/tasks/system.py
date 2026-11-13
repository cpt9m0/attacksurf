"""Housekeeping tasks."""

from datetime import UTC, datetime

import structlog

from attacksurf.services import artifacts
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
