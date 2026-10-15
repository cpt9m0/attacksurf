"""Housekeeping tasks."""

import structlog

from attacksurf.workers.app import app
from attacksurf.workers.base import TrackedTask

log = structlog.get_logger(__name__)


@app.task(base=TrackedTask, name="passive.ping")
def ping(*, org_id: str, job_id: str) -> None:
    """Does nothing: proves a worker picks up a job and records its lifecycle."""
    log.info("pong")
