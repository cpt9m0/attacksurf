"""Ownership verification tasks (#14). Thin: one service call, IDs in, no evidence out."""

from datetime import UTC, datetime
from uuid import UUID

import structlog

from attacksurf.infra.db.models import Job
from attacksurf.infra.db.tenancy import get_scoped
from attacksurf.infra.queue import CeleryTaskQueue
from attacksurf.services import ownership, verifications
from attacksurf.workers import runtime
from attacksurf.workers.app import app
from attacksurf.workers.base import TrackedTask

log = structlog.get_logger(__name__)


@app.task(base=TrackedTask, name="passive.verify_ownership")
def verify_ownership(*, org_id: str, job_id: str) -> None:
    """Check one proof's TXT record; the job row says which proof (ADR 0014)."""
    with runtime.session_factory()() as session:
        job = get_scoped(session, Job, UUID(job_id), UUID(org_id))
        if job is None:
            raise ValueError("verification job is gone")
        verification_id = (
            verifications.verification_for_asset(session, job.org_id, job.asset_id)
            if job.asset_id is not None
            else None
        )
        if verification_id is None:
            log.info("verification row is gone, nothing to check")
            return
        try:
            status = ownership.check_ownership(
                session,
                runtime.txt_lookup(),
                org_id=UUID(org_id),
                verification_id=verification_id,
            )
        except ownership.VerificationNotFound:
            log.info("verification row is gone, nothing to check")
            return
    log.info("ownership checked", status=str(status))


@app.task(name="passive.reverify_ownership")
def reverify_ownership() -> None:
    """Beat entry point: queue a tracked check for every proof that is due.

    Re-verification is system-wide (no tenant), so it isn't a `TrackedTask`: it only creates
    the per-proof jobs, which are tracked and show up in job history.
    """
    with runtime.session_factory()() as session:
        queued = verifications.enqueue_due_checks(
            session, CeleryTaskQueue(app), now=datetime.now(UTC)
        )
    log.info("re-verification queued", proofs=queued)
