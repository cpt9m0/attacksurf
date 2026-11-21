"""Notification worker tasks. Thin: one service call, IDs in, no secrets out."""

from uuid import UUID

from attacksurf.services import notifications
from attacksurf.workers import runtime
from attacksurf.workers.app import app
from attacksurf.workers.base import TrackedTask


@app.task(base=TrackedTask, name="passive.notify_scan")
def notify_scan(*, org_id: str, job_id: str) -> None:
    """Deliver per-user email digest notifications for a completed scan (#28)."""
    with runtime.session_factory()() as session:
        notifications.run_scan_notification(
            session,
            UUID(org_id),
            UUID(job_id),
            runtime.email_sender(),
            app_base_url=runtime.settings().app_base_url,
        )
