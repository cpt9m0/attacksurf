"""AI worker tasks (#24). Thin: one service call, IDs in, no secrets or prompts out."""

from uuid import UUID

from attacksurf.services import org_settings
from attacksurf.workers import runtime
from attacksurf.workers.app import app
from attacksurf.workers.base import TrackedTask


@app.task(base=TrackedTask, name="ai.test_connection")
def test_connection(*, org_id: str, job_id: str) -> None:
    """Run a tiny structured completion probe against the org's active LLM config."""
    with runtime.session_factory()() as session:
        org_settings.run_ai_connection_test(
            session,
            UUID(org_id),
            UUID(job_id),
            runtime.settings(),
            resolver=runtime.dns_resolver(),
        )
