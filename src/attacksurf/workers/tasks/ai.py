"""AI worker tasks. Thin: one service call, IDs in, no secrets or prompts out.

They use `TrackedTask`, never `PipelineTask`: an AI failure fails its own job, never a scan.
"""

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


@app.task(base=TrackedTask, name="ai.triage")
def triage(*, org_id: str, job_id: str) -> None:
    """A completed scan's AI triage (ADR 0029); skipped with a notice when AI is off or over
    budget."""
    with runtime.session_factory()() as session:
        org_settings.enforce_triage_budget(
            session,
            UUID(org_id),
            UUID(job_id),
            runtime.settings(),
            resolver=runtime.dns_resolver(),
        )
