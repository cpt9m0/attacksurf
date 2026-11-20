"""AI worker tasks. Thin: one service call, IDs in, no secrets or prompts out.

They use `TrackedTask` (or `ChordTask` inside a triage run), never `PipelineTask`: an AI failure
fails its own job, never a scan.
"""

from uuid import UUID

from attacksurf.infra.queue import CeleryTaskQueue
from attacksurf.services import org_settings
from attacksurf.services import triage as triage_service
from attacksurf.workers import runtime
from attacksurf.workers.app import app
from attacksurf.workers.base import ChordTask, TrackedTask


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
    """A completed scan's AI triage (ADR 0029): plans one batch job per asset with work."""
    with runtime.session_factory()() as session:
        triage_service.run_triage(
            session,
            CeleryTaskQueue(app),
            UUID(org_id),
            UUID(job_id),
            runtime.settings(),
            resolver=runtime.dns_resolver(),
        )


@app.task(bind=True, base=ChordTask, name="ai.triage_batch")
def triage_batch(self: ChordTask, *, org_id: str, job_id: str) -> None:
    """One LLM call for one asset's findings."""
    with runtime.session_factory()() as session:
        triage_service.run_triage_batch(
            session,
            UUID(org_id),
            UUID(job_id),
            runtime.settings(),
            retry_allowed=self.request.retries < (self.max_retries or 0),
            resolver=runtime.dns_resolver(),
        )


@app.task(base=ChordTask, name="ai.triage_done")
def triage_done(*, org_id: str, job_id: str) -> None:
    """Runs once every batch of the run has ended."""
    with runtime.session_factory()() as session:
        triage_service.finish_triage(session, UUID(org_id), UUID(job_id))


@app.task(base=TrackedTask, name="ai.triage_failed")
def triage_failed(*, org_id: str, job_id: str) -> None:
    """The run's error callback: a batch crashed, so its queued jobs are closed."""
    with runtime.session_factory()() as session:
        triage_service.fail_triage(session, UUID(org_id), UUID(job_id))
