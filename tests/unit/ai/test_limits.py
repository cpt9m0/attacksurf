"""Checks that the shared limits are consistent with each other and with the Celery task limit.

These are checks on the configured values only: whether a call actually stops at
`CALL_DEADLINE_SECONDS` is each adapter's job, proven in its own tests (ADR 0019).
"""

from attacksurf.ai.limits import CALL_DEADLINE_SECONDS, MAX_RETRIES, REQUEST_TIMEOUT_SECONDS
from attacksurf.workers.base import TrackedTask

# Room for the task's own work (DB reads/writes, usage recording) after the LLM call.
TASK_HEADROOM_SECONDS = 30


def test_call_deadline_leaves_room_inside_the_task_soft_time_limit() -> None:
    # A call that stops at its deadline ends as LLMUnavailable (retried), not a killed task.
    assert TrackedTask.soft_time_limit is not None
    assert TrackedTask.soft_time_limit - TASK_HEADROOM_SECONDS >= CALL_DEADLINE_SECONDS


def test_one_request_with_its_sdk_retries_fits_inside_the_call_deadline() -> None:
    assert (MAX_RETRIES + 1) * REQUEST_TIMEOUT_SECONDS <= CALL_DEADLINE_SECONDS
