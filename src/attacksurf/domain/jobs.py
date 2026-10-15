"""Background jobs: how services enqueue work, and which failures are worth retrying."""

from typing import Protocol
from uuid import UUID


class JobNotFound(LookupError):
    """No such job in this org (or another org's job: never says which)."""


class TransientJobError(Exception):
    """A failure that may pass on its own (timeout, rate limit, upstream 5xx): retry later."""


class TaskQueue(Protocol):
    def enqueue(self, task_name: str, *, org_id: UUID, job_id: UUID) -> str:
        """Send the task for an already committed `Job`; returns the queue's task id."""
        ...
