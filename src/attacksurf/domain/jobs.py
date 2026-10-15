"""Background jobs: how services enqueue work, and which failures are worth retrying."""

from typing import Protocol
from uuid import UUID


class JobNotFound(LookupError):
    """No such job in this org (or another org's job: never says which)."""


class JobError(Exception):
    """Raised by our own code with a message written for users: safe to store on the `Job`.

    Never put secrets, tokens, authenticated URLs or scan evidence in the message. Other
    exceptions are stored by type name only, since their messages can contain any of those.
    """


class TransientJobError(JobError):
    """A failure that may pass on its own (timeout, rate limit, upstream 5xx): retry later."""


class TaskQueue(Protocol):
    def enqueue(self, task_name: str, *, org_id: UUID, job_id: UUID) -> str:
        """Send the task for an already committed `Job`; returns the queue's task id."""
        ...
