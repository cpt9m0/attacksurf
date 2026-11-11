"""Time limits every provider adapter applies to its SDK client (ADR 0019).

The SDKs default to a 600 s timeout, longer than a Celery task may run, so each adapter builds
its client with `REQUEST_TIMEOUT_SECONDS` and `MAX_RETRIES` (its tests assert it).

`MAX_RETRIES` is 0: Celery retries the whole task on `LLMUnavailable` (with backoff, recorded on
the job), so SDK retries would only multiply requests and park a worker in `Retry-After` sleeps.

The request timeout still doesn't bound a call's total time: a read timeout limits the wait for
each chunk of a response, not the whole response, and one `complete()` call can make several
requests (the corrective retry, PR 3's format fallback). So each adapter (PR 2, PR 3) must also
enforce `CALL_DEADLINE_SECONDS` across one `complete()` call and raise `LLMUnavailable` when it
would be exceeded. Its tests prove that with a stubbed slow response, and that a 429 with a
large `Retry-After` fails at once instead of sleeping. `ai/providers/anthropic.py` shows one
way: a per-request timeout capped at the time left, and a thread abandoned at the deadline.
"""

REQUEST_TIMEOUT_SECONDS = 60.0  # one HTTP request; reasoning models need tens of seconds
MAX_RETRIES = 0  # no SDK retries: Celery retries the task (TrackedTask backoff)
CALL_DEADLINE_SECONDS = 240.0  # total for one complete() call, enforced by each adapter
