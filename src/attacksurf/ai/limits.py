"""Time limits every provider adapter applies to its SDK client (ADR 0019).

The SDKs default to a 600 s timeout, longer than a Celery task may run, so each adapter builds
its client with `REQUEST_TIMEOUT_SECONDS` and `MAX_RETRIES` (its tests assert it).

`MAX_RETRIES` is 0 (ADR 0024): Celery retries the whole task on `LLMUnavailable` (with backoff,
recorded on the job), so SDK retries would only multiply requests and park a worker in
`Retry-After` sleeps.

The request timeout still doesn't bound a call's total time: a read timeout limits the wait for
each chunk of a response, not the whole response (a server can trickle bytes forever), and one
`complete()` call can make several requests (the corrective retry, the format fallback). So
each adapter also enforces `CALL_DEADLINE_SECONDS` across one `complete()` call: it caps each
request's timeout at the time left, builds its SDK client on
`ai/providers/deadline.deadline_transport()` and sends inside `until(deadline)`, so the request
itself ends at the deadline (nothing is left running), and raises `LLMUnavailable`. Its tests
prove that against a trickling local server, and that a 429 with a large `Retry-After` fails at
once instead of sleeping.
"""

REQUEST_TIMEOUT_SECONDS = 60.0  # one HTTP request; reasoning models need tens of seconds
MAX_RETRIES = 0  # no SDK retries: Celery retries the task (TrackedTask backoff)
CALL_DEADLINE_SECONDS = 240.0  # total for one complete() call, enforced by each adapter
