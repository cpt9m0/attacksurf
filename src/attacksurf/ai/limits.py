"""Time limits every provider adapter applies to its SDK client (ADR 0019).

The SDKs default to a 600 s timeout, longer than a Celery task may run, so each adapter builds
its client with `REQUEST_TIMEOUT_SECONDS` and `MAX_RETRIES` (its tests assert it).

Those two values don't bound a call's total time on their own: a read timeout limits the wait
for each chunk of a response, not the whole response, and the SDKs sleep for whatever
`Retry-After` the server sends. So each adapter (PR 2, PR 3) must also enforce
`CALL_DEADLINE_SECONDS` across one `complete()` call, counting every attempt, SDK retry,
`Retry-After` wait and format-fallback request, and raise `LLMUnavailable` when it would be
exceeded. Its tests prove that with a stubbed large `Retry-After` and a stubbed slow response.
"""

REQUEST_TIMEOUT_SECONDS = 60.0  # one HTTP request; reasoning models need tens of seconds
MAX_RETRIES = 1  # SDK retries per request (429, 5xx, timeouts); Celery retries the task after
CALL_DEADLINE_SECONDS = 240.0  # total for one complete() call, enforced by each adapter
