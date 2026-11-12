# 0024. LLM calls send no sampling settings, and SDK clients don't retry

- Status: accepted (supersedes ADR 0019's `temperature` parameter and SDK retry count)
- Date: 2026-11-12

## Context
ADR 0019 (#131) gave `LLMProvider.complete()` an optional `temperature=None` and set
`ai/limits.MAX_RETRIES` to 1 for every SDK client. It left one question open for the two adapter
implementers (PR 2 Anthropic, PR 3 OpenAI-compatible): whether `MAX_RETRIES = 0` should leave
every retry to Celery. ADR 0019 also requires both implementers to agree to any contract change.
Building the Anthropic adapter (#23, PR 2, merged as #147) showed:

- The `anthropic` 2.x SDK sends API version `2026-10-21`, which rejects `temperature`, `top_p`
  and `top_k` with a 400 on every model. OpenAI reasoning models reject non-default values
  too. No caller passed a temperature.
- `LLMUnavailable` is a `TransientJobError`, so Celery's `TrackedTask` already retries the task
  (3 times, 1/2/4 s backoff with jitter, recorded on the job). SDK retries stack on top of that.
  Under errors, one `complete()` call (up to 2 attempts with the corrective retry) sends up to 16
  requests instead of 8 across the task's 4 runs.
- The SDKs sleep for a server's `Retry-After` before retrying, inside the worker. There are two
  `ai` workers, so one 429 with a long `Retry-After` takes half the AI capacity until the 240 s
  call deadline (ADR 0019) cuts the call off anyway.

## Decision
Both implementers agreed to both changes on 2026-11-09.

- **No sampling settings.** The contract is `complete(messages, *, schema, max_tokens)`.
  Adapters send no `temperature`, `top_p` or `top_k`, so each model's defaults apply. A setting
  that works on only one provider would mislead its callers. Each adapter's tests assert that
  none is sent.
- **No SDK retries.** `ai/limits.MAX_RETRIES = 0`: Celery's task retry is the only retry
  layer. A 429, a 5xx, a timeout or a lost connection raises `LLMUnavailable` at once, and the
  job records the retry.

## Consequences
- Each failing request costs one request. There are no sleeps inside the worker, and a large
  `Retry-After` fails at once instead of holding a worker until the deadline.
- After a brief provider outage, the next attempt is a task retry (backoff of 1 s or more, and
  the task runs again) instead of an instant SDK retry. AI tasks therefore make one `complete()`
  call each, or cache results per finding (#25), as ADR 0019 already requires.
- Celery's backoff ignores `Retry-After`. If 429s become frequent, pass the header's value
  through as the task's retry countdown.
- Output can vary from run to run, so features must not rely on it being deterministic. Results
  stay stable through the cache keyed on prompt version, model and input hash (`llm-prompt`
  skill), and evals compare prompt versions on the models' defaults.
- PR 3 (OpenAI-compatible) follows both rules: no sampling parameters and `max_retries=0`.
