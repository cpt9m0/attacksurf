# 0019. LLM provider contract and config resolution

- Status: accepted
- Date: 2026-11-05

## Context
ADR 0005 chose our own provider layer with an Anthropic and an OpenAI-compatible adapter. #23
needs the contract both adapters implement, built by two people in parallel, so their behavior
(validation, retries, errors, usage) must not drift apart. Orgs can bring their own key (#24).
For v1 the repo owner confirmed that orgs without a key use the operator's instance key, under
a cap. Development uses Meta's Muse Spark models, which serve both API formats with one key.

## Decision
- **Contract in `domain/llm.py`**: `LLMProvider.complete(messages, *, schema, max_tokens,
  temperature=None) -> LLMResult[T]`. A provider is built from one `LLMConfig`, so the model is
  not a call argument (unlike #23's sketch): a call cannot pair one source's key with another's
  model. `schema` is required, since every AI feature validates its output. `temperature=None`
  sends no temperature at all.
- **Structured output** uses each API's native JSON-schema format (Anthropic
  `output_config.format`, OpenAI `response_format` `json_schema`), not a forced tool call: Meta
  only accepts `tool_choice: "auto"`. Validation and the one retry live in
  `ai/structured.complete_structured`, shared by every provider: the retry appends the invalid
  reply (left out when empty: Anthropic rejects empty assistant text) and a correction listing
  field paths and messages (never the input). Usage is summed over attempts, and every
  `LLMError` carries the usage spent before it was raised (an invalid reply followed by a
  timeout still reports the first attempt's tokens), so failed calls are recorded and capped too.
- **Errors**: `LLMError` (a `JobError`) with `LLMUnavailable` (transient), `LLMAuthError`,
  `LLMRequestError`, `LLMOutputError`. One status mapping, `ai/errors.llm_error_for_status`.
  Messages never contain a key, prompt or model output.
- **Timeouts and retries**: the SDKs default to a 600 s timeout, longer than a Celery task may
  run (`TrackedTask.soft_time_limit` = 300 s), so every adapter passes `ai/limits.py`'s
  `REQUEST_TIMEOUT_SECONDS` (60 s) and `MAX_RETRIES` (1) to its SDK client. Those don't bound
  a call's total time: a read timeout limits each chunk's wait, not the whole response, the
  SDKs sleep for any server `Retry-After`, and PR 3's format fallback adds requests. So each
  adapter must also enforce `CALL_DEADLINE_SECONDS` (240 s) across one `complete()` call and
  raise `LLMUnavailable` when it would be exceeded, proven in its own tests with a stubbed large
  `Retry-After` and a slow response. The shared test only checks that the deadline leaves room
  under the soft limit; until the adapters enforce it, Celery's soft limit is the backstop.
  Open for PR 2/PR 3 to agree: `MAX_RETRIES = 0`, leaving all retries to Celery, would remove
  in-process `Retry-After` sleeps entirely. `LLMUnavailable` is a `TransientJobError`, so
  Celery retries the *task* with backoff: AI tasks must make one `complete()` call each, or
  cache results per finding (#25), so a retry doesn't pay again for calls that succeeded.
- **Config resolution** (`ai/config.resolve_llm_config`): the org's own key wins and brings its
  own provider, model and base URL; otherwise the instance config (`LLM_*`) applies if it has
  both a key and a model; otherwise AI is off. Sources never mix, and a failing org key never
  falls back to the instance key (it would spend the operator's money and send the org's data
  to a provider it didn't choose). `KeySource` records which one paid, for #24's cap.
- **Model names come only from config.** `LLM_MODEL` has no default in code; code passes a
  purpose, never a model name. Developers put the Meta development configuration
  (`openai_compat`, `https://api.meta.ai/v1`, `muse-spark-1.3`) in their own `.env`. One model
  per source for now; per-purpose models only if #25 needs them.
- **Base URLs**: `LLM_BASE_URL` is set by the operator and trusted. Org-supplied base URLs are
  accepted only once #24 validates them through ScopeGuard (SSRF), both when saved and when
  connecting; `resolve_llm_config` passes `OrgLLMConfig.base_url` through unchecked.
  Base URLs can contain credentials, so `Settings.llm_base_url`, `OrgLLMConfig.base_url` and
  `LLMConfig.base_url` use `SecretStr`. Resolution preserves the secret wrapper; adapters
  unwrap with `get_secret_value()` only when constructing the SDK client.
- **Tests**: `tests/fakes.FakeLLMProvider` runs the shared validator; every provider passes
  `tests/unit/ai/contract.ProviderContract` with stubbed HTTP. Live calls are marked `llm_live`
  and round-trip `contract.Verdict` on both APIs; a collection hook in `tests/conftest.py` skips
  them unless `RUN_LLM_TESTS=1` and an instance key and model are set, and always when `CI` is
  set.
- **Development** uses Meta (`https://api.meta.ai` for the Anthropic format,
  `https://api.meta.ai/v1` for the OpenAI format). `muse-spark-1.3-contributor` lets Meta train
  on prompts and replies, so it is for fixtures only, never real scan data.

## Consequences
- Both adapters only translate messages, schema and errors; validation, retries and usage
  totals behave identically by construction, and the contract suite proves the translation.
- Changing the contract after the provider work starts needs both implementers' agreement.
- Without a configured model, AI is off until the operator or an org sets one. Production picks
  its own provider and model.
- Each provider PR adds its own SDK; the contract itself adds no dependency.
