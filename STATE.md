# STATE

> Handoff for the next session. Overwritten at the end of every task; not a history log.

**Updated:** 2026-11-09 · **Branch:** `23-anthropic-provider` · **Issue:** #23 (LLM providers), PR 2 of 4 in progress

## Status
PR 1 (shared LLM contract) is merged: [#131](https://github.com/cpt9m0/attacksurf/pull/131),
squashed as `b7c0a1c`. PR 2 (Anthropic provider, Angela) is in progress on this branch; plan:
https://claude.ai/artifact/PnixRruj7R2cb7B6gLmvLi (written before the merge; corrections below).
Title `feat(ai): add anthropic provider`, footer `Refs #23`.

Committed: `04f9e9f` (no SDK retries, `MAX_RETRIES = 0`), `ab30ba8` (`anthropic` 2.3.0; 2.4.0+
are under two weeks old on 2026-11-09) and step 2, the adapter (`feat(ai): add anthropic
provider adapter`):
- `ai/providers/anthropic.py`: `AnthropicProvider(config, *, http_client=None)`; system messages
  joined into `system=`; `output_config.format` with `anthropic.transform_schema(schema)`; text
  blocks only (thinking skipped); cached input tokens added to input; `APIStatusError` /
  `APIConnectionError` mapped through `ai/errors.py` `from None`; base URL always explicit
  (`DEFAULT_BASE_URL`) so `ANTHROPIC_BASE_URL` can't redirect a key; timeout/retries from
  `ai/limits.py`.
- `temperature` removed from the contract (`domain/llm.py`, `FakeLLMProvider`, contract tests,
  ADR 0019): API version `2026-10-21`, which SDK 2.x sends, rejects sampling params with a 400.
- import-linter contract: only `attacksurf.ai.providers.**` may import `anthropic`.
- Tests `tests/unit/ai/providers/test_anthropic.py` (contract + 9 adapter tests) pass; ruff,
  pyright, lint-imports pass. Full suite not run: Docker Desktop was down (DB tests need it).

## Next step
Run the full suite with Docker Desktop up (not yet run on this branch), then:
3. Errors beyond status codes: `stop_reason` `max_tokens` (truncated JSON; the corrective retry
   can't help), `refusal`, an empty reply, `APIResponseValidationError` and other
   `anthropic.AnthropicError`s that aren't status/connection errors.
4. Enforce `CALL_DEADLINE_SECONDS` (240) across one `complete()` call (both attempts), raising
   `LLMUnavailable`; tests: a stubbed slow response, and a 429 with a large `Retry-After` failing
   at once (ADR 0019).
5. `llm_live` test against `https://api.meta.ai` (round-trip `contract.Verdict`); record in ADR
   0019 or `docs/development.md` that `api_key=` works there (SDK 2.x sends it as
   `Authorization: Bearer`, the header Meta's `auth_token=` sample produces, so no special case
   is expected). Then README/CHANGELOG/STATE.

## Open threads
- Both implementers agreed (2026-11-09) to the two contract changes: `MAX_RETRIES = 0` and no
  `temperature` in `complete()` (the OpenAI-compatible adapter sends none either).
- AGENTS.md says changing a decision means a new ADR; both changes were recorded in ADR 0019
  in place (dated) since #23 is still open. Write ADR 0020 instead if the owner prefers.
- PR 3 (OpenAI-compatible, partner) and PR 4 (`LLMUsage` + factory + AI-off startup warning,
  Angela; closes #23) are not started. PR 3 should add `openai` to the import-linter SDK contract.
- Org-supplied base URLs need ScopeGuard (SSRF) validation in #24 before use.
- `.env.example` lacks `ALLOW_SIGNUP`, `SESSION_LIFETIME_HOURS` and `PROXY_COUNT` (settings exist
  in `config.py`); small follow-up fix.
- Other open work: #114–#117 open; PRs #133 (Cloudflare Tunnel), #134 and #135 (sandbox, #84)
  open by other contributors.

## Notes for the next agent
- SDK 2.3.0 facts: HTTP stack is `httpx2` (stub with `httpx2.MockTransport`); it sleeps for any
  `Retry-After` (why SDK retries stay off); it still reads `ANTHROPIC_CUSTOM_HEADERS` from the
  environment (operator-controlled, harmless here). Meta only accepts `tool_choice: "auto"`;
  Anthropic-format base URL `https://api.meta.ai`.
- Windows dev machine: Postgres on host port 5433 (git-excluded `compose.override.yaml`).
  Tests: `TEST_DATABASE_URL=postgresql+psycopg://attacksurf:attacksurf@127.0.0.1:5433/attacksurf_test uv run pytest`
  with Docker Desktop running.
- Live LLM tests: `RUN_LLM_TESTS=1 uv run pytest -m llm_live --no-cov` with a key and model in
  your own `.env`; never in CI.
