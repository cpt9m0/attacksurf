# STATE

> Handoff for the next session. Overwritten at the end of every task; not a history log.

**Updated:** 2026-11-09 · **Branch:** `23-anthropic-provider` · **Issue:** #23 (LLM providers), PR 2 of 4 in progress

## Status
PR 1 (shared LLM contract) is merged: [#131](https://github.com/cpt9m0/attacksurf/pull/131),
squashed as `b7c0a1c`, merged 2026-11-06 by the repo owner. Before merge, two commits were
added on top of Angela's eight: `10081a5` reconciled the branch with `main` (LLM ADR renumbered
0014 → 0019, since 0014–0018 were taken by ownership and analysis ADRs) and `d1acef2` fixed a
credential leak by making LLM base URLs `SecretStr`. #23 stays open.

## Next step
PR 2, Anthropic provider (Angela): branch `23-anthropic-provider`, title
`feat(ai): add anthropic provider`, footer `Refs #23`. Plan:
https://claude.ai/artifact/PnixRruj7R2cb7B6gLmvLi (written before the merge; corrections below).
Done on this branch (uncommitted): `MAX_RETRIES = 0` (ADR 0019 updated; partner to confirm for
PR 3) and step 1, `anthropic` 2.3.0 added (2.4.0+ are under two weeks old on 2026-11-09).
Unit tests, ruff, pyright, lint-imports pass; the full suite still needs a run with Docker
Desktop up (DB tests errored only because Docker was down).
1. ~~Add the SDK.~~ Its HTTP stack is `httpx2` (not `httpx`): stub with
   `http_client=httpx2.Client(transport=httpx2.MockTransport(...))`. SDK 2.3.0 sleeps for any
   `Retry-After` (capped near 49 days), which is why SDK retries stay off.
2. Read the current Anthropic SDK docs (Context7 / `claude-api` skill) before writing code.
3. `ai/providers/anthropic.py`: `AnthropicProvider(config)`; system messages via `system=`;
   structured output via `output_config.format` (JSON schema, no forced tool call); omit
   `temperature` when `None`; map SDK errors through `ai/errors.py`.
4. Plug into `tests/unit/ai/contract.ProviderContract` with stubbed HTTP, plus one `llm_live`
   test against `https://api.meta.ai` using the same schema PR 3 will use.

## Corrections to the plan artifact
- The LLM decision record is ADR 0019 (`docs/adr/0019-llm-contract-and-config.md`), not 0014.
- Build the SDK client with `REQUEST_TIMEOUT_SECONDS` (60) and `MAX_RETRIES` (0) from
  `ai/limits.py`, and also enforce `CALL_DEADLINE_SECONDS` (240) across one whole `complete()`
  call (both attempts), raising `LLMUnavailable` when it would be exceeded. Tests: a stubbed
  slow response, and a 429 with a large `Retry-After` failing at once (ADR 0019).
- `LLMConfig.base_url` is `SecretStr | None` (as are `Settings.llm_base_url` and
  `OrgLLMConfig.base_url`): call `.get_secret_value()` only when constructing the SDK client.

## Open threads
- `MAX_RETRIES = 0` decided by Angela on 2026-11-09; the PR 3 partner still needs to agree
  before this branch merges (their adapter uses the same constant).
- PR 3 (OpenAI-compatible, partner) and PR 4 (`LLMUsage` + factory + AI-off startup warning,
  Angela; closes #23) are not started.
- Org-supplied base URLs need ScopeGuard (SSRF) validation in #24 before use.
- `.env.example` lacks `ALLOW_SIGNUP`, `SESSION_LIFETIME_HOURS` and `PROXY_COUNT` (settings exist
  in `config.py`); small follow-up fix.
- Other open work: #114–#117 open; PRs #133 (Cloudflare Tunnel), #134 and #135 (sandbox, #84)
  open by other contributors.

## Notes for the next agent
- Meta auth quirk for PR 2: Meta's Anthropic-format sample passes the key as `auth_token=`
  (Bearer). Try `api_key=` first; if rejected, use `auth_token=` when a custom base URL is set,
  and record which worked in ADR 0019 or `docs/development.md`. Meta only accepts
  `tool_choice: "auto"`; Anthropic format base URL `https://api.meta.ai`.
- Windows dev machine: Postgres on host port 5433 (git-excluded `compose.override.yaml`).
  Tests: `TEST_DATABASE_URL=postgresql+psycopg://attacksurf:attacksurf@127.0.0.1:5433/attacksurf_test uv run pytest`
  with Docker Desktop running.
- Live LLM tests: `RUN_LLM_TESTS=1 uv run pytest -m llm_live --no-cov` with a key and model in
  your own `.env`; never in CI.
