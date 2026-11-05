# STATE

> Handoff for the next session. Overwritten at the end of every task; not a history log.

**Updated:** 2026-11-05 · **Branch:** `23-llm-contract` · **Issue:** #23 (LLM provider abstraction), PR 1 of 4

## Status
PR 1 (shared LLM contract) is complete and committed locally in 7 commits; not pushed (pre-push
hook blocked on Windows, see Open threads).

## Last task
- `domain/llm.py` (protocol, config/result/usage types, `LLMError` subclasses that all carry
  `usage`), `ai/structured.py` (shared validation, one corrective retry, empty replies left out,
  usage kept when a retry raises), `ai/errors.py`, `ai/config.py` (`resolve_llm_config`)
- `ai/limits.py`: `REQUEST_TIMEOUT_SECONDS` 60, `MAX_RETRIES` 1, `CALL_DEADLINE_SECONDS` 240.
  SDK timeouts don't bound total time (per-chunk read timeout, uncapped `Retry-After` sleeps),
  so each adapter must enforce the deadline itself; the shared test only checks the values fit
  under `TrackedTask.soft_time_limit`
- `tests/conftest.py` skips `llm_live` tests unless `RUN_LLM_TESTS=1` + key + model, always in CI
- `LLM_MODEL` has no default in code; `.env.example` unchanged (Meta config goes in each
  developer's own `.env`, see `docs/development.md`)

## Next step
Partner reviews the contract (`domain/llm.py`, `ai/structured.py`, `ai/limits.py`,
`tests/unit/ai/contract.py`). Fix the Windows-only test failures in a separate small PR
(`.gitattributes` with `eol=lf`, UTF-8 license read, the `test_http.py` timeout case), then push
`23-llm-contract` and open PR 1 as a draft (`feat(ai): add llm provider contract and config
resolution`, `Refs #23`).

## Open threads
- PR 2/PR 3 must enforce `CALL_DEADLINE_SECONDS` (tests: stubbed large `Retry-After`, slow
  response). Decide together whether `MAX_RETRIES = 0` (all retries via Celery) is simpler.
- Deferred: wider code-fence parsing (PR 3, JSON-mode fallback); "AI is off" startup warning
  (PR 4); `.env.example` base-URL comment says openai_compat only (PR 2 updates it).
- Push is blocked on Windows: the pre-push pytest hook hits 3 Windows-only failures
  (`test_vendor.py` x2: `core.autocrlf` + cp1252 license read; `test_http.py` connection test).
  Never `--no-verify`.
- For the repo owner: one Meta key per developer? OK to split #23 into 4 PRs? Default
  monthly token cap (#24)?
- PR 2 Anthropic (Angela), PR 3 OpenAI-compatible (partner), PR 4 `LLMUsage` + factory
  (closes #23). Plan: https://claude.ai/artifact/PnixRruj7R2cb7B6gLmvLi

## Notes for the next agent
- Windows dev machine: Postgres on host port 5433 (git-excluded `compose.override.yaml`; a native
  PostgreSQL 18 service owns 5432). Tests:
  `TEST_DATABASE_URL=postgresql+psycopg://attacksurf:attacksurf@127.0.0.1:5433/attacksurf_test uv run pytest`
  (`127.0.0.1`, not `localhost`: IPv6 first means timeouts).
- uv 0.11.32 (pip `--user`, matches the Dockerfile).
- `core.autocrlf=true` here: hooks rewrite line endings after staging (`MM` in `git status`).
  Re-run `git add` + `git commit`; never `pre-commit run --all-files` (rewrites every file).
- Meta: OpenAI format `https://api.meta.ai/v1`, Anthropic format `https://api.meta.ai`
  (SDK sample uses `auth_token=`); only `tool_choice: "auto"`; `json_schema` supported.
