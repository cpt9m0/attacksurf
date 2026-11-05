# STATE

> Handoff for the next session. Overwritten at the end of every task; not a history log.

**Updated:** 2026-11-05 · **Branch:** `23-llm-contract` · **Issue:** #23 (LLM provider abstraction), PR 1 of 4

## Status
PR 1 (shared LLM contract) is complete: 7 commits plus the OS-agnostic test fixes (uncommitted).
Not pushed yet.

## Last task
- `domain/llm.py` (protocol, config/result/usage types, `LLMError` subclasses that all carry
  `usage`), `ai/structured.py` (shared validation, one corrective retry, empty replies left out,
  usage kept when a retry raises), `ai/errors.py`, `ai/config.py` (`resolve_llm_config`)
- `ai/limits.py`: `REQUEST_TIMEOUT_SECONDS` 60, `MAX_RETRIES` 1, `CALL_DEADLINE_SECONDS` 240.
  SDK timeouts don't bound total time (per-chunk read timeout, uncapped `Retry-After` sleeps),
  so each adapter must enforce the deadline itself
- `tests/conftest.py` skips `llm_live` tests unless `RUN_LLM_TESTS=1` + key + model, always in CI
- OS-agnostic tests (owner asked for them in this PR): `.gitattributes` (LF everywhere, vendor
  files `-text`), UTF-8 reads in `test_vendor.py`, simulated refusal in `test_http.py`. The three
  former Windows failures pass; this checkout was rewritten to LF.

## Next step
Commit the test fixes, run the full suite with Docker Desktop running, then push
`23-llm-contract` and open PR 1 as a draft (`feat(ai): add llm provider contract and config
resolution`, `Refs #23`). Partner reviews the contract (`domain/llm.py`, `ai/structured.py`,
`ai/limits.py`, `tests/unit/ai/contract.py`).

## Open threads
- PR 2/PR 3 must enforce `CALL_DEADLINE_SECONDS` (tests: stubbed large `Retry-After`, slow
  response). Decide together whether `MAX_RETRIES = 0` (all retries via Celery) is simpler.
- Deferred: wider code-fence parsing (PR 3, JSON-mode fallback); "AI is off" startup warning
  (PR 4); `.env.example` base-URL comment says openai_compat only (PR 2 updates it).
- For the repo owner: one Meta key per developer? Default monthly token cap (#24)?
- PR 2 Anthropic (Angela), PR 3 OpenAI-compatible (partner), PR 4 `LLMUsage` + factory
  (closes #23). Plan: https://claude.ai/artifact/PnixRruj7R2cb7B6gLmvLi

## Notes for the next agent
- Windows dev machine: Postgres on host port 5433 (git-excluded `compose.override.yaml`; a native
  PostgreSQL 18 service owns 5432). Tests:
  `TEST_DATABASE_URL=postgresql+psycopg://attacksurf:attacksurf@127.0.0.1:5433/attacksurf_test uv run pytest`
  (`127.0.0.1`, not `localhost`: IPv6 first means timeouts). Docker Desktop must be running.
- uv 0.11.32 (pip `--user`, matches the Dockerfile).
- Meta: OpenAI format `https://api.meta.ai/v1`, Anthropic format `https://api.meta.ai`
  (SDK sample uses `auth_token=`); only `tool_choice: "auto"`; `json_schema` supported.
