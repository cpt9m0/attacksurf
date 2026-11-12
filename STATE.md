# STATE

> Handoff for the next session. Overwritten at the end of every task; not a history log.

**Updated:** 2026-11-12 · **Branch:** `23-openai-compat-provider` · **Issue:** #23 (LLM providers, PR 3)

## Status
PR 3 (`23-openai-compat-provider`) implements `OpenAICompatProvider` on top of `main` (`917e2b4`,
which includes ADR 0024). Ready for review and merge before PR 4b (`23-llm-factory`).

## Last task
- Added `openai>=3.41.0,<3.42` (`3.41.0`, the newest release at least two weeks old) and extended
  the import-linter LLM SDK contract in `pyproject.toml` to forbid `openai` outside
  `attacksurf.ai.providers`.
- Implemented `OpenAICompatProvider` (`src/attacksurf/ai/providers/openai_compat.py`): Chat
  Completions with `max_completion_tokens`, explicit `api_key` and `base_url` (`DEFAULT_BASE_URL`),
  no sampling parameters (ADR 0024), `max_retries=0`, `json_schema` response format with HTTP 400
  fallback to `json_object` and then plain text (schema in system prompt), immediate `LLMOutputError`
  on `finish_reason` `length`/`content_filter` or `message.refusal`, `TokenUsage(reported=False)`
  when usage is omitted, and `CALL_DEADLINE_SECONDS` enforced across fallbacks and retries.
- Added unit and contract tests (`tests/unit/ai/providers/test_openai_compat.py`) and the opt-in
  live test (`tests/e2e/test_openai_compat_live.py`).

## Next step
Open PR 3 for review; once PR 3 and PR 4a (`23-llm-usage`) are ready, implement PR 4b
(`ai/factory.py` on `23-llm-factory`) to close #23.

## Open threads
- #23: PR 4a (`LLMUsage` table, pricing, `record_llm_usage`, AI-off startup warning) and PR 4b
  (`build_provider` factory + live verification on both providers) remain to close #23.
- Org-supplied base URLs still need ScopeGuard (SSRF) validation in #24 before use.

## Notes for the next agent
- `openai.APIStatusError` unwraps the top-level `"error"` object into `exc.body` and sets
  `exc.type`; `_error_type` checks `exc.type` first and falls back to `exc.body`.
- Format fallback (`json_schema` → `json_object` → plain text) triggers only on HTTP 400 before a
  format has succeeded; once a format returns 2xx, a corrective retry stays on that format.
