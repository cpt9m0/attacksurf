# STATE

> Handoff for the next session. Overwritten at the end of every task; not a history log.

**Updated:** 2026-11-05 · **Branch:** `23-llm-contract` · **Issue:** #23 (LLM providers), PR 1 of 4

## Status
PR [#131](https://github.com/cpt9m0/attacksurf/pull/131) defines the shared LLM contract/config.
Conflicts with current main are resolved. Codex found a base-URL credential leak on `10081a5`;
the fix masks URLs with SecretStr in settings and both contract types and awaits fresh review.
ADR 0019 covers LLM contracts; ownership and analysis ADRs 0014–0018 are retained.

## Last task
- Combine changelog entries and refresh this handoff for the current contract work.
- Preserve #127's early hermetic worker settings in `pytest_configure` alongside the new
  `pytest_collection_modifyitems` live-LLM guard; drop only the obsolete Iterator import.
- Renumber the LLM ADR to 0019 and update LLM-specific docs, skill, and code/test references.
- Mask endpoint credentials in settings and resolved org/instance configs; regression tests
  reproduce the leak before the fix and verify masking while retaining the exact URL.
- Preserve shared schema validation/retry, usage/error types, config resolution, timeout
  constants, provider contract tests, and the reviewed Windows test fixes.

## Next step
Request Codex review on the pushed SecretStr fix, then merge if review and CI pass.

## Open threads
- #23 remains open: next PRs implement Anthropic and OpenAI-compatible adapters; final PR adds
  LLMUsage/factory and closes #23. Each adapter must enforce the 240 s total call deadline.
- SDK retries vs. Celery-only retries remain an adapter decision; org base URLs require
  ScopeGuard validation in #24 before use; PR 4 adds the AI-off startup warning.
- #83 is closed with ADRs 0016–0018; sandbox/fetch/analyzer runtime is not implemented yet.
- Earlier local main handoffs are preserved in Git stashes, including
  `codex: preserve local handoff before PR 131`.
- Follow-ups: #114–#117. `.env.example` lacks ALLOW_SIGNUP, SESSION_LIFETIME_HOURS, PROXY_COUNT.

## Notes for the next agent
- Commits/pushes are authorized for all PRs in this chat; merge only when requested.
- Keep worker configuration hermetic before collection; live LLM tests stay opt-in and never run in CI.
- Validation: 1002 passed, 3 worker E2E skips, 97.72% coverage; all local checks pass.
