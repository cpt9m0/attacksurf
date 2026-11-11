# STATE

> Handoff for the next session. Overwritten at the end of every task; not a history log.

**Updated:** 2026-11-11 · **Branch:** `149-content-width` · **Issue:** #149 (PR #150, draft)

## Status
#149 is implemented and in review: `.content` fills the main column at every width (the 72rem cap
and `--content-max-width` are gone). At 1440px the content right edge is 1440px (was 1360px); the
390px phone layout is unchanged. E2E 14 passed; full pytest 1269 passed, 18 skipped, coverage
97.37%; ruff/pyright/import-linter/pre-commit clean.

## Last task
- `app.css` / `tokens.css`: removed the `.content` max-width and its now-unused token.
- `tests/e2e/web/test_shell_layout.py`: 1440px regression test (light + dark); the `shell` fixture
  takes a viewport `width` (Protocol-typed).
- `DESIGN.md` §3/§4 and `CHANGELOG.md` updated. PR #150 is a draft, rebased on `0bd583c` (#147)
  with the `CHANGELOG.md` conflict resolved.

## Next step
Drive PR #150 through review (CI, then mark ready); merge only on request. Next unblocked work:
#23 PR 3 (OpenAI-compatible provider, partner) and #84 PR 3 (sandbox launcher).

## Open threads
- #23: PR 3 mirrors ADR 0019 (no SDK retries/sampling, deadline per call) and adds `openai` to the
  SDK import-linter contract; PR 4 adds `LLMUsage` + factory + AI-off startup warning and closes
  #23. Org base URLs need ScopeGuard (#24).
- #84: PR 3 (launcher) must send exactly what `sandbox_proxy/policy.py` accepts; deployment must
  pass proxy settings as env vars, and `runsc` must be registered on the VPS. Resolve the 240 s
  registry cap vs ADR 0016's 600 s before the first analysis scanner.
- #29: backups, monitoring and hardening remain; signup should be closed until backups exist; the
  tunnel/API credentials recorded in #133 still need rotation. `.env.example` lacks
  `ALLOW_SIGNUP`, `SESSION_LIFETIME_HOURS` and `PROXY_COUNT`.
- Scans (ADR 0021): a user-facing "cancel scan" is not built. Lock rule to keep: scan rows before
  the root, and never read the root locked then upgrade that lock.
- #149 follow-up if wanted: cap per-card prose with `--measure` on ultra-wide screens.

## Notes for the next agent
- `.content` intentionally has no max-width (#149); change it only with a new `DESIGN.md` §4
  decision.
- Browser layout tests: `RUN_WEB_E2E=1 uv run pytest tests/e2e/web -m web_e2e --no-cov` (opt-in;
  CI runs them). In this sandbox `~/.cache` is read-only: set `UV_CACHE_DIR=/tmp/uv-cache` and
  `PLAYWRIGHT_BROWSERS_PATH=/tmp/ms-playwright`.
- DB-backed tests:
  `TEST_DATABASE_URL=postgresql+psycopg://attacksurf:attacksurf@localhost:5432/attacksurf_test`
  (compose Postgres is up).
- Due-verification tests are clock-pinned; `docs/plans/` is the user's temporary copy, never stage
  it.
