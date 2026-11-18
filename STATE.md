# STATE

> Handoff for the next session. Overwritten at the end of every task; not a history log.

**Updated:** 2026-11-18 · **Branch:** `23-llm-factory` · **Issue:** #23 (LLM providers, PR 4b)

## Status
PR 4b (provider factory + the review's deadline fix) is committed on `23-llm-factory` and merged
with `origin/main`, which now has PR 3 (#176); the PR's base is `main`. Unit tests, pyright and
ruff pass; not pushed since the fix.

## Last task
- `ai/factory.build_provider(config)`: picks the adapter for `config.provider`, ending in
  `assert_never`. Both `llm_live` tests pass against Meta (`muse-spark-1.3-contributor`).
- Review fix: at the call deadline both adapters left the request running in a daemon thread.
  Now their SDK clients run on `ai/providers/deadline.py` (`deadline_transport()` + `until`),
  which caps every connect, TLS handshake, read and write at the time left, so the request ends
  in its own thread and its connection closes. Tests use a trickling local server
  (`tests/unit/ai/providers/slow_server.py`).

## Next step
`git push`, reply to the review with the fix commit, add the deadline fix to the PR
description, then the partner reviews and it merges (closes #23). Then #24.

## Open threads
- The deadline layer replaces `httpx2.HTTPTransport`'s private `_pool`; an httpx2 upgrade that
  changes it fails the trickling-server tests. DNS lookups inside connect aren't capped (the
  resolver's own timeouts apply).
- `tests/integration/web/test_assets_api.py::test_admins_can_archive` failed once in a full run
  and passed alone, in its file and with all web tests: likely flaky.
- #24 needs the default monthly cap per org from the repo owner; Meta prices in
  `ai/pricing.py` need a check on developer.meta.com; org base URLs need ScopeGuard first.
- After CD deploys `cb7c061` (#178): `docker compose -f compose.prod.yaml logs --tail=20
  cloudflared | grep -c Registered` should be non-zero.

## Notes for the next agent
- The pre-push hook runs the full suite (~8 min on this laptop); without `ServerAliveInterval`
  in `~/.ssh/config` for `github-gmail`, GitHub drops the push while it runs.
- Git has no identity set in WSL here: set `user.name` / `user.email` before committing.
- Dev server: export `UV_CACHE_DIR=/tmp/uv-cache-ubuntu`, `PRE_COMMIT_HOME=/tmp/pre-commit-cache`
  and `TEST_DATABASE_URL=postgresql+psycopg://attacksurf:attacksurf@127.0.0.1:5432/attacksurf_test`
  for commits and pushes (home caches aren't writable there).
- `openai.APIStatusError` unwraps the top-level `"error"` object into `exc.body` and sets
  `exc.type`; format fallback only triggers on HTTP 400 before a format has succeeded.
