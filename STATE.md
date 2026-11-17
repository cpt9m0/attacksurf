# STATE

> Handoff for the next session. Overwritten at the end of every task; not a history log.

**Updated:** 2026-11-17 · **Branch:** `21-scans-ui` · **Issue:** #21 (Scans UI)

## Status
Done: draft PR #173 has Codex's green light ("Didn't find any major issues",
reviewed commit `21b1e8d`). Next: check CI, then mark ready for review.

## Last task
- #21 on branch `21-scans-ui` (9 commits): scans UI + `/api/v1/scans`, then review fixes:
  org-row lock serialising the quota count-and-insert (threaded regression test that
  fails without the lock), cancel dialog moved out of the polled subtree with OOB swaps
  for status/meta/actions via shared `_scan_parts.html` macros, disappeared-bucket
  truncation notice.
- Verified after the fixes: full `pytest` 2661 passed / 96.02%, `pre-commit`,
  `pyright`, `lint-imports`, `RUN_WEB_E2E=1` Chromium suite (14 passed).

## Next step
1. Check CI on PR #173; fix anything red, then mark ready for review.
2. If merged: next unblocked issue in epic #31 (dependencies closed).

## Open threads
- PR is ~1050 non-test added lines over the ~400 guideline (flagged in the PR description
  with justification); reviewer may ask to split.
- No live Compose-stack check was run (polling/cancel/diff covered by integration tests).

## Notes for the next agent
- Shell env needed here: `UV_CACHE_DIR=/tmp/uv-cache-ubuntu`,
  `PRE_COMMIT_HOME=/tmp/pre-commit-cache` (home cache is not writable),
  `TEST_DATABASE_URL='postgresql+psycopg://attacksurf:attacksurf@127.0.0.1:5432/attacksurf_test'`.
  Chromium: `PLAYWRIGHT_BROWSERS_PATH=/tmp/ms-playwright` (installed there).
- Hooks are authoritative: bare `ruff check` once looked green while the commit hook
  flagged PT018 — split compound `and` assertions in tests, always run the hooks.
- Quota counting uses DB-clock `func.now() - timedelta(hours=1)`; `ScanAlreadyActive.scan_id`
  is the running scan's UUID for the redirect/409 body.
