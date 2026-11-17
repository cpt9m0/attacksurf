# STATE

> Handoff for the next session. Overwritten at the end of every task; not a history log.

**Updated:** 2026-11-17 · **Branch:** `21-scans-ui` · **Issue:** #21 (Scans UI)

## Status
Done: draft PR #173 (`feat(web): add scans UI with live progress and diff view`) is pushed,
pre-push hooks (pyright + pytest) green. CI run still to check; then address review.

## Last task
- #21 on a branch off `origin/main` (5 commits): start-scan guards (root-row lock,
  `ScanAlreadyActive`, `SCAN_MAX_STARTS_PER_HOUR` quota, `cancel_scan`), `scan_views`
  read side, `/api/v1/scans`, scans pages with 2 s HTMX progress polling + diff, docs.
- Verified: full `pytest` 2659 passed / 95.33% coverage, `pre-commit run --all-files`,
  `pyright`, `lint-imports`, `RUN_WEB_E2E=1 pytest tests/e2e/web` (14 passed, real Chromium).

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
