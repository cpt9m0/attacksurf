# STATE

> Handoff for the next session. Overwritten at the end of every task; not a history log.

**Updated:** 2026-11-18 · **Branch:** `24-org-llm-settings` · **Issue:** #24 (Org AI settings)

## Status
PR #182 review fixes verified locally; awaiting publication and fresh Codex clearance.

## Last task
- Reproduced Codex finding `discussion_r4612613144`: production had no `ai` consumer.
- Added production `worker-ai` with the shared app image/config/secrets, concurrency 2,
  and a secret-aware healthcheck targeting `ai@$HOSTNAME`; deploy discovers it automatically.
- Added two regression tests that fail without the worker; updated deployment/architecture
  docs and the changelog. No new architecture decisions or agent conventions.
- Verification: pre-commit, ruff check/format and pyright pass; pytest reports
  2846 passed, 20 opt-in/empty-parameter skips, 95.92% coverage against real PostgreSQL.

## Next step
Push the fix to PR #182, reply in the original Codex thread, request `@codex review`, and
verify explicit current-head clearance plus CI. Resume with `/review https://github.com/cpt9m0/attacksurf/pull/182`.

## Open threads
- Fresh Codex review and CI for this fix are pending; do not merge on an older-head review.
- Deadline layer wraps `httpx2.HTTPTransport._pool`; Meta prices need an upstream check.

## Notes for the next agent
- Review worktree: `/data/workspace/attacksurf/.worktrees/182-review`.
- Ignored review ledger: `.worktrees/review/github.com-cpt9m0-attacksurf-182.json` within it.
- Writable caches: `UV_CACHE_DIR=/tmp/uv-cache-182`, `PRE_COMMIT_HOME=/tmp/pre-commit-182`,
  `GOCACHE=/tmp/go-build-182`. Test DB: `attacksurf_test` on 127.0.0.1:5432.
