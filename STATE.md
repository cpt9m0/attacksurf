# STATE

> Handoff for the next session. Overwritten at the end of every task; not a history log.

**Updated:** 2026-11-13 · **Branch:** `20-finding-deduplication-scan-diffing` · **Issue:** #20 (Finding deduplication and scan diffing)

## Status
PR #167 (`feat(scanners): add finding deduplication and scan diffing`, `Closes #20`) is open,
mergeable and green. Codex review passed on `29eb790` ("Didn't find any major issues") after
three rounds; every review thread is resolved. Local checks: ruff check/format, lint-imports
(6 kept), pyright, pytest 1911 passed / 19 skipped, coverage 95%.

## Last task
- Implemented #20: `FindingStatus.REGRESSED`, `Finding.scanner` provenance, and material-change
  reopening of suppressed findings (`FindingReopened`), all in migration 0008.
- `finding_observations` (one row per scan+finding) makes `Scan.stats` and the fix/regress
  decisions scan-scoped instead of depending on `last_seen_scan_id`;
  `assets.first_seen_scan_id` / `deactivated_by_scan_id` do the same for the asset diff.
- `services.scan_diff.diff_scan` (wired into `passive.diff`) fixes only findings whose scanner
  completed for the asset, marks re-observations of fixed findings `regressed`, records
  new/disappeared subdomains (a resolution verdict), writes `Scan.stats` and audits
  `scan.diffed` in one replay-safe transaction.
- `Finding.evidence_digest` (unordered DNS/RDAP collections normalized) drives material-change
  detection; a NULL baseline is initialized without reopening.
- Tests: 24 diff-service cases, 15 persistence cases, plus pipeline task, asset-view, DB
  invariant and tenant-isolation coverage. Docs: ADR 0027, architecture, CHANGELOG.

## Next step
1. Merge PR #167 (squash; `Closes #20` closes the issue), then delete the branch.
2. Pick the next unblocked issue in epic #31: #21 (scans UI, consumes `Scan.stats`) or #22.

## Open threads
- Concurrent scans of the same root can still both diff (#21 adds prevention); scan-scoped
  observation rows and the chronology guards keep them from corrupting each other's stats.
- Findings on deactivated assets are never auto-fixed (no scanner runs on them): intentional.
- A fail-open scanner (RDAP outage) can make its findings look fixed while the upstream is down.
- `Scan.stats` asset lists are capped at 1000 entries; `total` stays exact.
- Zone-level findings on two roots in one zone are not deduplicated across assets (from #19).

## Notes for the next agent
- `uv run` fails on the uv cache here (`/home/ubuntu/.cache`); use `.venv/bin/<tool>` directly.
- Git hooks need caches redirected (`UV_CACHE_DIR`, `PRE_COMMIT_HOME`, `GOCACHE`, `GOPATH` under
  /tmp) and the pre-push hook needs `TEST_DATABASE_URL` in the same command.
- DB tests: `TEST_DATABASE_URL='postgresql+psycopg://attacksurf:attacksurf@127.0.0.1:5432/attacksurf_test'`
  and `PATH="$PWD/.venv/bin:$PATH"` (the alembic CLI test shells out to `alembic`).
