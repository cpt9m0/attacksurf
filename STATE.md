# STATE

> Handoff for the next session. Overwritten at the end of every task; not a history log.

**Updated:** 2026-11-13 · **Branch:** `20-finding-deduplication-scan-diffing` · **Issue:** #20 (Finding deduplication and scan diffing)

## Status
PR #167 (`feat(scanners): add finding deduplication and scan diffing`, `Closes #20`) is open,
ready for review and mergeable: CI (lint, compose, secrets, test 3.12/3.13/3.15, web-e2e,
pr-title) passes. Local checks: ruff check/format, lint-imports (6 kept), pyright, pytest 1898
passed / 19 skipped, coverage 95.23%.

## Last task
- Implemented #20: `FindingStatus.REGRESSED` (fixed findings observed again; `fixed_at`
  cleared; counts as active in views), `Finding.scanner` provenance (migration 0008), and
  material-change reopening of `accepted_risk`/`false_positive` findings in persistence
  (`FindingReopened`).
- New `services.scan_diff.diff_scan` wired into the `passive.diff` stage: fixes an active
  finding only when its own scanner completed for its asset in this scan (per-scanner/asset
  coverage via `Job`), marks re-observed fixed findings `regressed`, diffs discovered assets
  (new; disappeared only with a completed discovery and an earlier completed scan), writes
  `Scan.stats` (new/fixed/regressed/total by severity + assets) and audits `scan.diffed` in one
  transaction, then publishes `FindingFixed`/`FindingRegressed`. Replay-safe.
- Tests: 21 diff-service cases, 8 persistence cases, plus pipeline task, asset-view and DB
  invariant coverage.
- Docs: ADR 0027, architecture, CHANGELOG.

## Next step
1. Merge PR #167 (squash; `Closes #20` closes the issue), then delete the branch.
2. Pick the next unblocked issue in epic #31: #21 (scans UI, consumes `Scan.stats`) or #22.

## Open threads
- Concurrent scans of the same root can still both diff (#21 adds prevention); conditional
  updates and `last_seen <= seen` keep an older scan from undoing a newer observation.
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
