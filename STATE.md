# STATE

> Handoff for the next session. Overwritten at the end of every task; not a history log.

**Updated:** 2026-11-10 · **Branch:** `116-archive-cancels-scans` · **Issue:** #116 (PR pending)

## Status
Archiving a root domain now cancels its queued/running scans in the archive's own transaction
(ADR 0021), and no in-flight scan can write under an archived root afterwards:

- `services/assets.archive_root_domain` cancels the root's `queued`/`running` scans (with
  `coalesce(started_at, now())` so the `finished_at >= started_at` constraint holds) and their
  unfinished jobs, and audits `asset.root_archived` (now carrying `scans_cancelled`) plus one
  `scan.cancelled` per scan. Completed scans and finished jobs are untouched.
- `services/scan_results.persist_scan_output` raises `ScanCancelled` (new `domain.scans` class)
  for a terminal scan and `AssetNotFound` for an archived root. It now takes the root's
  `FOR UPDATE` lock for every persist, the same lock the archive takes, so archive and persist
  are ordered either way. `_admit` no longer takes its own lock.
- `services/scans`: `dispatch_stage` and `finalize_scan` no-op for an inactive root
  (`_root_active`, fresh read); `start_scan` reads the root with `populate_existing`.
- No Celery revoke and no waiting (ADR 0021): queued tasks run once and no-op.
- UI: the archive dialog says scans in progress are cancelled; the existing `cancelled` pill
  (neutral) shows in the scan history.

Codex review on PR #148 (round 1) found two real races in the first version; both fixed:
- **Deadlock:** the archive locked the root *before* the scan rows, while persistence locked the
  scan row (`load_job_scan`) and then the root. Archive now cancels (locking scan rows) *before*
  `_lock_root`, and persistence only reads the root `FOR KEY SHARE` (upgrading to `FOR UPDATE`
  solely in `_admit`, for the cap). Rule: always scan rows → root. A deterministic regression
  test reproduces `DeadlockDetected` on the old order.
- **Timestamps:** `now()` is the transaction start, so a worker's `started_at` committed after
  the request began could exceed `finished_at` and roll back the archive. Cancellation now uses
  `clock_timestamp()`, jobs `greatest(started_at, clock_timestamp())`.

Verified: `pytest` 1210 passed, 19 skipped (all opt-in suites); ruff check/format, pyright
(`src` + `tests`), lint-imports clean. Docs synced: ADR 0021 (lock order + timestamps), ADR 0010,
`architecture.md`, `security.md`, `CHANGELOG.md`, `STATE.md`.

## Next step
Open the PR for this branch (`Closes #116`) and drive it through review.

## Open threads
- Local dev DB was reset on this machine: the `attacksurf_pgdata` volume held a postgres 16 data
  directory (empty `attacksurf` DB, a stale `attacksurf_test` schema) that the postgres 18
  compose service refuses to start on. The stack now runs on a fresh 18 volume (`make up`);
  nothing to recover, but any local data from before is gone.
- A user-facing "cancel scan" would reuse `services.assets._cancel_scans` and the persistence
  guards; not built here.
- #84: PR 3 (`84-sandbox-launcher`) is next; merge order port → proxy → launcher → analysis
  worker → CI. The launcher must send exactly what `sandbox_proxy/policy.py` accepts (user
  `65532:65532`, `LogConfig` none, `AutoRemove`, binds under the artifact root; attach before
  start, stdout only), and deployment must pass the proxy settings as environment variables
  (the proxy never reads `.env`).
- The scanner registry caps `timeout_seconds` at 240 s, but ADR 0016 allows 600 s sandbox runs.
  Resolve before the first analysis scanner; the runner client deadline is affected too.
- #23: Anthropic and OpenAI-compatible adapters and the factory remain; each must enforce the
  240 s deadline, and org base URLs need ScopeGuard validation (#24).
- #29: backups, monitoring and hardening remain; signup is enabled and should be closed until
  backups exist. The exposed tunnel/API credentials recorded in #133 still need rotation.
- `.env.example` lacks ALLOW_SIGNUP, SESSION_LIFETIME_HOURS, PROXY_COUNT.

## Notes for the next agent
- On this host there is no `uv` and no `.venv`; run Python tooling in the compose `web` image:
  `docker compose run --rm --no-deps --entrypoint sh -v ./tests:/app/tests -v ./.github:/app/.github:ro
  -e TEST_DATABASE_URL=postgresql+psycopg://attacksurf:attacksurf@postgres:5432/attacksurf_test
  web -c 'cd /app && pytest'`. Use `--no-deps`: without it compose recreates postgres and redis.
  `make test` mounts only `./tests`, so `tests/unit/test_test_database.py` fails to collect
  without the `.github` mount (it skips outside the container instead of failing).
- Pyright has no Node runtime in the image; run it from the host against an exported
  `attacksurf:dev` `.venv` with `pythonVersion 3.12` and `extraPaths` pointing at the exported
  site-packages and `src`.
- Browser layout tests: `RUN_WEB_E2E=1 uv run pytest tests/e2e/web -m web_e2e --no-cov` after
  `uv run playwright install chromium`; they skip by default.
- Deployment: `docs/deployment.md` (pull-based CD); secrets stay in `/etc/attacksurf/`, never git
  or images.
- `docs/plans/` holds the user's temporary plan copy: never stage it.
- Commits and pushes are authorized for this branch; merge only when requested.
- The due-verifications test is clock-pinned on `main` (explicit `NOW`); keep it that way.
