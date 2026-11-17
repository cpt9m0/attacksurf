# STATE

> Handoff for the next session. Overwritten at the end of every task; not a history log.

**Updated:** 2026-11-17 · **Branch:** `174-verification-queue` · **Issue:** #174 (ownership verification never completes)

## Status
Done: `worker-passive` + `beat` added to `compose.prod.yaml` with secret-aware healthchecks;
`scripts/deploy.sh` derives long-running services from the compose file, gates releases on
`--wait --wait-timeout 300`, and converges stopped workers; ownership card renders `Stalled`
with a queue explanation and stops polling past `QUEUE_STALL_AFTER` (5 min); regression tests
cover the stuck-queued, running-old, and requeued cases. All checks green, ready to commit/PR.

## Last task
- #174 on branch `174-verification-queue` off `origin/main` (16 files, +326/-55):
  prod compose (`worker-passive -Q passive -c 2`, `beat`, `env_file` moved to `x-app` anchor),
  deploy script (service list derived, orphan cleanup on rollback, all-services running check),
  `services/verifications.py` (`CheckState`/`InFlightCheck`, `QUEUE_STALL_AFTER`, newest-job /
  `updated_at` based stall), `web/ui.py` + `verification.html` + `_ownership.html` +
  `asset_detail.html` (stalled pill + `form-error role=alert`, no polling), unit + service +
  web integration tests, docs (`deployment.md` workers section + known gaps, `architecture.md`,
  `security.md`, ADR 0028, `DESIGN.md`), `CHANGELOG.md` Added + Fixed.
- Verified: `ruff check`, `ruff format`, `pyright` (0 errors), `lint-imports` (8 kept),
  `pytest` 2671 passed / 96.01%, `pre-commit run --all-files`, `RUN_WEB_E2E=1` Chromium (14 passed),
  `compose.prod.yaml config --quiet` with temp env (services resolve).

## Next step
1. Commit as `Ali Ayati <seyyedaliayati@gmail.com>` (2 commits: infra + web), push branch,
   open draft PR `fix(workers): run production workers and stop a stalled ownership card`,
   `Closes #174`.
2. After merge: CD timer deploys; verify `docker compose ps` (worker-passive + beat healthy),
   `nuxsystems.com` verifies on first `Verify now`. `worker-ai`, backups, monitoring stay #29.

## Open threads
- `worker-ai` intentionally out of scope (#29); AI jobs still queue.
- Newest-job-wins: repeated "Verify now" restarts the 5-min grace (pre-existing pile-up, harmless).
- Stalled card is static until reload; copy says so.

## Notes for the next agent
- Shell env needed here: `UV_CACHE_DIR=/tmp/uv-cache-ubuntu`,
  `PRE_COMMIT_HOME=/tmp/pre-commit-cache` (home cache is not writable),
  `TEST_DATABASE_URL='postgresql+psycopg://attacksurf:attacksurf@127.0.0.1:5432/attacksurf_test'`.
  Chromium: `PLAYWRIGHT_BROWSERS_PATH=/tmp/ms-playwright` (installed there).
- Hooks are authoritative: bare `ruff check` once looked green while the commit hook
  flagged PT018 — split compound `and` assertions in tests, always run the hooks.
- `compose.prod.yaml config` needs a temp `deploy/attacksurf.env` (copy from `.example`,
  delete after); `docker exec` healthchecks don't inherit entrypoint exports, hence the
  inline `REDIS_URL` substitution. `docker compose config` output re-escapes `$` as `$$`.
- Branch is off `origin/main` (includes #173); `21-scans-ui` work is merged, do not touch it.
