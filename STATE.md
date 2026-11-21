# STATE

> Handoff for the next session. Overwritten at the end of every task; not a history log.

**Updated:** 2026-11-20 · **Branch:** `28-email-notifications` · **Issue:** #28 (email digest notifications)

## Status
Implemented issue #28 (email digest notifications on new/regressed findings, ADR 0032) on branch
`28-email-notifications`. All unit tests, `ruff`, `pyright`, `lint-imports`, and offline Alembic
SQL generation pass; database integration tests (`tests/integration/services/test_notifications.py`)
require PostgreSQL (`TEST_DATABASE_URL` / `make test`) which was not running in this environment.

## Last task
- Added `domain/notifications.py` (`EmailSender`, `ScanDigest`, `DigestFinding`, `EmailDeliveryError`),
  `SMTP_*` and `APP_BASE_URL` settings in `config.py`, and `infra/email.py` (`SmtpEmailSender` +
  `render_digest_email` with plain-text & autoescaped HTML templates and no external tracking).
- Added migration `0014_add_notifications.py` (`finding_observations.regressed`,
  `notification_preferences`, `notification_deliveries`), updated `services/scan_diff.py` to mark
  regressed observations, and implemented `services/notifications.py` +
  `workers/tasks/notifications.py` (`passive.notify_scan`).
- Wired `queue_scan_notification` into the terminal exits of the post-scan AI stage
  (`services/summary.py`, `services/triage.py`, `services/scans.py`) and excluded `NOTIFY_STAGE`
  from scan progress counts in `services/scan_views.py`.
- Added per-user notification preferences UI on `/settings` (`POST /settings/notifications`) and
  added `mailpit` to `compose.yaml` + `.env.example`.

## Next step
Run `make test` (or `TEST_DATABASE_URL=... uv run pytest`) against PostgreSQL to execute
`tests/integration/services/test_notifications.py` and the full integration suite, then open PR
for #28. On the sandbox track, PR 5 (`84-sandbox-ci`) remains next.

## Open threads
- **Proxy trust:** the proxy has no caller authentication and `worker-analysis` shares the
  `sandbox` network with it. Written up in `docs/security.md`; #92 must close it before prod.
- **Dropped dev jobs:** `worker-analysis` drops `analysis.*` messages until #87/#101 register
  tasks; the job rows stay `queued`.
- **#92 prerequisites:** proxy, launcher and worker in `compose.prod.yaml`, `runsc` on the VPS,
  and the profile guard test in `tests/unit/scanners/test_profiles.py` removed or changed.
- Follow-up issue to file (before #92): after a proxy restart a stray `attacksurf-*` container
  is alerted on but not removed.
- The `/tmp/attacksurf-sandbox` default can be claimed first by another local user on a shared
  host (symlink risk, `sandbox_launcher/artifacts.py`). Accepted in dev; revisit before #92.
- Nothing enforces "the artifact belongs to the job's org" before `SandboxRunner.run`: the first
  analysis scanner must `get_scoped` the artifact first, with a tenant-isolation test.
- From the AI summary work (#26): human-review requests remain (prioritize assets in the
  200-asset summary input, live eval results, light/dark card screenshots); `ai/pricing.py`
  still has no Claude list prices.

## Notes for the next agent
- The launcher copies proxy constants and `domain.scanners.MAX_OUTPUT_BYTES` on purpose (it may
  not import them); a parity test guards each copy. Don't "fix" that by importing.
- `sandbox-images.lock` is `{}`: the catalog is empty, so every `POST /runs` is a 404.
- Compose sandbox services have no `curl`; healthchecks use `python -c`.
- ADR numbers move fast: check `origin/main` and open branches for the next free number first.
- Production plugins are registered in `src/attacksurf/app.py` and `src/attacksurf/workers/app.py`.
- DB tests need `TEST_DATABASE_URL`; the dev stack exposes PostgreSQL on `127.0.0.1:5432` with an
  `attacksurf_test` database (`make test` runs them in `web`).
- The ruff format hook strips imports that aren't used yet: add imports with their first use.
- Keep `(created_at, id)` summary recency identical to `services.summary_views`.
