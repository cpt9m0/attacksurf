# STATE

> Handoff for the next session. Overwritten at the end of every task; not a history log.

**Updated:** 2026-11-21 · **Branch:** `29-production-deployment` · **Issue:** #29 (production deployment hardening)

## Status
Implemented issue #29 on branch `29-production-deployment` (branched off `main` at `3d90648`):
container/network/Gunicorn hardening in `compose.prod.yaml` & `Dockerfile`, non-root `caddy`,
image pruning + `SENTRY_RELEASE` injection in `scripts/deploy.sh`, optional scrubbed Sentry
(`infra/sentry.py`), nightly off-box `rclone` backups + `restore.sh` drill + systemd units,
host hardening & log rotation docs (`docs/deployment.md`), and tag-triggered multi-arch GHCR
workflow (`.github/workflows/release.yml`).

## Last task
- Hardened `compose.prod.yaml` (`read_only: true`, `cap_drop: [ALL]`, PID/CPU/memory limits,
  `json-file` log rotation, `internal: true` network isolation, Redis `--maxmemory`), made
  Caddy non-root (`uid 10001`), tuned Gunicorn (`--timeout 120`, `--max-requests 1000`,
  `--worker-tmp-dir /dev/shm`) + `320m` `/tmp` `tmpfs` for uploads, and added old-image pruning
  to `scripts/deploy.sh`.
- Added optional env-gated Sentry (`SENTRY_DSN` et al.) in `config.py`, `infra/sentry.py`,
  `app.py`, `web/errors.py`, and `workers/app.py` using `sentry-sdk[flask,celery]==2.74.0`
  (two-week age policy), `send_default_pii=False`, `include_local_variables=False`, and shared
  redaction from `infra/logging.py`.
- Added `scripts/backup.sh`, `scripts/restore.sh`, `deploy/backup.env.example`, and
  `deploy/systemd/attacksurf-backup.{service,timer,tmpfiles.conf}` plus `.github/workflows/release.yml`
  and host hardening / restore-drill docs in `docs/deployment.md`.
- Added unit tests (`tests/unit/infra/test_sentry.py`, `tests/unit/test_backup_scripts.py`,
  config & `compose.prod.yaml` hardening assertions).

## Next step
Open PR for #29 against `main` (and after merge, run the manual VPS steps in `docs/deployment.md`:
install `rclone`/`age` + `attacksurf-backup.{service,timer}`, configure `/etc/attacksurf/backup.env`,
verify the first backup + `restore.sh --verify-only`, optionally set `SENTRY_DSN`, and walk through
the host hardening checklist). On the sandbox track, PR 5 (`84-sandbox-ci`) remains next.

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
