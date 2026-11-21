# STATE

> Handoff for the next session. Overwritten at the end of every task; not a history log.

**Updated:** 2026-11-21 · **Branch:** `main` · **Issue:** #84 (analysis sandbox)

## Status
PR #188 (analysis worker and sandbox services, PR 4 of 5 for #84) had its conflicts against main
resolved on the branch and was squash-merged. The dev `sandbox` profile
(`worker-analysis` → `sandbox-launcher` → `sandbox-proxy` → Docker, ADR 0031) is on main; prod
runs none of it until #92.

## Last task
- Merged `origin/main` into `84-analysis-worker`: `CHANGELOG.md` (both sides' entries kept),
  `STATE.md`, `compose.yaml` (kept `SCAN_DEFAULT_FREQUENCY` + the dev-launcher comment),
  `docs/architecture.md` (kept the `dns_scheduled` profile text + the guard-test sentence) and
  `tests/unit/scanners/test_profiles.py` (both new tests kept).
- The PR's ADR was renumbered **0029 → 0031**: while the branch was open, main claimed 0029 for
  the AI triage stage. The file is now
  `docs/adr/0031-open-analysis-queue-before-analyzers.md` and every reference (architecture,
  security, deployment, `compose.prod.yaml`, `services/uploads.py`, CHANGELOG, the guard test)
  says 0031. The per-commit plans under `docs/plans/84-analysis-sandbox/` still describe
  commit 0501d21 creating the file as 0029 — that is history; the file is 0031 now.
- `docs/security.md`'s "Active/analysis queues remain reserved" now says `active` only, matching
  the merged queue code (`analysis` is a consumed queue in dev).

## Next step
#28 (email notifications; depends on #20, #26, #27) is next in epic #31. On the sandbox track,
PR 5 (`84-sandbox-ci`) follows: fixture analyzer image, a real `sandbox-images.lock` entry, runsc
CI job.

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
