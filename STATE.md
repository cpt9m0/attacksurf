# STATE

> Handoff for the next session. Overwritten at the end of every task; not a history log.

**Updated:** 2026-11-20 · **Branch:** `84-analysis-worker` · **Issue:** #84 (analysis sandbox)

## Status
PR 4 (analysis worker) is code-complete locally: 8 of 8 commits, nothing pushed, no PR open. The
gate and `pre-pr-check` have not been run on this final commit yet.

## Last task
- Commit 8: architecture, security, changelog and this file now describe the dev `sandbox`
  profile (`worker-analysis` → `sandbox-launcher` → `sandbox-proxy` → Docker, ADR 0029).
- The `.env.example` `SANDBOX_ALLOW_RUNC=true` fix was squashed into the proxy/launcher commit.
- Plans live in `docs/plans/84-analysis-sandbox/84-pr4-analysis-worker/` (still untracked).

## Next step
Run the full gate (`ruff check`, `ruff format --check`, `pyright`, `lint-imports`, `pytest`) and
`pre-pr-check`, push, and open the draft PR `feat(workers): add analysis worker and sandbox
services` (merge order 4 of 5: after 3d, before PR 5; tick it in #84). Then PR 5
(`84-sandbox-ci`): fixture analyzer image, a real `sandbox-images.lock` entry, runsc CI job.

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
- Unverified: plain `make down` vs profile services; `--profile sandbox` build racing `make up`.
- Nothing enforces "the artifact belongs to the job's org" before `SandboxRunner.run`: the first
  analysis scanner must `get_scoped` the artifact first, with a tenant-isolation test.
- `/tmp/attacksurf-sandbox-test` is a root-owned leftover from earlier checks.

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
