# STATE

> Handoff for the next session. Overwritten at the end of every task; not a history log.

**Updated:** 2026-11-17 · **Branch:** `84-sandbox-launcher-service` · **Issue:** #84 (analysis sandbox)

## Status
PR 3c (sandbox launcher service, PR #172) merged `origin/main` locally and conflicts are
resolved (`AGENTS.md`, `CHANGELOG.md`, `STATE.md`, `docs/architecture.md`). Other merged
PRs now in this branch: #23 (llm usage), #85 (artifact storage), #86 (archive extractor),
#87 (repo upload), #101 (binary upload). Not yet committed/pushed.

## Last task
- Commits 1-4: shared `FakeDocker` (`tests/docker_fakes.py`), `runner.py` (run supervision),
  `server.py` (`GET /healthz`, `POST /runs`), `__main__.py` (`select_runtime`: `runsc` required
  in prod, `runc` only outside prod with `SANDBOX_ALLOW_RUNC=true`, otherwise exit non-zero).
- Commit 5: docs in `AGENTS.md`, `docs/architecture.md`, `docs/security.md`,
  `docs/development.md` and `CHANGELOG.md`. No ADR: ADR 0016 and ADR 0023 are implemented as
  written.
- Merge resolution: kept the launcher-service entries and main's `sandbox_tools/`,
  artifact/upload and llm-usage entries in `AGENTS.md` / `CHANGELOG.md` /
  `docs/architecture.md`; rewrote this file as the launcher handoff (main's `STATE.md` was
  the #101 handoff, now stale).

## Next step
1. Verify (`ruff`, `pyright`, `lint-imports`, `pytest`), commit the merge, push the branch to
   update PR #172; tick 3a-3c in #84 once merged.
2. PR 3d (`84-sandbox-runner-client`): `infra/sandbox.py` `LauncherSandboxRunner`, then wire it
   into `workers/runtime.scanner_gate()`; docs must add the tenant-safety note (the worker
   confirms the artifact belongs to the org before calling the launcher).

## Open threads
- #23, #85, #86, #87, #101 are merged on `main` and now merged into this branch.
- #21 (Scans UI) is not merged: the scan shows only in the asset's "Scan history" tab. No JSON API.
- Propose a follow-up issue after 3d: sweep leftover `attacksurf-*` containers after a launcher
  or proxy crash (before #92).
- `docs/plans/` is untracked; issue #84 is the source of truth for the PR split.

## Notes for the next agent
- The launcher copies proxy constants and `domain.scanners.MAX_OUTPUT_BYTES` on purpose (it may
  not import them); a parity test guards each copy. Don't "fix" that by importing.
- PR 3d's ~3 MiB reply cap assumes stdout is at most 2 MiB (base64 about 2.67 MiB).
- `sandbox-images.lock` does not exist yet (PR 5 adds it with the fixture analyzer); the catalog
  is empty, so every `POST /runs` is a 404 and local runs need a `{}` lock file.
- A container that exits before Docker registers the removed-wait fails the run (503) rather
  than guessing an exit code; the worker may retry.
- ADR numbers move fast: check `origin/main` and open branches for the next free number right
  before pushing a new ADR.
- Production plugins are registered explicitly in `src/attacksurf/app.py` and
  `src/attacksurf/workers/app.py`; a new plugin needs both imports.
- Tests that need Redis behavior use `tests.fakes.FakeCache`.
- The runtime image is Python 3.15; CI tests 3.12, 3.13 and 3.15.
- DB tests need `TEST_DATABASE_URL`; the dev Compose stack exposes PostgreSQL on
  `127.0.0.1:5432` with an `attacksurf_test` database (`make test` runs them in `web`).
- The ruff format hook strips imports that aren't used yet: add imports together with their
  first use.
