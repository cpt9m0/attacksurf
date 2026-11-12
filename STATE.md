# STATE

> Handoff for the next session. Overwritten at the end of every task; not a history log.

**Updated:** 2026-11-12 · **Branch:** `main` · **PR:** #157 (merged)

## Status
`main` has PR 3a of the #84 analysis sandbox: the sandbox proxy answers `GET /info` with the
registered runtime names (ADR 0023), so the launcher can refuse to start in prod without
`runsc`. Full suite: 1395 passed, 18 skipped, coverage 97.40%; ruff, pyright and lint-imports
are clean. The runtime image is Python 3.15 (`python:3.15-slim`), pydantic 2.14.1 /
pydantic-core 2.50.1, and CI tests 3.12, 3.13 and 3.15.

## Last task
- Merged #157 (`84-sandbox-runtime-info`); the code merged cleanly and only `STATE.md`
  conflicted with `main`.
- `sandbox-proxy` allows exactly one read call, `GET /info`. It answers with sorted runtime
  names only, caches a good answer for 60 s with one daemon call at a time, logs the failure
  status code, and reads up to 8 MiB. The three Docker round trips share `_docker_call`.
- ADR 0023 records the change (ADR 0016 has an "amended by" pointer); `docs/security.md` and
  `CHANGELOG.md` are updated.

## Next step
PR 3b (`84-sandbox-launcher-core`, #158) is open and now needs a merge of `main`, which
conflicts only in `STATE.md`. Then 3c (launcher service and the `runsc` startup check) and 3d
(worker-side client). Order and scope: issue #84's merge-order checklist.

## Open threads
- Optional one-line `/info` note in the `docs/architecture.md` proxy box: user hasn't decided.
- The PR 3 plan (4 PRs, commits, testing gate) lived in
  `docs/plans/84-pr3-sandbox-launcher-split-4-prs.md`, which is untracked and absent from this
  checkout, so issue #84 is the current source of truth for the split.

## Notes for the next agent
- Production plugins are registered explicitly in `src/attacksurf/app.py` and
  `src/attacksurf/workers/app.py`; a new plugin needs both imports.
- `ScanOutput.wildcard_zones` is validated by `services.scan_results`; a marker for a non-root
  input is rejected. Tests that need Redis behavior use `tests.fakes.FakeCache`.
- Bumping the Python base image again needs a `pydantic-core` release with wheels for that
  CPython; `grimp` 3.18 is the first with aarch64 cp315 wheels (dev only).
- DB tests need `TEST_DATABASE_URL`; the dev Compose stack exposes PostgreSQL on
  `127.0.0.1:5432` with an `attacksurf_test` database (`make test` runs them in `web`).
- The ruff format hook strips imports that aren't used yet: add imports together with their
  first use.
