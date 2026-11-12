# STATE

> Handoff for the next session. Overwritten at the end of every task; not a history log.

**Updated:** 2026-11-12 · **Branch:** `main` · **PRs:** #151–#154 (merged)

## Status
All four open Dependabot PRs are merged; `main` is `c77df93`. The runtime image is Python 3.15
(`python:3.15-slim`), pydantic 2.14.1 / pydantic-core 2.50.1, and CI tests 3.12, 3.13 and 3.15.
Image digests: postgres 18.6, redis 8.10.3, cloudflared 2026.10.7. All checks are green.

## Last task
- Merged #151 (redis), #152 (cloudflared 2026.10.0 → 2026.10.7) and #153 (postgres) digest bumps.
- Merged #154 (Python 3.13 → 3.15) with a follow-up commit: pydantic 2.14.1 and grimp 3.18 are
  needed because pydantic-core 2.46.5 has no cp315 wheel and the 3.15 build failed without one;
  added `test (3.15)` to CI, updated `docs/development.md`, the pre-PR skill and `CHANGELOG.md`.
- Verified pytest on 3.12/3.14/3.15 (1269 passed, 18 skipped each), dev/prod image builds,
  ruff/pyright/import-linter/pre-commit, and worker smoke tests on the rebuilt dev stack.

## Next step
Implement #16 (DNS resolution + asset graph); read `Asset.details["wildcard"]` before treating
wildcard answers as real hosts and reuse `ctx.runtime.cache` for RDAP-style source data.

## Open threads
- The dev Compose stack is up on Python 3.15 and the new postgres/redis digests; no production
  deploy was done.
- Redis still holds the public CT result for `example.com`
  (`attacksurf:scan-cache:v1:ct:v1:example.com`, TTL 6 h); safe to leave.

## Notes for the next agent
- Production plugins are registered explicitly in `src/attacksurf/app.py` and
  `src/attacksurf/workers/app.py`; a new plugin needs both imports.
- `ScanOutput.wildcard_zones` is validated by `services.scan_results`; a marker for a non-root
  input is rejected. Tests that need Redis behavior use `tests.fakes.FakeCache`.
- Bumping the Python base image again needs a `pydantic-core` release with wheels for that
  CPython; `grimp` 3.18 is the first with aarch64 cp315 wheels (dev only).
