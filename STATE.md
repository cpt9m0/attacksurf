# STATE

> Handoff for the next session. Overwritten at the end of every task; not a history log.

**Updated:** 2026-11-26 · **Branch:** `84-sandbox-ci` · **Issue:** #84 (Analysis sandbox runner and analysis worker)

## Status
Implemented and documented in draft PR #207, with `main` (through #202) merged in. CI must pass on the merge, then PR review and merge remain.

## Last task
- Added the fixture analyzer image and dev/CI-only fixtures, the runtime tests, the `runsc` CI job, the image build workflow and the compose isolation tests; `/tmp` is read-only (ADR 0034).
- Documented them in `docs/development.md`, `docs/security.md`, `CHANGELOG.md` and `AGENTS.md`.
- CI passed at `12b2426`, before the merge: `sandbox (runsc)` had 14 passed and 1 skipped (the prod-refusal test, which passed in its own step before `runsc` was installed).
- #84's gaps are decided: prod compose moves to #92, the sandbox stays opt-in (`--profile sandbox`), and the worker's staging mount follows ADR 0028.
- On `main`: #78 (`web.exposures`) merged as #202.

## Next step
Confirm CI is green on PR #207 and that #84, #92 and the PR description reflect the decisions above, then review the PR (`pre-pr-check` self-review), take it out of draft and merge.

## Open threads
- Web epic #66: #79 (WordPress exposures) is next, then #80 to #82.
- Compose guard gap: the all-services socket check misses a `/run` or `/var/run` mount.
- **Proxy trust:** the proxy has no caller authentication and `worker-analysis` shares its network (`docs/security.md`; #92 must close it before prod).
- **Dropped dev jobs:** no `analysis.*` task is registered, so `worker-analysis` drops those messages and job rows stay `queued`. #87 and #101 are closed; comments and docs saying they will register tasks are stale (`compose.yaml`, `docs/architecture.md`).
- Also stale: `docs/architecture.md` says no analyzer image exists (the test fixture does); the `pre-pr-check` skill's CI job list lacks `sandbox (runsc)`.
- **#92 prerequisites:** proxy, launcher and worker in `compose.prod.yaml` (extend the compose guard), `runsc` on the VPS, and the profile guard test in `tests/unit/scanners/test_profiles.py` removed or changed.
- Follow-up issues to file before #92: stray `attacksurf-*` container cleanup after a proxy restart; `/tmp/attacksurf-sandbox` symlink hardening.
- First analysis scanner calling `SandboxRunner.run` must `get_scoped` the artifact first, with a tenant-isolation test.
- From AI summary (#26): prioritize assets in the 200-asset summary input, live eval results, and Claude list prices in `ai/pricing.py`.

## Notes for the next agent
- The sandbox work continues with #92 after #84 (check its other dependencies first).
- The 1k scale test exceeds 90 s on the two-core dev machine: use `SCALE_BUDGET_SECONDS` (`docs/development.md`).
- DB tests need `TEST_DATABASE_URL`; `.github/scripts/pytest-hook.sh` resolves it.
