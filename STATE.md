# STATE

> Handoff for the next session. Overwritten at the end of every task; not a history log.

**Updated:** 2026-11-26 · **Branch:** `84-sandbox-ci` · **Issue:** #84 (Analysis sandbox runner and analysis worker)

## Status
Draft PR #207: CI passed at `8c408e4`. Not yet ready to merge: the commit that records the `runsc` results in ADR 0034 still needs the steps below.

## Last task
- Added the fixture analyzer image and dev/CI-only fixtures, the runtime tests, the `runsc` CI job, the image build workflow and the compose isolation tests; `/tmp` is read-only (ADR 0034, which now records the `runsc` results).
- Updated #84 to match what was built (prod compose moved to #92, opt-in `sandbox` profile, the worker's ADR 0028 staging mount).
- Health check: `worker-analysis` and its dependencies, including proxy and launcher, started healthy with a one-off `SANDBOX_ALLOW_RUNC=true` on a host without `runsc`. Without it the launcher exited (no permitted runtime). The other app services weren't started.
- `pre-pr-check`: hooks, Pyright and the full suite passed (4025 passed, 81 skipped, coverage 94.64%, `SCALE_BUDGET_SECONDS=180`). The branch review found no new code defect; `.env.example`'s diff was not reviewed (the command naming it was denied).
- On `main`: #78 (`web.exposures`) merged as #202.

## Next step
After committing the ADR 0034 results and this handoff, in order (skip any already done; commit, push and merge only when the author asks):
1. Push: `SCALE_BUDGET_SECONDS=180 git push` (the pre-push hook runs Pyright and the full suite).
2. Wait for all PR #207 checks to pass, including `sandbox (runsc)`. If no checks start, look for merge conflicts with `main` (`gh pr view 207 --json mergeable`); merge `main` in, don't force-push.
3. Update PR #207's description: change `Refs #84` to `Closes #84` (and remove the sentence saying the closing keyword comes later), tick the finished items (`runsc` results in ADR 0034; self-review) and add the review limits under Last task. `gh pr edit` failed here on a Projects (classic) error; use `gh api -X PATCH repos/cpt9m0/attacksurf/pulls/207 -F body=@<file>`.
4. Author review: the `.env.example` diff (not yet reviewed), the `/tmp` change (ADR 0034), and the AI-assistance checkbox.
5. Take the PR out of draft and squash-merge. Check the final message: title as the subject, with `Closes #84`.
6. After the merge, confirm #84 closed and CI on `main` passed. Then start the next work (#79 for the web epic, or #92 for the sandbox once its dependencies are checked).

## Open threads
- Output over 2 MiB: tests show the run is killed and flagged, not that an analysis job fails (no analysis task exists yet).
- PR #207 is over the ~400-line guideline (noted in its description).
- Web epic #66: #79 (WordPress exposures) is next, then #80 to #82.
- Compose guard gap: the all-services socket check misses a `/run` or `/var/run` mount.
- **Proxy trust:** the proxy has no caller authentication and `worker-analysis` shares its network (`docs/security.md`; #92 must close it before prod).
- **Dropped dev jobs:** no `analysis.*` task is registered, so `worker-analysis` drops those messages and job rows stay `queued`. #87 and #101 are closed; comments and docs saying they will register tasks are stale (`compose.yaml`, `docs/architecture.md`, `docs/security.md`).
- Also stale: `docs/architecture.md` says no analyzer image exists (the test fixture does); the `pre-pr-check` skill's CI job list lacks `sandbox (runsc)`.
- **#92** now also holds prod compose, `runsc` on the VPS, the proxy bypass and prod isolation tests. It must also remove or change the profile guard test in `tests/unit/scanners/test_profiles.py`.
- Follow-up issues to file before #92: stray `attacksurf-*` container cleanup after a proxy restart; `/tmp/attacksurf-sandbox` symlink hardening.
- First analysis scanner calling `SandboxRunner.run` must `get_scoped` the artifact first, with a tenant-isolation test.
- From AI summary (#26): prioritize assets in the 200-asset summary input, live eval results, and Claude list prices in `ai/pricing.py`.

## Notes for the next agent
- The sandbox work continues with #92 after #84 (check its other dependencies first).
- The 1k scale test exceeds 90 s on the two-core dev machine: use `SCALE_BUDGET_SECONDS` (`docs/development.md`).
- DB tests need `TEST_DATABASE_URL`; `.github/scripts/pytest-hook.sh` resolves it.
