# STATE

> Handoff for the next session. Overwritten at the end of every task; not a history log.

**Updated:** 2026-11-11 · **Branch:** `84-sandbox-runtime-info` · **Issue:** #84 (analysis sandbox), PR 3a of the split PR 3

## Status
PR 3a is committed (code + tests + ADR 0023, then docs) and pushed, and a PR is open
(`gh pr view 84-sandbox-runtime-info`). It is waiting on CI and review.

## Last task
- `sandbox-proxy` allows one read call, `GET /info`. It answers with runtime names only,
  caches a good answer for 60 s with one daemon call at a time, logs failure reasons (status
  code only), and reads up to 8 MiB. Docker round trips share `_docker_call`.
- ADR 0023 records the change (ADR 0016 has an "amended by" pointer); security.md and
  CHANGELOG are updated.
- Tests in the existing `tests/unit/sandbox_proxy/test_{policy,server}.py` cover the happy path,
  boundaries, invalid requests, Docker failures, caching and concurrency. `FakeDocker` serves
  `/info`. Full suite: 1395 passed, 18 skipped, coverage 97.48%.

## Next step
Start PR 3b (`84-sandbox-launcher-core`) from up-to-date `main`, following
`docs/plans/84-pr3-sandbox-launcher-split-4-prs.md` (it doesn't depend on 3a). Merge 3a first
when its review passes.

## Open threads
- Issue #84's merge-order checklist lists 3a to 3d; `84-analysis-sandbox.md` (untracked) still
  shows a single PR 3.
- Optional one-line `/info` note in the `docs/architecture.md` proxy box: user hasn't decided.

## Notes for the next agent
- The PR 3 plan (4 PRs, commits, testing gate) is in `docs/plans/84-pr3-sandbox-launcher-split-4-prs.md`
  (untracked).
- The user wants explanations in plain language, and tests run before every commit.
- The ruff format hook strips imports that aren't used yet: add imports together with their
  first use.
