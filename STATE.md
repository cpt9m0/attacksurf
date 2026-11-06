# STATE

> Handoff for the next session. Overwritten at the end of every task; not a history log.

**Updated:** 2026-11-05 · **Branch:** `docs/83-analysis-tools-adr` · **Issue:** #83 (analysis sandbox ADRs)

## Status
PR [#130](https://github.com/cpt9m0/attacksurf/pull/130) is the final #83 ADR PR.
Codex review passed on `556d188`; user requests conflict resolution and merge.
Sandbox ADR 0016 and fetching ADR 0017 are merged. Tools/images use ADR 0018.
No sandbox, fetching worker, or analyzer runtime is implemented yet.

## Last task
- Resolve the STATE.md conflict with a current handoff covering all three #83 decisions.
- Rename the tools ADR to 0018; refer to sandbox ADR 0016 and fetching ADR 0017.
- Preserve the reviewed tools, license table, image pinning, and offline OSV data decisions.
- Update changelog and supply-chain references without changing runtime behavior.
  Validation: 923 passed, 3 worker E2E skips, 97.63% coverage; ruff, pyright, and hooks pass.

## Next step
Wait for CI on the pushed conflict resolution, then squash-merge #130.
Verify #83 closes and update local main.

## Open threads
- Implementation follows these ADRs; fetch/analysis queues remain reserved until built.
- Sandbox wall time defaults to 600 s, but tracked tasks default to a 300 s soft limit;
  #84 must configure an analysis-task override.
- OSV data sync (#93) needs a capped streaming transport; the scanner client stays at 1 MiB.
- Earlier local main handoffs are preserved in Git stashes, including
  `codex: preserve local handoff before PR 130`.
- Follow-ups: #114–#117. `.env.example` lacks ALLOW_SIGNUP, SESSION_LIFETIME_HOURS, PROXY_COUNT.

## Notes for the next agent
- Commits/pushes are authorized for all PRs in this chat; merge only when requested.
- ADRs 0014/0015 cover ownership; 0016 sandbox; 0017 fetching; 0018 tools/images.
- The reviewed architecture is documentation only; sandbox security guarantees still need tests.
