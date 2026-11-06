# STATE

> Handoff for the next session. Overwritten at the end of every task; not a history log.

**Updated:** 2026-11-05 · **Branch:** `docs/83-fetcher-adr` · **Issue:** #83 (analysis sandbox ADRs)

## Status
PR [#129](https://github.com/cpt9m0/attacksurf/pull/129) documents repository fetching and archives.
Its review fixes include this handoff and ADR numbering reconciled with current main.
Sandbox ADR 0016 is merged in #128. Fetching is ADR 0017; no runtime is implemented yet.

## Last task
- Include this handoff in the same PR as the fetching decision, addressing Codex review.
- Rename the fetching ADR to 0017; preserve ownership ADRs 0014/0015 and refer to sandbox
  ADR 0016 for its roles, proxy policy, scratch storage, and plaintext artifact mount.
- Update the changelog, architecture fetch-queue row, and security references.
- Document forge-allowlisted smart HTTP with pinned connections, opaque pack storage,
  sandbox-only ownership verification/extraction, and archive rejection/size rules.
  Validation: 923 passed, 3 worker E2E skips, 97.63% coverage; ruff, pyright, and hooks pass.

## Next step
Request Codex review on the pushed fixes, then merge #129 only if review and CI pass.

## Open threads
- #83 remains open until [#130](https://github.com/cpt9m0/attacksurf/pull/130), which covers
  analysis tools, pinned images, and licenses. Reconcile its ADR number and references next.
- Fetch/analysis queues remain reserved until their implementations exist.
- Earlier local main handoffs are preserved in Git stashes, including
  `codex: preserve local handoff before PR 129`.
- Follow-ups: #114–#117. `.env.example` lacks ALLOW_SIGNUP, SESSION_LIFETIME_HOURS, PROXY_COUNT.

## Notes for the next agent
- Commits/pushes are authorized for all PRs in this chat; merge only when requested.
- User requests the same review/CI-gated merge workflow for PR #129 as for #128.
- Ownership verification and hermetic worker settings are already merged; retain them.
