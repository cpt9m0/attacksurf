# STATE

> Handoff for the next session. Overwritten at the end of every task; not a history log.

**Updated:** 2026-11-05 · **Branch:** `docs/83-sandbox-adr` · **Issue:** #83 (analysis sandbox ADRs)

## Status
PR [#128](https://github.com/cpt9m0/attacksurf/pull/128) documents the sandbox decision.
Review fixes are local: the required handoff is included and ADR numbering is reconciled with main.
This is the first of three PRs for #83; no sandbox runtime is implemented yet.

## Last task
- Document static analysis in fresh gVisor containers, with no network or credentials,
  read-only input, capped JSON stdout, and per-run resource limits.
- Separate the credentialed worker, credential-free launcher, Docker-socket policy proxy,
  and untrusted artifact parser; reflect the decision in architecture/security docs.
- Update this handoff in the same PR, addressing the Codex review comment.
- Rename the sandbox decision to ADR 0016: merged ADRs 0014/0015 cover ownership verification.
  Update sandbox references and link follow-up PRs rather than assigning their ADR numbers.
- Resolve the changelog conflict with main by retaining both entries.
  Validation: 923 passed, 3 worker E2E skips, 97.63% coverage; ruff, pyright, and hooks pass.

## Next step
Wait for Codex review on the pushed fixes and green CI, then squash-merge #128 and update main.

## Open threads
- #83 remains open: [#129](https://github.com/cpt9m0/attacksurf/pull/129) covers fetching and
  archives; [#130](https://github.com/cpt9m0/attacksurf/pull/130) covers tool images/licenses
  and closes #83. Reconcile their ADR numbers/references with main before merging them.
- User authorizes merging #128 after Codex review passes and CI is green.
- Earlier local main handoffs are preserved in Git stashes, including
  `codex: preserve local handoff before PR 128`.
- Follow-ups: #114–#117. `.env.example` lacks ALLOW_SIGNUP, SESSION_LIFETIME_HOURS, PROXY_COUNT.

## Notes for the next agent
- The `analysis` queue stays reserved until the worker, launcher, proxy, and an analyzer exist.
- Only sandbox-proxy holds the Docker socket; its policy validates each container create request.
- PRs #123–#127 are merged; do not restore their earlier ownership or worker-settings code.
