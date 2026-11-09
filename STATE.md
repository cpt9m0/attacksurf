# STATE

> Handoff for the next session. Overwritten at the end of every task; not a history log.

**Updated:** 2026-11-09 · **Branch:** `84-sandbox-port` · **Issue:** #84 (sandbox runner), PR 1 of 5

## Status
#84 was rewritten to follow ADR 0016 and lists the merge order. This branch adds the sandbox
port (`domain/sandbox.py`), `ScannerGrant.sandbox_analyzers` and `ctx.runtime.sandbox`, checked
per run by ScopeGuard. No runner is wired yet, so granted calls still fail closed.

## Next step
Open PR 2 (`84-sandbox-proxy`) alongside this one. Merge order: port → proxy → launcher →
analysis worker (after #133) → CI.

## Open threads
- The scanner registry caps `timeout_seconds` at 240 s, but ADR 0016 allows 600 s sandbox runs.
  Resolve before the first analysis scanner; the runner client deadline (PR 3) is affected too.
- PR 3 wires a real runner into `workers/runtime.py`.
- PR 4 adds a new ADR for consuming the `analysis` queue before a real analyzer exists.
- `runsc` must be registered on the VPS before PR 4 is deployed to prod.
- #23: PR #131 merged; Anthropic and OpenAI-compatible adapters and the factory remain. Each
  adapter must enforce the 240 s total deadline. Org base URLs need ScopeGuard validation (#24).
- Follow-ups: #114–#117. `.env.example` lacks ALLOW_SIGNUP, SESSION_LIFETIME_HOURS, PROXY_COUNT.

## Notes for the next agent
- `docs/plans/` holds the user's temporary plan copy: never stage it.
- Commits and pushes are authorized for #84's PRs; merge only when requested.
