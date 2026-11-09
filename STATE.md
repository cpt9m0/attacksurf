# STATE

> Handoff for the next session. Overwritten at the end of every task; not a history log.

**Updated:** 2026-11-09 · **Branch:** `84-sandbox-port` · **Issue:** #84, PR #134 (1 of 5)

## Status
PR #134 includes current `main` (Cloudflare deployment, #133) without dropping the sandbox
port, analyzer grants or per-run ScopeGuard checks. No runner is wired; calls fail closed.

## Last task
- Resolved #134's conflicts by retaining both changelog entries and consolidating this handoff.
- Kept #133's fixed-clock due-verifications test: both checks use explicit `NOW`, never wall time.
- Preserved #133's production stack, deployment runbook and forwarded-visitor rate limits.

## Next step
Review and merge PR #135 (`84-sandbox-proxy`) after #134. Order: port → proxy → launcher →
analysis worker (#133 prerequisite is merged) → CI. Remaining parts of #84 are not deployed here.

## Open threads
- Scanner timeout is capped at 240 s; ADR 0016 allows 600 s. Resolve before the first analyzer.
- PR 3 wires the real runner; PR 4 documents consuming `analysis` before an analyzer exists.
- Register `runsc` on the VPS before deploying PR 4.
- #23: provider adapters/factory remain; enforce the 240 s total deadline and ScopeGuard (#24).
- Production handoff from #133: no workers/beat; backups, monitoring and hardening remain (#29).
  Signup was enabled; close it until backups exist. A dedicated VPS remains an open question.
- #133 recorded exposed tunnel/API credentials requiring rotation/revocation; confirm separately.
- Replace `/opt/attacksurf`'s plain source files with an authenticated clone for main-based deploys.
- Follow-ups #114–#117; `.env.example` lacks ALLOW_SIGNUP, SESSION_LIFETIME_HOURS, PROXY_COUNT.

## Notes for the next agent
- Deployment: `docs/deployment.md`; secrets stay in `/etc/attacksurf/`, never git or images.
- `PROXY_COUNT` counts hops (1 behind the tunnel); validate Caddy configuration before deploy.
- `docs/plans/` is the user's temporary plan copy: never stage it.
- Commits/pushes authorized for #84; merge only when requested. #134's merge is requested.
