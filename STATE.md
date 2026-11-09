# STATE

> Handoff for the next session. Overwritten at the end of every task; not a history log.

**Updated:** 2026-11-09 · **Branch:** `main` · **Issue:** #84 (sandbox runner), PR 2 of 5 merged

## Status
PR #134 (`84-sandbox-port`) is merged: the port, analyzer grants and per-run ScopeGuard checks.
PR #135 (`84-sandbox-proxy`) is merged after this handoff: `sandbox_proxy/` is the only holder of
the Docker socket — a deny-by-default guard plus its create policy and an import-linter isolation
contract. Removals retain ownership unless Docker confirms success or absence; a successful
`wait?condition=removed` also reclaims capacity after AutoRemove. In-flight creates count against
the cap. Unknown create outcomes keep a reserved slot and a proxy-generated cleanup name;
subsequent creates retry cleanup, and only confirmed deletion releases uncertain capacity. Legacy
Docker API prefixes below v1.30 are denied so clients cannot disable AutoRemove or downgrade
removed-wait semantics. Proxy settings are documented in `.env.example` and its tests clear the
environment. Nothing deploys the proxy yet; compose comes in PR 4 and the images lock in PR 5.

`main` also carries the Cloudflare Tunnel production stack (ADR 0020, #133), the pull-based CD
units and `scripts/deploy.sh`/`make deploy` (#136–#139, #141, #142) — see `docs/deployment.md`.

## Next step
Build PR 3 (`84-sandbox-launcher`). Merge order: port → proxy → launcher → analysis worker (its
#133 prerequisite is merged) → CI.

## Open threads
- Proxy settings are documented in `.env.example`; deployment must explicitly pass them as
  environment variables without app credentials (the proxy never reads `.env`).
- The launcher must send exactly what the proxy accepts: see `sandbox_proxy/policy.py` (user
  `65532:65532`, `LogConfig` none, `AutoRemove`, binds under the artifact root). Attach before
  start, and only stdout.
- The scanner registry caps `timeout_seconds` at 240 s, but ADR 0016 allows 600 s sandbox runs.
  Resolve before the first analysis scanner; the runner client deadline (PR 3) is affected too.
- PR 3 wires a real runner into `workers/runtime.py`.
- PR 4 adds a new ADR for consuming the `analysis` queue before a real analyzer exists, and
  names the OSV volume `attacksurf_osv` to match the proxy.
- `runsc` must be registered on the VPS before PR 4 is deployed to prod.
- #23: Anthropic and OpenAI-compatible adapters and the factory remain. Each adapter must enforce
  the 240 s total deadline. Org base URLs need ScopeGuard validation (#24).
- Production handoff from #133: no workers/beat; backups, monitoring and hardening remain (#29).
  Signup was enabled; close it until backups exist. A dedicated VPS remains an open question.
- #133 recorded exposed tunnel/API credentials requiring rotation/revocation; confirm separately.
- Follow-ups: #114–#117. `.env.example` lacks ALLOW_SIGNUP, SESSION_LIFETIME_HOURS, PROXY_COUNT.

## Notes for the next agent
- Deployment: `docs/deployment.md` (pull-based CD); secrets stay in `/etc/attacksurf/`, never git
  or images. `PROXY_COUNT` counts hops (1 behind the tunnel); validate Caddy before deploying.
- `docs/plans/` holds the user's temporary plan copy: never stage it.
- Commits and pushes are authorized for #84's PRs; merge only when requested.
- The due-verifications test is clock-pinned on `main` (explicit `NOW`); PR #135's earlier
  duplicate of that fix was dropped in the merge, so both #84 branches now share main's version.
