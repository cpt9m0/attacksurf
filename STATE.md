# STATE

> Handoff for the next session. Overwritten at the end of every task; not a history log.

**Updated:** 2026-11-09 · **Branch:** `84-sandbox-proxy` · **Issue:** #84 (sandbox runner), PR 2 of 5

## Status
Draft PR #134 (`84-sandbox-port`) adds the port and grants. This branch adds `sandbox_proxy/`:
the deny-by-default Docker socket guard, its create policy, and an import-linter isolation
contract. Removals retain ownership unless Docker confirms success or absence; a successful
`wait?condition=removed` also reclaims capacity after AutoRemove. In-flight creates count against
the cap. Unknown create outcomes keep a reserved slot and a proxy-generated cleanup name;
subsequent creates retry cleanup, and only confirmed deletion releases uncertain capacity.
Proxy settings tests clear the environment; `.env.example` lists all defaults.
Nothing deploys it yet; compose comes in PR 4 and the images lock in PR 5.

## Next step
Merge #134, then this PR, then build PR 3 (`84-sandbox-launcher`). Merge order: port → proxy →
launcher → analysis worker (after #133) → CI.

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
- Follow-ups: #114–#117. `.env.example` lacks ALLOW_SIGNUP, SESSION_LIFETIME_HOURS, PROXY_COUNT.

## Notes for the next agent
- `docs/plans/` holds the user's temporary plan copy: never stage it.
- Commits and pushes are authorized for #84's PRs; merge only when requested.
- The test-clock commit is on both #84 branches and drops out on rebase.
