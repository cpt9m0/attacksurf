# STATE

> Handoff for the next session. Overwritten at the end of every task; not a history log.

**Updated:** 2026-10-27 · **Branch:** `56-fix-signup-database-startup` · **Issue:** #56 (signup 500)

## Status
Signup fixed on the running stack; branch verified locally and prepared for PR review.

## Last task
- Signup 500 came from an unmigrated database: no `users` table. The failed signup saved no
  account. Applied existing migrations through `0004`.
- `make up` now builds, waits for PostgreSQL/Redis, runs `make migrate`, then starts apps.
  Added four host-side orchestration regression tests (confirmed failing before the fix),
  and an opt-in signup smoke test using the stack's existing schema with rolled-back writes.
- CI now exercises `make up`, signup/worker checks, then migration repeatability. Updated
  README, changelog, development/architecture docs, ADRs 0008/0012, and AGENTS.md.
- Ruff check/format, pyright and pre-commit pass. DB-backed pytest: 517 passed, 3 opt-in
  tests skipped, 98.09% coverage; all 3 opt-in Compose tests pass separately. Repeated
  `make migrate` succeeds. No schema, UI, auth policy or secret changes.
- Tracking issue #56; branch renamed to match it. All checks rerun before PR publication.

## Next step
Review the PR for this branch (`gh pr view`); require all CI checks green before merging.
The next unblocked roadmap item is #12 (ScopeGuard/safe clients).

## Open threads
- Roadmap: #12 (ScopeGuard/safe clients) is next; #11 is merged via #54.
- #53 tracks a clock-boundary CSRF test flake; #20 finding lifecycle/diffs, #21 stale jobs,
  #25 triage. `.env.example` still needs auth settings (ALLOW_SIGNUP, SESSION_LIFETIME_HOURS,
  PROXY_COUNT).

## Notes for the next agent
- Stale shell groups: use `sg docker -c 'make up'` or reconnect. Never chmod the Docker socket.
- Tailnet-only HTTPS Serve proxies to localhost:5000; disable with
  `sudo tailscale serve --https=443 off`. No public Funnel. All six dev services are healthy.
- Existing CLIProxyAPI management UI on tailnet port 8317 returns HTTP 200; its systemd unit
  is running with unchanged configuration.
- DB tests use the separate issue11 Postgres container on 5433:
  `TEST_DATABASE_URL=postgresql+psycopg://attacksurf:attacksurf@localhost:5433/attacksurf_test uv run pytest`.
