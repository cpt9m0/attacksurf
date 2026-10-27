# STATE

> Handoff for the next session. Overwritten at the end of every task; not a history log.

**Updated:** 2026-10-27 · **Branch:** `fix/docker-group-session` · **Issue:** none (Docker access fix)

## Status
Docker access diagnosed, stack healthy; documentation fix prepared for a draft PR pending CI.

## Last task
- Confirmed `ubuntu` is already configured in the `docker` group, but the current login
  session lacks it. No socket permissions, group memberships or Makefile behavior changed.
- Ran `sg docker -c 'make up'`: all six services are healthy; `/healthz` returns `ok`.
- Added safe Linux Docker permission troubleshooting to `docs/development.md`, linked it
  from `README.md`, and updated `CHANGELOG.md`. No app/UI/schema/agent convention changes.
- Ruff check/format, pyright and pre-commit pass; DB-backed pytest: 513 passed,
  2 opt-in worker tests skipped, coverage 98.09%. No behavior changed, so no new tests needed.

## Next step
Review the draft PR for this branch and wait for CI before marking it ready. In the user's
terminal, run `newgrp docker` or reconnect over SSH before using plain `make up`.
Then continue the roadmap with #12
(ScopeGuard/safe clients); #11 is merged in main via #54.

## Open threads
- #53 tracks an existing clock-boundary CSRF test flake.
- #20 owns finding lifecycle/diffs; #21 owns stale-job sweeping/cancellation; #25 owns triage.
- `.env.example` still needs auth settings (ALLOW_SIGNUP, SESSION_LIFETIME_HOURS, PROXY_COUNT).

## Notes for the next agent
- Existing agent/tmux shells retain stale groups: prefix Docker commands with `sg docker -c`
  or restart the session. Docker group access is root-equivalent; never `chmod 666` the socket.
- Dev Compose stack is running; the existing issue11 Postgres container also runs on port 5433.
- DB tests: `TEST_DATABASE_URL=postgresql+psycopg://attacksurf:attacksurf@localhost:5433/attacksurf_test uv run pytest`.
