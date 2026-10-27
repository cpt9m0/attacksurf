# 0012. Migrate the database in the dev startup command

- Status: accepted; supersedes ADR 0008's explicit-only migrations for dev `make up`
- Date: 2026-10-27

## Context
`make up` can report a healthy fresh stack while signup fails because the `users` table does
not exist. `/healthz` intentionally checks liveness, not database schema readiness. Requiring a
second, easily missed command makes the recommended one-command dev setup unreliable.

## Decision
Dev `make up` builds images, starts PostgreSQL/Redis and waits for health, invokes the existing
`make migrate` target, then starts the application services and waits for health. Each step
must succeed before the next runs. Migrations stay outside Flask and worker startup; there is
one migration command, not one per application process. CI exercises this same entrypoint on a
fresh database and runs worker checks before any separate migration command.

## Consequences
- Fresh dev stacks are ready for signup after `make up`; repeated upgrades are no-ops at head.
- A migration failure stops the command before it starts application services. Already-running
  services are not stopped; this is dev orchestration, not a production deployment strategy.
- Direct `docker compose up` and non-dev deployments still require explicit migrations.
- No schema changes, migration rewrites, database resets or readiness endpoint are introduced.
