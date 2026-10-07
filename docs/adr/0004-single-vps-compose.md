# 0004. Single VPS with Docker Compose

- Status: accepted
- Date: 2026-10-07

## Context
MVP stage, cost-sensitive, possibly a SaaS later.

## Decision
Deploy everything with Docker Compose on one VPS behind Caddy (automatic TLS). Nightly
`pg_dump` off-box.

## Consequences
- Cheap and simple. Single point of failure, accepted for the MVP.
- Sandboxing for future code/binary analysis uses gVisor (`runsc`) and Docker network policies on
  the same host.
- Scale path: workers to a second host, then managed Postgres.
