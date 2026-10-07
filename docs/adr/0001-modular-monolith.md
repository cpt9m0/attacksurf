# 0001. Modular monolith with layered packages

- Status: accepted
- Date: 2026-10-07

## Context
Small team (one human plus AI agents), early product, five future target types (DNS, IP, web,
code, binary). Microservices would add deployment and consistency costs with no payoff yet.

## Decision
One Python package (`src/attacksurf`) deployed as several processes (web, workers, beat).
Layers: `web`/`workers` → `services` → `domain`, with adapters in `infra`, `scanners`, `ai`.
`domain` imports nothing from other layers.

## Consequences
- Simple deploys and refactors; a single test suite.
- Boundaries must be enforced by review/lint (import contracts), not by the network.
- A module (likely binary analysis) can be extracted into a service later.
