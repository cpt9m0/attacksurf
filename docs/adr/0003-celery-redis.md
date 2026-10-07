# 0003. Celery + Redis for background work

- Status: accepted
- Date: 2026-10-07

## Context
Scans and LLM calls take seconds to minutes and must never run in web requests. We need retries,
chained pipeline stages, per-risk queues, and scheduling.

## Decision
Celery with Redis as broker and result backend. Queues: `passive`, `ai` (later `active`,
`analysis`). Per-org schedules live in the DB; a single beat task each minute enqueues due scans.

## Consequences
- Mature: chains/chords, routing, retries, beat.
- Celery's config surface is large; keep tasks thin and idempotent (`acks_late`).
- Redis also serves as cache and rate-limit store.
