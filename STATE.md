# STATE

> Handoff for the next session. Overwritten at the end of every task; not a history log.

**Updated:** 2026-11-21 · **Branch:** `26-ai-summary` · **Issue:** #26 (AI exposure summary)

## Status
PR #187's latest Codex finding is fixed locally; publish the fix and merge once CI passes.

## Last task
- Serialized summary publication with a tenant-scoped root `FOR UPDATE` lock, acquired only
  after the LLM call and held through summary storage, tag synchronization, and commit.
- Only the newest completed scan with a stored summary can sync `notable` tags, using the
  dashboard's `(created_at, id)` order. Older scans retain their historical summary and usage.
- Regression tests cover out-of-order completion, timestamp ties, a newer unsummarized scan,
  and real PostgreSQL lock contention with no incidental asset UPDATE to mask a missing lock.
  Usage is added after the root lock to preserve scan startup's root-before-org lock order;
  the two-connection regression proves the competing Org lock remains available.
- Updated ADR 0030 decision 7 and CHANGELOG. No README, DESIGN, or agent-rule changes needed:
  no new UI, settings, dependencies, or conventions.
- Local gates: 3,451 passed, 27 opt-in/empty-case skips; coverage 95.92%; ruff check/format,
  pyright, import-linter (8 contracts), and pre-commit all pass.

## Next step
Push the review fix, verify CI, reply to/resolve Codex thread, and squash-merge PR #187 as
requested. After merging, #28 (email notifications; depends on #20, #26, #27) is next in epic #31.

## Open threads
- Earlier human-review requests beyond this Codex fix remain: prioritize assets in the
  200-asset summary input, live eval results, light/dark card screenshots, and the author's
  AI-assistance acknowledgement. Do not claim those were completed by this task.
- `ai/pricing.py` still has no Claude list prices.

## Notes for the next agent
- Local verification uses the dedicated `attacksurf187_test` PostgreSQL database on port 5433;
  never run fixture schema resets against production or a database another session is using.
- Keep `(created_at, id)` summary recency identical to `services.summary_views`.
