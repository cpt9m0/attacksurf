# STATE

> Handoff for the next session. Overwritten at the end of every task; not a history log.

**Updated:** 2026-11-20 · **Branch:** `26-ai-summary` · **Issue:** #26 (AI exposure summary and notable assets)

## Status
Done locally: all 8 commits are on `26-ai-summary` (branched from `origin/main` after #186 merged) with lint, format, pyright, import-linter, migration round-trip, and full pytest suite passing.

## Last task
- Implemented #26 across 8 commits: ADR 0030; `ExposureSummary`/`StoredSummary` contract and schema snapshot; `summary/v1` prompt (pinned SHA-256) with `build_summary_messages`, `summarize`, and `validate_summary`; migration `0013_add_scan_ai_summary`; `services.summary`, `ai.summarize` task, `SUMMARY_STAGE`, and queueing hooks from `run_triage`/`finish_triage`; AI-owned `notable` tag syncing on `Asset.tags`; `services.summary_views`, polled `#scan-summary` card, and per-root "Latest AI summary" dashboard cards; summary eval cases (`risky_scan`, `clean_scan`), offline harness tests, and docs sync.

## Next step
Run live `make eval` with an LLM key in `.env`, verify a real scan on the dev stack shows the summary cards, push `26-ai-summary`, and open the draft PR `feat(ai): add the ai exposure summary` (`Closes #26`) with the eval model/results recorded.

## Open threads
- Live `make eval` and dev-stack smoke test were not run in this session (no `.env` LLM API key and Docker Desktop daemon was not running).
- `ai/pricing.py` still has no Claude list prices (carried over from #25).
- If manual asset tagging is added in a future issue, reserve `"notable"` for AI summaries (ADR 0030).

## Notes for the next agent
- `scan_data_block` defaults to `max_items=50`; `build_summary_messages` passes `max_items=MAX_SUMMARY_ASSETS` (200) explicitly.
- Keep `ai_label(item, at=...)` compatible with both `StoredTriage.triaged_at` and `StoredSummary.generated_at`.
- `tests/unit/web/conftest.py` and `tests/e2e/web/conftest.py` stub `summary_views.list_latest_root_summaries` alongside `finding_views.get_dashboard` for DB-less web tests.
