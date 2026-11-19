# STATE

> Handoff for the next session. Overwritten at the end of every task; not a history log.

**Updated:** 2026-11-19 · **Branch:** `22-findings-ui` · **Issue:** #22 (findings UI)

## Status
Issue #22 is implemented and open as PR #184 (`Closes #22`); its CI run is green (lint,
test 3.12/3.13/3.15, web-e2e, compose, secrets, pr-title). Two commits are pushed; nothing is
merged.

## Last task
- `services/finding_views.py`: list/filter/sort/pagination, "new since last scan" (latest
  completed scan + `Finding.first_seen_scan_id`), detail evidence/timeline, exports, dashboard.
- `services/findings.py`: accept risk / false positive (comment required) and reopen, audited in
  the same transaction; bulk is all-or-nothing and capped at 50.
- `web/finding_params.py`, `/findings` list/detail/status/bulk/export routes, dashboard route,
  `/api/v1/findings` list/detail/status/bulk, templates and the bulk-selection script.
- No migration: status comments live in `AuditLog.details`.
- Bulk selection uses plain event delegation in `static/js/app.js` (the Alpine CSP build did
  not run handlers on the swapped table); unit and browser-layout tests stub the finding views.

## Next step
Review and merge PR #184; then pick the next unblocked issue (AI triage #25 builds on the
finding detail's AI panel).

## Open threads
- Issue #22 wants `/api/v1/findings`; implemented as list/detail/status/bulk, without API file
  exports (the UI downloads are the contract for now).
- Status comments are audit history, not a mutable note on the finding; a per-finding note
  column would need a migration and an ADR if the product wants it.
- Bulk selection is cleared by a filter swap (the results region is replaced); the count is a
  client convenience only, the server owns the 50-finding cap.
- "New since last scan" uses the latest completed scan of the selected root, or of the org when
  no root is selected.
- `fixed_at` is cleared on a manual reopen; a later scan may fix the finding again.
- The PR is larger than the ~400-line guideline; the Codex plan proposed four slices
  (list/detail/workflow/exports+dashboard) if review prefers them.

## Notes for the next agent
- DB tests need `TEST_DATABASE_URL`; locally a throwaway Postgres was run in
  `attacksurf-test-db` on port 5433 (`attacksurf_test`).
- Unit web tests stub `finding_views` in `tests/unit/web/conftest.py`; new DB-backed pages need
  a stub there or they fail without a database.
- `EXPORT_LIMIT` (5000), `MAX_EVIDENCE` (20) and `MAX_STATUS_COMMENT` (2000) are the caps; CSV
  cells starting with `= + - @` (and tab/CR) get an apostrophe prefix.
- `tests/integration/factories.make_finding` now builds findings/evidence for tests.
- AI triage is still a placeholder (#25); nothing calls an LLM from a web request.
