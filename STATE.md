# STATE

> Handoff for the next session. Overwritten at the end of every task; not a history log.

**Updated:** 2026-11-19 · **Branch:** `22-findings-ui` · **Issue:** #22 (findings UI)

## Status
Issue #22 is implemented locally on `22-findings-ui`; nothing is pushed and no PR is open. The
full suite passes (3029 tests, 95.7% coverage) and ruff/format/pyright are clean.

## Last task
- `services/finding_views.py`: list/filter/sort/pagination, "new since last scan" (latest
  completed scan + `Finding.first_seen_scan_id`), detail evidence/timeline, exports, dashboard.
- `services/findings.py`: accept risk / false positive (comment required) and reopen, audited in
  the same transaction; bulk is all-or-nothing and capped at 50.
- `web/finding_params.py`, `/findings` list/detail/status/bulk/export routes, dashboard route,
  `/api/v1/findings` list/detail/status/bulk, templates and `findingSelection` Alpine component.
- No migration: status comments live in `AuditLog.details`.
- Tests: `tests/integration/services/test_finding_views.py`, `test_findings.py`,
  `tests/integration/web/test_findings_ui.py`, `test_findings_api.py`,
  `tests/unit/web/test_export.py`, `test_finding_params.py`.

## Next step
Run `pre-pr-check`, then push `22-findings-ui` and open its PR (`Closes #22`). Splitting the
branch into the four commits the plan named (list/filters, detail, workflow, exports/dashboard)
is optional; the working tree is done.

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

## Notes for the next agent
- DB tests need `TEST_DATABASE_URL`; locally a throwaway Postgres was run in
  `attacksurf-test-db` on port 5433 (`attacksurf_test`).
- Unit web tests stub `finding_views` in `tests/unit/web/conftest.py`; new DB-backed pages need
  a stub there or they fail without a database.
- `EXPORT_LIMIT` (5000), `MAX_EVIDENCE` (20) and `MAX_STATUS_COMMENT` (2000) are the caps; CSV
  cells starting with `= + - @` (and tab/CR) get an apostrophe prefix.
- `tests/integration/factories.make_finding` now builds findings/evidence for tests.
- AI triage is still a placeholder (#25); nothing calls an LLM from a web request.
