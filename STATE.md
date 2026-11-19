# STATE

> Handoff for the next session. Overwritten at the end of every task; not a history log.

**Updated:** 2026-11-19 · **Branch:** `22-findings-ui` · **Issue:** #22 / PR #184

## Status
PR #184 addresses the three Codex review threads. The P1 browser-fixture finding was already
fixed in `d6b3789`; `3994f9a` preserves DNS resolver evidence and `9f73477` warns when exports
are capped. Head `e355e39` is pushed; all eight CI checks pass and the PR is mergeable. Replies
are posted on all three review threads; they stay unresolved for the reviewer.

## Last task
- `finding_views._evidence_row`: DNS evidence now falls back to the resolver's singular `value`
  and appends its ordered `cname_chain`, so HTML and `/api/v1/findings/<id>` keep the address.
- `web/ui._findings_page` passes `EXPORT_LIMIT`; `pages/_finding_results.html` warns when the
  filtered `result.total` exceeds it. The download keeps its `X-Export-Truncated` header.
- Regression tests cover A/AAAA API bodies, the HTML evidence block, the exact-limit boundary,
  HTMX results and a truncated CSV.
- Docs updated (`DESIGN.md`, `docs/architecture.md`, `CHANGELOG.md`, this file).

## Next step
Reviewer resolves the three threads and merges PR #184; then pick the next unblocked issue
(AI triage #25 builds on the finding detail's AI panel).

## Open threads
- P1 is fixed but unresolved on GitHub: cite `d6b3789` and the database-free layout run
  (14 passed) rather than changing `web-e2e` or adding PostgreSQL.
- The export warning is a render-time hint; the download-time header/JSON flag stays
  authoritative if the set changes before download.
- A per-finding mutable status note still needs a migration + ADR; comments remain audit history.
- The PR is larger than the ~400-line guideline; the Codex plan proposed four slices.

## Notes for the next agent
- Local checks after the fixes: full suite 3033 passed / 20 skipped, coverage 95.74%;
  ruff/pyright/import-linter/pre-commit clean; browser layout 14 passed with
  `env -u TEST_DATABASE_URL RUN_WEB_E2E=1`. Remote CI on `e355e39` is green.
- DB tests need `TEST_DATABASE_URL`; the throwaway `attacksurf-test-db` on port 5433 is running.
- `uv run ruff format --check .` also sees untracked `.hermes/plans/*.md` code blocks; CI and
  pre-commit only see tracked files. Use `ruff format --check src tests` locally.
- Unit and browser-layout tests stub `finding_views`; new DB-backed pages need stubs in both
  `tests/unit/web/conftest.py` and `tests/e2e/web/conftest.py`.
- `EXPORT_LIMIT` (5000), `MAX_EVIDENCE` (20), `MAX_STATUS_COMMENT` (2000); CSV cells starting
  with `= + - @` (and tab/CR) get an apostrophe prefix.
- AI triage is still a placeholder (#25); nothing calls an LLM from a web request.
