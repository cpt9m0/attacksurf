# STATE

> Handoff for the next session. Overwritten at the end of every task; not a history log.

**Updated:** 2026-10-31 · **Branch:** `13-assets-ui` · **Issue:** #13 (Assets UI)

## Status
#13 is complete in two PRs: PR 1 (#113, services + `/api/v1/assets`) is merged; PR 2 (UI,
Closes #13) is open from `13-assets-ui`. When it merges, #13 is done.

## Last task
- Pages in `web/ui.py`: `/assets` (add-domain form with HTMX inline errors, filter bar swapping
  only `#asset-results`, pagination), `/assets/<id>?tab=overview|findings|scans` (metadata,
  relations both ways, findings, scan history), `POST /assets/<id>/archive` (admin, confirm dialog).
- Components: `confirm_dialog` (`<dialog>` + `Alpine.data("confirmDialog")`), `select_field`,
  `form_field(autofocus=)`, `relative_time` (`web/formatting.py` filters), `data_table` call blocks.
- CSS: `.content { min-width: 0 }` so wide tables scroll inside `.table-wrap`; new tokens
  `--color-backdrop`, `--field-min-width`, `--filter-min-width`, `--meta-column-min-width`.
- Review fixes (Codex on #118): history restores get the full page (`web/rendering.py`), and
  filter forms / tab bars use `hx-sync="this:replace"`; both reproduced and verified in Chromium.
- Checked in real Chromium (light + dark): add/invalid add, search focus, filters, tabs, dialog
  (Escape/Cancel/confirm), archive; no console errors besides the intended 422.

## Next step
Pick up #14 (DNS TXT ownership verification): it unblocks active checks and plugs a real
`OwnershipChecker` into `workers.runtime.scanner_gate()`. #116 (cancel scans on archive) is a
small MVP bug that can go first if preferred.

## Open threads
- Follow-ups filed: #114 shell overflows at 390px (pre-existing, every page), #115 tag editing,
  #116 in-flight scans keep running after their root is archived, #117 overlapping roots.
- `.env.example` still lacks ALLOW_SIGNUP, SESSION_LIFETIME_HOURS, PROXY_COUNT.
- The Playwright MCP expects Google Chrome (`/opt/google/chrome`), which isn't installed. The
  user approved Playwright's Chromium in `~/.cache/ms-playwright`; drive it with a scratchpad
  script via `uv run --no-project --with playwright==1.55.0 python …`.

## Notes for the next agent
- `web/` can't import SQLAlchemy (import-linter): read models live in `services/asset_views.py`.
- DB-backed web tests: each request closes the shared `db_session` at teardown, detaching ORM rows;
  pass ids around and re-read (`tests/integration/web/test_assets_ui.py` helpers).
- Unit tests in `tests/unit/web/test_ui.py` stub `asset_views` (no DB there).
- HTMX keeps its history cache in **sessionStorage** (`htmx-history-cache`); clear it there to
  force a server history restore when testing Back navigation.
- When reproducing a client race in Playwright, run a control with the fix removed (e.g. strip the
  attribute via JS); a repro that passes both ways proves nothing. See #118 review fixes.
- HTMX `hx-push-url` changes use pushState: in Playwright wait with `expect(page).to_have_url()`,
  not `wait_for_url` (it waits for a load event that never comes).
- Signup is rate limited to 5/hour per IP, also in dev; reuse accounts when testing by hand.
- DB tests: `TEST_DATABASE_URL=postgresql+psycopg://attacksurf:attacksurf@localhost:5432/attacksurf_test`.
- Stale shell groups: use `sg docker -c 'make up'`. Never chmod the Docker socket.
