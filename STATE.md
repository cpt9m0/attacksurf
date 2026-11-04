# STATE

> Handoff for the next session. Overwritten at the end of every task; not a history log.

**Updated:** 2026-11-04 · **Branch:** `test/126-hermetic-worker-settings` · **Issues:** #126, #83

## Status
- #126 (test leak) is fixed on `test/126-hermetic-worker-settings` (from `main`): hermetic
  worker settings moved from a session fixture to `pytest_configure` in `tests/conftest.py`;
  regression test `tests/unit/workers/test_app.py::test_module_level_tasks_do_not_load_real_settings_during_collection`.
  Full suite, ruff, pyright and import-linter pass. Not yet pushed / no PR.
- #83 (sandbox ADRs) is split into three PRs, each on its own branch from `main`:
  - `docs/83-sandbox-adr`: ADR 0014 (gVisor sandbox, `sandbox-launcher` + purpose-built
    `sandbox-proxy` as the only Docker-socket holder), architecture analysis diagram + queue
    row, security.md threat rows. 3 commits, not pushed: its pre-push hook failed on #126.
  - `docs/83-fetcher-adr`: ADR 0015 (fetchers under ScopeGuard, safe unpacking, "malicious
    archive" threat row). Empty.
  - `docs/83-analysis-tools-adr`: ADR 0016 (tool images by digest, license table). Empty;
    this PR closes #83.

## Next step
Push `test/126-hermetic-worker-settings` and open its PR (`Closes #126`); then push
`docs/83-sandbox-adr` (pre-push now passes once #126 is on the branch or merged; until then
the hook fails locally on that branch) and open its draft PR (`Refs #83`). Then write ADR 0015.

## Open threads
- Branch names here use the user's chosen type prefixes (`docs/`, `test/`), not the
  `<issue#>-<slug>` form in `docs/conventions.md`; ask before changing the convention.
- PR titles/commits use `docs(security): …` for the #83 PRs.
- Follow-ups still open: #114, #115, #116, #117. `.env.example` still lacks ALLOW_SIGNUP,
  SESSION_LIFETIME_HOURS, PROXY_COUNT.

## Notes for the next agent
- The pre-push pytest hook needs the dev DB: `sg docker -c 'make up'` (test DB on port 5434:
  `postgresql+psycopg://attacksurf:attacksurf@localhost:5434/attacksurf_test`).
- Celery task proxies defined at module level in tests are evaluated during *collection*;
  anything tests patch for the worker app must be in place by `pytest_configure`.
- Playwright: use Chromium in `~/.cache/ms-playwright` via
  `uv run --no-project --with playwright==1.55.0 python …` (no Google Chrome installed).
- `web/` can't import SQLAlchemy (import-linter): read models live in `services/asset_views.py`.
- Never chmod the Docker socket; use `sg docker -c …` for stale shell groups.
- DB-backed web tests: each request closes the shared `db_session` at teardown, detaching ORM
  rows; pass ids around and re-read (`tests/integration/web/test_assets_ui.py` helpers).
- HTMX keeps its history cache in sessionStorage (`htmx-history-cache`); `hx-push-url` uses
  pushState, so in Playwright wait with `expect(page).to_have_url()`, not `wait_for_url`.
- When reproducing a client race in Playwright, run a control with the fix removed.
- Signup is rate limited to 5/hour per IP, also in dev; reuse accounts when testing by hand.
