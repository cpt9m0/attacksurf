# STATE

> Handoff for the next session. Overwritten at the end of every task; not a history log.

**Updated:** 2026-11-22 · **Branch:** `ui-ux-improve` · **Task:** All-page screenshot harness & UI/UX improvement pass

## Status
Completed the hermetic all-page Playwright screenshot capture harness (`scripts/capture_screenshots.py`,
`make screenshots`, `tests/e2e/web/ui_fixtures.py`) covering 20 screens/states across light & dark
themes at desktop (`1440×900`) and mobile (`390×844`), visually reviewed all 80 baseline screenshots,
and implemented the full UI/UX improvement pass across `tokens.css`, `app.css`, `app.js`, `ui.py`,
and page/component templates, verified by `tests/unit/web/test_design_tokens.py` and expanded
`tests/e2e/web/test_shell_layout.py`.

## Last task
- Added `tests/e2e/web/ui_fixtures.py` and `scripts/capture_screenshots.py` (`make screenshots`,
  `screenshots/` in `.gitignore`) using in-memory Playwright HTTP routing (`http://attacksurf.local`)
  so external SVG sprite icons (`<use href="/static/icons.svg#...">`) render hermetically without
  network sockets or a database.
- Upgraded `tokens.css` and `app.css` (and updated `DESIGN.md`): WCAG 2.2 AA contrast-verified
  light/dark palette, semantic tinted status pills, styled `<progress>` bar and file inputs,
  padded `.card > .card-header` + `.card-body:empty` collapse on scan detail cards, card-aligned
  outer table column padding, fixed `.field.field-check` row direction, and `max-width: 22rem;
  overflow-wrap: break-word` on table cells.
- Improved templates and UX flows: compact tabbed asset intake card on `/assets`
  (`Alpine.data("assetIntake")`), Dashboard empty-state CTA, auth page brand icon + theme toggle,
  clickable findings on Asset Detail (`?tab=findings`), grouped `.page-actions` on Asset Detail and
  Scan Detail, active sidebar nav highlight on Scan Detail and Finding Detail, aligned Findings
  filter bar with live debounced Asset search, stacked 2-line finding title/metadata cells, and
  copyable evidence blocks on Finding Detail.
- Added `tests/unit/web/test_design_tokens.py` (27 fg/bg contrast pairs × 2 themes + dark-mode
  block parity) and expanded `tests/e2e/web/test_shell_layout.py`, `test_ui.py`, and
  `test_components.py`.

## Next step
Review and merge the `ui-ux-improve` PR against `main` (and run the manual VPS backup/hardening
steps in `docs/deployment.md` from #29). On the sandbox track, PR 5 (`84-sandbox-ci`) remains next.

## Open threads
- **Proxy trust:** the proxy has no caller authentication and `worker-analysis` shares the
  `sandbox` network with it. Written up in `docs/security.md`; #92 must close it before prod.
- **Dropped dev jobs:** `worker-analysis` drops `analysis.*` messages until #87/#101 register
  tasks; the job rows stay `queued`.
- **#92 prerequisites:** proxy, launcher and worker in `compose.prod.yaml`, `runsc` on the VPS,
  and the profile guard test in `tests/unit/scanners/test_profiles.py` removed or changed.
- Follow-up issue to file (before #92): after a proxy restart a stray `attacksurf-*` container
  is alerted on but not removed.
- The `/tmp/attacksurf-sandbox` default can be claimed first by another local user on a shared
  host (symlink risk, `sandbox_launcher/artifacts.py`). Accepted in dev; revisit before #92.
- Nothing enforces "the artifact belongs to the job's org" before `SandboxRunner.run`: the first
  analysis scanner must `get_scoped` the artifact first, with a tenant-isolation test.
- From the AI summary work (#26): human-review requests remain (prioritize assets in the
  200-asset summary input, live eval results); light/dark AI summary card screenshots are now
  generated via `make screenshots`; `ai/pricing.py` still has no Claude list prices.

## Notes for the next agent
- Run `make screenshots` (or `uv run python scripts/capture_screenshots.py --out screenshots/latest`)
  after any template/CSS change to inspect all 20 views in light/dark at 1440px and 390px.
- The launcher copies proxy constants and `domain.scanners.MAX_OUTPUT_BYTES` on purpose (it may
  not import them); a parity test guards each copy. Don't "fix" that by importing.
- `sandbox-images.lock` is `{}`: the catalog is empty, so every `POST /runs` is a 404.
- Compose sandbox services have no `curl`; healthchecks use `python -c`.
- ADR numbers move fast: check `origin/main` and open branches for the next free number first.
- Production plugins are registered in `src/attacksurf/app.py` and `src/attacksurf/workers/app.py`.
- DB tests need `TEST_DATABASE_URL`; the dev stack exposes PostgreSQL on `127.0.0.1:5432` with an
  `attacksurf_test` database (`make test` runs them in `web`).
- The ruff format hook strips imports that aren't used yet: add imports with their first use.
- Keep `(created_at, id)` summary recency identical to `services.summary_views`.
