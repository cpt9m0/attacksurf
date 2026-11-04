# STATE

> Handoff for the next session. Overwritten at the end of every task; not a history log.

**Updated:** 2026-11-04 · **Branch:** `docs/83-analysis-tools-adr` · **Issue:** #83 (sandbox ADR)

## Status
All three #83 ADRs are written and in draft PRs, none merged. No sandbox code exists yet.

## Last task
- ADR 0014, sandbox execution model: #128 (`docs/83-sandbox-adr`).
- ADR 0015, repository fetching and archive extraction: #129 (`docs/83-fetcher-adr`).
- ADR 0016, tools, licenses and images: `docs/83-analysis-tools-adr`, which closes #83.

## Next step
Merge in this required order: #128 → #129 → the ADR 0016 PR. Reviews can happen in any order.
Then pick up #14 (DNS TXT ownership verification), or #84 (sandbox runner) if the code module
goes first.

## Open threads
- Decided: ADR 0015 allows only `github.com` and `gitlab.com`, so no self-hosted servers. OSV
  data uses #93's read-only volume (ADRs 0014 and 0016). #93's text stays as written, but its
  sync needs the streaming port from ADR 0016, because the scanner client caps at 1 MiB.
- #127 (test leak, #126) is open and also rewrites this file; keep the newer handoff.
- Follow-ups filed: #114 shell overflows at 390px (pre-existing, every page), #115 tag editing,
  #116 in-flight scans keep running after their root is archived, #117 overlapping roots.
- ADR 0014 allows 600 s of wall time, but tracked tasks have a 300 s soft limit, so analysis
  tasks need an override (#84).
- `.env.example` still lacks ALLOW_SIGNUP, SESSION_LIFETIME_HOURS, PROXY_COUNT.
- The Playwright MCP expects Google Chrome (`/opt/google/chrome`), which isn't installed. The
  user approved Playwright's Chromium in `~/.cache/ms-playwright`; drive it with a scratchpad
  script via `uv run --no-project --with playwright==1.55.0 python …`.

## Notes for the next agent
- Until #127 merges, set `REDIS_URL=redis://localhost:6379/0` for pushes and pytest runs.
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
