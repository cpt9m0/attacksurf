# STATE

> Handoff for the next session. Overwritten at the end of every task; not a history log.

**Updated:** 2026-10-09 · **Branch:** `claude/blissful-goldberg-rd3suo` · **Issue:** #6 (UI foundation)

## Status
#6 implemented; PR open, waiting for CI + review, then squash-merge. #1–#5 merged.

## Last task
- Shell `templates/layouts/base.html` (+ `fragment.html` for HTMX), 5 nav pages (empty states),
  `errors/error.html`; macros in `templates/components/`
- `static/css/tokens.css` (placeholder tokens, light/dark) + `app.css`; `js/theme.js`, `js/app.js`
  (`themeToggle`); vendored HTMX 2.0.11 + Alpine CSP 3.17.4 (`vendor/SHA256SUMS`); Lucide sprite
- `web/rendering.py` (`render_page`, `is_htmx`), `web/security.py` (CSP etc., HSTS prod),
  `web/errors.py` (HTML/JSON, 500 logs + request ID)
- Verified in Chromium: no CSP violations, theme toggle persists, HTMX swap, skip link, mobile
  layout; screenshots in `docs/images/`

## Next step
After #6 merges: #7 (auth: Flask-Login, signup/login/logout with `register_user` and
`Argon2PasswordHasher.verify`, CSRF incl. HTMX `hx-headers`, Flask-Limiter, `@require_role`
using `domain.accounts.has_role`, audit login events). Forms must stay CSP-clean.

## Open threads
- Optional (user): ruleset on `main` requiring PRs + checks `lint`, `test (3.12)`,
  `test (3.13)`, `secrets`, `compose`, `pr-title`
- #32: GitHub Sponsors / Ko-fi accounts not set up yet (Ko-fi username assumed `cpt9m0`)
- Repo settings for the user: description, topics, Discussions, Sponsorships,
  private vulnerability reporting, social preview
- `DESIGN.md` visual values are placeholders in `static/css/tokens.css` (`TODO(DESIGN.md)`):
  replace via Claude Design (tokens, severity colors, favicon/brand); no template changes needed
- context7 MCP blocked by the environment's network proxy (403); brave-search needs `BRAVE_API_KEY`;
  playwright MCP wants Google Chrome (absent): use Python Playwright with
  `executable_path=/opt/pw-browsers/chromium-1194/chrome-linux/chrome` instead

## Notes for the next agent
- Repo: default branch `main`, squash-merge only (PR title = commit subject), head branches
  auto-deleted
- Cloud sandbox: start Docker with `dockerd &`; Docker Hub may rate-limit (429), so use
  `mirror.gcr.io/library/<image>` with the same digest; GHCR blob downloads are blocked by the proxy;
  image builds need the proxy CA (build from a scratch copy that adds it, never commit that)
- Tests: `tests.helpers.make_settings(...)` ignores `.env` and OS env; env-loading tests use
  `settings_from_env()` + `clean_env` fixture
- `flask --app attacksurf` works (`create_app` lazily re-exported from `__init__.py`)
- First `pre-commit` run downloads hook envs (gitleaks builds with Go): takes a minute
