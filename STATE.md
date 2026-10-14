# STATE

> Handoff for the next session. Overwritten at the end of every task; not a history log.

**Updated:** 2026-10-14 · **Branch:** `claude/blissful-goldberg-rd3suo` · **Issue:** #7 (authentication)

## Status
#7 implemented; PR open, waiting for CI + review, then squash-merge. #1–#6 merged.

## Last task
- `services/auth.py`: `authenticate` (generic failure, equal hashing work, rehash, audit
  login/login_failed), `record_logout`, `load_session_user` → `SessionUser`, `has_users`
- `web/auth.py`: Flask-Login, `CSRFProtect`, Flask-Limiter (per-app limiter), default-deny gate
  (`PUBLIC_ENDPOINTS`; HTMX → `HX-Redirect`, `/api/` → 401), `require_role`, `/login`,
  `/signup`, `POST /logout`, `_safe_next`
- Templates: `layouts/auth.html`, `layouts/_head.html`, `auth/login.html`, `auth/signup.html`,
  `components/form.html`; user menu + logout in the shell; `<body hx-headers>` CSRF token
- Settings `ALLOW_SIGNUP`, `SESSION_LIFETIME_HOURS`, `PROXY_COUNT` (not yet in `.env.example`:
  this sandbox can't read that file; the user adds the lines)
- ADR 0009. 242 tests, 99% coverage with DB, 86% without. Verified in Chromium.

## Next step
After #7 merges: next unblocked issue in epic #31 (check #8+ dependencies).

## Open threads
- `.env.example` needs: `ALLOW_SIGNUP=true`, `SESSION_LIFETIME_HOURS=12`, `PROXY_COUNT=0`
  (prod behind Caddy: `PROXY_COUNT=1`)
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
