# STATE

> Handoff for the next session. Overwritten at the end of every task; not a history log.

**Updated:** 2026-10-14 · **Branch:** `claude/blissful-goldberg-rd3suo` · **Issue:** #7 follow-up

## Status
#1–#7 merged (#7 = PR #45). Follow-up PR open with fixes for Codex's late review of #45.

## Last task
- `register_user(..., first_user_only=True)`: advisory lock + recheck (`SignupClosed`)
- `authenticate` rejects passwords > `MAX_PASSWORD_LENGTH` before hashing
- `web/auth.py`: login gate registered before `CSRFProtect`; logout clears the session even if the
  audit write fails; absolute session lifetime via `session["auth_at"]` checked in the user
  loader (+ `SESSION_REFRESH_EACH_REQUEST=False`)
- Tests: 252 with DB (99%), 198 without (84%)

## Next step
After the follow-up merges: #8 (Asset model + relations graph, value normalization, migration
`0003`; acceptance: re-upserting a discovered asset updates `last_seen`).

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
