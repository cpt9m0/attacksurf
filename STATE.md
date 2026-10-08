# STATE

> Handoff for the next session. Overwritten at the end of every task; not a history log.

**Updated:** 2026-10-08 · **Branch:** `claude/blissful-goldberg-rd3suo` · **Issue:** #5 (Org/User/Membership)

## Status
#5 implemented; PR open, waiting for CI + review, then squash-merge. #1–#4 merged.

## Last task
- Migration `0002`: `orgs.slug` (backfilled, unique) + `plan`; `users` (global, email unique
  lowercase), `memberships` (TenantScoped, role VARCHAR+CHECK, unique org/user), `audit_log`
  (TenantScoped, `details` JSONB, append-only)
- `domain/accounts.py`: `Role`, `has_role`, email/password (12–1024)/org-name rules, `slugify`,
  `PasswordHasher` protocol, `InvalidSignup`, `EmailAlreadyRegistered`
- `infra/crypto.py`: `Argon2PasswordHasher` (moved here from #7's scope; commented on #7)
- `services/accounts.py`: `register_user` (one commit; race on email → `EmailAlreadyRegistered`);
  `services/audit.py`: `audit()` (caller's transaction)
- Tests: `tests/fakes.py` (`FakePasswordHasher`), unit + integration; 119 tests, 100% coverage

## Next step
After #5 merges: #6 (UI foundation) needs `DESIGN.md` values (Claude Design) — check with the
user; otherwise #7 (auth: Flask-Login, login/logout, CSRF, rate limit) builds on `register_user`
and `Argon2PasswordHasher.verify`.

## Open threads
- Optional (user): ruleset on `main` requiring PRs + checks `lint`, `test (3.12)`,
  `test (3.13)`, `secrets`, `compose`, `pr-title`
- #32: GitHub Sponsors / Ko-fi accounts not set up yet (Ko-fi username assumed `cpt9m0`)
- Repo settings for the user: description, topics, Discussions, Sponsorships,
  private vulnerability reporting, social preview
- `DESIGN.md` values are `TBD`: to be completed with Claude Design before/during #6
- context7 MCP blocked by the environment's network proxy (403); brave-search needs `BRAVE_API_KEY`

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
