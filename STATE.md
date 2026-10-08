# STATE

> Handoff for the next session. Overwritten at the end of every task; not a history log.

**Updated:** 2026-10-08 · **Branch:** `claude/blissful-goldberg-rd3suo` · **Issue:** #3 (Docker Compose dev stack)

## Status
#3 implemented; PR open, waiting for CI (incl. new `compose` job) + review, then squash-merge.
#2 is merged (PR #36).

## Last task
- `Dockerfile`: `dev` target (dev deps, Flask debug, hot reload via bind mount) and `prod`
  target (no dev deps, gunicorn, uid 10001); base image pinned by digest; uv 0.11.32 from PyPI
- `compose.yaml`: `web` (127.0.0.1:5000), `postgres:16` (volume `pgdata`), `redis:7`, all
  healthchecked; `worker-passive`/`worker-ai`/`beat` placeholders behind profile `workers`
- `Makefile` (`up/down/logs/ps/build/shell/test/check/migrate`), `.dockerignore`
- CI `compose` job (prod image non-root check, `compose up --wait`, curl `/healthz`);
  Dependabot watches `docker` + `docker-compose`
- Verified locally with a real Docker daemon: stack healthy, `/healthz` 200, hot reload, 39 tests
  pass in-container, prod image runs as uid 10001 and fails fast without a strong `SECRET_KEY`

## Next step
After #3 merges: implement #4 (DB foundation: SQLAlchemy 2.0, Alembic, base mixins with `org_id`).
Postgres runs in compose; `make migrate` is a placeholder until then. Use the `db-migration` skill.

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
