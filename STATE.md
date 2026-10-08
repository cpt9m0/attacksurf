# STATE

> Handoff for the next session. Overwritten at the end of every task; not a history log.

**Updated:** 2026-10-08 · **Branch:** `claude/blissful-goldberg-rd3suo` · **Issue:** #2 (layout, config, logging)

## Status
#2 implemented; PR open, waiting for CI + review, then squash-merge.

## Last task
- Layer packages created (`web`, `services`, `domain`, `scanners`, `ai`, `infra`, `workers`);
  templates/static moved to `web/`
- `create_app(settings=None)` in `app.py`; blueprints `ui` (`/`), `health` (`/healthz`), `api_v1`
- `Settings` in `config.py` (pydantic-settings, `.env.example`); prod requires `SECRET_KEY`
- structlog in `infra/logging.py`: JSON in prod, request IDs (validated `X-Request-ID`), redaction
- import-linter contracts in `pyproject.toml` + pre-commit hook (runs in CI `lint`)
- Also merged earlier: #33 (`uv_build` <0.13), #35 (Dependabot title prefixes)

## Next step
After #2 merges: implement #3 (Docker Compose dev stack: web, postgres, redis, worker, beat).
Compose services should use the `DATABASE_URL` / `REDIS_URL` defaults in `config.py`.

## Open threads
- Optional (user): ruleset on `main` requiring PRs + checks `lint`, `test (3.12)`,
  `test (3.13)`, `secrets`, `pr-title`
- #32: GitHub Sponsors / Ko-fi accounts not set up yet (Ko-fi username assumed `cpt9m0`)
- Repo settings for the user: description, topics, Discussions, Sponsorships,
  private vulnerability reporting, social preview
- `DESIGN.md` values are `TBD`: to be completed with Claude Design before/during #6
- context7 MCP blocked by the environment's network proxy (403); brave-search needs `BRAVE_API_KEY`

## Notes for the next agent
- Repo: default branch `main`, squash-merge only (PR title = commit subject), head branches
  auto-deleted
- Tests: build settings with `tests.helpers.make_settings(...)` (ignores local `.env`)
- `flask --app attacksurf` still works (`create_app` re-exported from `__init__.py`)
- First `pre-commit` run downloads hook envs (gitleaks builds with Go): takes a minute
- `jq` is needed by the Claude Code hooks (they no-op without it)
