# STATE

> Handoff for the next session. Overwritten at the end of every task; not a history log.

**Updated:** 2026-10-08 · **Branch:** `claude/blissful-goldberg-rd3suo` · **Issue:** #4 (DB foundation)

## Status
#4 implemented; PR open, waiting for CI + review, then squash-merge. #1–#3 merged.

## Last task
- `infra/db/`: `Base` (naming convention), mixins `UUIDPrimaryKey` (UUIDv7 from `domain/ids.py`),
  `Timestamps`, `TenantScoped` (`org_id` FK → `orgs.id`), `models.Org` (id, name, timestamps),
  `session.py` (engine/sessionmaker from Settings), `tenancy.py` (`scoped`, `get_scoped`)
- `web/db.py`: per-request session (`get_session()`, closed at teardown), wired in `create_app`
- Alembic: root `alembic.ini`, migrations in `attacksurf.infra.db:migrations`, `0001_create_orgs`;
  `make migrate`, `make revision id=0002 m="..."`
- Tests: `tests/integration/` (`db_engine`, `db_session` rollback fixtures; tenant isolation,
  `alembic check`, down/up round trip, CLI); skip locally without `TEST_DATABASE_URL`, fail in CI
- CI: Postgres service in `test` jobs; compose job runs migrations. ADR 0008.
- import-linter: `web` (except `web/db.py`), `scanners`, `ai` can't import SQLAlchemy/Alembic
- Verified locally: 62 tests, 100% coverage on host + in compose (`make test`), `make migrate`

## Next step
After #4 merges: #5 (Org/User/Membership/AuditLog). Extend `Org` (slug, plan) via migration
`0002`; use the `db-migration` skill.

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
