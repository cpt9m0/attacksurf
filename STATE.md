# STATE

> Handoff for the next session. Overwritten at the end of every task; not a history log.

**Updated:** 2026-10-26 · **Branch:** `main` · **Issue:** #11 (scanner plugin framework)

## Status
#1–#10 merged (#49); `main` is green. Postgres/Redis/Python/uv dependency bumps merged
(#41–#43, #50). Next up: #11.

## Last task
- Merged Dependabot PRs #42, #43, #50 (PostgreSQL 18, Redis 8, `python:3.13-slim` digest) and
  #41 (setup-uv 10.3.0)
- PostgreSQL 18 keeps data in a major-version subdirectory, so `pgdata` now mounts
  `/var/lib/postgresql`; the old `/var/lib/postgresql/data` mount made the container exit.
  Upgrade note in `docs/development.md`
- Verified on the merged combination: fresh PG18 volume + full migration chain, `/healthz`,
  real-worker e2e test, prod image as uid 10001; Redis 8 exercised as the Celery broker
- #51 moves the CI test job onto the same PostgreSQL 18 image

## Next step
Implement #11 (scanner plugin framework): `ScanOutput`, registry/profiles, pipeline chain/chord,
persistence of assets/findings by fingerprint, fake scanner.

## Open threads
- #51: CI `test` jobs still use `postgres:16`; needs a `workflow`-scoped token to push
- `.env.example` needs `ALLOW_SIGNUP=true`, `SESSION_LIFETIME_HOURS=12`, `PROXY_COUNT=0`
  (prod behind Caddy: `PROXY_COUNT=1`)
- Later issues own: upserting findings by fingerprint + evidence size cap (#11), a sweeper for
  jobs left `running` or `queued` without a message (#21), status transitions/regressions/
  `Scan.stats` (#20), one active scan per root + severity ordering (#21/#22); marking assets gone
  sets `is_active=False` and `deactivated_at` together
- Optional (user): ruleset on `main` requiring PRs + checks `lint`, `test (3.12)`, `test (3.13)`,
  `secrets`, `compose`, `pr-title`
- #32: GitHub Sponsors / Ko-fi accounts not set up yet (Ko-fi username assumed `cpt9m0`)
- Repo settings for the user: description, topics, Discussions, Sponsorships,
  private vulnerability reporting, social preview
- `DESIGN.md` visual values are placeholders in `static/css/tokens.css` (`TODO(DESIGN.md)`):
  replace via Claude Design; no template changes needed
- context7 MCP blocked by the proxy (403); brave-search needs `BRAVE_API_KEY`; playwright MCP
  wants Google Chrome (absent): use Python Playwright with
  `executable_path=/opt/pw-browsers/chromium-1194/chrome-linux/chrome`

## Notes for the next agent
- Repo: default branch `main`, squash-merge only (PR title = commit subject), head branches
  auto-deleted; commits here use the repo-local `Claude <noreply@anthropic.com>` identity
- The GitHub token in this sandbox has `repo`/`gist`/`read:org` only: it cannot push or merge
  anything touching `.github/workflows/` (needs `workflow` scope) — do those from the UI
  (`gh auth refresh -s workflow` fixes it)
- Local stack is PostgreSQL 18 + Redis 8; a `pgdata` volume from the 16 images must be recreated
  (`docker compose down -v`). Here Docker needs `sudo docker` (user is not in the `docker` group)
- Docker Hub may rate-limit (429): use `mirror.gcr.io/library/<image>`; GHCR blobs are
  proxy-blocked; image builds need the proxy CA (never commit that)
- Test Postgres outside compose: `docker start testpg` (`mirror.gcr.io/library/postgres:16`,
  127.0.0.1:5433, db `attacksurf_test`)
- New migration: point `DATABASE_URL` at a scratch DB, `alembic upgrade head`, then
  `alembic revision --autogenerate --rev-id 000N`; remove the duplicate enum CHECKs it emits
  (`create_constraint=False` + the convention-named `ck_*`)
- Tests: `tests.helpers.make_settings(...)` ignores `.env` and OS env; env-loading tests use
  `settings_from_env()` + `clean_env` fixture
- `flask --app attacksurf` works (`create_app` lazily re-exported from `__init__.py`)
- First `pre-commit` run downloads hook envs (gitleaks builds with Go): takes a minute
