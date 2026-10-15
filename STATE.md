# STATE

> Handoff for the next session. Overwritten at the end of every task; not a history log.

**Updated:** 2026-10-15 · **Branch:** `claude/blissful-goldberg-rd3suo` · **Issue:** #9 (scan results model)

## Status
#9 implemented; PR open, waiting for CI + Codex review (wait for it before merging), then
squash-merge. #1–#8 merged.

## Last task
- `domain/scans.py`: `ScanStatus`, `ScanTrigger`, `JobStatus` (`skipped` = not run)
- `domain/findings.py`: `Severity`, `Confidence`, `FindingStatus`, `EvidenceKind`,
  `finding_fingerprint(org_id, asset_id, rule_id, location="")` (SHA-256 of
  `["v1", org, asset, rule, location]`; pinned by a test)
- `domain/rules/`: `Rule` (remediation via `string.Template`), `build_catalog`, `get_rule`,
  `UnknownRule`; catalog empty until scanners land (#15–#19 add `domain/rules/dns.py`)
- Models `Scan`, `Job`, `Finding`, `Evidence` (migration `0004`): composite same-org FKs;
  finding scan refs and job asset use `ON DELETE SET NULL (col)` (Postgres 15+); CHECKs for
  `fixed_at` ⇔ `fixed`, `last_seen >= first_seen`, finish ≥ start, `attempts >= 0`
- Tests: 420 with DB (99%)

## Next step
After #9 merges: #10 (Celery app, queues, `TrackedTask` updating `Job` rows, compose workers).

## Open threads
- `.env.example` needs: `ALLOW_SIGNUP=true`, `SESSION_LIFETIME_HOURS=12`, `PROXY_COUNT=0`
  (prod behind Caddy: `PROXY_COUNT=1`)
- Later issues own: upserting findings by fingerprint + evidence size cap (#11), status
  transitions/regressions/`Scan.stats` (#20), one active scan per root + severity ordering
  (#21/#22); the scan that marks assets gone sets `is_active=False` and `deactivated_at` together
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
- Cloud sandbox: start Docker with `dockerd &`; test Postgres: `docker start testpg`
  (`mirror.gcr.io/library/postgres:16`, 127.0.0.1:5433, db `attacksurf_test`); Docker Hub may
  rate-limit (429), so use `mirror.gcr.io/library/<image>`; GHCR blob downloads are blocked by
  the proxy; image builds need the proxy CA (build from a scratch copy, never commit that)
- New migration: point `DATABASE_URL` at a scratch DB, `alembic upgrade head`, then
  `alembic revision --autogenerate --rev-id 000N`; remove the duplicate enum CHECKs it emits
  (`create_constraint=False` + the convention-named `ck_*`)
- Tests: `tests.helpers.make_settings(...)` ignores `.env` and OS env; env-loading tests use
  `settings_from_env()` + `clean_env` fixture
- `flask --app attacksurf` works (`create_app` lazily re-exported from `__init__.py`)
- First `pre-commit` run downloads hook envs (gitleaks builds with Go): takes a minute
