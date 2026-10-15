# STATE

> Handoff for the next session. Overwritten at the end of every task; not a history log.

**Updated:** 2026-10-15 · **Branch:** `claude/blissful-goldberg-rd3suo` · **Issue:** #10 (Celery)

## Status
#10 implemented; PR open, waiting for CI + Codex review (wait for it before merging), then
squash-merge. #1–#9 merged.

## Last task
- `infra/queue.py`: `create_celery(settings)` (Redis broker/backend from `REDIS_URL`, JSON,
  `acks_late`, prefetch 1, results ignored), queues `passive`/`ai` (+ reserved
  `active`/`analysis`), task-name prefix = queue (`queue_for`), `CeleryTaskQueue`
- `domain/jobs.py`: `TaskQueue` port, `TransientJobError`, `JobNotFound`
- `services/jobs.py`: `create_job` (commit, then enqueue; broker error → job failed),
  `mark_job_running` (None for finished jobs = skip redelivery), `mark_job_completed`,
  `mark_job_failed`, `mark_job_retrying`; row-locked, DB-clock timestamps, cancellation wins
- `workers/`: `app.py` (entrypoint, `TASK_MODULES`, logging + per-process DB pool signals),
  `runtime.py`, `base.py` (`TrackedTask`), `tasks/system.py` (`passive.ping`)
- `web/queue.py`: `get_task_queue()`; compose runs `worker-passive`, `worker-ai`, `beat`;
  CI compose job + `make test-worker` run `tests/e2e/test_worker.py` against a real worker
- Deps: `celery[redis]` 5.6.3, dev `celery-types`; young transitive releases pinned back in
  `[tool.uv] constraint-dependencies`
- Codex round 1 fixed: retry on DB outage at job start/finish, empty task suffix rejected,
  lazy worker settings (hermetic tests), ADR 0010 (worker sessions, lifecycle, errors),
  sanitized `Job.error`/logs (`JobError` messages only, Celery tracer silenced), fresh row
  after lock, delivery cap `max_retries + 2` against poison tasks
- Tests: 475 with DB (99%) + 1 real-worker test (`make test-worker`, CI)

## Next step
After #10 merges: #11 (scanner plugin framework, `ScanOutput`, registry/profiles, pipeline
chain/chord, persistence of assets/findings by fingerprint, fake scanner).

## Open threads
- `.env.example` needs: `ALLOW_SIGNUP=true`, `SESSION_LIFETIME_HOURS=12`, `PROXY_COUNT=0`
  (prod behind Caddy: `PROXY_COUNT=1`)
- Later issues own: upserting findings by fingerprint + evidence size cap (#11), a sweeper for
  jobs left `running` (hard time-limit kill) or `queued` without a message (web died between
  commit and enqueue) (#21), status
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
