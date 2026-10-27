# Development

## Prerequisites

- [uv](https://docs.astral.sh/uv/) (manages Python 3.12+ and dependencies)
- Docker + Docker Compose, with access to the Docker daemon (see [Docker permissions](#docker-permissions-on-linux))
- Node.js (only for the `npx`-based MCP servers used by AI agents)
- `jq` (used by the Claude Code formatting hook)

## Setup

```bash
uv sync
cp .env.example .env                        # local settings (see below)
uv run pre-commit install                   # git hooks: commit, commit-msg, pre-push
uv run flask --app attacksurf run --debug   # http://127.0.0.1:5000
```

## Docker Compose stack

`make up` builds the `dev` image, waits for PostgreSQL and Redis, applies Alembic migrations,
then starts the application services and waits until every service is healthy. A failed build,
dependency or migration stops the command before it starts the application services.
Open http://127.0.0.1:5000/signup to create an account (no default credentials).

| Service | Host port (localhost only) | Notes |
|---|---|---|
| `web` | 5000 | Flask debug server, hot reload (`./src` is bind-mounted) |
| `postgres` | 5432 | PostgreSQL 18, user/password/db `attacksurf` (dev only), volume `pgdata` |
| `redis` | 6379 | Redis 8 |
| `worker-passive`, `worker-ai` | n/a | Celery workers for the `passive` / `ai` queues; no hot reload: `docker compose restart worker-passive worker-ai` after code changes |
| `beat` | n/a | Celery beat (schedules arrive with #27) |

Inside compose, `DATABASE_URL` / `REDIS_URL` point at the service names; your `.env` supplies the
rest. Targets: `make up | down | logs | ps | build | shell | test | test-worker | check | migrate |
revision`. `make test-worker` (after `make up`) checks signup against the existing schema
(account writes roll back), then checks real worker jobs; CI's compose job runs the same suite
(`make` lists them). `make down` keeps the database; `docker compose down -v` wipes it.

PostgreSQL 18 stores data in a major-version subdirectory of `/var/lib/postgresql` (mounted as
`pgdata`), so a `pgdata` volume created by PostgreSQL 16 cannot be reused: run
`docker compose down -v` once to start a fresh one (dev data only; restore from a dump if needed).

### Docker permissions on Linux

If `make up` reports `permission denied` connecting to `/var/run/docker.sock`, the current
shell cannot access the Docker daemon. This is a host login/permissions issue, not a Compose
configuration error. Compare the current session's groups with the configured membership:

```bash
id -nG
getent group docker
```

If your username appears in the `docker` group entry but `id -nG` does not list `docker`,
refresh your login session: disconnect and reconnect over SSH, or open a subshell with:

```bash
newgrp docker
docker info
make up
```

For a single command without opening an interactive shell, use `sg docker -c 'make up'`.
Existing shells (including terminal multiplexers and agent sessions) retain their old groups
until restarted; adding the user again will not refresh them.

If your user is not a member, an administrator can grant access on a trusted development host:

```bash
sudo usermod -aG docker "$USER"
```

Then reconnect or run `newgrp docker` as above. **The `docker` group grants root-equivalent
access**; only add trusted users. For environments where that is inappropriate, configure
[rootless Docker](https://docs.docker.com/engine/security/rootless/) instead. Never make the
socket world-writable (`chmod 666`), and do not add automatic `sudo` to the Makefile.

## Database and migrations

| Task | Command |
|---|---|
| Apply migrations | `make migrate` (in compose) or `uv run alembic upgrade head` (uses `DATABASE_URL`) |
| New migration from model changes | `make revision id=0002 m="add assets"` (then review it, see the `db-migration` skill) |
| Current revision / history | `uv run alembic current` / `uv run alembic history` |

The app process never migrates on startup. The dev `make up` command runs `make migrate` before
starting application services (ADR 0012); direct `docker compose up` bypasses this orchestration
and still requires `make migrate`. Re-running migrations is safe. Migrations live in
`src/attacksurf/infra/db/migrations/`. Outside the dev Makefile (including production), apply
migrations explicitly before serving requests.

If signup fails with a missing `users` table on an already-running stack, run `make migrate`,
then retry signup: the failed attempt did not create an account. `/healthz` checks process
liveness only, not whether the schema has been migrated.

**DB tests** (`tests/integration/`) need PostgreSQL via `TEST_DATABASE_URL`; the database name
must end in `_test` because its schema is wiped at the start of the run. Without it they are
skipped locally (and fail in CI). `make test` sets it to compose's `attacksurf_test` database,
which is created when the `pgdata` volume is first initialized (older volume: `docker compose
down -v` once, or `docker compose exec postgres createdb -U attacksurf attacksurf_test`). Outside
compose, with `make up` running:

```bash
TEST_DATABASE_URL=postgresql+psycopg://attacksurf:attacksurf@localhost:5432/attacksurf_test uv run pytest
```

Each DB test runs in a transaction that is rolled back (fixture `db_session`).

## Configuration

All settings live in `src/attacksurf/config.py` and are read from environment variables or `.env`
(see `.env.example`). Leave `SECRET_KEY` empty in dev (an ephemeral key is generated);
`ENV=prod` refuses to start without a random `SECRET_KEY` of ≥ 32 characters. Never commit `.env`.

Auth settings: `ALLOW_SIGNUP` (default `true`; when `false` only the first user can sign up),
`SESSION_LIFETIME_HOURS` (default 12), `PROXY_COUNT` (reverse proxies in front of the app; 0 in
dev, 1 behind Caddy). Login/signup rate limits use Redis (`REDIS_URL`) and fall back to memory if
it is down. Open http://127.0.0.1:5000, sign up; the first account owns a new org.

## Everyday commands

| Task | Command |
|---|---|
| Run tests (+ coverage gate 80%) | `uv run pytest` |
| Lint / autofix | `uv run ruff check --fix .` |
| Format | `uv run ruff format .` |
| Type-check | `uv run pyright` |
| All git hooks on all files | `uv run pre-commit run --all-files` |
| Layer rules (import-linter) | `uv run lint-imports` |
| Add a dependency | `uv add <pkg>` (dev: `uv add --dev <pkg>`) |

Never use `pip install`, and never edit `uv.lock` by hand.

Commit message template: `git config commit.template .gitmessage`. Issue/commit/PR rules:
[conventions.md](conventions.md).

## Project layout

```
src/attacksurf/   application package (src layout)
tests/            pytest suite, mirrors src/
docs/             architecture, ADRs, guides
.claude/          Claude Code settings, hooks, skills
AGENTS.md         rules for AI coding agents (CLAUDE.md imports it)
.mcp.json         MCP servers for AI agents
```

## Git hooks and CI

| When | What runs |
|---|---|
| `git commit` | trailing whitespace/EOF/line endings, YAML/TOML/JSON syntax, merge markers, large files, private keys, **gitleaks** (secrets), **ruff** check + format, **import-linter** (layer rules) |
| commit message | Conventional Commits check (`.github/scripts/check-commit-msg.sh`, same rules as PR titles) |
| `git push` | **pyright**, **pytest** (80% coverage gate) |
| CI on push to `main` / every PR | `lint` (pre-commit hooks + pyright), `test (3.12)`, `test (3.13)` (with a Postgres service), `secrets` (gitleaks over full git history), `compose` (builds the prod image, checks it runs as non-root, starts the dev stack, curls `/healthz`, runs migrations), `pr-title` (also re-runs on title edits) |

Remote hooks and GitHub Actions are pinned to commit SHAs; Dependabot proposes updates. ruff,
pyright and pytest versions come from `uv.lock`.

## Testing

- Coverage must stay **≥ 80%** (`--cov-fail-under=80` in `pyproject.toml`; CI enforces it).
- No live network in tests: use fixtures under `tests/fixtures/` and fake providers.
- Layout: `tests/unit/`, `tests/integration/` (DB, Celery; fixtures `db_engine`, `db_session`),
  `tests/e2e/` (against the running stack, e.g. `make test-worker`; Playwright later).
- Celery tasks in tests: `task.apply(kwargs=...)` runs them in-process; patch
  `workers.runtime.session_factory` to share the test's connection
  (`tests/integration/workers/test_tracked_task.py`).
- Pipeline fixtures live in `tests/scanner_fixtures.py`; eager integration tests patch the
  registry, rule catalog and gate, and use an in-memory result backend. `send_task` does not
  honor Celery eager mode: the kickoff is recorded with `FakeQueue` and applied explicitly.
- `tests/e2e/test_pipeline.py` starts a real prefork test worker against Redis/Postgres with
  an isolated broker/result key prefix. It exercises Redis chords with fake, no-network
  plugins and a failing check; production workers never load those plugins. `make test-worker`
  runs both this test and the original Compose worker ping (CI uses the same command).

## Working with AI agents

This project is built mostly by AI coding agents. The setup:

- **`AGENTS.md`**: the rulebook every agent reads (architecture rules, conventions, definition
  of done). `CLAUDE.md` imports it and adds Claude-specific notes.
- **`STATE.md`**: the current handoff: what was just done and the exact next step. Overwritten
  at the end of every task (no history). Read it first when you open the project.
- **`DESIGN.md`**: the web UI design system (tokens, components, HTMX patterns). Values are
  completed with Claude Design or a similar tool; agents follow it for all UI work.
- **Skills** (`.claude/skills/`): `implement-issue`, `add-scanner`, `db-migration`, `llm-prompt`,
  `pre-pr-check`, `create-issue`, `finish-task`.
- **Keep-in-sync rule**: after every task the agent runs `finish-task` (also `/finish-task`):
  tests, docs, `DESIGN.md`, `CHANGELOG.md`, `AGENTS.md`/`CLAUDE.md`/skills, and `STATE.md`.
- **Hooks** (`.claude/settings.json`): ruff on every edited Python file; at session start
  `uv sync` runs and `STATE.md` is loaded into context; on stop, a reminder fires if code
  changed but `STATE.md` didn't.
- **MCP servers** (`.mcp.json`):

| Server | Use | Setup |
|---|---|---|
| context7 | current library docs | optional `CONTEXT7_API_KEY` (higher rate limits) |
| brave-search | web search | requires `BRAVE_API_KEY` ([get one](https://brave.com/search/api/)) |
| playwright | browser testing of the UI | none (`npx`) |

Export the keys in your shell (or in your cloud environment's secrets); never commit them.
Other agents (Codex, Cursor, ...) read `AGENTS.md` directly; configure the same MCP servers in
their own config if wanted.

### Recommended workflow

1. Open `STATE.md`: it names the next step (usually the next unblocked issue in epic #31).
2. Ask the agent: "implement #N" or "continue" (it runs the `implement-issue` skill, ending with
   `finish-task`).
3. Review the PR: check the acceptance criteria and the security checklist in `pre-pr-check`.
4. Merge, then repeat.
