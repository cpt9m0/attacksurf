# Development

## Prerequisites

- [uv](https://docs.astral.sh/uv/) (manages Python 3.12+ and dependencies)
- Docker + Docker Compose (from issue #3 onward)
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

`make up` builds the `dev` image and starts the stack, waiting until every service is healthy.

| Service | Host port (localhost only) | Notes |
|---|---|---|
| `web` | 5000 | Flask debug server, hot reload (`./src` is bind-mounted) |
| `postgres` | 5432 | PostgreSQL 16, user/password/db `attacksurf` (dev only), volume `pgdata` |
| `redis` | 6379 | Redis 7 |
| `worker-passive`, `worker-ai`, `beat` | n/a | placeholders until #10; start with `docker compose --profile workers up` |

Inside compose, `DATABASE_URL` / `REDIS_URL` point at the service names; your `.env` supplies the
rest. Targets: `make up | down | logs | ps | build | shell | test | check | migrate | revision`
(`make` lists them). `make down` keeps the database; `docker compose down -v` wipes it.

## Database and migrations

| Task | Command |
|---|---|
| Apply migrations | `make migrate` (in compose) or `uv run alembic upgrade head` (uses `DATABASE_URL`) |
| New migration from model changes | `make revision id=0002 m="add assets"` (then review it, see the `db-migration` skill) |
| Current revision / history | `uv run alembic current` / `uv run alembic history` |

The app never migrates on startup. Migrations live in `src/attacksurf/infra/db/migrations/`.

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
  `tests/e2e/` (Playwright).

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
