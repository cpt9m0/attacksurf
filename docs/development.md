# Development

## Prerequisites

- [uv](https://docs.astral.sh/uv/) (manages Python 3.12+ and dependencies)
- Docker + Docker Compose (from issue #3 onward)
- Node.js (only for the `npx`-based MCP servers used by AI agents)
- `jq` (used by the Claude Code formatting hook)

## Setup

```bash
uv sync
uv run flask --app attacksurf run --debug   # http://127.0.0.1:5000
```

## Everyday commands

| Task | Command |
|---|---|
| Run tests (+ coverage gate 80%) | `uv run pytest` |
| Lint / autofix | `uv run ruff check --fix .` |
| Format | `uv run ruff format .` |
| Type-check | `uv run pyright` |
| Add a dependency | `uv add <pkg>` (dev: `uv add --dev <pkg>`) |

Never use `pip install`, and never edit `uv.lock` by hand.

## Project layout

```
src/attacksurf/   application package (src layout)
tests/            pytest suite, mirrors src/
docs/             architecture, ADRs, guides
.claude/          Claude Code settings, hooks, skills
AGENTS.md         rules for AI coding agents (CLAUDE.md imports it)
.mcp.json         MCP servers for AI agents
```

## Testing

- Coverage must stay **≥ 80%** (`--cov-fail-under=80` in `pyproject.toml`; CI enforces it).
- No live network in tests: use fixtures under `tests/fixtures/` and fake providers.
- Layout: `tests/unit/`, `tests/integration/` (DB, Celery), `tests/e2e/` (Playwright).

## Working with AI agents

This project is built mostly by AI coding agents. The setup:

- **`AGENTS.md`**: the rulebook every agent reads (architecture rules, conventions, definition
  of done). `CLAUDE.md` imports it and adds Claude-specific notes.
- **Skills** (`.claude/skills/`): `implement-issue`, `add-scanner`, `db-migration`, `llm-prompt`,
  `pre-pr-check`.
- **Hooks** (`.claude/settings.json`): ruff runs on every edited Python file; `uv sync` runs at
  session start.
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

1. Pick the next unblocked issue from the epic (#31).
2. Ask the agent: "implement #N" (it runs the `implement-issue` skill).
3. Review the PR: check the acceptance criteria and the security checklist in `pre-pr-check`.
4. Merge, then repeat.
