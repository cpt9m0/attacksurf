@AGENTS.md

# Claude Code specifics

`AGENTS.md` above is the source of truth for all agents. This section only adds Claude Code tooling.

## Skills (`.claude/skills/`)

Use these instead of improvising the workflow:

- `implement-issue`: end-to-end workflow for a GitHub issue (plan → TDD → checks → PR)
- `add-scanner`: add a scanner plugin + rules + fixtures + tests
- `db-migration`: model change → Alembic migration → verify
- `llm-prompt`: add/change an AI prompt with versioning, schema, injection defense, eval
- `pre-pr-check`: the full verification + self-review checklist before opening a PR
- `create-issue`: file/split issues and epics following `docs/conventions.md`
- `finish-task`: end-of-task sync of tests, docs, agent files, and `STATE.md` (`/finish-task`)

## MCP servers (`.mcp.json`)

- **context7**: up-to-date library docs. Use it before writing code against Flask, SQLAlchemy,
  Alembic, Celery, HTMX, pydantic, dnspython, anthropic, or openai APIs.
- **brave-search**: web search (CVE details, RFCs, tool docs) when Context7 doesn't cover it.
  Needs `BRAVE_API_KEY`.
- **playwright**: drive the running app in a browser to verify UI/HTMX changes.

## Hooks (`.claude/settings.json`)

- Python files are auto-formatted with ruff after each edit.
- `SessionStart` runs `uv sync`, installs the git hooks (`pre-commit install`), and loads
  `STATE.md` into context, so every session starts from the latest handoff.
- `Stop`: if code changed but `STATE.md` didn't, you're reminded once to run `/finish-task`.
  If the task isn't finished yet (e.g. you're asking the user a question), just continue.
