# 0007. src layout, uv, and quality gates for AI-written code

- Status: accepted
- Date: 2026-10-07

## Context
Most code will be written by AI agents. Quality has to be enforced by tooling and written rules,
not by memory.

## Decision
- `src/` layout (`src/attacksurf`), `tests/`, `docs/`, config at the root. uv for everything.
- Gates: ruff (lint + format), pyright, pytest with **≥ 80% coverage** (`--cov-fail-under=80`).
- `AGENTS.md` is the single rulebook for agents; `CLAUDE.md` imports it. Repeatable workflows are
  Claude Code skills; formatting runs in a hook.

## Consequences
- Agents get fast, objective feedback.
- Coverage is a floor, not a goal; reviews still check that tests test behavior.
