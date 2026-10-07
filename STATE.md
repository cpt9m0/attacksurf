# STATE

> Handoff for the next session. Overwritten at the end of every task; not a history log.

**Updated:** 2026-10-07 · **Branch:** `main` · **Issue:** none (project setup)

## Status
Done. Project scaffolding, agent tooling, open-source files, and handoff/design-system setup are
complete and merged to `main`.

## Last task
- Added the end-of-task sync rule (`AGENTS.md`), `finish-task` skill, and hooks (SessionStart
  loads this file; Stop reminds if code changed without a `STATE.md` update)
- Added `DESIGN.md` (UI design system skeleton, values `TBD`) and linked it from UI issues
- Earlier: src layout + quality gates, AGENTS/CLAUDE.md, skills, MCP, docs/ADRs, AGPL + community files

## Next step
Implement #1 (Dev tooling and CI): ruff/pyright/pytest are already configured, so what's left is
`.pre-commit-config.yaml` (incl. gitleaks) and the GitHub Actions workflow (`uv sync --locked`,
ruff, pyright, pytest with the 80% coverage gate). Then #2.

## Open threads
- #32: GitHub Sponsors / Ko-fi accounts not set up yet (Ko-fi username assumed `cpt9m0`)
- Repo settings for the user to do: description, topics, Discussions, Sponsorships,
  private vulnerability reporting, social preview, `good first issue` labels
- `DESIGN.md` values are `TBD`: to be completed with Claude Design before/during #6

## Notes for the next agent
- Package is `src/attacksurf` (uv_build backend); run the app with `uv run flask --app attacksurf run --debug`
- Issue bodies in #2 list paths as `attacksurf/...`; they live under `src/attacksurf/...` now
- `jq` is needed by the Claude Code hooks (they no-op without it)
