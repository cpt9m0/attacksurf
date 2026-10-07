# STATE

> Handoff for the next session. Overwritten at the end of every task; not a history log.

**Updated:** 2026-10-07 · **Branch:** `main` · **Issue:** none (project setup)

## Status
Done. Project scaffolding, agent tooling, open-source files, handoff/design-system setup, and
issue/commit/PR conventions are complete and on `main`.

## Last task
- Added issue/commit/PR conventions: `docs/conventions.md`, task + epic issue forms,
  `.github/labels.yml`, `.gitmessage`, updated PR template, `create-issue` skill, AGENTS.md summary
- Before that: end-of-task sync rule (`AGENTS.md`), `finish-task` skill, and hooks (SessionStart
  loads this file; Stop reminds if code changed without a `STATE.md` update)
- Added `DESIGN.md` (UI design system skeleton, values `TBD`) and linked it from UI issues
- Earlier: src layout + quality gates, AGENTS/CLAUDE.md, skills, MCP, docs/ADRs, AGPL + community files

## Next step
Implement #1 (Dev tooling and CI): ruff/pyright/pytest are already configured, so what's left is
`.pre-commit-config.yaml` (incl. gitleaks + a Conventional Commits `commit-msg` hook) and the
GitHub Actions workflow (`uv sync --locked`, ruff, pyright, pytest with the 80% coverage gate,
PR-title lint, label sync from `.github/labels.yml`). See the comments on #1. Then #2.

## Open threads
- #32: GitHub Sponsors / Ko-fi accounts not set up yet (Ko-fi username assumed `cpt9m0`)
- Repo settings for the user to do: description, topics, Discussions, Sponsorships,
  private vulnerability reporting, social preview, `good first issue` labels
- Labels in `.github/labels.yml` aren't synced to GitHub yet; existing issues lack type labels
- `DESIGN.md` values are `TBD`: to be completed with Claude Design before/during #6

## Notes for the next agent
- Package is `src/attacksurf` (uv_build backend); run the app with `uv run flask --app attacksurf run --debug`
- Issue bodies in #2 list paths as `attacksurf/...`; they live under `src/attacksurf/...` now
- `jq` is needed by the Claude Code hooks (they no-op without it)
