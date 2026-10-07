# STATE

> Handoff for the next session. Overwritten at the end of every task; not a history log.

**Updated:** 2026-10-07 · **Branch:** `claude/blissful-goldberg-rd3suo` · **Issue:** #1 (Dev tooling and CI)

## Status
#1 implemented; PR open, waiting for green CI and a squash merge by the user.

## Last task
- Git hooks via pre-commit (`.pre-commit-config.yaml`): hygiene checks, gitleaks, ruff (from
  `uv.lock`), commit-message check, pyright + pytest on push
- CI (`.github/workflows/ci.yml`): `lint`, `test (3.12)`, `test (3.13)`, `pr-title`; actions
  pinned by SHA
- Shared rule script: `.github/scripts/check-pr-title.sh` (PR titles) is reused by
  `check-commit-msg.sh` (commit subjects), so both follow the same rule
- SessionStart hook now installs the git hooks; docs/AGENTS/CLAUDE/skills updated

## Next step
After #1 is merged: implement #2 (layered package layout, pydantic-settings config, structlog)
on a fresh branch from `main`.

## Open threads
- Optional (user): ruleset on `main` requiring PRs + checks `lint`, `test (3.12)`,
  `test (3.13)`, `pr-title`
- #32: GitHub Sponsors / Ko-fi accounts not set up yet (Ko-fi username assumed `cpt9m0`)
- Repo settings for the user: description, topics, Discussions, Sponsorships,
  private vulnerability reporting, social preview
- `DESIGN.md` values are `TBD`: to be completed with Claude Design before/during #6

## Notes for the next agent
- Repo: default branch `main`, squash-merge only (PR title = commit subject), head branches
  auto-deleted
- Package is `src/attacksurf` (uv_build backend); run the app with `uv run flask --app attacksurf run --debug`
- Issue bodies in #2 list paths as `attacksurf/...`; they live under `src/attacksurf/...` now
- First `pre-commit` run downloads hook envs (gitleaks builds with Go): takes a minute
- `jq` is needed by the Claude Code hooks (they no-op without it)
