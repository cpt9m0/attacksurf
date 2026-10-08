# STATE

> Handoff for the next session. Overwritten at the end of every task; not a history log.

**Updated:** 2026-10-08 · **Branch:** `claude/blissful-goldberg-rd3suo` · **Issue:** none (Dependabot follow-up)

## Status
#1 done (PR #34 merged, CI green on `main`). Small follow-up PR open: Dependabot title handling.
Dependabot PR #33 (`uv_build` range → `<0.13`) verified locally, waiting for its rebase + CI, then
merge.

## Last task
- Merged #34 (pre-commit hooks + CI), closing #1
- Verified #33: real `uv_build` 0.12.x builds an identical wheel; retitled it to
  `build(deps): allow uv_build 0.12`
- `.github/dependabot.yml`: commit prefixes `build(deps)` / `ci(deps)`; `pr-title` runs
  `check-pr-title.sh --bot` for `dependabot[bot]` (prefix-only check); rule in `docs/conventions.md`

## Next step
Implement #2 (layered package layout, pydantic-settings config, structlog) on a fresh branch from
`main`.

## Open threads
- Optional (user): ruleset on `main` requiring PRs + checks `lint`, `test (3.12)`,
  `test (3.13)`, `secrets`, `pr-title`
- #32: GitHub Sponsors / Ko-fi accounts not set up yet (Ko-fi username assumed `cpt9m0`)
- Repo settings for the user: description, topics, Discussions, Sponsorships,
  private vulnerability reporting, social preview
- `DESIGN.md` values are `TBD`: to be completed with Claude Design before/during #6
- context7 MCP blocked by the environment's network proxy (403); brave-search needs `BRAVE_API_KEY`

## Notes for the next agent
- Repo: default branch `main`, squash-merge only (PR title = commit subject), head branches
  auto-deleted
- Package is `src/attacksurf` (uv_build backend); run the app with `uv run flask --app attacksurf run --debug`
- Issue bodies in #2 list paths as `attacksurf/...`; they live under `src/attacksurf/...` now
- First `pre-commit` run downloads hook envs (gitleaks builds with Go): takes a minute
- `jq` is needed by the Claude Code hooks (they no-op without it)
