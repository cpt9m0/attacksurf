# STATE

> Handoff for the next session. Overwritten at the end of every task; not a history log.

**Updated:** 2026-11-12 · **Branch:** `23-llm-usage` · **Issue:** #23 (LLM providers)

## Status
PR 4a (LLM usage tracking) is done on this branch and ready for a PR (`feat(ai): record llm
usage`, `Refs #23`). PR 4b (provider factory, closes #23) is the partner's, after PR 3
(OpenAI-compatible adapter).

## Last task
- `ai/pricing.py`: list prices in code (Muse Spark 1.3 and its contributor tier) and
  `estimate_cost()`; unknown model or unreported usage gives None, never 0.
- `LLMUsage` model + migration `0008_add_llm_usage` (rules as CHECKs, `(org_id, created_at)` index).
- `services.llm_usage.record_llm_usage`: one row per finished call, failed ones included; it
  doesn't commit.
- `create_app` warns once when the instance key or model is missing (AI off).
- Docs: architecture (data model, AI layer), security (what's stored per call), development,
  the `llm-prompt` skill, CHANGELOG.

## Next step
Open the PR for this branch. Right before pushing, check that `0008` is still the next free
migration on `origin/main` (`git ls-tree --name-only origin/main
src/attacksurf/infra/db/migrations/versions/`); if it's taken, renumber the file and its
`revision`/`down_revision`.

## Open threads
- Meta's list prices in `ai/pricing.py` came from third-party trackers; re-check them on
  developer.meta.com before merging.
- PR 4b must agree with PR 3 that `OpenAICompatProvider(config)` takes the config as its only
  required argument.
- #24 builds on this: the monthly instance-key cap sums `llm_usage` per org, and the usage page.
- #84 PR 3c (`runner.py`, `server.py`, `__main__.py`) per issue #84's checklist.

## Notes for the next agent
- #25 callers: on a failed `complete()`, call `record_llm_usage(..., outcome=error)`, commit,
  then re-raise, or the row rolls back with the task and the cap never counts it.
- `tests/unit/sandbox_launcher/test_container.py` fails on Windows (53 tests): it treats
  `/srv/...` as absolute, which `pathlib` on Windows doesn't. CI (Linux) passes; run the suite
  with `--ignore=tests/unit/sandbox_launcher` locally.
- `.github/scripts/pytest-hook.sh` ignores CLI args: pass paths through `PYTEST_ADDOPTS`.
- Windows dev machine: Postgres on host port 5433 (git-excluded `compose.override.yaml`); if
  Docker Desktop is down, start it, then `docker compose up -d --wait postgres`.
- ADR and migration numbers move fast: check `origin/main` and open branches right before
  pushing. ADR 0025 (DNS resolution, #16) is the latest; migrations stop at 0007 on `main`.
- The ruff format hook strips imports that aren't used yet: add imports with their first use.
