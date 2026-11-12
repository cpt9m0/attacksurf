# STATE

> Handoff for the next session. Overwritten at the end of every task; not a history log.

**Updated:** 2026-11-12 · **Branch:** `23-llm-adr-0024` · **Issue:** #23 (LLM providers)

## Status
`main` (65aa36c) has the sandbox proxy `/info` endpoint (#157, ADR 0023) and the sandbox launcher
building blocks (#158, PR 3b). This branch adds ADR 0024, which supersedes ADR 0019's
`temperature` parameter and SDK retry count: adapters send no sampling settings, and
`ai/limits.MAX_RETRIES` is 0 because Celery retries the task. ADR 0019's contract and retry
paragraphs are back to their accepted wording, each with a "Superseded by ADR 0024" note; its
error-handling, deadline-enforcement and live-verification additions stay, since they fill in
what 0019 already required. Citations in `architecture.md`, `ai/limits.py`, `domain/llm.py`, the
`llm-prompt` skill, `CHANGELOG.md` and two test comments now point to ADR 0024. PR #160 is open,
merged with `main`; the only conflict was this file.

## Last task
- Added `docs/adr/0024-no-llm-sampling-or-sdk-retries.md`; numbers 0022 (CT discovery) and 0023
  (sandbox runtime check) were taken on `main` in the meantime.
- Restored ADR 0019's two paragraphs and added the supersession notes; the other #147 additions
  remain because they don't change the accepted decision.
- Merged `origin/main` (65aa36c) into the branch and resolved the `STATE.md` conflict.

## Next step
1. Merge #160 once CI is green, then reply on #147's review thread with the link (the existing
   reply names ADR 0022; the number is now 0024).
2. PR 3c for #84 (`runner.py`, `server.py` with `POST /runs`, `__main__.py`) per issue #84's
   merge-order checklist.
3. PR 4a (usage tracking) on `23-llm-usage` from `origin/main`; PR 4b (factory, closes #23)
   after PR 3 (OpenAI-compatible). The migration is `0008` unless another PR takes it first.

## Open threads
- #23: PR 3 must mirror ADR 0019 and ADR 0024 (no SDK retries, no sampling parameters,
  `finish_reason` `length`/`content_filter` fail at once, deadline per call) and add `openai` to
  the import-linter SDK contract. Org-supplied base URLs need ScopeGuard validation (#24).
- #84: 3a and 3b are merged, so PR 3c can start; 3d is the worker-side client. The PR 3 plan
  (4 PRs, commits, testing gate) lived in
  `docs/plans/84-pr3-sandbox-launcher-split-4-prs.md`, which is untracked and absent from this
  checkout, so issue #84 is the current source of truth for the split.
- Optional one-line `/info` note in the `docs/architecture.md` proxy box: not decided.

## Notes for the next agent
- PR 3c `runner.py` must decide the outcome from its own flags (`timed_out`, cap tripped) before
  any stream error: a kill mid-frame reaches `read_stdout` as `MalformedStream`. It strips the
  proxy's HTTP response head before handing frames to `read_stdout`.
- PR 3c moves `FakeDocker` to `tests/docker_fakes.py`; it must be able to script stdout/stderr
  frames split across writes.
- PR 3d's ~3 MiB reply cap assumes stdout is at most 2 MiB (base64 about 2.67 MiB).
- The launcher copies proxy constants and `domain.scanners.MAX_OUTPUT_BYTES` on purpose (it may
  not import them); a parity test guards each copy. Don't "fix" that by importing.
- ADR numbers move fast: check `origin/main` and open branches for the next free number right
  before pushing a new ADR.
- Production plugins are registered explicitly in `src/attacksurf/app.py` and
  `src/attacksurf/workers/app.py`; a new plugin needs both imports.
- Tests that need Redis behavior use `tests.fakes.FakeCache`.
- The runtime image is Python 3.15; CI tests 3.12, 3.13 and 3.15. A base-image bump needs a
  `pydantic-core` release with wheels for that CPython.
- DB tests need `TEST_DATABASE_URL`; the dev Compose stack exposes PostgreSQL on
  `127.0.0.1:5432` with an `attacksurf_test` database (`make test` runs them in `web`). The
  Windows dev machine uses a git-excluded `compose.override.yaml` on host port 5433.
- The ruff format hook strips imports that aren't used yet: add imports together with their
  first use.
