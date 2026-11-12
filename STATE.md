# STATE

> Handoff for the next session. Overwritten at the end of every task; not a history log.

**Updated:** 2026-11-12 · **Branch:** `23-llm-adr-0024` · **Issue:** #23 (LLM providers)

## Status
Review follow-up to #147 (Anthropic provider, merged): its reviewer asked for a superseding ADR
instead of editing ADR 0019 in place. The fix wasn't pushed before #147 merged, so it lands
here, on a branch from `main` (`a673a6e`), uncommitted:
- `docs/adr/0024-no-llm-sampling-or-sdk-retries.md` records "no sampling settings" and "no SDK
  retries" (`MAX_RETRIES = 0`), with reasons and trade-offs. Numbers 0022 (CT discovery) and
  0023 (sandbox runtime check) were taken on `main` in the meantime.
- ADR 0019's contract and retry paragraphs are back to their accepted wording, each with a
  "Superseded by ADR 0024" line, and its Status line says so. Its error-handling,
  deadline-enforcement and live-verification additions stay, since they fill in what 0019
  already required.
- Citations of these two decisions point to ADR 0024: `architecture.md`, `ai/limits.py`,
  `domain/llm.py`, the `llm-prompt` skill, `CHANGELOG.md` and two test comments. Main's own
  ADR 0022 and 0023 citations are untouched.

## Next step
1. Commit (`docs(ai): record no sampling and no sdk retries in adr 0024`, footer `Refs #23`),
   push, and open the PR. Reply to the reviewer on #147 with its link.
2. Then PR 4a (usage tracking, Angela) on `23-llm-usage` from `origin/main`. The plan, with the
   PR 4 split, is at https://claude.ai/artifact/PnixRruj7R2cb7B6gLmvLi. PR 4b (factory, closes
   #23) is the partner's, after PR 3 (OpenAI-compatible). The migration is `0008` unless
   another PR takes it first.

## Open threads
- #23: PR 3 must mirror ADR 0019 and ADR 0024 (no SDK retries, no sampling params,
  `finish_reason` `length`/`content_filter` fail at once, deadline per call) and add `openai`
  to the import-linter SDK contract. Org-supplied base URLs need ScopeGuard validation (#24).
- #84: PR 3b (`84-sandbox-launcher-core`, #158) is open and needs a merge of `main` (conflicts
  only in `STATE.md`). Then 3c (launcher service and the `runsc` startup check) and 3d
  (worker-side client); order and scope: issue #84's merge-order checklist.
- Optional one-line `/info` note in the `docs/architecture.md` proxy box: not decided.

## Notes for the next agent
- ADR numbers move fast: check `origin/main` and open branches for the next free number right
  before pushing a new ADR.
- Production plugins are registered explicitly in `src/attacksurf/app.py` and
  `src/attacksurf/workers/app.py`; a new plugin needs both imports.
- Tests that need Redis behavior use `tests.fakes.FakeCache`.
- The runtime image is Python 3.15; CI tests 3.12, 3.13 and 3.15. A base-image bump needs a
  `pydantic-core` release with wheels for that CPython.
- DB tests need `TEST_DATABASE_URL`. Windows dev machine: Postgres on host port 5433
  (git-excluded `compose.override.yaml`).
- The ruff format hook strips imports that aren't used yet: add imports with their first use.
