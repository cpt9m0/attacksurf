# STATE

> Handoff for the next session. Overwritten at the end of every task; not a history log.

**Updated:** 2026-11-09 · **Branch:** `23-anthropic-provider` · **Issue:** #23 (LLM providers), PR 2 of 4 ready to open

## Status
PR 1 (shared LLM contract) is merged: [#131](https://github.com/cpt9m0/attacksurf/pull/131),
squashed as `b7c0a1c`. PR 2 (Anthropic provider, Angela) is code-complete on this branch, not
pushed. Plan: https://claude.ai/artifact/PnixRruj7R2cb7B6gLmvLi (written before PR 1 merged; the
ADR number, retry count and `temperature` in it are outdated: ADR 0019 is the source of truth).

Commits on top of `main`: `04f9e9f` no SDK retries · `ab30ba8` `anthropic` 2.3.0 (2.4.0+ under
two weeks old) · `5f358bf` adapter + `temperature` removed from the contract + import-linter SDK
contract · `8d1f38e` replies a retry can't fix (`max_tokens`/`refusal` → `LLMOutputError`,
context overflow → `LLMRequestError`, unreadable 2xx → `LLMUnavailable`, missing usage →
unreported) · `48fa361` call deadline (per-request timeout capped at time left; request thread
abandoned at `CALL_DEADLINE_SECONDS`). Uncommitted, step 5: `tests/e2e/test_anthropic_live.py`
(`llm_live`) passed live against `https://api.meta.ai` on 2026-11-09 (plain `api_key=` works,
schema honored first try, usage reported); ADR 0019, `docs/development.md` and CHANGELOG record
it. Unit tests (720), ruff, pyright, lint-imports pass.

## Next step
Step 5 is committed (`de523e8`). The full suite passes (1054 passed, 4 opt-in skips) after
`test(security): pin the clock in due-verification tests`: two tests in
`tests/integration/services/test_verifications.py` called `record_check` without `now=NOW`, so
one failed on `main` from about 2026-11-07 (blocking every push) and the other passed vacuously.
Tell the repo owner `main` is affected; mention the commit in the PR.
1. Push and open a draft PR: title `feat(ai): add anthropic provider`, footer `Refs #23`
   (#23 stays open until PR 4), every section of the PR template filled. About 435 changed lines
   excluding tests and `uv.lock` (about 200 of them code, the rest docs), so slightly over the
   ~400 guideline: say so in the PR.

## Open threads
- Both implementers agreed (2026-11-09) to `MAX_RETRIES = 0` and no `temperature` in
  `complete()`. ADR 0019 records both in place (dated); AGENTS.md says a changed decision gets
  a new ADR: write ADR 0020 instead if the repo owner prefers.
- PR 3 (OpenAI-compatible, partner): mirror ADR 0019's rules (no SDK retries, no sampling
  params, `finish_reason` `length`/`content_filter` fail at once, deadline per call) and add
  `openai` to the import-linter SDK contract in `pyproject.toml`.
- PR 4 (`LLMUsage` + factory + AI-off startup warning, Angela; closes #23) not started.
- Known limit, accepted: a request abandoned at the deadline runs on until its own timeouts
  (immediately for normal servers; unbounded only for a server trickling bytes). Fix if
  needed: an httpx2 response event hook that checks the deadline per chunk and closes the
  connection.
- Org-supplied base URLs need ScopeGuard (SSRF) validation in #24 before use.
- `.env.example` lacks `ALLOW_SIGNUP`, `SESSION_LIFETIME_HOURS` and `PROXY_COUNT` (settings exist
  in `config.py`); small follow-up fix.
- Other open work: #114–#117 open; PRs #133 (Cloudflare Tunnel), #134 and #135 (sandbox, #84)
  open by other contributors.

## Notes for the next agent
- SDK 2.3.0: HTTP stack `httpx2` (stub with `httpx2.MockTransport`); sends API version
  `2026-10-21` (rejects `temperature`/`top_p`/`top_k`); sends `api_key=` as Bearer; doesn't
  validate 2xx bodies; sleeps for any `Retry-After` if retries were on; reads
  `ANTHROPIC_BASE_URL` when no base URL is given (the adapter always passes one).
- Meta: only `tool_choice: "auto"`; thinking counts toward `max_tokens` (564 output tokens for
  one sentence), so size `max_tokens` generously.
- Windows dev machine: Postgres on host port 5433 (git-excluded `compose.override.yaml`).
- Live LLM tests: see `docs/development.md` (env vars override `.env` for one run); never in CI.
