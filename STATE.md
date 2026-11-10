# STATE

> Handoff for the next session. Overwritten at the end of every task; not a history log.

**Updated:** 2026-11-10 · **Branch:** `23-anthropic-provider` · **Issue:** #23 (LLM providers), PR 2 of 4

## Status
PR 1 (shared LLM contract) is merged: [#131](https://github.com/cpt9m0/attacksurf/pull/131).
PR 2 (Anthropic provider, Angela) is code-complete and in review. `origin/main` (`da70e1e`,
archiving cancels scans, ADR 0021) is being merged in, with the `CHANGELOG.md` and `STATE.md`
conflicts resolved. Plan:
https://claude.ai/artifact/PnixRruj7R2cb7B6gLmvLi (outdated on ADR number, retry count and
`temperature`: ADR 0019 is the source of truth).

Commits on top of `main`: `04f9e9f` no SDK retries · `ab30ba8` `anthropic` 2.3.0 · `5f358bf`
adapter + `temperature` removed from the contract + import-linter SDK contract · `8d1f38e`
replies a retry can't fix · `48fa361` call deadline · `de523e8` live test (passed against
`https://api.meta.ai` on 2026-11-09) · `45faf84` clock pin in due-verification tests. `main`
pinned the failing one itself (#133); this branch still pins the archived-roots test, which
passed without testing the archive filter. `84c58b3`: pyright checks as Linux and the
sandbox proxy server tests skip on Windows, so pushes from Windows pass the hooks.

## Next step
1. Commit the merge of `da70e1e` and push.
2. Review feedback: the reviewer asked for a superseding ADR instead of editing ADR 0019 in
   place. Write `docs/adr/0022-...` with "no sampling settings" and "no SDK retries" (reasons
   and trade-offs moved from 0019). Restore those two 0019 paragraphs to their merged wording
   plus a "Superseded in part by ADR 0022" note. Keep 0019's error-handling and deadline
   additions, which fill in what 0019 already required. Update the links in
   `docs/architecture.md`, the `llm-prompt` skill and CHANGELOG.
3. PR size: about 420 changed lines excluding tests and `uv.lock` (about 210 of them code),
   slightly over the ~400 guideline; the PR description says so.

## Open threads
- #23:
  - Both implementers agreed (2026-11-09) to `MAX_RETRIES = 0` and no `temperature` in
    `complete()`; moving into ADR 0022 (next step 2).
  - PR 3 (OpenAI-compatible, partner): mirror ADR 0019's rules (no SDK retries, no sampling
    params, `finish_reason` `length`/`content_filter` fail at once, deadline per call) and add
    `openai` to the import-linter SDK contract in `pyproject.toml`.
  - PR 4 (`LLMUsage` + factory + AI-off startup warning, Angela; closes #23) not started.
  - Known limit, accepted: a request abandoned at the deadline runs on until its own timeouts
    end it. That is immediate for normal servers and unbounded only for a server trickling
    bytes. Fix if needed: an httpx2 response event hook that checks the deadline per chunk and
    closes the connection.
  - Org-supplied base URLs need ScopeGuard (SSRF) validation in #24 before use.
- #84: PR 3 (`84-sandbox-launcher`) is next; merge order port → proxy → launcher → analysis
  worker → CI.
  - The launcher must send exactly what `sandbox_proxy/policy.py` accepts: user
    `65532:65532`, `LogConfig` none, `AutoRemove`, binds under the artifact root, attach before
    start, stdout only.
  - Deployment must pass the proxy settings as environment variables (the proxy never reads
    `.env`).
  - The scanner registry caps `timeout_seconds` at 240 s, but ADR 0016 allows 600 s sandbox
    runs. Resolve this before the first analysis scanner; the runner client deadline is
    affected too.
  - PR 4 adds a new ADR for consuming the `analysis` queue before a real analyzer exists, and
    names the OSV volume `attacksurf_osv` to match the proxy.
  - `runsc` must be registered on the VPS before the proxy is deployed to prod.
- #29: backups, monitoring and hardening remain.
  - Signup is enabled and should be closed until backups exist.
  - The exposed tunnel/API credentials recorded in #133 still need rotation.
- `.env.example` lacks `ALLOW_SIGNUP`, `SESSION_LIFETIME_HOURS` and `PROXY_COUNT` (the settings
  exist in `config.py`).
- Scans (ADR 0021): a user-facing "cancel scan" would reuse `services.assets._cancel_scans` and
  the persistence guards; not built. Lock rule to keep: scan rows before the root, and no
  transaction reads the root locked and later upgrades that lock.
- Follow-ups: #115, #117.

## Notes for the next agent
- SDK 2.3.0:
  - HTTP stack is `httpx2`; stub it with `httpx2.MockTransport`.
  - Sends API version `2026-10-21`, which rejects `temperature`/`top_p`/`top_k`.
  - Sends `api_key=` as Bearer and doesn't validate 2xx bodies.
  - Would sleep for any `Retry-After` if retries were on.
  - Reads `ANTHROPIC_BASE_URL` when no base URL is given; the adapter always passes one.
- Meta accepts only `tool_choice: "auto"`. Thinking counts toward `max_tokens` (564 output tokens
  for one sentence), so size `max_tokens` generously.
- Live LLM tests: see `docs/development.md` (env vars override `.env` for one run); never in CI.
- Browser layout tests: `RUN_WEB_E2E=1 uv run pytest tests/e2e/web -m web_e2e --no-cov` after
  `uv run playwright install chromium`. They skip by default, so `uv run pytest` stays fast.
- Deployment: `docs/deployment.md` (pull-based CD).
  - Secrets stay in `/etc/attacksurf/`, never in git or images.
  - `PROXY_COUNT` counts hops (1 behind the tunnel); validate Caddy before deploying.
- Windows dev machine: Postgres on host port 5433 (git-excluded `compose.override.yaml`).
- `docs/plans/` holds the user's temporary plan copy: never stage it.
- Due-verification tests are clock-pinned (explicit `NOW`); keep them that way.
