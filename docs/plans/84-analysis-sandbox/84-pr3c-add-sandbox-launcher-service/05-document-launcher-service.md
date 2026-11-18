# Plan: PR 3c, commit 5: `docs(infra): document the sandbox launcher service`

Branch `84-sandbox-launcher-service` · `Refs #84` · follows `feat(security): refuse to start the
launcher without runsc in prod` (commit 4 of PR 3c; see `../84-pr3-sandbox-launcher-split-4-prs.md`).

## Purpose

**In plain words.** The launcher now exists as a running service, but the project's documents
still say "nothing runs these parts yet". This commit brings them up to date: what the launcher
does, what it refuses, how it cleans up, how to run it on a laptop, and where work stops next.
It changes no code.

**Technical.** Runs the `finish-task` procedure for PR 3c: `docs/architecture.md` (launcher
service section and the `analysis` row), `docs/security.md` (the launcher's role, limits,
cleanup, start-up rule and the residual wait race), `docs/development.md` (running proxy and
launcher locally), the `AGENTS.md` layout line for `sandbox_launcher/`, `CHANGELOG.md`
`[Unreleased]` and a new `STATE.md`. No ADR: commits 1–4 implement ADR 0016 and ADR 0023 without
changing a decision.

## Context
PR 3b's docs commit described the building blocks with "nothing runs them yet". Commits 1–4 of
PR 3c added `proxy.py`, `runner.py`, `server.py` and `__main__.py`. PR 3d (worker client) and PR 4
(compose) read these docs next. Separate commit so code commits stay reviewable and the docs are
checked against the final code.

## Decisions
1. **Replace, don't append.** The "building blocks" section in `docs/architecture.md` becomes
   "Sandbox launcher", covering both the blocks and the service; the "launcher service does not
   exist yet" wording is removed everywhere.
2. **Security doc states the guarantees and the limits.** Wall-time kill decided by the launcher's
   own deadline; 2 MiB cap with partial output dropped; stderr discarded; cleanup on every path
   with `sandbox_cleanup_failed` as the alert signal; fixed-menu API; 404 that doesn't reveal
   which part is unknown; prod start-up refusal; the removed-wait race failing safe.
3. **Development doc is runnable.** Commands to start the proxy and the launcher with
   `SANDBOX_ALLOW_RUNC=true` and the expected `healthz`/`runs` answers with the empty catalog.
4. **No new settings,** so `.env.example` and `compose.yaml` are untouched (compose is PR 4).
5. **This commit is the docs commit** of PR 3c, per `finish-task`.

## Requirements
- [ ] `AGENTS.md` layout: `sandbox_launcher/` line names the service (API, runner, proxy client).
- [ ] `docs/architecture.md`: launcher section covers `server.py`, `runner.py`, `proxy.py`,
      `__main__.py`; the `analysis` table row no longer says the launcher service is missing.
- [ ] `docs/security.md`: the points in decision 2.
- [ ] `docs/development.md`: the local run of decision 3.
- [ ] `CHANGELOG.md` `[Unreleased]`: one entry for the launcher service.
- [ ] `STATE.md` overwritten: PR 3c status, next step (open/merge PR 3c, then PR 3d).
- [ ] No code changes.

## Acceptance criteria
- [ ] **Accuracy:** every name, constant and status code in the docs matches the code (checked
      by grep against `src/attacksurf/sandbox_launcher/`).
- [ ] **No stale claims:** `grep -rn "nothing runs them yet\|launcher service.*not yet"` in
      `docs/` and `AGENTS.md` finds nothing.
- [ ] **Gate:** full gate passes; `pre-pr-check` done; diff size ≤ ~400 non-test lines.

## Changes

### 1. `AGENTS.md` (1–2 lines edited)
### 2. `docs/architecture.md` (~+20 lines, section rewritten)
### 3. `docs/security.md` (~+12 lines)
### 4. `docs/development.md` (~+15 lines)
### 5. `CHANGELOG.md` (+3 lines)
### 6. `STATE.md` (replaced)

## Order of work
1. Edit the docs; grep the docs against the code for every name used.
2. Full gate:
   ```bash
   uv run ruff check . && uv run ruff format --check . && uv run pyright \
     && uv run lint-imports && uv run pytest
   ```
3. `pre-pr-check`; check `git diff --stat main...` for size.
4. Commit with subject `docs(infra): document the sandbox launcher service`, footer `Refs #84`,
   Co-Authored-By trailer. Never `--no-verify`.

## Reused code
- `docs/plans/84-analysis-sandbox/84-pr3b-launcher-building-blocks/05-document-launcher-building-blocks.md`: the
  previous docs commit's structure.

## Verification
- Read each changed doc section against the code; the grep checks above.
- Optional manual smoke: follow the new `docs/development.md` steps.

## Notes for later commits
- **PR 3c description:** `Merge order: 3c of #84. Merge after #158, before <3d PR>. See #84.`
- **PR 3d:** adds the tenant-safety note (worker confirms the artifact belongs to the org) and
  the runner client docs.
- **After 3d:** propose the crash-sweep follow-up issue (leftover `attacksurf-*` containers).
