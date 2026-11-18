# Plan: PR 3d, commit 3: `docs(infra): document the sandbox runner client`

Branch `84-sandbox-runner-client` · `Refs #84` · follows `feat(workers): wire the sandbox runner
into the scanner gate` (commit 2 of PR 3d; see `../84-pr3-sandbox-launcher-split-4-prs.md`).

## Purpose

**In plain words.** The worker can now talk to the launcher, but the documents still say the
worker side doesn't exist. This commit updates them:
- how the worker calls the launcher
- what it does when the launcher is busy or down
- how to turn the feature on
- one rule every future caller must follow: before asking for a run, the worker must check that
  the artifact belongs to the organization.

The launcher can't check that itself, because it knows nothing about organizations. The commit
changes no code.

**Technical.** Runs the `finish-task` procedure for PR 3d:
- `docs/architecture.md`: the analysis path, the "Sandbox launcher" section and the `analysis`
  queue row.
- `docs/security.md`: a tenant-safety note, and why the client is not SSRF-guarded.
- `docs/development.md`: `SANDBOX_LAUNCHER_URL`.
- `AGENTS.md`: the `infra/` layout line.
- `CHANGELOG.md` `[Unreleased]` and a new `STATE.md`.

There is no ADR: commits 1 and 2 implement ADR 0016 as written.

## Context
- **The stale wording:** after PR 3c's docs commit, `docs/architecture.md:25-27` and `:348` say
  "the worker-side client and the analysis worker do not yet" exist.
- **What changed:** commits 1 and 2 added `infra/sandbox.py` and the `SANDBOX_LAUNCHER_URL`
  setting. The analysis worker itself is still missing (PR 4 and PR 5).
- **The ownership gap:** `_GuardedSandbox` checks the analyzer allowlist, but nothing checks
  artifact ownership yet. There is no artifact table until #85. That gap must be written down
  before any scanner calls `runtime.sandbox`.
- **Why a separate commit:** the code commits stay reviewable, and the docs are checked against
  the final code.

## Decisions
1. **Edit and replace, don't append.** The "worker-side client … do not yet" wording becomes
   "the analysis worker does not yet". The client becomes a short subsection under "Sandbox
   launcher" in `docs/architecture.md`, next to the service it calls.
2. **The tenant-safety note is a rule, stated where reviewers look.** It goes in
   `docs/security.md`, in the "Sandbox launcher" section:
   - The launcher has no authentication and no notion of orgs.
   - Any code that calls `runtime.sandbox.run(analyzer, artifact_id)` must first confirm that
     the artifact belongs to `ctx.org_id`.
   - Until #85 adds the artifact table, nothing may call it with an ID derived from user input.
   - The paragraph is not copied into code. The `infra/sandbox.py` docstring already says
     "ownership is checked by the caller" (commit 1), so the docs and the code agree.
3. **Document the failure mapping as a table** (status → worker error → retried?):
   - Reviewers of PR 5's scanner will read it.
   - It also records the timeout ordering, 900 s client > 840 s wall ceiling, and the 3 MiB
     reply cap.
4. **Say why the client is not SSRF-guarded.** One sentence in `docs/security.md`: the launcher
   URL comes from operator config, is internal by design (ADR 0016) and is checked as
   `http://host[:port]` at startup. Scanners never reach this client except through
   `_GuardedSandbox`.
5. **No `README.md` change.** Nothing is user-visible yet. Users see analysis results only after
   PR 5.
6. **This commit is the docs commit** of PR 3d, per `finish-task`. `STATE.md` is overwritten with
   the handoff, including the stacked-PR rebase steps.

## Requirements
- [ ] `docs/architecture.md`:
  - [ ] The analysis-path intro (lines ~25-27) and the `analysis` row (~348) no longer say the
        worker-side client is missing.
  - [ ] A "Worker client" subsection covers `LauncherSandboxRunner`, `SANDBOX_LAUNCHER_URL` (off
        by default) and the status table.
- [ ] `docs/security.md`, in the "Sandbox launcher" section:
  - [ ] the tenant-safety rule of decision 2
  - [ ] the not-SSRF-guarded reason of decision 4
  - [ ] the reply cap and the fixed error messages
- [ ] `docs/development.md`: "Running the sandbox services locally" shows
      `SANDBOX_LAUNCHER_URL=http://127.0.0.1:8791` for a local worker.
- [ ] `AGENTS.md` layout: the `infra/` line adds `sandbox` (launcher client).
- [ ] `CHANGELOG.md` `[Unreleased]`: one entry for the worker-side sandbox client (off by default).
- [ ] `STATE.md` overwritten: PR 3d status, next steps (see Order of work), open threads carried
      over.
- [ ] No code changes.

## Acceptance criteria
- [ ] **Accuracy:** every name, constant, status and message in the docs matches the code (grep
      `src/attacksurf/infra/sandbox.py`, `config.py`, `sandbox_launcher/server.py`).
- [ ] **No stale claims:** `grep -rn "worker-side client" docs/ AGENTS.md` finds nothing that
      says it is missing.
- [ ] **Rule present:** `grep -n "belongs to" docs/security.md` hits the tenant-safety note.
- [ ] **Gate:** the full gate passes, `pre-pr-check` is done, and the PR diff is at most ~400
      non-test lines (estimate ~80 code plus ~60 docs).

## Changes

### 1. `docs/architecture.md` (~+20 lines)
- Analysis-path intro: the client now exists. The diagram's `worker-analysis` box is unchanged
  because that worker is still later.
- A "Worker client" subsection under "Sandbox launcher" covering:
  - module and setting
  - the `httpx` options and why
  - the status table: 200 → result; 503 / transport → `TransientJobError`, retried; other →
    `SandboxError`
  - timeouts and the reply cap
- `analysis` row: "the analysis worker is not yet implemented".

### 2. `docs/security.md` (~+8 lines)
- Tenant-safety rule, not SSRF-guarded reason, reply cap and fixed messages.

### 3. `docs/development.md` (~+3 lines)
- The `SANDBOX_LAUNCHER_URL` export and the expected 404 → `SandboxError` with the empty catalog.

### 4. `AGENTS.md` (1 line edited)
- `infra/` line: `…, scope_guard, dns, public_suffix, safe http client, sandbox (launcher
  client), crypto`.

### 5. `CHANGELOG.md` (+2 lines)

### 6. `STATE.md` (replaced)

## Order of work
1. Edit the docs, then grep them against the code for every name, status and constant used.
2. Full gate:
   ```bash
   uv run ruff check . && uv run ruff format --check . && uv run pyright \
     && uv run lint-imports && uv run pytest
   ```
3. Run `finish-task` (this commit) and `pre-pr-check`. Check `git diff --stat
   84-sandbox-launcher-service...` for size. That compares against the 3c branch, which is the
   PR's base while 3c is open.
4. Commit:
   - Subject: `docs(infra): document the sandbox runner client`.
   - Footer: `Refs #84` and the Co-Authored-By trailer.
   - Never `--no-verify`.
5. Push and open PR 3d as a draft with base `84-sandbox-launcher-service`. Description line:
   `Merge order: 3d of #84. Merge after <3c PR>. See #84.` Do this only when the user asks.

## Reused code
- `../84-pr3c-add-sandbox-launcher-service/05-document-launcher-service.md`: the previous docs
  commit's structure.
- `docs/security.md` "Sandbox launcher" and `docs/architecture.md` "Sandbox launcher" sections
  (extended, not duplicated).

## Verification
- Read each changed doc section against the code, then run the grep checks above.
- Optional manual smoke: follow the updated `docs/development.md` steps. The launcher should
  answer 404 for the empty catalog, and the worker-side call should raise `SandboxError`.

## Notes for later commits
- **After 3c merges:**
  - Retarget PR 3d to `main`.
  - Run `git rebase --onto origin/main 84-sandbox-launcher-service 84-sandbox-runner-client`.
  - Push with `git push --force-with-lease`, wait for CI, then squash-merge.
- **After 3d merges:**
  - Tick 3a to 3d in #84.
  - Propose the follow-up issue: sweep leftover `attacksurf-*` containers after a launcher or
    proxy crash (before #92).
- **PR 4 (compose):** the analysis worker gets `SANDBOX_LAUNCHER_URL`, and the launcher's port
  stays on the internal network.
- **#85 (artifacts):** replaces the documented rule with a real ownership check before
  `runtime.sandbox.run`, plus a tenant-isolation test.
