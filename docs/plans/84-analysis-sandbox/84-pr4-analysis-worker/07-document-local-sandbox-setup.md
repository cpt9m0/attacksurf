# Plan: PR 4, commit 7: `docs(workers): document running the analysis sandbox locally`

Branch `84-analysis-worker` · `Refs #84` · follows `feat(workers): add the analysis worker to the
dev stack` (commit 6 of PR 4; see `84-pr4-analysis-worker-overall-plan.md`).

## Purpose

**In plain words.** The local setup now has the sandbox services, but the developer guide still
tells you to start them by hand. This commit rewrites that guide section to use the new opt-in
command. It explains what happens to uploads while no analysis task exists. It also adds a short
note to the deployment guide listing what production needs before these services can go there.

**Technical.**
- `docs/development.md:185-205` ("Running the sandbox services locally"): replaced with the
  `--profile sandbox` workflow.
- `docs/deployment.md`: an "Analysis sandbox (not deployed yet)" note.
- `src/attacksurf/services/uploads.py`: the `AnalysisRequest` docstring.

Three files, docs and a docstring only. The architecture, security, changelog and handoff updates
are commit 8.

## Context
Commits 5 and 6 added `sandbox-proxy`, `sandbox-launcher` and `worker-analysis` under the
`sandbox` profile. `make down` now also stops them. Commit 4 made the manual `echo '{}' >
/tmp/sandbox-images.lock` step unnecessary.

This commit is split from commit 8 to keep each commit at 5 files or fewer:
- **Commit 7, this one:** the "how do I run it" guides.
- **Commit 8:** the "how does it work and where are we" records.

## Decisions
1. **Replace the manual run instructions; don't keep both.** The profile is the supported way
   now.
   - One sentence keeps `uv run python -m attacksurf.sandbox_launcher` for debugging outside
     Docker.
2. **The `AnalysisRequest` docstring.** It currently says "The `analysis` queue has no worker until
   #84". It becomes: "In dev the opt-in `worker-analysis` consumes the queue but has no analysis
   tasks until #87/#101; prod has no consumer until #92 (ADR 0029). The job stays queued."
   - The UI text "queued until the analysis worker is available" (`web/ui.py`) stays true for prod
     and is left as is.
3. **The deployment note is a checklist for #92, not instructions to follow now.** Prod runs none
   of this yet (ADR 0029). The note keeps #92 from forgetting the VPS steps.
4. **Docs in this commit.** The three files above. Commit 8 carries `docs/architecture.md`,
   `docs/security.md`, `CHANGELOG.md` and `STATE.md`.

## Requirements
- [ ] `docs/development.md`, "Running the sandbox services locally":
      - `docker compose --profile sandbox up -d --wait`, `docker compose --profile sandbox logs
        sandbox-launcher`, and `make down` stopping everything;
      - `SANDBOX_ALLOW_RUNC` (default `true` in dev) and `SANDBOX_ARTIFACT_ROOT` (default
        `/tmp/attacksurf-sandbox`, same path on the host and in the containers);
      - the catalog is empty until PR 5, so `POST /runs` is a 404;
      - the dropped-jobs limitation (upload jobs sent while `worker-analysis` runs are discarded
        until #87/#101; their rows stay `queued`).
- [ ] The manual `echo '{}' …` and `export …` block is gone.
- [ ] The 3d paragraph on pointing `SANDBOX_LAUNCHER_URL` at a self-run launcher is replaced by
      "Compose sets it on `worker-analysis`".
- [ ] `docs/deployment.md` note lists the #92 prerequisites:
      - `runsc` registered in the VPS `daemon.json`;
      - a host staging path, mounted at the same path;
      - the Docker socket's group for uid 10001 (`group_add`);
      - the fact that `deploy.sh` waits for every service to be healthy.
- [ ] `services/uploads.py`: only the docstring changes.

## Acceptance criteria
- [ ] **Contract:** from a stopped stack (`make down`), following the development section step by
      step ends with every sandbox service healthy, and `make down` stops them all.
- [ ] **Tight fit:** `grep -n "no worker until #84\|echo '{}'" docs/development.md
      src/attacksurf/services/uploads.py` returns nothing.
- [ ] **Isolation:** no Python behaviour changes. `git diff --stat` shows exactly three files.
- [ ] **Gate:** the full gate passes. Hooks pass without `--no-verify`.

## Changes

### 1. `docs/development.md` (~25 lines replaced)
- The rewritten section as in Requirements.

### 2. `docs/deployment.md` (~8 lines)
- The new note, near the existing service list.

### 3. `src/attacksurf/services/uploads.py` (docstring, 2 lines)

### 4. Tests
None: docs only.

#### A. Happy path
None.

#### B. Boundary cases
None.

#### C. Invalid inputs
None.

#### D. Neighbor rejection and drift guards
The `grep` in Acceptance criteria checks for stale wording.

## Order of work (red → green)
1. Run the `grep`. It finds hits (red).
2. Edit the three files until it is clean.
3. Follow the new development section from a stopped stack.
4. Full gate:
   ```bash
   uv run ruff check . && uv run ruff format --check . && uv run pyright \
     && uv run lint-imports && uv run pytest
   ```
5. `finish-task` deferred to commit 8.
6. Commit. Body: "the dev guide now uses the sandbox profile; the deployment note lists what #92
   needs before prod". Footer `Refs #84`, Co-Authored-By trailer.

## Reused code
- `docs/plans/84-analysis-sandbox/84-pr3d-sandbox-runner-client/03-document-sandbox-runner-client.md`:
  the shape of a docs commit.
- The commands from the Acceptance criteria of commits 5 and 6.

## Verification
- `grep` clean. The section was followed end to end.
- `git diff --stat HEAD~1` lists three files.

## Notes for later commits
- **Commit 8:** architecture, security, changelog and handoff. It also runs the final stale-wording
  `grep` across `docs/` and `src/`, plus `finish-task` and `pre-pr-check`.
- **#87 / #101:** remove the dropped-jobs paragraph once the tasks are registered.
- **#92:** turns the deployment note into real steps.
