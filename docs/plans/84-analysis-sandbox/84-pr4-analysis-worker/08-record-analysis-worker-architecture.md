# Plan: PR 4, commit 8: `docs(workers): record the analysis worker in the architecture and changelog`

Branch `84-analysis-worker` · `Refs #84` · follows `docs(workers): document running the analysis
sandbox locally` (commit 7 of PR 4; see `84-pr4-analysis-worker-overall-plan.md`).

## Purpose

**In plain words.** This is the last commit of PR 4. It updates the project's description of
how the pieces fit together and its security notes. It adds a line to the change log, and writes
the handoff note for whoever works next. After it, you run the end-of-task checks and open the PR.

**Technical.** The `finish-task` sync for PR 4:
- `docs/architecture.md`: the dev topology. That means the two networks, the `sandbox` profile,
  which service holds what, and that prod has none of it yet (ADR 0029). The 3d sentence about
  Compose having no launcher goes.
- `docs/security.md`: the sandbox network has no outside route, only the proxy holds the socket,
  and `runc` is allowed in dev but never in prod.
- `CHANGELOG.md` `[Unreleased]` and a `STATE.md` overwrite.

Four files. Then `pre-pr-check` and the draft PR.

## Context
Commits 1 to 7 are done. The PR 3d docs (on `main` after the rebase) describe the worker-side
client but still say the stack has no launcher.

This is split from commit 7 to keep each commit at 5 files or fewer. It holds the "how it works"
records, not the "how to run it" guides.

## Decisions
1. **Architecture shows the chain once.** `worker-analysis → sandbox-launcher → sandbox-proxy →
   Docker`, with each service's network and what it holds:
   - the worker holds DB and Redis credentials;
   - the launcher and proxy hold none;
   - the proxy holds the socket.

   The text links ADR 0016, ADR 0028 and ADR 0029 instead of repeating them.
2. **`AGENTS.md` is unchanged unless `pre-pr-check` shows a gap.** Its rule "New service or env
   var? Update `compose.yaml` and `.env.example`" already covers this PR. Add one short clause
   only if agents keep missing `--profile sandbox`. Otherwise the final report says "no
   agent-file change needed".
3. **`STATE.md` names the next step.** That is PR 5 (`84-sandbox-ci`): the fixture image, a real
   lock entry and the runsc CI job.
4. **Docs in this commit.** The four files above. Commit 7 covered the guides.

## Requirements
- [ ] `docs/architecture.md` shows the chain, the two networks and "dev only until #92
      (ADR 0029)". There is no sentence saying the stack has no launcher.
- [ ] `docs/security.md` covers:
      - the internal `sandbox` network;
      - the socket mounted only on the proxy;
      - the launcher and proxy having no app secrets;
      - dev `runc` versus prod `runsc`.
- [ ] `CHANGELOG.md` `[Unreleased]` has one "Added" entry: the analysis worker and sandbox
      services in the dev stack (opt-in `sandbox` profile), the analysis queue opened (ADR 0029),
      and an empty `sandbox-images.lock`.
- [ ] `STATE.md` is overwritten with:
      - the current status and next step (PR 5);
      - open threads:
        - dropped dev jobs until #87/#101;
        - #92's prod prerequisites;
        - the profile guard test #92 must change;
        - the container-sweep follow-up issue carried over from 3d.

## Acceptance criteria
- [ ] **Tight fit:** `grep -rn "no sandbox launcher yet\|no worker until #84" docs src compose.yaml`
      returns nothing across the whole PR.
- [ ] **Contract:** every statement in `architecture.md` and `security.md` matches `compose.yaml`
      as committed (services, networks, mounts, env).
- [ ] **Isolation:** no code changes. `git diff --stat HEAD~1` shows four files.
- [ ] **Gate:** full gate green. `pre-pr-check` done with no open items. Hooks pass without
      `--no-verify`.

## Changes

### 1. `docs/architecture.md` (~10 lines)
- The sandbox section and the Compose services list.

### 2. `docs/security.md` (~4 lines)
- The sandbox launcher paragraph.

### 3. `CHANGELOG.md` (1 entry)

### 4. `STATE.md` (overwrite)

### 5. Tests
None: docs only.

#### A. Happy path
None.

#### B. Boundary cases
None.

#### C. Invalid inputs
None.

#### D. Neighbor rejection and drift guards
The PR-wide `grep` in Acceptance criteria.

## Order of work (red → green)
1. Run the PR-wide `grep`. Any hits are the work list.
2. Edit the four files.
3. Full gate:
   ```bash
   uv run ruff check . && uv run ruff format --check . && uv run pyright \
     && uv run lint-imports && uv run pytest
   ```
4. Run `finish-task` (this commit is its output), then `pre-pr-check`.
5. Commit. Footer `Refs #84` (PR 5 closes #84), Co-Authored-By trailer.
6. Push, then open a draft PR:
   - Title: `feat(workers): add analysis worker and sandbox services`.
   - Description: "Merge order: 4 of 5. Merge after 3d (link the 3d PR number), before PR 5. See
     #84."
   - Fill every template section. The test section lists the Compose commands from commits 5 and 6.
   - Tick the PR 4 box in #84's merge-order checklist once it opens.

## Reused code
- `.claude/skills/finish-task/SKILL.md`, `.claude/skills/pre-pr-check/SKILL.md`.
- `docs/plans/84-analysis-sandbox/84-pr3d-sandbox-runner-client/03-document-sandbox-runner-client.md`.

## Verification
- `grep` clean. Full gate green.
- `git diff --stat origin/main...HEAD` for the whole PR: under ~400 non-test lines.
- Every PR 4 commit touches 5 files or fewer.

## Notes for later commits
- **PR 5 (`84-sandbox-ci`):** fills `sandbox-images.lock` with the fixture analyzer digest and
  adds the runsc CI job. It can use `docker compose --profile sandbox` for its integration tests.
- **#87 / #101 / #92:** each updates `STATE.md`. #92 also updates the architecture text when the
  services reach prod.
