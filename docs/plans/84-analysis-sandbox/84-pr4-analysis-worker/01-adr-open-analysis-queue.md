# Plan: PR 4, commit 1: `docs(adr): record opening the analysis queue before an analyzer exists`

Branch `84-analysis-worker` (new, from `origin/main`) · `Refs #84` · follows `022e53e feat(ai):
build llm providers from config (#23) (#179)` (the tip of `main` when this was planned; see
`84-pr4-analysis-worker-overall-plan.md`).

## Purpose

**In plain words.** An earlier written decision (ADR 0016) says the analysis queue stays switched
off until a worker, the launcher, the proxy and at least one analyzer all exist. PR 4 switches it
on before any analyzer exists, so the project rules require a new decision record that says so and
explains why. This commit writes that record first, before any code changes, so reviewers can agree
on the rule before reading the code that follows it. It changes no behaviour.

**Technical.** Adds `docs/adr/0029-open-analysis-queue-before-analyzers.md` and edits only the
Status line of `docs/adr/0016-analysis-sandbox.md`. ADR 0029:
- supersedes the ADR 0016 Consequences bullet "The `analysis` queue stays reserved until the
  worker, launcher, proxy and at least one analyzer exist";
- replaces it with three rules:
  - the queue is consumed in dev, behind the opt-in `sandbox` Compose profile;
  - prod runs no sandbox service until the first analysis task is registered (#92), copying the
    `worker-ai` precedent in `compose.prod.yaml`;
  - a unit test keeps every production scan profile from selecting an analysis scanner until #92.

The commit is docs only, so the gate is unaffected.

## Context
ADR 0016 (sandbox architecture) and ADR 0028 (artifact staging) are accepted. PRs 1 to 3c merged;
3d (worker client) is pending.
- `infra/queue.py` still lists `analysis` in `RESERVED_QUEUES`.
- Upload services already enqueue `analysis.code_scan` (`services/repos.py`) and
  `analysis.binary_static` (`services/binaries.py`), but nothing registers those tasks yet.

Commits 2 to 6 put this ADR into practice. It is a separate commit because `AGENTS.md` says
"Changing a decision means writing a new ADR", and a docs-only commit is easy to review on its own.

## Decisions
1. **Number 0029.** `docs/adr/` on `main` ends at 0028, and no local or remote branch has a 0029
   or 0030 file. This was checked with `git ls-tree` across `git branch -r` while planning.
   Re-check right before committing, because ADR numbers move fast (`STATE.md`).
2. **Supersede one line, not the whole ADR.** This follows `0010-celery-worker-runtime.md:3`
   ("supersedes the worker-session line of ADR 0008") and `0024-…md:3`. ADR 0016's Status
   becomes `accepted; the reserved-queue consequence superseded by 0029`.
3. **Prod waits for a registered analysis task, not just for an analyzer image.** Otherwise a
   prod worker would receive `analysis.*` messages with no matching task and drop them. Uploads
   would then never finish, even after the task is added later.
4. **The guard is a test, not runtime code.** No profile selects an analysis scanner today, so a
   failing test is enough to stop someone adding one too early. Runtime code would be dead code.
5. **What it deliberately leaves out.** The queue move, the compose services and the guard test
   (commits 2 to 6).
6. **Docs in this commit.** Only the two ADR files. `docs/architecture.md`, `CHANGELOG.md` and
   `STATE.md` come in commit 8.

## Requirements
- [ ] `docs/adr/0029-open-analysis-queue-before-analyzers.md` follows `docs/adr/0000-template.md`:
      title, `Status: accepted (supersedes ADR 0016's reserved analysis queue consequence)`,
      `Date:` the day it is committed, Context, Decision, Consequences.
- [ ] Context names the two upload tasks already sent to the queue and the deploy constraint
      (every prod service must become healthy; the launcher needs `runsc`).
- [ ] Decision lists the three rules in Technical above, plus "the empty `sandbox-images.lock`
      allows no image, so the sandbox cannot run anything until PR 5 adds one".
- [ ] Consequences says:
      - a dev `worker-analysis` drops `analysis.*` messages it has no task for (the job row stays
        `queued`) until #87/#101 register them;
      - prod gets the three services together with the VPS `runsc` change;
      - the guard test must be removed or changed by #92.
- [ ] ADR 0016 changes only on its Status line.
- [ ] No source, test or compose file changes.

## Acceptance criteria
- [ ] **Contract:** the ADR's rules match what commits 2 to 6 build. A reviewer can tick each
      rule against a later commit.
- [ ] **Tight fit:** `git diff --stat` shows exactly two files under `docs/adr/`.
- [ ] **Gate:** the commit passes the hooks (`ruff`, `gitleaks`, commit-msg) without
      `--no-verify`.

## Changes

### 1. `docs/adr/0029-open-analysis-queue-before-analyzers.md` (~35 lines)
- **Context:**
  - ADR 0016 kept the queue reserved.
  - Uploads already queue `analysis.*` jobs.
  - The deploy script waits on every service in `compose.prod.yaml`.
  - The launcher exits without `runsc` in prod (`sandbox_launcher/__main__.py`).
  - Developers need the full chain locally to build #87/#101/#92 against.
- **Decision:** the three rules, plus the empty lock.
- **Consequences:** as listed in Requirements. Also: the `active` queue stays reserved.

### 2. `docs/adr/0016-analysis-sandbox.md` (1 line)
- Status line only.

### 3. Tests
None: docs-only commit.

#### A. Happy path
None.

#### B. Boundary cases
None.

#### C. Invalid inputs
None.

#### D. Neighbor rejection and drift guards
None. Commit 2's test is the guard this ADR promises.

## Order of work (red → green)
1. Re-check the free ADR number:
   `for b in $(git branch -r | grep -v HEAD); do git ls-tree --name-only $b docs/adr/; done | grep 0029`
   prints nothing.
2. Write the ADR and the Status-line edit.
3. Gate: `uv run pre-commit run --all-files`.
4. No `finish-task` yet: deferred to commit 8 (see Decisions).
5. Commit with the subject above. The body explains why: the queue goes live before an analyzer
   so the dev chain exists to build analyzers against. Footer `Refs #84`, then the Co-Authored-By
   trailer. Never `--no-verify`.

## Reused code
- `docs/adr/0000-template.md`: the section layout.
- `docs/adr/0010-celery-worker-runtime.md`, `docs/adr/0024-no-llm-sampling-or-sdk-retries.md`:
  the "supersedes one line" wording.

## Verification
- `git diff --stat HEAD~1` lists only the two ADR files.
- Read the ADR against `compose.prod.yaml:99-101` (the `worker-ai` comment): the reasoning matches.

## Notes for later commits
- **Commit 2:** implements the guard test the ADR promises.
- **Commit 3:** moves the queue; its commit body cites ADR 0029.
- **Commit 6:** its `compose.prod.yaml` comment cites ADR 0029.
- **#92 (first analyzer):** must remove or change the commit 2 guard, add the prod services and
  register `runsc` on the VPS.
