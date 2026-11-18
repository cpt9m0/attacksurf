# Plan: PR 3b, commit 5: `docs(infra): document the launcher building blocks`

Branch `84-sandbox-launcher-core` · `Refs #84` · follows `be32af9 feat(infra): read capped
stdout from docker attach streams` (commit 4 of PR 3b; see
`../84-pr3-sandbox-launcher-split-4-prs.md`).

## Purpose

**In plain words.** The first four commits of this PR added the pure parts of the sandbox
launcher: its settings, its menu of analysis tools, the check that an uploaded artifact is a real
folder, the recipe for the container request, and the reader for the tool's output. They are
code only, and nothing runs them yet. This commit writes them down so the next person (or agent)
does not have to find them by searching. It tells the reader which folder holds them, what each
piece guarantees, and which parts of the picture are still missing. It adds no behavior and
changes no code, so it cannot make anything safer or less safe. It can only make the
documentation true again.

**Technical.** Docs only. Updates `AGENTS.md` (layout), `docs/architecture.md` (the analysis-path
note, a short launcher-modules section and the `analysis` queue row), `docs/security.md` (the
sandbox-output rows, where the stream reader now enforces the 2 MiB cap and fails closed),
`CHANGELOG.md` (`[Unreleased]`) and `STATE.md` (overwritten with the current handoff). It follows
the `finish-task` skill's table. No ADR: ADR 0011, 0016 and 0018 already record every decision
these modules implement, and none of the four commits made a new one. No source, test, config,
compose or `pyproject.toml` file changes.

## Context
PR 3b is the "pure parts" PR of the 3a to 3d split of #84's launcher. Its code commits are:
1. `54c1f1b` `SandboxLauncherSettings` in `config.py` (env only, no `.env`, wall time at most 840 s;
   `.env.example` already updated in that commit).
2. `2fd8ab1` `sandbox_launcher/catalog.py` (`SandboxLimits`, `AnalyzerSpec`, `Analyzer`, empty
   `CATALOG`, `load_catalog`), `artifacts.py` (`resolve_artifact`, `ArtifactNotFound`) and the
   import-linter contract "sandbox launcher stays isolated from the app, the proxy and Docker"
   (already in `pyproject.toml`).
3. `d9bfc8e` `container.py` (`build_create_body`, checked against the real
   `sandbox_proxy.policy.validate_create` in tests).
4. `be32af9` `stream.py` (`read_stdout`, `OutputLimitExceeded`, `MalformedStream`).

Each of those plans deferred its docs here ("commit 5 of PR 3b carries `AGENTS.md`,
`docs/architecture.md`, `CHANGELOG.md` and `STATE.md`"). What is stale today:
- `AGENTS.md:38` lists `sandbox_proxy/` in the layout but not `sandbox_launcher/`.
- `docs/architecture.md:25` says the analysis path is "not built yet", and `:220` says "launcher
  and worker are not yet" implemented. The proxy and the launcher's building blocks are in the
  repo; the launcher service (3c) and the worker client (3d) are not.
- `CHANGELOG.md` has a `sandbox-proxy` entry but nothing for the launcher.
- `STATE.md` still describes the merged #15 on `main`.

It is a separate commit because the split plan scopes every PR's docs into its last commit, so
the code commits stay reviewable on their own and the docs describe the finished set.

## Decisions
1. **Describe what exists, mark what does not.** Wording says "building blocks" and keeps
   `*(later)*` on the launcher service, the worker and the `sandbox-launcher` Compose service,
   so no doc claims a running launcher. The analysis-path diagram stays as the target picture;
   only its lead-in sentence changes.
2. **One short section, not a new doc.** The module facts go in `docs/architecture.md` as a
   "Sandbox launcher building blocks" subsection next to the analysis-path diagram (about 12
   lines). The launcher is described by what each piece refuses, which is what a reviewer of 3c
   needs. No new file under `docs/`.
3. **`AGENTS.md` gets one layout line and no new rule.** The import-linter contract already
   enforces the isolation; the layout line names it. The copied-constants-plus-parity-test
   pattern (`MAX_STDOUT_BYTES`, `LIMIT_CEILINGS`, `_DIGEST`, the create-body constants) is
   already stated in each module docstring and goes in the architecture subsection, not in
   the rulebook, because it applies only to this package.
4. **`docs/security.md`: edit the two sandbox-output rows, nothing else.** The "Parser exploit"
   row gains: the cap is checked on the declared frame size before the payload is read, and a
   truncated or unknown frame fails the run instead of returning partial output. The "Resource
   exhaustion" row stays as is: wall-time and concurrency enforcement arrive in 3c. Both rows
   keep their `*(later)*` tag.
5. **`docs/development.md` is not touched.** There is nothing to run or configure yet: the
   launcher settings are already documented in `.env.example` (commit 1) and there is no
   service, command or Compose entry. 3c's docs commit owns `docs/development.md`.
6. **`CHANGELOG.md`: one entry under `### Added`**, in the style of the `sandbox-proxy` entry,
   with `(#84)`. Not under `Fixed`: nothing was broken.
7. **`STATE.md` is overwritten for the branch, not for `main`.** Status is "PR 3b code and docs
   complete, not pushed"; next step is the PR 3b gate (see Order of work). It records the
   decisions the next PR needs (see Notes) and drops everything about #15.
8. **No plan files in the commit.** `docs/plans/` is untracked and stays that way, as in the
   four earlier commits.
9. **No `README.md`, `DESIGN.md`, skills or `CLAUDE.md` changes.** Nothing is user-visible, no UI
   changed, no workflow or command is new.

## Requirements
- [ ] `AGENTS.md`: one new layout line under `sandbox_proxy/`, in the same column and style:
      `sandbox_launcher/  Sandbox run building blocks (ADR 0016): analyzer catalog, artifact
      resolver, create-body builder, capped stdout reader; isolated by import-linter`. No other
      line changes.
- [ ] `docs/architecture.md` analysis-path lead-in (`:25`) says the proxy and the launcher's
      building blocks exist and the launcher service and worker do not; it no longer says "not
      built yet".
- [ ] `docs/architecture.md` has a "Sandbox launcher building blocks" subsection that names, for
      each module, what it does and what it refuses:
  - `config.SandboxLauncherSettings`: process env only, no app secrets, wall time capped at 840 s
    (below the proxy's 900 s).
  - `catalog.py`: fixed command and limits in code, image digest from `sandbox-images.lock`; an
    analyzer missing from either is unavailable; the catalog starts empty.
  - `artifacts.py`: `{root}/{uuid}` only if it is a real directory, not a symlink, directly
    inside the root.
  - `container.py`: the one place the ADR 0016 create body is spelled out; every body is checked
    against the real proxy policy in tests.
  - `stream.py`: demultiplexes Docker's attach frames, keeps stdout, drops stderr, caps stdout at
    2 MiB on the declared frame size, fails closed on a cut-off or unknown frame.
  - The package imports nothing from the app or `sandbox_proxy`; the constants it copies
    (ceilings, digest pattern, create-body values, `MAX_STDOUT_BYTES`) are held equal by unit
    tests.
- [ ] `docs/architecture.md` `analysis` queue row (`:220`) says the proxy and the launcher's
      building blocks are implemented, and the launcher service and the worker are not.
- [ ] `docs/security.md` "Parser exploit in an analysis tool" row adds the declared-size cap check
      and the fail-closed rule; the existing facts in the row are unchanged.
- [ ] `CHANGELOG.md` `[Unreleased]` / `### Added` has one entry for the launcher building blocks
      with `(#84)`, written for a user of the project (what the launcher can and cannot do yet),
      not as a file list.
- [ ] `STATE.md` is the whole file rewritten from the `finish-task` template: date `2026-11-12`,
      branch `84-sandbox-launcher-core`, issue #84, present tense, at most about 40 lines, no
      history.
- [ ] Wording matches the code: every function, class and constant name in the docs exists in the
      repo (checked by grep, see Verification).
- [ ] No change to any file under `src/`, `tests/`, `.github/`, `.claude/`, `compose*.yaml`,
      `.env.example`, `pyproject.toml` or `docs/adr/`.

## Acceptance criteria
- [ ] **Accuracy:** each module fact in `docs/architecture.md` can be tied to a line in the code
      or a test (2 MiB, 840 s, "not a symlink", "empty catalog", "stderr dropped"). Nothing is
      claimed that a later commit (3c, 3d) will add.
- [ ] **No stale claims:** the phrases "not built yet" and "launcher and worker are not yet" no
      longer appear in `docs/architecture.md`, and nothing in the docs says the launcher runs.
- [ ] **Sync complete:** the `finish-task` table was walked, and the final report lists the files
      updated and, for each skipped doc (`development.md`, `README.md`, `DESIGN.md`, ADRs,
      skills), a one-line reason.
- [ ] **STATE.md is usable cold:** the next step names a concrete command or action, and the
      notes cover the three cross-PR constraints (runner flags before stream error, 3 MiB reply
      cap, `FakeDocker` frame scripting).
- [ ] **Hooks:** `uv run pre-commit run --all-files` passes (whitespace, end-of-file, gitleaks);
      the commit is made without `--no-verify`.
- [ ] **Gate:** `ruff check`, `ruff format --check`, `pyright`, `lint-imports` and full `pytest`
      still pass with coverage >= 80% (unchanged, since only Markdown moves).
- [ ] **PR size:** `git diff main...HEAD --stat` for PR 3b stays at about 400 changed lines or
      fewer, excluding tests and fixtures (the split plan estimates ~230 for the source).

## Changes

### 1. `AGENTS.md` (+1 line)
Add the `sandbox_launcher/` layout line beneath `sandbox_proxy/` (Requirements has the text).
Keep the column alignment; keep the line within the file's width.

### 2. `docs/architecture.md` (~+14 lines, 2 lines edited)
- Edit the analysis-path lead-in at `:25`: keep "ADR 0016" and the no-network, no-credentials
  clause; replace "not built yet" with "the proxy and the launcher's building blocks exist; the
  launcher service and the worker do not".
- Add the "Sandbox launcher building blocks" subsection directly below the diagram, as a short
  list, one bullet per module (Requirements has the facts). End with one sentence on the
  copy-and-parity-test rule and one on what 3c adds (`runner.py`, `server.py`, `__main__.py`).
- Edit the `analysis` row at `:220` to match.

### 3. `docs/security.md` (1 row edited)
Extend the "Parser exploit in an analysis tool" row: "output is JSON on stdout, capped at 2 MiB
(checked on each frame's declared size before the payload is read) and validated as `ScanOutput`
before use; a cut-off or unknown frame fails the run; stderr is discarded (it can echo found
secrets)".

### 4. `CHANGELOG.md` (+4 lines)
New first bullet under `### Added`, for example: "Sandbox launcher building blocks: settings, an
analyzer catalog (empty until the first analyzer), an artifact resolver that refuses symlinks and
paths outside the artifact root, a create-body builder checked against the proxy policy, and a
stdout reader that drops stderr, caps output at 2 MiB and rejects truncated streams. The launcher
service itself is not yet built (#84)."

### 5. `STATE.md` (whole file replaced, ~35 lines)
Follows the `finish-task` template:
- **Status:** PR 3b (launcher building blocks) is complete on `84-sandbox-launcher-core`: five
  commits, all gates green, not pushed, no PR open.
- **Last task:** the five commits in one line each (settings; catalog and resolver; create-body
  builder; capped stdout reader; docs). No history beyond that.
- **Next step:** run `pre-pr-check`, check the PR 3b diff size, push the branch and open a draft
  PR titled `feat(infra): add sandbox launcher building blocks` with
  `Merge order: 3b of #84. Merge after #<3a PR>, before #<3c PR>. See #84.`
  Then 3c (`runner.py`) once 3a and 3b are merged.
- **Open threads:** 3a (`84-sandbox-runtime-info`) is independent and may not have started; the
  issue #84 merge-order checklist still needs the 3a to 3d rewrite the split plan describes
  (shown to the user first, `gh issue edit` only after approval); `docs/plans/` is untracked.
- **Notes for the next agent:** the three constraints in "Notes for later commits" below, plus:
  the launcher copies proxy constants and `domain.scanners.MAX_OUTPUT_BYTES` on purpose, with a
  parity test for each; do not "fix" that by importing them.

## Order of work
Docs only, so there is no red phase. The checks below take the place of it.
1. Re-read each module's docstring (`catalog.py`, `artifacts.py`, `container.py`, `stream.py`) and
   `SandboxLauncherSettings` in `config.py`, and list the facts to state. Write only facts
   found there.
2. Edit `AGENTS.md`, `docs/architecture.md`, `docs/security.md` and `CHANGELOG.md`.
3. Run the stale-claims and name checks (Verification).
4. Run the `finish-task` steps: walk its table, then overwrite `STATE.md`.
5. Full gate (unchanged code, so this is a safety net):
   ```bash
   uv run ruff check . && uv run ruff format --check . && uv run pyright \
     && uv run lint-imports && uv run pytest
   ```
6. Run `pre-pr-check` for the whole of PR 3b (all five commits) before the PR opens.
7. Commit on `84-sandbox-launcher-core` with subject
   `docs(infra): document the launcher building blocks`, a body explaining *why* (the code
   commits deferred their docs so each stayed reviewable, and the docs described a launcher as
   unbuilt), footer `Refs #84`, and the Co-Authored-By trailer. Never `--no-verify`.

## Reused code
- `.claude/skills/finish-task/SKILL.md`: the table of what to update and the `STATE.md` template.
- `docs/plans/plan-template.md`: this plan's structure.
- Existing doc wording to match: the `sandbox-proxy` bullet in `CHANGELOG.md`, the analysis-path
  diagram in `docs/architecture.md`, and the sandbox rows in `docs/security.md`.
- Module docstrings in `src/attacksurf/sandbox_launcher/` (source of the facts; not edited).
- No code is reused or changed.

## Verification
- Names exist: for each identifier written into the docs (`SandboxLauncherSettings`,
  `load_catalog`, `resolve_artifact`, `build_create_body`, `read_stdout`, `MAX_STDOUT_BYTES`),
  `grep -rn <name> src/attacksurf/` finds it.
- Numbers match the code: `grep -n "840\|2 \* 1024" src/attacksurf/config.py
  src/attacksurf/sandbox_launcher/stream.py`.
- Stale text is gone: `grep -n "not built yet\|launcher and worker are not" docs/architecture.md`
  returns nothing.
- `git diff --stat` shows only `AGENTS.md`, `docs/architecture.md`, `docs/security.md`,
  `CHANGELOG.md` and `STATE.md`.
- `uv run pre-commit run --all-files` passes, then the full gate above.
- Read `STATE.md` once as a new agent: can the next step start with no other context?
- No manual smoke: nothing runs.

## Notes for later commits
- **PR 3b is done after this commit.** Open it as a draft, run `pre-pr-check` and check the
  diff-size limit.
- **PR 3c, `runner.py`:** strips the HTTP head from the proxy's attach reply and calls
  `read_stdout`. It must decide the outcome from its own flags (`timed_out`, cap tripped) before
  the stream error, because a kill mid-frame reaches it as `MalformedStream`. `FakeDocker` moves
  to `tests/docker_fakes.py` and must be able to script frames split across writes.
- **PR 3c docs commit:** owns `docs/development.md`, the launcher section of `docs/security.md`,
  and flips `*(later)*` on the launcher service.
- **PR 3d, worker client:** its ~3 MiB reply cap assumes stdout is at most 2 MiB (base64 about
  2.67 MiB); changing `MAX_STDOUT_BYTES` means changing that cap and the parity test.
- **Tenant safety:** the worker, not the launcher, must confirm an artifact belongs to the org
  before calling it; the 3d docs commit records this.
