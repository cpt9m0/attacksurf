---
name: finish-task
description: End-of-task sync. Updates tests, docs, DESIGN.md, CHANGELOG, agent instructions (AGENTS.md, CLAUDE.md, skills) and overwrites STATE.md with a handoff. Use at the end of every task, before the final commit, or when asked to "wrap up", "hand off", or "update state".
---

# Finish task

Run this after the work itself is done and `pre-pr-check` passes, before the final commit.

## 1. Look at what changed
```bash
git status --short
git diff main...HEAD --stat     # or against the branch base
```
For each changed area, decide what else it made stale. Use the table below.

| You changed... | Then check / update... |
|---|---|
| behavior, new code | tests exist and pass; obsolete tests removed |
| models, pipeline, layers, queues | `docs/architecture.md` |
| setup, commands, tooling, env vars | `docs/development.md`, `README.md` quick start, `AGENTS.md` Commands |
| outbound traffic, auth, secrets, LLM payloads | `docs/security.md` |
| an architectural choice | new ADR in `docs/adr/` (copy `0000-template.md`) |
| templates, CSS, UI components, UX patterns | `DESIGN.md` |
| user-visible features | `README.md` Features, `CHANGELOG.md` `[Unreleased]` |
| a new convention / recurring workflow, or found a rule outdated | `AGENTS.md`, `CLAUDE.md`, or the relevant `.claude/skills/*` |
| scanner rules | rule list in `docs/` |

## 2. Update agent instructions carefully
- `AGENTS.md` is the shared rulebook (all agents). `CLAUDE.md` only holds Claude Code specifics.
- Edit in place: replace outdated lines rather than appending contradictions. Keep it concise:
  every line is loaded into every session.
- Only record things that are durable and non-obvious. Not task-specific notes (those go in
  `STATE.md`).

## 3. Overwrite `STATE.md`
Replace the **whole file** using the template below. Present tense, current state only, no history
(git log and closed issues are the history). Keep it under ~40 lines.

```markdown
# STATE

> Handoff for the next session. Overwritten at the end of every task; not a history log.

**Updated:** YYYY-MM-DD · **Branch:** `<branch>` · **Issue:** #N (title)

## Status
<one line: done / in progress / blocked>

## Last task
- What was done (2-5 bullets, link PR if any)

## Next step
<the single most important next action, concrete enough to start immediately,
e.g. "Implement #4: DB foundation; start with the TenantScoped mixin">

## Open threads
- Unfinished bits, known issues, decisions waiting on the user (or "none")

## Notes for the next agent
- Gotchas discovered, commands that matter, where to look first (or "none")
```

To pick the next step: the next unblocked, open issue in epic #31 (dependencies closed), unless
the current task is unfinished.

## 4. Report
In the final message, list which files were updated in this step, or state "no doc/agent updates
needed" with a one-line reason.
