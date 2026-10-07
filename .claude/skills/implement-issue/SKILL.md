---
name: implement-issue
description: End-to-end workflow for implementing a GitHub issue in attacksurf. Use when asked to work on, implement, start, or pick up an issue (e.g. "do #12", "implement the next issue").
---

# Implement a GitHub issue

## 1. Understand
- Read `STATE.md` first, then the issue in full **including comments**: tasks, acceptance
  criteria, and its "Depends on #N" line.
- Check every dependency is closed/merged. If not, stop and tell the user which ones block it.
- Read `AGENTS.md`, the relevant `docs/` pages and ADRs, and the existing code the issue touches.
- Look up current library APIs with Context7 instead of relying on memory.

## 2. Plan
- Write a short plan: files to add or change, new models/migrations, tests to write.
- If the issue is ambiguous, or conflicts with an ADR or `AGENTS.md`, ask before coding.
- Keep the scope to the issue. Note follow-ups instead of building them.

## 3. Branch
`git checkout -b <issue#>-<short-slug>` from an up-to-date `main` (unless the session assigns a branch).

## 4. Build test-first
- For each acceptance criterion: write a failing test, then implement until it passes.
- Respect the layers: routes/tasks thin, logic in `services/`, pure rules in `domain/`.
- Model change → use the `db-migration` skill. New check → `add-scanner`. New prompt → `llm-prompt`.

## 5. Verify
Run the `pre-pr-check` skill. Every check must pass, with coverage ≥ 80%.
For UI changes, run the app and check the page with the Playwright MCP.

## 6. Sync
Run the `finish-task` skill: tests, docs, `DESIGN.md`, `CHANGELOG.md`, agent instructions, and
overwrite `STATE.md` with the handoff.

## 7. Ship
- Conventional commits (`feat: ...`, `test: ...`).
- Push and open a PR titled like the issue, body: summary, checklist of acceptance criteria,
  how it was tested, `Closes #N`.
