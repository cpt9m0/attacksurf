---
name: create-issue
description: Create or refine GitHub issues for attacksurf following the project's issue conventions (title, body format, labels, dependencies, epic linking). Use when asked to create, file, open, split, or plan issues/tasks/epics.
---

# Create an issue

Full rules: `docs/conventions.md` §1. Labels: `.github/labels.yml`.

1. **Check for duplicates**: search open and closed issues for the topic first.
2. **Size it**: one PR's worth (≤ ~400 changed lines excl. tests/fixtures/lockfile). Too big →
   split into several tasks and, if 3+, group them under an epic.
3. **Title**: imperative, specific, ≤ 80 chars, no trailing period (`Add DMARC policy check`).
   Epics: `[Epic] <outcome>`.
4. **Body** (the API bypasses issue forms, so write this structure yourself):
   ```markdown
   ## Goal
   ## Tasks
   - [ ] ...
   ## Acceptance criteria
   - ...
   ## Out of scope        (optional)

   Depends on #N          (omit if none)
   Part of #<epic>        (if applicable)
   ```
   Acceptance criteria must be observable and testable. Mention `DESIGN.md` for UI work and
   the relevant ADR/doc when the issue touches it.
5. **Labels**: exactly one type (`bug`/`enhancement`/`chore`/`docs`/`new-check`/`epic`), at
   least one `area:*`, plus `mvp`/`priority:*`/`blocked`/`needs-design`/`good first issue` as
   relevant. Only use labels from `.github/labels.yml`.
6. **Link**: add the new issue to its epic's checklist (edit the epic body) and update
   `Depends on` lines of affected issues.
7. **Order**: when creating a sequence, create dependencies first so you can reference real
   issue numbers.
8. End GitHub-posted text with the tool's attribution footer if the environment requires one.
9. Report the created issue links to the user.
