---
name: pre-pr-check
description: Full verification and adversarial self-review before committing or opening a PR. Use before saying a task is done, before committing, or before opening a pull request.
---

# Pre-PR check

## 1. Automated checks (all must pass, run them, don't assume)
```bash
uv run pre-commit run --all-files   # ruff format/check, hygiene, gitleaks
uv run pyright
uv run pytest                       # fails if coverage < 80%
```
After pushing, confirm the CI run for the PR is green (`lint`, `test (3.12)`, `test (3.13)`,
`secrets`, `pr-title`); a red CI means not done.
If a migration changed: `uv run alembic upgrade head && uv run alembic downgrade -1 && uv run alembic upgrade head`.

## 2. Self-review the diff (`git diff main...`)
Answer each; fix anything that fails:

**Correctness**
- [ ] Every acceptance criterion in the issue has a test that proves it.
- [ ] Error paths tested (timeouts, bad input, provider failure).

**Architecture**
- [ ] `domain/` has no Flask/SQLAlchemy/SDK imports.
- [ ] Routes and Celery tasks are thin; logic is in `services/`.
- [ ] No scan or LLM call happens inside a web request.

**Security**
- [ ] Every query on tenant data is scoped by `org_id`; new endpoints have isolation tests.
- [ ] Outbound requests go through ScopeGuard / safe client; active checks require verification.
- [ ] Scan-derived content is escaped in templates (no `|safe`) and delimited in prompts.
- [ ] No secrets in code, logs, error messages, fixtures, or test output.
- [ ] Forms/HTMX POSTs carry CSRF tokens.

**Conventions** (`docs/conventions.md`)
- [ ] Commits are Conventional Commits (`<type>(<scope>): <subject>`, ≤ 72 chars, why in body).
- [ ] PR title is the squash-commit subject; every PR template section filled; `Closes #N`.
- [ ] Diff is one concern and ≤ ~400 lines excl. tests/fixtures/lockfile (or split it).

**Hygiene**
- [ ] No debug prints, commented-out code, or TODOs without an issue number.
- [ ] New dependencies are justified, maintained, and added via `uv add`.
- [ ] Docs/ADRs updated if behavior or architecture changed.

## 3. Report
Summarize what was checked and the results (including coverage %). If anything was skipped,
say so explicitly.
