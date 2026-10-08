# Conventions: issues, pull requests, commits

Rules for humans and AI agents. `AGENTS.md` has the short version; this is the full reference.

---

## 1. Issues

### Types and templates

| Type | Template | Use for |
|---|---|---|
| Task | `task.yml` | planned work with clear acceptance criteria (most roadmap items) |
| Bug | `bug_report.yml` | something broken |
| Feature | `feature_request.yml` | idea / user need, not yet planned |
| New check | `new_check.yml` | proposed security check |
| Epic | `epic.yml` | a group of tasks forming a milestone (e.g. #31) |

Blank issues are disabled. Agents creating issues via the API must follow the **Task body format**
below (the API skips forms).

### Title
- Imperative, specific, ≤ 80 chars, no trailing period: `Add DMARC policy check`, not
  `DMARC stuff` / `Bug!!!`.
- Bugs describe the symptom: `Scan stays "running" after worker restart`.
- Epics: `[Epic] <outcome>`.

### Task body format
```markdown
## Goal
One or two sentences: the outcome and why it matters.

## Tasks
- [ ] Concrete, checkable step
- [ ] ...

## Acceptance criteria
- Observable, testable result (each becomes at least one test)

## Out of scope
- What this issue deliberately doesn't do (optional)

Depends on #N, #M        <!-- omit if none -->
Part of #<epic>          <!-- if it belongs to an epic -->
```

### Sizing
- An issue should fit in **one PR** (roughly ≤ 1–2 days of human work, ≤ ~400 changed lines
  excluding tests/fixtures/lockfile). Bigger → split, and group under an epic.
- One concern per issue. Found something unrelated while working? Open a new issue.

### Labels (see `.github/labels.yml`)

`.github/labels.yml` is the source of truth; the `Sync labels` workflow applies it to GitHub on
every change to `main`. Add or change labels there, never only in the GitHub UI.
Every issue gets **one type** label, **at least one area**, and status labels as needed.

| Group | Labels |
|---|---|
| Type | `bug`, `enhancement`, `chore`, `docs`, `new-check`, `epic` |
| Area | `area:infra`, `area:data`, `area:auth`, `area:ui`, `area:workers`, `area:scanners`, `area:dns`, `area:ai`, `area:security` |
| Priority | `priority:high`, `priority:low` (default = normal, no label) |
| Status | `triage`, `blocked`, `needs-design`, `good first issue`, `help wanted` |
| Milestone / other | `mvp`, `funding` |

### Dependencies
- Write `Depends on #N` in the body. Don't start an issue whose dependencies are open.
- When a dependency closes, nothing to do. When scope changes, update the dependents' bodies.

---

## 2. Commits

### Format: [Conventional Commits](https://www.conventionalcommits.org/en/v1.0.0/)
```
<type>(<scope>): <subject>

<body: what and why, wrapped at 72>

<footer: Refs #N / Closes #N / BREAKING CHANGE: ... / trailers>
```

**Types**

| Type | When | In changelog |
|---|---|---|
| `feat` | new user-visible capability | Added |
| `fix` | bug fix | Fixed |
| `perf` | performance improvement | Changed |
| `refactor` | code change, no behavior change | n/a |
| `test` | tests only | n/a |
| `docs` | documentation only (incl. AGENTS.md, STATE.md, DESIGN.md) | n/a |
| `build` | dependencies, packaging, Docker | n/a |
| `ci` | GitHub Actions, CI config | n/a |
| `chore` | tooling, repo maintenance | n/a |
| `security` | security fix or hardening | Security |
| `revert` | reverts a commit | n/a |

**Scopes** (optional but encouraged; use the area): `dns`, `scanners`, `ai`, `web`, `api`, `ui`,
`db`, `workers`, `auth`, `infra`, `security`, `deps`, `agents` (AI-agent tooling).

### Rules
- Subject: imperative mood ("add", not "added"/"adds"), lowercase start, no period, **≤ 72
  chars** including type/scope.
- Body: explain **why** and any non-obvious **what**. Skip it for trivial commits.
- Footer: `Refs #N` for related issues; `Closes #N` only in the commit/PR that finishes it.
- Breaking changes: `!` after type/scope **and** a `BREAKING CHANGE:` footer.
- One logical change per commit; every commit should build and pass tests.
- Never commit secrets, `.env`, generated files, or commented-out code.
- AI-written commits keep the tool's attribution trailer (e.g. `Co-Authored-By:`). Never put a
  model identifier in the subject or body.

### Examples
```
feat(dns): add DMARC policy check

Flags domains with no DMARC record or p=none, since they can be
spoofed. Evidence includes the raw TXT record.

Refs #17
```
```
fix(workers): mark scan failed when a chord callback errors

Previously the scan stayed "running" forever if finalize raised.

Closes #57
```
```
refactor(db)!: rename Finding.state to Finding.status

BREAKING CHANGE: API field `state` is now `status`.
```

Use the template: `git config commit.template .gitmessage`.

---

## 3. Pull requests

### Rules
- **One issue per PR**; link it with `Closes #N` in the body.
- **Title = the squash-commit message subject** (Conventional Commits format), e.g.
  `feat(dns): add DMARC policy check (#17)`. PRs are **squash-merged**, so the title becomes
  the commit on `main`.
- Branch name: `<issue#>-<short-slug>`, e.g. `17-dmarc-check`.
- Keep it small: aim for ≤ ~400 changed lines excluding tests/fixtures/lockfile. Larger → split.
- Open as **draft** while in progress; mark ready only when the template checklist is done.
- Fill in every section of the PR template; delete nothing, write "n/a" where needed.
- UI changes include screenshots (light + dark theme).
- Breaking changes, migrations, new dependencies, and security-relevant changes are called out in
  their own section of the description.
- Don't mix refactors or formatting churn with feature work.

### Before requesting review
The `pre-pr-check` and `finish-task` skills pass (checks green, coverage ≥ 80%, docs and
`STATE.md` updated).

### Review and merge
- At least one approving review (a human for security-relevant or architectural changes).
- All CI checks green, all conversations resolved.
- Squash and merge; delete the branch.
- **Dependabot PRs**: `.github/dependabot.yml` sets the type prefix (`build(deps)` for Python,
  `ci(deps)` for Actions); `pr-title` only checks that prefix for them, since Dependabot writes
  "Bump …"/"Update …" subjects. When merging, retitle to a lowercase subject ≤ 72 chars
  (e.g. `build(deps): bump the python-deps group`).
- Reviewers: comment on code, not people; prefix optional suggestions with `nit:`.
