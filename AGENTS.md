# AGENTS.md

Instructions for AI coding agents (Claude Code, Codex, Cursor, Copilot, etc.) working on this repo.
Humans: read `docs/` first; this file is the condensed rulebook.

## Project

**attacksurf**: AI-powered attack surface management (ASM) web app. Users register assets
(domains first; later IPs, websites, codebases, binaries), scanners find issues, an LLM triages
them. Defensive tool: it must never become an attack tool.

- **Start every session by reading `STATE.md`**: it says where work stopped and what's next.
- Roadmap: GitHub epic issue #31. Each issue lists its dependencies; respect the order.
- UI work follows `DESIGN.md` (design system: tokens, components, patterns).
- Architecture: `docs/architecture.md`. Decisions: `docs/adr/`. Read the relevant ADR before
  changing anything it covers. Changing a decision means writing a new ADR.

## Stack

Python 3.12+ · uv · Flask (app factory, blueprints) · Jinja + HTMX + Alpine.js · SQLAlchemy 2.0 +
Alembic · PostgreSQL · Celery + Redis · pydantic / pydantic-settings · Anthropic + OpenAI-compatible
LLM providers (official SDKs, no LiteLLM) · Docker Compose on a single VPS.

## Layout

```
src/attacksurf/   application code (src layout, import name `attacksurf`)
  app.py          create_app() factory (re-exported from attacksurf/__init__.py)
  config.py       Settings (pydantic-settings) + get_settings(); the only place env is read
  web/            Flask blueprints: ui (HTMX pages) + api/v1 (JSON); templates/, static/
  services/       use cases: one verb function per action (register_user, start_scan, ...)
  domain/         entities, enums, value objects, events. NO Flask/SQLAlchemy/SDK imports
  scanners/       scanner plugins grouped by target type (dns/, ip/, web/, code/, binary/)
  ai/             providers/, prompts/ (versioned templates), triage, summaries
  infra/          logging (structlog + request IDs), db, queue (Celery), storage, scope_guard,
                  http client, crypto
  workers/        Celery task entrypoints (thin, call services)
tests/            pytest; mirrors src/attacksurf/ structure (unit/, integration/, e2e/)
docs/             architecture, ADRs, development, security, conventions
```

All layer packages exist; add modules inside them as issues need them. Layer rules are
machine-checked by import-linter (contracts in `pyproject.toml`, run `uv run lint-imports`, also a
pre-commit hook and in CI).

## Commands

```bash
uv sync                                  # install (never pip install)
cp .env.example .env                     # local config (all settings: src/attacksurf/config.py)
make up / make down / make test          # Docker Compose dev stack (web, postgres, redis); `make` lists all
make migrate                             # alembic upgrade head (in compose); new migration: make revision id=0002 m="..."
uv add <pkg> / uv add --dev <pkg>        # add deps (never edit lockfile by hand)
uv run flask --app attacksurf run --debug
uv run pytest                            # tests + coverage (fails under 80%)
uv run ruff check --fix . && uv run ruff format .
uv run pyright
uv run pre-commit install                # once: git hooks (pre-commit, commit-msg, pre-push)
uv run pre-commit run --all-files        # all hooks: ruff, import-linter, hygiene, gitleaks
uv run lint-imports                      # layer rules only
```

Git hooks run ruff + gitleaks on commit, check the commit message, and run pyright + pytest on
push. CI (`.github/workflows/ci.yml`) runs the same checks plus a compose smoke test and the
PR-title check. New service or env var? Update `compose.yaml` and `.env.example` too.
**Never bypass hooks (`--no-verify`) or weaken CI to get green**: fix the cause.

**Definition of done for any change:** ruff check, ruff format, pyright and pytest all pass
locally, coverage ≥ 80% overall, new code has its own tests, **and the "Keep the project in
sync" rule below is satisfied**. Do not claim done without running them.

## Architecture rules (enforced in review)

1. **Layers point inward:** `web`/`workers` → `services` → `domain`. `infra` and `scanners`
   implement interfaces the services use. `domain` imports nothing from the other layers.
2. **Thin routes, thin tasks:** routes and Celery tasks parse input, call one service, render or
   return. Business logic lives in `services/`.
3. **Never run scans or LLM calls inside a web request.** Enqueue a Celery task, return a job ID,
   poll with HTMX.
4. **Every tenant-owned row has `org_id`** (model inherits `TenantScoped`), and every query is
   scoped by it via `infra/db/tenancy` (`scoped()`, `get_scoped()`). No cross-org reads, ever.
   Each new endpoint gets a tenant-isolation test.
5. **Scanners are plugins** (`@register_scanner`) that return normalized pydantic output. They
   never write to the DB directly; the pipeline persists.
6. **All outbound network traffic from scanners goes through `infra/scope_guard` + the safe HTTP
   client.** No raw `requests`/`httpx`/sockets in scanners. Active (non-passive) checks require
   verified ownership.
7. **LLMs judge, scanners detect.** AI never invents findings, never auto-closes them, and only
   sees normalized findings. All LLM output is schema-validated (pydantic).
8. **Scan-derived content is untrusted:** escape in templates (never `|safe` on it), and wrap it as
   delimited data in prompts (prompt-injection defense).

## Code conventions

- Full type hints; pyright clean. Prefer `dataclass`/pydantic models over dicts across boundaries.
- Small, pure functions; explicit over clever. No speculative abstractions: build what the
  current issue needs.
- Names: services are verbs (`start_scan`), rule IDs are dotted (`dns.email.dmarc_missing`).
- Config only via `Settings` (`attacksurf.config`), never `os.environ`. New setting = field +
  `.env.example` entry + test. Secrets (incl. URLs that can embed passwords) are `SecretStr`;
  call `.get_secret_value()` only where the value is used (e.g. opening a connection).
- `attacksurf/__init__.py` re-exports `create_app` lazily; keep it that way so importing an inner
  layer never loads Flask (a test enforces it).
- Logging via structlog with context (org_id, scan_id, job_id). Never log secrets, tokens,
  API keys, or full scan evidence.
- Errors: raise domain-specific exceptions in services; map them to HTTP responses in `web/`.
- Services: verb functions taking a `Session` (plus adapters via `domain` protocols); they
  commit once per use case and record security-relevant actions with `services.audit.audit()`
  in the same transaction. See `services/accounts.py`.
- Comments explain *why*, not *what*. No commented-out code.
- DB schema changes only through Alembic migrations (see `.claude/skills/db-migration`).

## Testing

- pytest, Arrange/Act/Assert, one behavior per test, descriptive names (`test_<unit>_<behavior>`).
- Build settings with `tests.helpers.make_settings(...)`: it ignores `.env` **and** OS env, so
  tests are hermetic. Tests of env loading use `settings_from_env()` with the `clean_env`
  fixture. Use the `app` / `client` fixtures from `tests/conftest.py`.
- DB tests go in `tests/integration/` and use `db_session` (rolled back per test); they need
  `TEST_DATABASE_URL` (a `*_test` database; `make test` sets it). Real Postgres, never SQLite.
- **No live network in tests.** Mock DNS/HTTP/LLM with fixtures (recorded responses in
  `tests/fixtures/`). LLM tests use a fake provider.
- Coverage gate: 80% minimum (configured in `pyproject.toml`). Don't game it: test behavior,
  including error paths and security checks.
- Bug fix ⇒ regression test first.

## Security (non-negotiable)

- No exploitation, brute forcing, DoS, or scanning of unverified targets for active checks.
- Block private/link-local/metadata IP ranges for any outbound request (SSRF).
- Secrets: env vars or encrypted in DB (org API keys). Never commit `.env`, keys, or tokens.
  Never print them in logs, errors, or UI.
- Uploaded codebases/binaries (future) are never executed; analysis runs sandboxed.
- New dependency? Check it's maintained and widely used; prefer stdlib. Pin via `uv.lock`.
- See `docs/security.md`.

## License

AGPL-3.0-or-later. Keep the "Source code" link in the UI footer (AGPL §13). Only add
dependencies with AGPL-compatible licenses (MIT, BSD, Apache-2.0, LGPL, GPL-3.0, AGPL-3.0);
never copy code from incompatible or unlicensed sources.

## Keep the project in sync (after every task)

The codebase changes fast; stale instructions mislead the next agent. At the end of **every**
task (feature, fix, refactor, docs, config) run the `finish-task` procedure
(`.claude/skills/finish-task/SKILL.md`, `/finish-task` in Claude Code). In short:

1. **Tests**: new/changed behavior is tested; obsolete tests removed.
2. **Docs**: update whatever the change made stale: `docs/` (architecture, development,
   security), ADRs for decisions, `DESIGN.md` for UI patterns/tokens, `README.md` for
   user-visible features, `CHANGELOG.md` (`[Unreleased]`).
3. **Agent instructions**: if you introduced a new convention, command, layer, or recurring
   workflow, or found a rule here to be wrong or outdated, update `AGENTS.md`, `CLAUDE.md`, or
   the relevant skill. Keep them short: edit and replace, don't just append.
4. **`STATE.md`**: overwrite it with the current handoff (what was done, current status,
   exact next step). It holds the present state only, never history.

If nothing needed updating, say so explicitly in your final report.

## Issues, commits, PRs

Full rules and examples: `docs/conventions.md`. Essentials:

- **Issues**: imperative title; body = Goal / Tasks / Acceptance criteria / (Out of scope) /
  `Depends on #N` / `Part of #epic`; one type label + ≥1 `area:*` label from
  `.github/labels.yml`; one PR's worth of work. Use the `create-issue` skill.
- **Commits**: Conventional Commits, `<type>(<scope>): <subject>`, imperative, ≤ 72 chars.
  Types: `feat fix perf refactor test docs build ci chore security revert`. Scopes: `dns scanners
  ai web api ui db workers auth infra security deps agents`. Body explains *why*; footer
  `Refs #N` / `Closes #N`; breaking → `!` + `BREAKING CHANGE:`. One logical change per commit.
- **PRs**: one issue per PR; title = Conventional Commit subject (PRs are squash-merged);
  branch `<issue#>-<slug>`; ≤ ~400 changed lines excl. tests/fixtures/lockfile; fill every
  section of the PR template; draft until checks pass.
- Never commit to `main` directly once branch protection is on. Never force-push shared branches.

## When unsure

Check the issue, `docs/`, and existing code patterns first. Use Context7 for current library docs
instead of relying on memory (Flask, SQLAlchemy 2.0, Celery, HTMX, pydantic APIs change).
If a requirement is ambiguous or conflicts with these rules, stop and ask rather than guessing.
