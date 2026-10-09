# Changelog

All notable changes to this project are documented here.
Format: [Keep a Changelog](https://keepachangelog.com/en/1.1.0/); versioning: [SemVer](https://semver.org/).

## [Unreleased]

### Added
- UI foundation: app shell (top bar, nav for Dashboard/Assets/Scans/Findings/Settings, light/dark
  theme toggle, AGPL source link), HTMX fragment rendering, Jinja component macros (button,
  severity badge, status pill, data table, pagination, empty state, flash), design tokens as CSS
  custom properties (placeholder values), vendored HTMX 2.0.11 + Alpine 3.17.4 (CSP build) with
  checksums, Lucide icons
- Security headers (strict CSP, frame/sniffing/referrer/permissions policies, HSTS in prod) and
  403/404/500 error pages (JSON under `/api/`)
- Accounts: `users`, `memberships` (roles owner/admin/member), `audit_log` tables and org
  `slug`/`plan` (migration `0002`); `register_user` service (user + personal org + owner
  membership + audit entry in one transaction); argon2id password hashing; `audit()` helper
- Database foundation: SQLAlchemy 2.0 base with constraint naming convention, UUIDv7 primary
  keys, `Timestamps` and `TenantScoped` (`org_id`) mixins, tenant-scoped query helpers,
  per-request sessions, Alembic migrations (`make migrate`, `make revision`), minimal `orgs`
  table; DB tests against PostgreSQL in CI and `make test`
- Docker: multi-stage `Dockerfile` (`dev` with hot reload, `prod` with gunicorn as non-root),
  `compose.yaml` dev stack (web, PostgreSQL 16, Redis 7, worker/beat placeholders), `Makefile`,
  CI `compose` smoke test
- Layered package layout (`web`, `services`, `domain`, `scanners`, `ai`, `infra`, `workers`) with
  import-linter contracts; app factory with `ui`, `health` (`/healthz`) and `api_v1` blueprints
- Typed settings (pydantic-settings, `.env.example`; prod requires a strong `SECRET_KEY`) and
  structured logging (structlog, incl. stdlib/library logs) with request IDs and secret redaction
- Project skeleton: Flask app factory, src layout, uv, ruff, pyright, pytest with 80% coverage gate
- Architecture docs, ADRs, security model
- AI-agent setup: AGENTS.md, CLAUDE.md, Claude Code skills, hooks, MCP servers
- Open-source community files: AGPL-3.0 license, contributing guide, code of conduct, security
  policy, issue/PR templates, funding
- `STATE.md` handoff file, `finish-task` skill + keep-in-sync rule, SessionStart/Stop hooks
- `DESIGN.md` web UI design system skeleton
- Issue/commit/PR conventions (`docs/conventions.md`), task and epic issue forms, label
  definitions, commit message template, `create-issue` skill
- Label sync workflow from `.github/labels.yml`
- Dependabot commit prefixes (`build(deps)`, `ci(deps)`); `pr-title` checks only the prefix on
  Dependabot PRs
- Git hooks via pre-commit (ruff, hygiene checks, gitleaks, Conventional Commits message check,
  pyright + pytest on push) and GitHub Actions CI (lint, tests on Python 3.12/3.13, PR-title check)
