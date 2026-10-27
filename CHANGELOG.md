# Changelog

All notable changes to this project are documented here.
Format: [Keep a Changelog](https://keepachangelog.com/en/1.1.0/); versioning: [SemVer](https://semver.org/).

## [Unreleased]

### Fixed
- Run database migrations as part of dev `make up`, before starting application services,
  preventing signup from returning HTTP 500 on a fresh database.
- Document the Docker socket permission fix for Linux sessions with stale group membership,
  including safe setup steps and the security implications of Docker access.
- Auth hardening from review: atomic first-user signup, login password length bound, login
  gate before CSRF (anonymous writes get 401/redirect), logout clears the session even if the
  audit write fails, absolute session lifetime enforced server-side
- Review follow-ups on the ScopeGuard PR: the run-scoped HTTP client now enforces the grant
  policy before its first request (not only on redirects) and applies the body-size ceiling
  whatever limit a plugin passes; the discovered-asset cap counts against the scan root so a
  check on a discovered subdomain cannot claim a fresh allowance; a `ScopePolicyError` from the
  gate fails only its job instead of the whole scan (ADR 0013).

### Added
- ScopeGuard and the scanner network boundary (ADR 0013): target validation against the bundled
  Public Suffix List (no internal names, single labels or IP literals), public-only resolved
  addresses (private, loopback, link-local/metadata, CGNAT, reserved, IPv6 equivalents), a frozen
  `ScannerGrant` per plugin enforced on every DNS lookup and HTTP request, an ownership check
  that keeps active checks denied until verification (#14), and a pinned HTTP client that
  applies the allowlist before the first request and at every redirect, ignores env proxies and
  caps time and body size. Scan profiles can cap discovered assets per root.
- Scanner plugin framework and scan pipeline (ADR 0011): validated `ScanOutput`, explicit
  registry/profiles, tenant-scoped start/finalize services, Celery discovery/check chords and
  continuation chain, atomic fingerprint/evidence persistence, bounded scanner budgets and
  isolated errors, and post-commit domain events. Diff/AI stages are seams for #20/#25.
  No network-enabled checks yet.
- Celery workers (ADR 0003): `passive` / `ai` queues routed by task-name prefix, `TrackedTask`
  base recording each task's lifecycle on its `Job` (attempts, retries with backoff for
  `TransientJobError`, time limits, redelivery-safe), `services.jobs.create_job` (commit, then
  enqueue), compose `worker-passive`, `worker-ai`, `beat`, and a real-worker check in CI
  (`make test-worker`)
- Scan results model (migration `0004`): `scans` and `jobs` (status, trigger, timings,
  stats), `findings` unique by `(org_id, fingerprint)` with severity, confidence, status
  lifecycle and AI triage slot, and `evidence`; stable versioned finding fingerprints and an
  in-code rule catalog (`domain.rules`)
- Asset model: `assets` (domain, subdomain, IP, URL; repo/binary reserved) with per-type value
  normalization (IDNA2008 punycode, canonical IPs, credential-free http(s) URLs with
  RFC 3986/3987 normalization) and `asset_relations` graph (migration `0003`); same-org links
  enforced by composite foreign keys; atomic upserts that update `last_seen` instead of
  duplicating; `deactivated_at` so delayed results can't reactivate an asset; user-added
  assets are roots, so deleting a parent only removes what was discovered under it
- Authentication: signup, login, logout (Flask-Login), login required everywhere by default,
  `@require_role`, CSRF on all POSTs incl. HTMX, rate-limited login/signup (Flask-Limiter),
  hardened session cookies, audit of login/logout/failed logins; settings `ALLOW_SIGNUP`,
  `SESSION_LIFETIME_HOURS`, `PROXY_COUNT`
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
  `compose.yaml` dev stack (web, PostgreSQL, Redis, worker/beat placeholders), `Makefile`,
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
