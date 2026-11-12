# Changelog

All notable changes to this project are documented here.
Format: [Keep a Changelog](https://keepachangelog.com/en/1.1.0/); versioning: [SemVer](https://semver.org/).

## [Unreleased]

### Added
- Sandbox launcher building blocks: env-only settings, an analyzer catalog (empty until the first
  analyzer ships), an artifact resolver that refuses symlinks and anything outside the artifact
  root, a create-body builder checked against the proxy's policy, and a stdout reader that drops
  stderr, caps output at 2 MiB and rejects truncated streams. The launcher service that runs
  them is not built yet (#84).
- Subdomain discovery from Certificate Transparency: `dns.discovery.ct` queries crt.sh's JSON
  endpoint with Cert Spotter as fallback, normalizes and caps names per root (1000), caches
  complete results in a namespaced Redis cache for six hours, and detects wildcard DNS zones.
  Wildcard zones are persisted as `Asset.details["wildcard"] = true` for later resolution, and
  all network access stays behind ScopeGuard (ADR 0022, #15).
- `sandbox-proxy` service: the only holder of the Docker socket, allowing six container actions
  on containers it created and refusing any create request outside the sandbox policy (#84).
- CD is verified end-to-end: a merge to `main` reaches production within one timer
  interval, and the running `web` image tag matches the recorded deployed SHA (#29).
- Pull-based CD: `scripts/deploy.sh` (also `make deploy`) fetches `origin/main`, builds the
  images tagged with the short SHA, runs `migrate` before replacing `web`, smoke-tests
  `/healthz` through the ingress and rolls back to the previously deployed SHA on failure; the
  deployed SHA is recorded in `/var/lib/attacksurf/deployed-sha` (#138).
- Pull-based CD units (`deploy/systemd/`): `attacksurf-deploy.timer` runs `scripts/deploy.sh`
  every 3 minutes (±45 s jitter) as root under a `flock`, so a merge to `main` reaches
  production within one interval with no inbound port, no GitHub secret and no runner; the
  deployed SHA lands in the journal and in `/var/lib/attacksurf/deployed-sha` (#29).
- Sandbox port for scanners: `ctx.runtime.sandbox.run(analyzer, artifact_id)`, limited to the
  analyzers in a plugin's `ScannerGrant` and refused until a runner is configured (#84).
- Production stack (`compose.prod.yaml`) published through a Cloudflare Tunnel: `cloudflared`,
  Caddy, gunicorn, PostgreSQL and Redis on a private network with no inbound ports, `www`
  redirecting to the apex, and a deploy runbook in `docs/deployment.md` (ADR 0020, #132).

### Fixed
- The content area fills the main column on every viewport instead of stopping at a 72rem cap,
  so wide screens no longer leave empty space to the right of the dashboard (#149).
- Pyright and pytest pass on Windows again: pyright checks as Linux (where the app runs), and
  the sandbox proxy server tests, which need Unix sockets, skip on Windows (#84).
- The archived-roots due-verification test recorded its check at the real time instead of the
  test clock, so it passed without testing the archive filter (#14).
- Archiving a root domain now cancels its queued and running scans in the same transaction, and
  they show as `cancelled` in the scan history. Nothing under an archived root becomes active or
  produces a new finding afterwards, whatever stage the scan was in: persistence drops output for
  a cancelled scan or an archived root (ADR 0021, #116).
- The app shell fits a phone viewport: the top bar wraps and truncates the user menu (full text
  in `title`) and the mobile nav row scrolls inside itself instead of widening the page (#114).
- The `playwright` dev dependency is pinned to 1.64.1 (`>=1.64.1,<1.65`), the newest release
  that satisfies the two-week dependency-age policy, instead of the day-old 1.65.0 (#114).
- Deploying into a checkout owned by another user (the pre-CD copied tree, or a clone made by a
  person while the timer runs as root) no longer fails with git's "dubious ownership" error:
  `scripts/deploy.sh` trusts its own `APP_DIR` for its git calls (#29).
- Sandbox proxy retains ownership after rejected removals, reclaims capacity after confirmed
  automatic removal, and reserves in-flight create capacity atomically, so concurrent requests
  cannot exceed its container cap (#84, PR #135).
- Unknown Docker-create outcomes retain their reserved slot and receive a proxy-generated
  name for forced cleanup; failed cleanup (including 404 while creation may still be running)
  never frees capacity. Subsequent create requests retry reconciliation (#84, PR #135).
- Legacy Docker API prefixes below v1.30 are denied so clients cannot disable AutoRemove or
  downgrade removed-wait semantics and bypass the container cap (#84, PR #135).
- Proxy settings tests clear all application and proxy environment fields, including the
  documented dev runtime fallback, before constructing settings (#84, PR #135).
- Proxy environment settings and defaults are documented in `.env.example` (#84).
- Login and signup rate limits key on the visitor address Cloudflare forwards
  (`CF-Connecting-IP`, else the leftmost `X-Forwarded-For` entry) instead of the first proxy
  hop, so visitors behind the tunnel no longer share one budget (#132).
- LLM endpoint credentials are masked in settings and provider-config representations;
  base URLs remain `SecretStr` through config resolution (#23).
- The test suite passes on Windows checkouts: `.gitattributes` keeps LF line endings whatever
  the local `core.autocrlf` setting (vendored files are never converted, so their SHA-256
  checks hold), the vendor tests read files as UTF-8, and the connection-failure test simulates
  a refused connection instead of dialing a closed port (Windows retries it until the timeout).
- Tests: hermetic worker settings are installed before pytest collection, so collecting a
  module-level Celery task can't load `.env` into the worker config and fail the suite on
  machines whose `REDIS_URL` differs from the default (#126).
- Ownership review fixes (#14): renew proofs four hours before authorization expires, keep
  inherited subdomain cards read-only across polling, and retry zone-discovery failures
  instead of treating them as missing proof records (migration 0007; ADR 0015).
- Flaky CSRF test: corrupting a token's last base64 character can keep the signature valid
  (padding bits), so the test now changes the first one (#119).
- Run database migrations as part of dev `make up`, before starting application services,
  preventing signup from returning HTTP 500 on a fresh database.
- Document the Docker socket permission fix for Linux sessions with stale group membership,
  including safe setup steps and the security implications of Docker access.
- Auth hardening from review: atomic first-user signup, login password length bound, login
  gate before CSRF (anonymous writes get 401/redirect), logout clears the session even if the
  audit write fails, absolute session lifetime enforced server-side
- Review follow-ups on the ScopeGuard PR: the run-scoped HTTP client now enforces the grant
  policy before its first request (not only on redirects) and applies the body-size ceiling to
  the decoded body whatever limit a plugin passes; a `TARGET` HTTP grant always requires
  verified ownership; the discovered-asset cap counts against the scan root under a row lock, so
  neither overlapping scans nor checks on discovered subdomains can exceed it; and a
  `ScopePolicyError` from the gate fails only its job instead of the whole scan (ADR 0013).
- Response decoding clamps every fallback to the requested limit (a corrupt or unknown
  `Content-Encoding` no longer returns the oversized wire buffer), decodes all concatenated
  gzip members — carrying unread bytes across members instead of dropping them — and reports a
  stream that ends before its final block as truncated instead of returning partial content
  silently.

### Changed
- The LLM contract has no `temperature` any more: Anthropic API version `2026-10-21` (sent by
  the `anthropic` 2.x SDK) rejects sampling parameters on every model, and nothing used it, so
  models run with their defaults (ADR 0019, #23).
- LLM SDK clients no longer retry (`ai/limits.MAX_RETRIES = 0`): Celery's task retry is the
  only retry layer, so errors don't multiply requests or park an `ai` worker in `Retry-After`
  sleeps (ADR 0019, #23).
- Dependencies: add the `anthropic` SDK (2.3.0, the newest release at least two weeks old;
  `jiter` and `opentelemetry-api` pinned back the same way). The scanner network-boundary test
  also bans its `httpx2`/`httpcore2` HTTP stack and the LLM SDKs (#23).
- `LLM_MODEL` no longer defaults to a Claude model in code: model names come only from config,
  and an instance without both `LLM_API_KEY` and `LLM_MODEL` has AI off (ADR 0019).
  Developers set the Meta development configuration in their own `.env` (see
  `docs/development.md`). `LLM_PROVIDER` is validated as a `ProviderKind`.
- Deleting a scan keeps its jobs (with `scan_id` NULL) instead of deleting them, so job history
  survives scan pruning and work outside a scan can be tracked.

### Added
- Anthropic provider (`ai/providers/anthropic.py`, #23): Messages API requests with native
  JSON-schema output, the system prompt split out, thinking blocks ignored, cached input
  tokens counted as input, SDK errors mapped to `LLMError`s without the response body, and the
  base URL always passed explicitly so `ANTHROPIC_BASE_URL` can't redirect a key. Replies cut
  off at the token limit, refused, or over the context window fail at once instead of paying
  for a corrective retry; an unreadable 2xx body is transient; a reply without usage is kept
  with usage marked unreported; failed calls log status, error type and request ID. A whole
  `complete()` call stops at `CALL_DEADLINE_SECONDS`, even against a server that trickles
  bytes, and the corrective retry gets only the time left. Passes the
  shared provider contract against a stubbed API, and an opt-in `llm_live` test against Meta's
  Anthropic-format endpoint (`tests/e2e/test_anthropic_live.py`). An import-linter contract keeps LLM SDK
  imports inside `ai/providers/`.
- LLM provider contract (#23, ADR 0019): `LLMProvider` protocol, result/usage types and
  `LLMError` subclasses in `domain/llm.py`; shared schema validation with one corrective retry
  (`ai/structured.py`); one HTTP-status error mapping (`ai/errors.py`); `resolve_llm_config`
  choosing the org's own key, else the capped instance key, else AI off (`ai/config.py`);
  shared SDK timeout/retry values and a total per-call deadline for adapters to enforce,
  sized to leave room under the Celery soft time limit (`ai/limits.py`); `FakeLLMProvider` and a contract test suite every provider adapter must
  pass; `llm_live` pytest marker for opt-in calls to a real provider, skipped unless
  `RUN_LLM_TESTS=1` and a key and model are set, and always in CI.
- ADR 0016: sandbox for code and binary analysis (per-job gVisor containers started by a
  credential-free launcher, no network, read-only input, resource limits) (#83).
- Ownership card on a domain's overview page (#14): shows the TXT record to publish with
  a copy button, its last check / verification / recheck times, and admin-only actions (start,
  verify now via HTMX, which queues a check without rotating the token, and rotate behind a
  confirm). The card polls itself while a check runs, so the outcome appears without a
  reload. Inventory shows a "Verified" badge on roots; `passive.verify_ownership` runs each
  check and an hourly beat entry re-queues due proofs.
- Ownership proof by DNS TXT (#14): `start_verification` issues (or rotates) a
  `_attacksurf-verify.<root>` token and queues a `passive.verify_ownership` job, an
  authoritative lookup records `verified`/`pending`/`revoked` with a day-long recheck window and
  a revoke grace, and `DbOwnershipChecker` makes ScopeGuard let active checks run only on a
  verified, unexpired root (subdomains inherit it). Roots added as subdomains are checked in
  their enclosing zone; failing nameservers are retried rather than read as a missing record.
  New `verifications` table (migrations 0005, 0006); `jobs.scan_id` is nullable so verification
  jobs no longer need a scan. See ADR 0014.
- Assets pages (#13): add a root domain from `/assets` (inline HTMX validation errors), browse
  assets with filters (type, root, tag, search, status) kept in the URL, and open an asset's
  detail page with its relations, findings and scan history tabs. Admins archive a root domain
  through a confirm dialog. New components: `confirm_dialog`, `select_field`, `relative_time`;
  `data_table` takes a call block for rich cells.
- ADR 0017: how repositories are fetched under ScopeGuard and how archives are extracted (#83).
- Root domains and asset browsing, service + JSON side (#13): `add_root_domain` validates names
  with the ScopeGuard rules (registrable or subdomain; no IPs, internal or bare-suffix names),
  `archive_root_domain` deactivates a root and everything discovered under it (admin only),
  both audited. `/api/v1/assets` lists assets (filters by type, root, tag, search, status;
  paginated; open-finding count and worst severity per asset) and serves detail with relations,
  findings and scan history.
- ADR 0018: the analysis tools, their licenses, and how their images are built and updated (#83).
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
