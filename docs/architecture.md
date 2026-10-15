# Architecture

Status: target design for the MVP. Parts are not built yet; see the roadmap epic (#31).

## Overview

attacksurf is a **modular monolith**: one Flask codebase, deployed as several processes
(web, Celery workers, beat) on one VPS with Docker Compose.

```
            ┌────────────── Caddy (TLS) ──────────────┐
            │                                          │
        ┌───▼────┐   enqueue   ┌────────┐   consume  ┌─▼──────────────┐
Browser ─► web    ├────────────►│ Redis  ├───────────►│ worker-passive │─► DNS / CT logs / RDAP
 (HTMX) │ Flask  │◄─ poll ─────┤ broker │            │ worker-ai      │─► LLM provider
        └───┬────┘             └────▲───┘            │ (worker-active,│
            │                       │ schedule       │  worker-       │
            │                  ┌────┴───┐            │  analysis:     │
            │                  │ beat   │            │  later)        │
            │                  └────────┘            └──────┬─────────┘
            │                                               │
            └──────────────────► PostgreSQL ◄───────────────┘
```

## Layers

```
web/ (blueprints: ui, api/v1)   workers/ (Celery tasks)
            │                        │
            └──────► services/ ◄─────┘        use cases, transactions, authz
                        │
                        ▼
                     domain/                  entities, enums, rules, events (pure Python)
                        ▲
    infra/ ─────────────┘ scanners/  ai/      adapters: DB, queue, HTTP, DNS, LLM
```

- `domain` depends on nothing. `services` orchestrate domain + adapters. `web` and `workers` are
  thin entry points.
- Pragmatism over purity: SQLAlchemy models live in `infra/db`; the Repository pattern is only
  added where it simplifies testing.
- **Enforced**: import-linter contracts in `pyproject.toml` fail the build if `domain` imports
  another layer (or Flask/SQLAlchemy/structlog), or if any inner layer imports `web`/`workers`.

## App, config, logging

- `create_app(settings=None)` (`app.py`) builds the Flask app from a `Settings` object and
  registers blueprints: `ui` (`/`), `health` (`/healthz`, liveness only), `api_v1` (`/api/v1`).
- `Settings` (`config.py`, pydantic-settings) reads env vars and `.env`. `ENV=prod` requires a
  `SECRET_KEY` of ≥ 32 characters that isn't a known placeholder; dev/test fall back to an
  ephemeral key with a warning. Secrets and connection URLs are `SecretStr`.
- Logging (`infra/logging.py`): structlog **and** stdlib logging (Flask, Werkzeug, libraries)
  share one pipeline: JSON in prod, console in dev/test; every line carries the request's
  `request_id` (from a valid `X-Request-ID` header or generated, echoed back in the response);
  keys that look like secrets are redacted.
- `import attacksurf.domain` (or any inner layer) never loads Flask: the package re-exports
  `create_app` lazily.

## Database

- SQLAlchemy 2.0 + Alembic, no Flask extensions (ADR 0008). Code in `infra/db/`: `base.py`
  (declarative `Base`, constraint naming convention, mixins), `models.py`, `session.py`
  (engine + session factory from `Settings`), `tenancy.py`, `migrations/`.
- Mixins: `UUIDPrimaryKey` (UUIDv7, `domain/ids.py`), `Timestamps` (`created_at`, `updated_at`,
  DB-side `now()`), `TenantScoped` (UUID key + `org_id` → `orgs.id`, NOT NULL, indexed,
  `ON DELETE CASCADE`).
- Tenant rows are read only via `scoped(Model, org_id)` (a `Select` with the org filter) or
  `get_scoped(session, Model, id, org_id)` (returns `None` for another org's row).
- Sessions: one per request in `web` (`web.db.get_session()`, closed at teardown); Celery
  tasks open `with runtime.session_factory()() as session:` (one factory per worker
  process). Services commit.
- import-linter: `web` (except `web/db.py`), `scanners`, `ai` never import SQLAlchemy/Alembic.
- Services are verb functions (`register_user(session, ...)`): they validate with pure `domain`
  rules, take adapters through `domain` protocols (e.g. `PasswordHasher`, implemented by
  `infra.crypto.Argon2PasswordHasher`), commit once, and raise domain exceptions
  (`InvalidSignup`, `EmailAlreadyRegistered`) that `web` maps to responses.

## Core model

| Entity | Purpose |
|---|---|
| `Org`, `User`, `Membership` | tenancy; every tenant row carries `org_id`. `User` is global (one login, many orgs); `Membership.role` is `owner`/`admin`/`member` (`domain.accounts.has_role`) |
| `Asset` | polymorphic target: `domain`, `subdomain`, `ip`, `url`, `repo`, `binary`; one row per `(org_id, type, value)` with `value` normalized by `domain.assets.normalize_asset_value` (hostnames lowercase punycode via `idna`, canonical IPs, `http(s)` URLs without credentials/fragment/default port; repo/binary not yet); `source` user/discovered, `parent_id` = asset a discovered one was found under (set once at first sighting, so no cycles; user-added assets are roots; deleting a parent cascades to its discovered children), `first_seen`/`last_seen`, `is_active` + `deactivated_at` (only sightings after it reactivate), `tags`, `details` |
| `AssetRelation` | graph edges: `subdomain_of`, `cname_to`, `resolves_to`, `serves`; unique per `(org_id, from, to, kind)`, no self-edges. `services.assets.record_asset` / `record_relation` upsert atomically (`INSERT … ON CONFLICT`): re-seen rows extend `last_seen`, never downgrade `source=user`, don't commit (the pipeline commits once), and raise `AssetNotFound` for a parent or endpoint that isn't the org's (locked `FOR KEY SHARE` so it can't vanish before the insert) |
| `Verification` | proof of ownership (DNS TXT); gates active checks |
| `Scan`, `Job` | one run of a profile (`dns_passive`, …) against a root asset (`queued/running/completed/failed/cancelled`, triggered by `user`/`schedule`, `stats`), and its jobs: a pipeline stage, or one scanner on one asset (`skipped` = not run, e.g. denied by ScopeGuard). Deleting the root asset deletes its scans and jobs; deleting another asset keeps the job with `asset_id` NULL |
| `Finding`, `Evidence` | normalized result, one row per issue across scans: unique `(org_id, fingerprint)`, with `fingerprint = domain.findings.finding_fingerprint(org_id, asset_id, rule_id, location)` (SHA-256 of a versioned JSON array; `location` tells apart several issues of one rule on one asset). `rule_id` points into the rule catalog (`domain.rules`: title, default severity, remediation template, references). Status `open → fixed / accepted_risk / false_positive` (`fixed_at` set exactly when `fixed`); regression detection in #20. Deleting a scan keeps its findings (scan references become NULL); evidence (`dns_record`/`http_response`/`raw`) goes with its finding |
| `OrgSettings`, `LLMUsage` | LLM provider config (encrypted keys) and token/cost tracking |
| `ScanSchedule`, `AuditLog` | continuous monitoring and an append-only audit trail (`services.audit.audit()`, written in the same transaction as the change) |

## Scan pipeline

```
discover ─► per-asset checks (parallel group) ─► persist/normalize ─► dedupe + diff ─► AI triage ─► AI summary ─► notify
```

- Implemented as a Celery `chain`/`chord`; each stage is idempotent and tracked as a `Job`.
- **Scanners are plugins** (`@register_scanner`) returning normalized pydantic `ScanOutput`.
  A scan **profile** (e.g. `dns_passive`) selects the scanners to run.
- A failing scanner fails only its job, not the scan.
- **ScopeGuard** runs before every scanner: it validates the target, blocks private/metadata IP
  ranges, and requires verified ownership for active checks. Scanners only reach the network
  through the guarded HTTP client / DNS resolver.

## AI layer

- `LLMProvider` protocol with `AnthropicProvider` and `OpenAICompatProvider` (configurable
  `base_url`). Official SDKs, no meta-library.
- Every call: versioned prompt, pydantic output schema, usage recorded, budget enforced, results
  cached by `(prompt_version, model, input hash)`.
- AI consumes **normalized findings only**; scan-derived text is treated as untrusted data.
- AI output is advisory: adjusted severity is shown next to the scanner's severity and never
  auto-closes findings.

## Queues

| Queue | Work | Isolation |
|---|---|---|
| `passive` | DNS, CT logs, RDAP, public APIs | normal egress |
| `ai` | LLM calls | rate-limited per org |
| `active` *(later)* | port/web probes on verified targets | separate network, egress rules |
| `analysis` *(later)* | code/binary analysis | gVisor, no network, read-only FS |

- `infra/queue.py`: `create_celery(settings)` (Redis broker + result backend from `REDIS_URL`,
  JSON only, `acks_late` + `reject_on_worker_lost`, prefetch 1, results ignored unless a
  chord needs them). A task's **name prefix is its queue** (`passive.ping` → `passive`);
  unknown prefixes are rejected, so nothing waits in a queue no worker reads.
- Enqueue through the `domain.jobs.TaskQueue` port (`infra.queue.CeleryTaskQueue`, sent by
  name; `web.queue.get_task_queue()` in web). `services.jobs.create_job` commits the `Job` row
  first, then enqueues; a broker error marks the job `failed`.
- Tasks (`workers/tasks/`, registered in `workers.app.TASK_MODULES`) use
  `base=workers.base.TrackedTask` and take `org_id` + `job_id` keyword arguments. It records
  the lifecycle on the `Job` (`queued → running → completed / failed`, back to `queued` on
  retry; `attempts`, `celery_task_id`, DB-clock timings, capped `error`), skips redelivered
  tasks of finished jobs, never overwrites a cancellation, binds `org_id`/`job_id`/`scan_id`
  to the log context, retries only `domain.jobs.TransientJobError` (exponential backoff with
  jitter, 3 retries) and has a 300 s soft time limit. Workers don't build a Flask app.
- Known gap: a hard time-limit kill (330 s) leaves the job `running`; a stale-job sweeper
  comes with scan cancellation (#21).

## Frontend

Server-rendered Jinja templates + HTMX for partial updates (polling for job progress) + Alpine.js
(CSP build) for small client-side state. A JSON API (`/api/v1`) shares the same services.

- `web/rendering.py`: `render_page()` returns a fragment for HTMX requests, the full shell otherwise.
- `web/security.py`: CSP and other security headers on every response; `web/errors.py`: HTML error
  pages, JSON errors under `/api/`, unexpected exceptions logged and shown as a 500 with the
  request ID.
- Styling and components follow `DESIGN.md` (plain CSS + tokens, Jinja macros).

## Authentication (ADR 0009)

- `web/auth.py`: Flask-Login + signed cookie sessions, `CSRFProtect`, Flask-Limiter, the login
  gate (default deny) and `@require_role(Role.X)`. Pages: `/login`, `/signup`, `POST /logout`.
- `services/auth.py`: `authenticate` (checks credentials, audits, rehashes), `record_logout`,
  `load_session_user` (per request: the user and the org they act in, as a `SessionUser`;
  MVP: their first membership), `has_users`.
- Templates get `current_user` (`email`, `org_name`, `role`); services get org IDs from it.

## Deployment

Single VPS: Caddy → gunicorn (web), Celery workers, beat, PostgreSQL, Redis, all in Docker Compose.
Nightly `pg_dump` off-box. See issue #29.

The `Dockerfile` has two targets: `dev` (dev deps, Flask debug server, source bind-mounted by
`compose.yaml` for hot reload) and `prod` (no dev deps, gunicorn, non-root uid 10001). Base and
service images are pinned by digest and updated by Dependabot. The dev `compose.yaml` runs `web`,
`postgres`, `redis`, the Celery workers `worker-passive` (`-Q passive -c 4`) and `worker-ai`
(`-Q ai -c 2`) with `inspect ping` healthchecks, and `beat` (broker-connection healthcheck; no
schedules until #27). Each queue has its own exchange and routing key.

## Decisions

See `docs/adr/` for the reasoning behind each choice above.
