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

## Core model

| Entity | Purpose |
|---|---|
| `Org`, `User`, `Membership` | tenancy; every tenant row carries `org_id` |
| `Asset` | polymorphic target: `domain`, `subdomain`, `ip`, `url`, `repo`, `binary` |
| `AssetRelation` | graph edges: `subdomain_of`, `cname_to`, `resolves_to`, `serves` |
| `Verification` | proof of ownership (DNS TXT); gates active checks |
| `Scan`, `Job` | one scan run, and its per-stage/per-scanner jobs |
| `Finding`, `Evidence` | normalized result, unique by `(org_id, fingerprint)`; lifecycle `open → fixed / accepted_risk / false_positive`, with regression detection |
| `OrgSettings`, `LLMUsage` | LLM provider config (encrypted keys) and token/cost tracking |
| `ScanSchedule`, `AuditLog` | continuous monitoring and an audit trail |

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

## Frontend

Server-rendered Jinja templates + HTMX for partial updates (polling for job progress) + Alpine.js
for small client-side state. A JSON API (`/api/v1`) shares the same services.

## Deployment

Single VPS: Caddy → gunicorn (web), Celery workers, beat, PostgreSQL, Redis, all in Docker Compose.
Nightly `pg_dump` off-box. See issue #29.

## Decisions

See `docs/adr/` for the reasoning behind each choice above.
