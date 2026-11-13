# Architecture

Status: target design for the MVP. Parts are not built yet; see the roadmap epic (#31).

## Overview

attacksurf is a **modular monolith**: one Flask codebase, deployed as several processes
(web, Celery workers, beat) on one VPS with Docker Compose.

```
            ┌─ Cloudflare edge ─► cloudflared ─► Caddy ─┐   (ADR 0020)
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

Analysis path (ADR 0016; `sandbox-proxy` and the launcher's building blocks exist, the launcher
service and the analysis worker do not yet): only `sandbox-proxy` holds the Docker socket, and the
sandbox that reads the artifact has no network and no credentials.

```
worker-analysis ─ run(artifact ID, analyzer) ─► sandbox-launcher ─► sandbox-proxy ─► Docker
(DB/Redis creds,                                (no credentials)    (only socket holder, │
 never opens artifacts)                                              checks each create) │
        ▲                                                                                │ starts
        └──── JSON on stdout, ≤ 2 MiB, via launcher ◄──── gVisor sandbox, one per job ◄──┘
                                                          no network · read-only /input
                                                          tmpfs /scratch · CPU/mem/pids/time caps
```

### Sandbox launcher building blocks

`sandbox_launcher/` holds the pure parts of `sandbox-launcher`; nothing runs them yet. Each one
refuses rather than guesses:

- `config.SandboxLauncherSettings`: process env only (no `.env`, no app secrets); the proxy URL
  may embed credentials, so it is a `SecretStr` unwrapped only where connecting, and must be
  plain `http://` with a host; wall time is at most 840 s, below the proxy's 900 s, so
  the launcher's own kill fires first; `runc` is refused in prod.
- `catalog.py`: each analyzer's command and limits are code, its image digest comes from
  `sandbox-images.lock`; `load_catalog` keeps only analyzers present in both. `CATALOG` is empty
  until the first analyzer ships.
- `artifacts.py`: `resolve_artifact` returns `{root}/{uuid}` only if it is a real directory
  directly inside the root, never a symlink; `ArtifactNotFound` never names the path.
- `container.py`: `build_create_body` is the one place the ADR 0016 create body is spelled out;
  tests run every body through the real `sandbox_proxy.policy.validate_create`.
- `stream.py`: `read_stdout` demultiplexes Docker's attach frames, keeps stdout and drops stderr.
  It caps stdout at 2 MiB (ADR 0011) on each frame's *declared* size, before the payload is
  read, and raises on a cut-off or unknown frame, so partial output is never returned.

The package imports nothing from the app or `sandbox_proxy` (import-linter). The values it
shares with them (proxy limit ceilings, the digest pattern, create-body constants,
`MAX_STDOUT_BYTES`) are copies that unit tests keep equal. PR 3c of #84 adds the service around
them: `runner.py` (create, attach, start, kill), `server.py` (`POST /runs`) and `__main__.py`.

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
| `Asset` | polymorphic target: `domain`, `subdomain`, `ip`, `url`, `repo`, `binary`; one row per `(org_id, type, value)` with `value` normalized by `domain.assets.normalize_asset_value` (hostnames lowercase punycode via `idna`, canonical IPs, `http(s)` URLs without credentials/fragment/default port; repo/binary not yet); `source` user/discovered, `parent_id` = asset a discovered one was found under (set once at first sighting, so no cycles; user-added assets are roots; deleting a parent cascades to its discovered children), `first_seen`/`last_seen`, `is_active` + `deactivated_at` (only sightings after it reactivate), `tags`, `details` (a JSONB bag for scan-derived metadata: CT discovery stores `{"wildcard": true}` on wildcard zones; DNS resolution stores `dns` records/chain and `ip` PTR/ASN/organisation, plus an `observed_at` marker so stale scans cannot replace newer details, ADR 0025). Roots come from `services.assets.add_root_domain` (any name `check_public_hostname` accepts, registrable or subdomain; re-adding an archived root restores it) and are removed only by `archive_root_domain` (root + its discovered children go inactive; findings and scans are kept) |
| `AssetRelation` | graph edges: `subdomain_of`, `cname_to`, `resolves_to`, `serves`; unique per `(org_id, from, to, kind)`, no self-edges. `services.assets.record_asset` / `record_relation` upsert atomically (`INSERT … ON CONFLICT`): re-seen rows extend `last_seen`, never downgrade `source=user`, don't commit (the pipeline commits once), and raise `AssetNotFound` for a parent or endpoint that isn't the org's (locked `FOR KEY SHARE` so it can't vanish before the insert) |
| `Verification` | proof of ownership of a root domain (`_attacksurf-verify.<root>` TXT, `pending`/`verified`/`revoked`, `verified_at`, `last_checked_at`, `recheck_at`, `expires_at`; unique per `(org_id, asset_id)`). Renewals are due after 20 hours; authorization expires after 24 hours. Subdomains inherit their root's proof; a `verified` row counts only while `expires_at` is in the future. Written by `services.verifications` / `services.ownership`, read by `DbOwnershipChecker` (ADRs 0014, 0015) |
| `Scan`, `Job` | one run of a profile (`dns_passive`, …) against a root asset (`queued/running/completed/failed/cancelled`, triggered by `user`/`schedule`, `stats`), and its jobs: a pipeline stage, or one scanner on one asset (`skipped` = not run, e.g. denied by ScopeGuard). `scan_id` is NULL for work that isn't part of a scan (ownership verification). Deleting the root asset deletes its scans (their jobs are kept with `scan_id` NULL); deleting another asset keeps the job with `asset_id` NULL |
| `Finding`, `Evidence` | normalized result, one row per issue across scans: unique `(org_id, fingerprint)`, with `fingerprint = domain.findings.finding_fingerprint(org_id, asset_id, rule_id, location)` (SHA-256 of a versioned JSON array; `location` tells apart several issues of one rule on one asset). `rule_id` points into the rule catalog (`domain.rules`: title, default severity, remediation template, references). Status `open → fixed / accepted_risk / false_positive` (`fixed_at` set exactly when `fixed`); regression detection in #20. Deleting a scan keeps its findings (scan references become NULL); evidence (`dns_record`/`http_response`/`raw`) goes with its finding |
| `LLMUsage` | one row per finished LLM call, successful or not: provider, model, `purpose`, `key_source` (`org`/`instance`), input/output tokens, `usage_reported`, `estimated_cost_usd` (snapshotted from `ai/pricing.py` list prices; NULL for an unpriced model or unreported usage), latency (NULL on failure), `success` + `error_type` (class name only). Append-only; indexed by `(org_id, created_at)` for #24's monthly instance-key cap. Written by `services.llm_usage.record_llm_usage` |
| `OrgSettings` *(#24)* | per-org LLM provider config (encrypted keys) |
| `ScanSchedule`, `AuditLog` | continuous monitoring and an append-only audit trail (`services.audit.audit()`, written in the same transaction as the change) |

## Scan pipeline

```
discover ─► per-asset checks (parallel group) ─► persist/normalize ─► dedupe + diff ─► AI triage ─► AI summary ─► notify
```

- Implemented as a Celery `chain`/`chord`; each stage is idempotent and tracked as a `Job`.
- **Scanners are plugins** (`@register_scanner`) returning normalized pydantic `ScanOutput`.
  A scan **profile** (e.g. `dns_passive`) selects the scanners to run.
- A failing scanner fails only its job, not the scan.
- Implemented framework (ADR 0011/0013): `domain/scanners.py` defines pydantic `ScanOutput`,
  `AssetRef(type, value)`, relations, raw rule findings/evidence, `AssetObservation` details,
  `ScanContext`, the `Scanner` protocol, the frozen `ScannerGrant` and `ScannerRuntime`
  (validated DNS/HTTP adapters, raw record lookups, the run cache, offline IP intel and the
  grant-checked sandbox port from `domain/sandbox.py`). Plugins
  declare `name`, `asset_types`, `queue`, `requires_verification`, `timeout_seconds`
  (0 < timeout <= 240 s) and `grant`, and return `run(ctx, asset) -> ScanOutput`.
  `ScanOutput.wildcard_zones` marks assets that are wildcard DNS zones rather than hosts; a
  discovery profile's cap reaches the plugin through `ScanContext.max_discovered_assets`.
  `ScanOutput.observations` carries per-asset details and lifecycle claims; persistence merges
  the details and may deactivate only discovered assets.
- `scanners/registry.py` supplies `@register_scanner`; `workers/app.py` and `app.create_app`
  import production plugin modules explicitly, so each process registers them once.
  `scanners/profiles.py`
  selects discovery/check plugins by name. `dns_passive` runs `dns.discovery.ct` for discovery
  and `dns.resolve` for checks, with `max_discovered_assets=1000`; empty/unknown profiles are
  rejected. Profiles cannot route to
  the reserved `active`/`analysis` queues before those workers are implemented.
- **CT discovery (#15, ADR 0022):** `dns.discovery.ct` queries crt.sh's JSON endpoint and falls
  back to Cert Spotter when crt.sh fails, times out or truncates. Names are normalized, filtered
  to the root, deduplicated and capped (shallow names first). Complete results are cached per
  root in Redis for six hours through `ctx.runtime.cache`; failures are misses, never job
  failures. A bounded number of random-label DNS lookups (`ctx.runtime.dns`) detects wildcard
  zones, and detected zones are persisted as `Asset.details["wildcard"] = true`. When both
  sources fail the scanner raises `TransientJobError`, so Celery retries with backoff.
- **DNS resolution (#16, ADR 0025):** `dns.resolve` queries A, AAAA, CNAME, MX, NS, TXT, CAA
  and SOA through the configured public resolvers, follows CNAMEs up to five hops, resolves the
  terminal name, and stores capped records in `Asset.details["dns"]`. A/AAAA answers create IP
  assets and `resolves_to` edges; in-root CNAME hops create `cname_to` edges (external targets
  stay in `cname_chain`). Reverse DNS and an optional offline ip2asn database fill
  `Asset.details["ip"]`; private/special-purpose addresses emit the info finding
  `dns.records.private_ip_exposed`. A discovered subdomain with no records becomes inactive;
  roots/user assets and wildcard-marked zones are never deactivated. A partial lookup failure
  withholds the DNS details replacement (and a failed PTR lookup withholds that IP's `ip`
  subtree), so the last complete observation stays; NUL bytes in TXT values are stored as `\0`
  because PostgreSQL JSONB rejects U+0000. `Asset.details["observed_at"]` orders observations,
  so a delayed older result cannot replace newer details.
- `services.scans.start_scan` validates a tenant-owned, active domain root, audits and commits
  the scan/kickoff job, then enqueues `passive.discover`. Two waves use Celery chords:
  discovery on the root, then checks on the active root and its known direct children, filtered
  by each plugin's supported asset types. Continuations use immutable signatures and tracked
  jobs: `checks`, then `persist → diff → triage → finalize`. Batch rows commit before messages.
- Each scanner task normalizes/persists before its chord receipt: discovery assets are ready
  for fan-out, and Redis sees only IDs/`None`, not scan evidence. The `persist` stage is a
  barrier. `services.scan_results.persist_scan_output` composes asset/relation upserts, rule
  catalog rendering, fingerprint upserts, and evidence inserts; it does not commit. The caller
  commits data and the scanner's completed `Job` together. Per-scan deterministic evidence IDs
  prevent duplicates on redelivery; sightings use monotonic first/last timestamps/scan IDs.
- References may name only the input asset or assets in that output. Scanners cannot set org
  IDs, database IDs, finding status, or ownership. Output is capped at 2 MiB; each evidence
  JSON object is capped at 64 KiB (UTF-8), with collection limits too. Oversize output fails
  the check rather than silently truncating evidence.
- Scanner execution uses a bounded daemon thread, with no DB transaction held during I/O.
  Budget exhaustion discards the result; ordinary errors and exhausted retries fail the job
  but release the chord. Guard denial skips it. Unexpected pipeline errors fail the scan and
  cancel queued work. Terminal scan status and an inactive root are checked again before
  persistence: a cancelled scan or an archived root writes nothing (ADR 0021).
- Archiving a root domain cancels its queued/running scans and their unfinished jobs in the same
  transaction (audited `scan.cancelled`), and is the only cancellation path for now. Archive and
  persistence lock the scan rows and then the root, in the same order, and take the root lock
  once (never upgrading it), so overlapping runs never deadlock; cancellation timestamps come
  from `clock_timestamp()`, and a stage that finds its
  root archived cancels the scan rather than leaving it `queued` (ADR 0021). No Celery
  revoke is sent: tasks that are already queued or running see the cancelled scan or the inactive
  root and drop their output, and `start_scan`/`dispatch_stage`/`finalize_scan` refuse an
  archived root even when a stale session copy still says active (ADR 0021).
  Threads cannot be killed: safe network adapters need their own deadlines, four unfinished
  threads exhaust that child's capacity, and prefork children recycle after 100 tasks.
- `diff` (#20) and `triage` (#25) are no-op seams for now; no finding lifecycle transitions or
  stats are inferred. Finalization completes only after scanner/barrier work is terminal;
  scanner failures do not make the whole scan fail. Identifier-only `FindingCreated` and
  `ScanCompleted` events publish after commit through `infra.events.InProcessDispatcher`;
  handler errors are isolated. `FindingFixed` is reserved for #20. Delivery is best-effort.
- **ScopeGuard** runs before every scanner (`infra/scope_guard.py`, ADR 0013): it validates the
  target (public domain under the bundled PSL; no internal/single-label names or IP literals;
  resolved addresses must be public), requires verified ownership for active checks, and returns
  run-scoped DNS/HTTP adapters bounded by the plugin's `ScannerGrant` (declared public data
  services only, or the target after verification), plus the run cache and offline IP intel.
  `workers.runtime.scanner_gate()` wires it with `services.ownership.DbOwnershipChecker`, so an
  active check runs
  only while the target's root has a verified, unexpired TXT proof (ADR 0014).
- Scanners only reach the network through those adapters: `infra/http.py` pins the validated
  address (keeping `Host`/SNI), re-checks redirects against the grant, ignores env proxies and
  caps time and body size; `infra/dns.py` queries configurable public resolvers without search
  domains and bounds each run by the plugin's DNS budget. Raw `lookup_many` records are data
  only; connection paths still validate every address, so a private answer can be reported but
  never dialed. A test fails if scanner modules import raw network libraries. Profiles may cap
  discovered assets per root (`max_discovered_assets`), enforced by the scanner and at
  persistence; CT discovery marks wildcard zones in `Asset.details`, and `dns.resolve` does not
  deactivate a marked zone on an empty answer.
- Repository fetches (ADR 0017, not built yet) use `ScopeGuard.check_fetch` and a separate
  streaming port for git smart HTTP (dulwich over the pinned client). There's no `git` binary
  with network access, hosts come from an allowlist in code, and packs are stored unparsed.
  Archives arrive by upload only and are extracted inside the sandbox.

## AI layer

- `LLMProvider` protocol (`domain/llm.py`, ADR 0019) with `AnthropicProvider`
  (`ai/providers/anthropic.py`) and `OpenAICompatProvider` (configurable `base_url`). Official
  SDKs, no meta-library; only `ai/providers/` imports one (an import-linter contract). No
  sampling settings: models run with their defaults (ADR 0024).
- A provider is built from one `LLMConfig` chosen by `ai/config.resolve_llm_config`: the org's
  own key (and its provider/model/base URL), else the instance `LLM_*` config (capped per org,
  #24), else AI off. Sources never mix; no failover between keys. Model names only from config.
- Structured output via each API's JSON-schema format; validation plus one corrective retry is
  shared (`ai/structured.complete_structured`). Errors map to `LLMError` subclasses
  (`ai/errors.py`). Adapters pass `ai/limits.py`'s timeout and retry count (0: no SDK retries, ADR 0024)
  to their SDK and enforce its total `CALL_DEADLINE_SECONDS` per call (which leaves room under
  `TrackedTask.soft_time_limit`); Celery alone retries `LLMUnavailable`, at task level, so AI
  tasks make one call each or cache per finding.
- Every call: versioned prompt, pydantic output schema, usage recorded, budget enforced, results
  cached by `(prompt_version, model, input hash)`. Usage is recorded for failed calls too (the
  tokens their earlier attempts spent, `LLMError.usage`); the caller commits that row before
  re-raising, or it rolls back with the task. Cost is an estimate from list prices in code, not
  a bill.
- Without an instance key and model, `create_app` logs once that AI is off for orgs without
  their own key.
- AI consumes **normalized findings only**; scan-derived text is treated as untrusted data.
- AI output is advisory: adjusted severity is shown next to the scanner's severity and never
  auto-closes findings.

## Queues

| Queue | Work | Isolation |
|---|---|---|
| `passive` | DNS, CT logs, RDAP, public APIs | normal egress |
| `ai` | LLM calls | rate-limited per org |
| `fetch` *(later)* | git smart-HTTP fetches | egress to allowlisted forges through ScopeGuard; no access to `sandbox-launcher`; never parses repository content (ADR 0017) |
| `active` *(later)* | port/web probes on verified targets | separate network, egress rules |
| `analysis` *(later)* | code/binary analysis (`sandbox_proxy/` and the `sandbox_launcher/` building blocks are implemented; the launcher service and the worker are not yet) | worker never parses artifacts; `sandbox-launcher` runs each job in a fresh gVisor container: no network, no credentials, read-only input, CPU/memory/pids/time/disk limits (ADR 0016) |

- `infra/queue.py`: `create_celery(settings)` (Redis broker + result backend from `REDIS_URL`,
  JSON only, `acks_late` + `reject_on_worker_lost`, prefetch 1, results ignored unless a
  chord needs them). A task's **name prefix is its queue** (`passive.ping` → `passive`);
  unknown prefixes are rejected, so nothing waits in a queue no worker reads.
- Enqueue through the `domain.jobs.TaskQueue` port (`infra.queue.CeleryTaskQueue`, sent by
  name; `web.queue.get_task_queue()` in web). `services.jobs.create_job` commits the `Job` row
  first, then enqueues; a broker error marks the job `failed`.
- Pipeline batches use `services.jobs.enqueue_workflow` (commit then publish) and the
  `domain.jobs.PipelineQueue` port, implemented by the same adapter with Celery `chain`/`chord`.
  `PipelineTask` enables results for chord synchronization and sanitizes exceptions/retries
  before Redis can store them. Ordinary isolated scanner failures return `None` receipts.
- Tasks (`workers/tasks/`, registered in `workers.app.TASK_MODULES`) use
  `base=workers.base.TrackedTask` and take `org_id` + `job_id` keyword arguments (ADR 0010).
  It records the lifecycle on the `Job` (`queued → running → completed / failed`, back to
  `queued` on retry; `attempts`, `celery_task_id`, DB-clock timings), skips redelivered tasks of
  finished jobs, never overwrites a cancellation, binds `org_id`/`job_id`/`scan_id` to the log
  context, retries `domain.jobs.TransientJobError` and database outages (exponential backoff with
  jitter, 3 retries), caps deliveries at `max_retries + 2` (a task that keeps killing its
  worker ends `failed`), and has a 300 s soft time limit. Workers don't build a Flask app and
  read `Settings` lazily.
- Error data: `Job.error` and logs hold the exception type (plus the message only for our own
  `domain.jobs.JobError`s) and stack frames, never raw third-party exception messages; Celery's
  tracer logger is silenced in workers.
- Known gaps, closed by the stale-job sweeper (#21): a web process killed between commit and
  enqueue leaves a `queued` job without a message, and a hard time-limit kill (330 s) leaves one
  `running`.

## Frontend

Server-rendered Jinja templates + HTMX for partial updates (polling for job progress) + Alpine.js
(CSP build) for small client-side state. A JSON API (`/api/v1`) shares the same services.

- `web/rendering.py`: `render_page()` returns a fragment for HTMX requests, the full shell
  otherwise (including boosted requests and HTMX history restores, which swap the whole body).
- `web/security.py`: CSP and other security headers on every response; `web/errors.py`: HTML error
  pages, JSON errors under `/api/`, unexpected exceptions logged and shown as a 500 with the
  request ID.
- Styling and components follow `DESIGN.md` (plain CSS + tokens, Jinja macros).
- Read side: `services/asset_views.py` returns frozen dataclasses (`AssetRow`, `AssetDetail`,
  `AssetPage`, …) so `web/` never handles ORM rows; `web/asset_params.py` parses list filters
  (`type`, `root`, `tag`, `q`, `status`, `page`; 400 on bad values) for pages and API alike.
- `/api/v1/assets` (session auth, writes need `X-CSRFToken`): `GET` list, `POST {"value"}` adds a
  root domain (201 / 422 / 409), `GET /<id>` detail with relations, `GET /<id>/findings`,
  `GET /<id>/scans`, `POST /<id>/archive` (admin). Errors are `{"error", "message"}`.

## Authentication (ADR 0009)

- `web/auth.py`: Flask-Login + signed cookie sessions, `CSRFProtect`, Flask-Limiter, the login
  gate (default deny) and `@require_role(Role.X)`. Pages: `/login`, `/signup`, `POST /logout`.
- `services/auth.py`: `authenticate` (checks credentials, audits, rehashes), `record_logout`,
  `load_session_user` (per request: the user and the org they act in, as a `SessionUser`;
  MVP: their first membership), `has_users`.
- Templates get `current_user` (`email`, `org_name`, `role`); services get org IDs from it.

## Deployment

Single VPS: Cloudflare Tunnel → Caddy → gunicorn (web), plus PostgreSQL and Redis, all in Docker
Compose (`compose.prod.yaml`); no inbound ports (ADR 0020, `docs/deployment.md`). Celery workers
and beat are not part of the production stack yet. Nightly `pg_dump` off-box. See issue #29.

The `Dockerfile` has two targets: `dev` (dev deps, Flask debug server, source bind-mounted by
`compose.yaml` for hot reload) and `prod` (no dev deps, gunicorn, non-root uid 10001). Base and
service images are pinned by digest and updated by Dependabot. The dev `compose.yaml` runs `web`,
`postgres`, `redis`, the Celery workers `worker-passive` (`-Q passive -c 4`) and `worker-ai`
(`-Q ai -c 2`) with `inspect ping` healthchecks, and `beat` (broker-connection healthcheck; no
schedules until #27). Each queue has its own exchange and routing key.
Dev `make up` builds images, waits for PostgreSQL/Redis, runs `make migrate`, then starts
application services (ADR 0012). Migration failure stops startup; application processes never
run migrations themselves. `/healthz` is liveness only and does not establish schema readiness.

## Decisions

See `docs/adr/` for the reasoning behind each choice above.
