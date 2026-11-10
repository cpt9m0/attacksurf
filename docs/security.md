# Security model

attacksurf is a defensive tool that sends traffic to the internet on behalf of users and handles
their security data. Both make it a target. These rules apply to all code.

## Responsible use

- **Passive checks** (public DNS, Certificate Transparency, RDAP) may run on any registered domain.
- **Active checks** (zone transfer now; port/web probing later) run **only on assets whose
  ownership is verified** (DNS TXT token, ADR 0014). ScopeGuard enforces this; scanners cannot
  bypass it. A proof is a `_attacksurf-verify.<root>` TXT record with a random per-asset token;
  it is due for re-check after 20 hours, revoked if the record is absent after its expiry, and
  expires for the gate after a day without a successful check (ADR 0015). Zone-discovery
  failures trigger retries rather than falling back to an unconfirmed parent zone.
- **Out of scope, always:** exploitation, brute forcing, credential attacks, DoS, actually
  claiming takeover-able resources, and scanning of third-party targets.

## Protecting the platform

| Threat | Control |
|---|---|
| SSRF via user targets, redirects, custom LLM `base_url` | ScopeGuard (ADR 0013) validates every scanner target: public Suffix only (bundled PSL, no fetch), no single-label or internal names (`localhost`, `.local`, `.corp`, `.internal`, …), no IP literals. Resolved answers must all be public (RFC1918, loopback, link-local incl. `169.254.169.254`, CGNAT, multicast, reserved, ULA, IPv6 mapped/6to4/NAT64 equivalents). The safe HTTP client pins the validated address, keeps `Host`/SNI, re-checks the scanner's grant
before the first request and every redirect hop, ignores env proxies, and caps time and body
size — the ceiling applies to the *decoded* body, so a compressed response can't expand past it,
and a plugin-supplied limit cannot raise it. A `TARGET` HTTP grant always requires verified
ownership, whatever the plugin declares. Scanners may only contact declared public data
services; active checks (target HTTP) require a verified, unexpired ownership proof |
| SSRF via the ownership check | The check follows a zone's nameservers, which the domain's owner controls. Every nameserver address is validated with the scan-target policy (no private, loopback, link-local/metadata, multicast or reserved ranges) and an internal-only delegation simply fails; replies are read, never followed, and only a direct TXT record for the exact name counts. Bounded: 3 nameservers, 2 s each, 64 KiB responses (ADR 0014) |
| Cross-tenant data access | `org_id` on every tenant row, scoped queries, an isolation test per endpoint; links between tenant rows (asset parent and relations, scans, jobs, findings, evidence) use composite foreign keys `(id, org_id)`, so the database itself rejects a link to another org's row; Postgres RLS later |
| XSS from scan data (TXT records, HTML, banners) | Jinja autoescape, never `|safe` on scan data; CSP `default-src 'self'; script-src 'self'; style-src 'self'; object-src 'none'; frame-ancestors 'none'` (no `unsafe-inline`/`unsafe-eval`; Alpine CSP build; a test rejects inline script/style/handlers in rendered pages) |
| CSRF | Flask-WTF `CSRFProtect` on every POST/PUT/PATCH/DELETE: hidden `csrf_token` in forms, `X-CSRFToken` header for HTMX via `<body hx-headers>`; `SameSite=Lax` session cookie; logout is POST-only |
| Clickjacking, sniffing, downgrade | `X-Frame-Options: DENY` + `frame-ancestors 'none'`, `nosniff`, `Referrer-Policy: strict-origin-when-cross-origin`, `Permissions-Policy`, HSTS in prod (`web/security.py`) |
| Tampered front-end dependencies | HTMX/Alpine vendored from verified npm tarballs, pinned by `static/vendor/SHA256SUMS` (checked by a test) |
| Information leaks in errors | error pages show static text only; 500s show the request ID, details go to logs |
| Credentials in asset values | URL assets with `user:pass@` are rejected, never stored; error messages don't echo them |
| Prompt injection via scan data | scan data is delimited and size-capped in prompts, output is schema-validated, AI cannot take actions |
| Secret leakage / forged sessions | env vars and connection URLs typed as `SecretStr` (masked in repr); `ENV=prod` refuses to start unless `SECRET_KEY` is ≥ 32 chars and not a placeholder such as `change-me`; org API keys encrypted at rest (Fernet/MultiFernet); structlog redacts secret-looking keys; keys never rendered back in full |
| Malicious archive *(later)* | extracted only inside the sandbox by a purpose-built loop that never creates links; links, device nodes and FIFOs are skipped with a reason; absolute paths, `..`, duplicate paths and corrupt archives reject the whole artifact; size, file-count, depth and ratio caps count while writing and fail the job, because a partial tree would read as clean; nested archives aren't unpacked (ADR 0017) |
| Repository fetch abuse (SSRF, `git` transports) *(later)* | no `git` binary with network access: smart HTTP in Python over the pinned safe client; exact-match forge allowlist in code; URLs rebuilt from a validated `host/path`; no redirects; dumb HTTP refused; size and time caps; the pack is stored unparsed; analysis waits for ownership proof (ADR 0017) |
| Log injection | client `X-Request-ID` accepted only if it matches `[A-Za-z0-9-]{1,64}`, otherwise replaced; structured (JSON) logs |
| Malicious uploads *(later)* | never executed or built; static analysis only, in a fresh gVisor container per job started by `sandbox-launcher` through `sandbox-proxy`, the only holder of the Docker socket, which rejects any create request outside the sandbox policy, acts only on containers it created, and turns off container logging so tool output never lands on the host (ADR 0016); the Celery worker holding DB/Redis credentials never opens artifact bytes |
| Parser exploit in an analysis tool *(later)* | the sandbox has no network (`--network=none`), no credentials or Docker socket, a read-only root and input, non-root UID, all capabilities dropped, `no-new-privileges`; output is JSON on stdout, capped at 2 MiB and validated as `ScanOutput` before use; stderr is discarded (it can echo found secrets) |
| Resource exhaustion by an artifact *(later)* | per-run CPU, memory (no swap), pids, open files, `tmpfs` scratch size and a wall-time kill enforced by the launcher; worker concurrency caps parallel sandboxes; prod refuses to run without `runsc` |
| Account attacks | argon2id hashing (`infra/crypto.py`, argon2-cffi defaults, rehash on login when parameters change); passwords 12–1024 chars (upper bound limits hashing DoS), never logged or echoed in errors; emails normalized to lowercase and unique; login passwords over 1024 chars are rejected without hashing the submitted value (a fixed dummy value is hashed instead, so the path costs the same argon2 work for known and unknown accounts; known accounts are audited with reason `password_too_long`); one generic "Invalid email or password" for every failure and equal argon2 work for unknown emails (no account enumeration via login or timing); inactive users can't log in and lose access on their next request; audit log of `user.login`, `user.login_failed` (with reason), `user.logout`, `asset.root_added` / `asset.root_restored` / `asset.root_archived` and `scan.cancelled` (archiving a root cancels its in-flight scans; `details` never holds secrets) |
| Brute force | Flask-Limiter (Redis, in-memory fallback): login 5/min and 20/h per IP plus 10/h per email across IPs, signup 5/h per IP, 429 with `Retry-After`; real client IP behind the proxy via `PROXY_COUNT` (`ProxyFix`) |
| Session theft / fixation | signed cookie session cleared on login and logout; `HttpOnly`, `SameSite=Lax`, prod: `Secure` + `__Host-` prefix; absolute lifetime `SESSION_LIFETIME_HOURS` (12h) counted from login and checked server-side (`auth_at` in the session), so activity can't extend it; cookie not re-issued on every request; no remember-me. Known limit: a stolen cookie stays valid until it expires (server-side revocation later) |
| Open redirect | login `next` accepts only same-site paths (`/…`, not `//…`, no scheme/host) |
| Unauthenticated access | default deny (the login gate runs before CSRF validation, so anonymous writes get 401/redirect): every route needs login except `/login`, `/signup`, `/healthz`, static; HTML redirects to login, HTMX gets `HX-Redirect`, `/api/` gets 401 JSON; roles via `@require_role` |
| Job errors and worker logs | `Job.error` and worker logs keep the exception type and stack frames; messages only for our own `JobError`s (third-party messages can embed tokens, authenticated URLs or response bodies); Celery's tracer logger is silenced in workers |
| Supply chain | locked deps (`uv.lock`), only releases at least two weeks old (transitive ones pinned via `[tool.uv] constraint-dependencies`), `pip-audit` in CI, pinned MCP server versions, minimal dependencies; analysis images *(later)* are built in CI and allowed only by digest, with base images, tool checksums and CI actions pinned, the same two-week rule for tool versions, rules baked in, and nothing fetched inside the sandbox; OSV data comes from a read-only volume synced by a passive task, with each snapshot's date and hash recorded (ADR 0018) |

## Scanner execution boundary

Scanners never touch the network directly. Every run passes `ScopeGuard` first
(`infra/scope_guard.py`, ADR 0013): the target is validated, ownership is required for active
checks, and the plugin receives only DNS/HTTP adapters bounded by its frozen `ScannerGrant`
(allowlisted public data services, or the target after verification; a DNS budget; the
sandbox analyzers it may name, none by default). Declared
services are re-checked and resolved before the run starts; every DNS answer and HTTP host
(each request, including every redirect hop) is validated again when used. A scan profile's
`max_discovered_assets` caps what one root can add, counting against the scan root under a row
lock so overlapping scans can't each claim the full allowance and a check on a discovered
subdomain cannot claim a fresh one; a policy error fails only its job.

Active/analysis queues remain reserved and cannot be selected in a scan profile; active checks
run only on assets whose root domain proved ownership by DNS TXT (ADR 0014).

Repository fetches (ADR 0017, not built yet) pass the same gate through `check_fetch` and are
not scanners: `worker-fetch` reaches only allowlisted forges, using a streaming transport
limited to the two smart-HTTP requests. Scanners keep the GET-only client with its 1 MiB cap.
The fetcher stores packs unparsed, so hostile objects are first parsed inside the sandbox.

Plugins receive immutable context/value objects, never sessions or ORM rows. Threads cannot
write results: services validate normalized `ScanOutput` again, select tenant-scoped assets,
and commit data together with terminal job state. Output is limited to 2 MiB and individual
evidence objects to 64 KiB of JSON UTF-8; invalid/oversize results fail the check. No scan
output/evidence is carried through Celery results; exceptions are sanitized before Redis sees
them, including retry failures. Evidence itself must not contain credentials or tokens.

A scanner budget timeout **does not kill its Python thread**. Late results are discarded;
unfinished work is capped at four threads per child, and prefork children recycle after 100
tasks. Future network adapters must enforce their own timeouts and response-size caps. This
is error isolation, not a sandbox for executing user-supplied scanner code.

## Accounts

Signup is open by default (`ALLOW_SIGNUP=true`). With `ALLOW_SIGNUP=false` only the first user
can sign up (the instance admin); everyone else gets 404. The first-user check runs under a
Postgres advisory lock inside the signup transaction, so concurrent bootstrap signups can't both win. Signup reveals whether an email is
already registered (rate-limited); login never does.

## Data sent to LLM providers

Only normalized findings (rule, severity, asset name, trimmed evidence) and aggregate stats.
Never: credentials, API keys, raw uploads. Each AI feature documents its payload here as it is
added. Orgs can disable AI or bring their own provider key.

## Reporting a vulnerability

Open a private security advisory on GitHub rather than a public issue.
