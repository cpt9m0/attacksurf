# Security model

attacksurf is a defensive tool that sends traffic to the internet on behalf of users and handles
their security data. Both make it a target. These rules apply to all code.

## Responsible use

- **Passive checks** (public DNS, read-only authoritative SOA/DNSKEY probes, Certificate
  Transparency, RDAP) may run on any registered domain.
- **Active checks** (zone transfer now; port/web probing later) run **only on assets whose
  ownership is verified** (DNS TXT token, ADR 0014). ScopeGuard enforces this; scanners cannot
  bypass it. A proof is a `_attacksurf-verify.<root>` TXT record with a random per-asset token;
  it is due for re-check after 20 hours, revoked if the record is absent after its expiry, and
  expires for the gate after a day without a successful check (ADR 0015). Zone-discovery
  failures trigger retries rather than falling back to an unconfirmed parent zone.
- **Takeover detection (#18)** only *observes*: dangling CNAME/NS candidates come from public
  DNS answers, and the one confirmation probe is a single passive GET of the scanned asset
  itself, classified as an active (`TARGET`) check so it too runs only on verified assets.
  The response is matched against known "unclaimed instance" signatures; nothing is ever
  registered, claimed or written to a third-party service.
- **DNS hygiene (#19)** only *observes*. The authoritative probes are single read-only
  SOA/DNSKEY queries to the scanned zone's own nameservers (validated public addresses); the
  only active check is one AXFR request per nameserver of a **verified** zone apex, and only the
  number of records in the first response is kept — zone content is never stored. RDAP is
  queried only for the scanned domain's registration, through IANA's bootstrap registry.
- **Out of scope, always:** exploitation, brute forcing, credential attacks, DoS, actually
  claiming takeover-able resources, and scanning of third-party targets.

## Protecting the platform

| Threat | Control |
|---|---|
| SSRF via user targets, redirects, custom LLM `base_url` | ScopeGuard (ADR 0013) validates every scanner target: public Suffix only (bundled PSL, no fetch), no single-label or internal names (`localhost`, `.local`, `.corp`, `.internal`, …), no IP literals. Resolved answers must all be public (RFC1918, loopback, link-local incl. `169.254.169.254`, CGNAT, multicast, reserved, ULA, IPv6 mapped/6to4/NAT64 equivalents). The safe HTTP client pins the validated address, keeps `Host`/SNI, re-checks the scanner's grant before the first request and every redirect hop, ignores env proxies, and caps time and body size — the ceiling applies to the *decoded* body, so a compressed response can't expand past it, and a plugin-supplied limit cannot raise it. Custom org LLM `base_url` values go through `infra.scope_guard.validate_llm_base_url` both on save and before connecting: embedded `user:pass@` credentials, queries, fragments, private/internal hostnames and resolved private/metadata IPs are rejected, and `https` is required unless a hostname is explicitly allowlisted via `LLM_ALLOWED_BASE_HOSTS`. Both `AnthropicProvider` and `OpenAICompatProvider` instantiate `DefaultHttpxClient` with `follow_redirects=False` and `trust_env=False` (no redirect hops or env proxy overrides), and `_DeadlineBackend.connect_tcp` re-checks all resolved socket addresses with `domain.scope.check_addresses` immediately before dialing unless `allow_private_base_url=True` (instance config or an allowlisted org host). A `TARGET` HTTP grant always requires verified ownership, whatever the plugin declares. Scanners may only contact declared public data services; active checks (target HTTP) require a verified, unexpired ownership proof |
| SSRF via authoritative probes or RDAP | Nameservers come from the resolver, and every one of their addresses is validated with the scan-target policy before a query; answers are read, never followed, and AXFR only targets a name that owns NS records itself. RDAP base URLs come from IANA's bootstrap, must be `https`, and are reached through the same pinned client; only the scanned domain's registration is requested (ADR 0026) |
| SSRF via the ownership check | The check follows a zone's nameservers, which the domain's owner controls. Every nameserver address is validated with the scan-target policy (no private, loopback, link-local/metadata, multicast or reserved ranges) and an internal-only delegation simply fails; replies are read, never followed, and only a direct TXT record for the exact name counts. Bounded: 3 nameservers, 2 s each, 64 KiB responses (ADR 0014) |
| Cross-tenant data access | `org_id` on every tenant row, scoped queries, an isolation test per endpoint; links between tenant rows (asset parent and relations, scans, jobs, findings, evidence) use composite foreign keys `(id, org_id)`, so the database itself rejects a link to another org's row; Postgres RLS later |
| XSS from scan data (TXT records, HTML, banners) | Jinja autoescape, never `|safe` on scan data; CSP `default-src 'self'; script-src 'self'; style-src 'self'; object-src 'none'; frame-ancestors 'none'` (no `unsafe-inline`/`unsafe-eval`; Alpine CSP build; a test rejects inline script/style/handlers in rendered pages) |
| CSRF | Flask-WTF `CSRFProtect` on every POST/PUT/PATCH/DELETE: hidden `csrf_token` in forms, `X-CSRFToken` header for HTMX via `<body hx-headers>`; `SameSite=Lax` session cookie; logout is POST-only |
| Clickjacking, sniffing, downgrade | `X-Frame-Options: DENY` + `frame-ancestors 'none'`, `nosniff`, `Referrer-Policy: strict-origin-when-cross-origin`, `Permissions-Policy`, HSTS in prod (`web/security.py`) |
| Tampered front-end dependencies | HTMX/Alpine vendored from verified npm tarballs, pinned by `static/vendor/SHA256SUMS` (checked by a test) |
| Oversized or disguised uploads | every request body is capped at 2 MiB by the app (`MAX_CONTENT_LENGTH`) and at 2 MB by Caddy; only `POST /assets/upload` and `POST /assets/upload-binary` get `ARTIFACT_MAX_BYTES` plus 64 KiB of multipart framing, set before CSRF reads the form, so Werkzeug stops reading at the cap (413) and `store_artifact` enforces the exact artifact size and org quota again while encrypting; the upload must start with zip, gzip, bzip2, xz or tar magic bytes (415 otherwise) and is never parsed or extracted outside the sandbox; the file name only yields a slug (`[a-z0-9._-]`, 64 chars) for the asset value and is otherwise kept for display without path or control characters (255 chars) and shown escaped; CSRF, login and 20 uploads per user per hour (one allowance shared by all upload endpoints) apply; without `APP_ENCRYPTION_KEY` uploads are refused; the rate limit and the missing-key refusal are decided from the request headers, before the body ceiling is raised, so a refused request never gets a large body read. Known gaps: Werkzeug spools an accepted upload to a temp file in the web container (plaintext, removed when the request ends) before it is encrypted; an uploaded artifact is purged after `ARTIFACT_RETENTION_HOURS` (24 h when 0) even though its scan is still queued, because no analysis task is registered until #87; an upload that fails in storage (too large, quota) leaves its empty repo asset (#87) |
| Uploaded binaries and mobile apps (#101) | same route gates as archives (body ceiling, CSRF, login, rate limit, encryption key); the upload must start with ELF, `MZ`, Mach-O, universal Mach-O or zip magic bytes (415 otherwise, before anything is stored or any asset exists); the app and workers never execute, emulate, parse, unpack or decrypt it: the web process only hashes it, and the asset value is that SHA-256, so no attacker-chosen text becomes an identifier; the file name is kept for display only (last path component, no control characters, 255 chars) and always rendered escaped; the stored artifact's digest must equal the hashed one or it is deleted; format detection (`sandbox_tools.detect`) runs only inside the sandbox, reads fixed-size headers and a zip's central directory (refused whole above 4 MiB or 50,000 entries, so no name is ever judged cut short), never decompresses entry data, never follows a symlink and prints only numbers and fixed words; a zip whose end record and directory disagree, or that is both an APK and an IPA, is rejected rather than guessed at; the org quota is checked before the asset is created. Known gaps: the leading-bytes gate lets through anything with a matching magic (a Java class file, any zip, a DOS program) and such an upload sits encrypted and unanalysed until it is purged; the `binary_static` scan stays queued until #101; the same file uploaded twice is stored twice (two artifacts, both counted against the quota); an upload that fails after the quota check (storage unavailable, digest mismatch, a concurrent upload taking the last of the quota) leaves its binary asset without an artifact, and for a re-upload the newer file name; zip entries with zip64 extra fields are accepted as long as the end record is not zip64 |
| Information leaks in errors | error pages show static text only; 500s show the request ID, details go to logs |
| Credentials in asset values | URL assets with `user:pass@` are rejected, never stored; error messages don't echo them |
| Prompt injection via scan data | scan data is delimited and size-capped in prompts, output is schema-validated, AI cannot take actions |
| Secret leakage / forged sessions | env vars and connection URLs typed as `SecretStr` (masked in repr); `ENV=prod` refuses to start unless `SECRET_KEY` is ≥ 32 chars and not a placeholder such as `change-me`; org API keys are encrypted in the DB via `infra.crypto.SecretCipher` (AES-256-GCM under `APP_ENCRYPTION_KEY`, bound with `org_id` AAD, supporting decryption via `APP_ENCRYPTION_OLD_KEYS` for key rotation, with `api_key_last4` stored separately); settings errors never print the rejected value; structlog redacts secret-looking keys (`api_key`, `base_url`, URL credentials, `encryption_key`, `old_keys`, etc.); stored keys are never returned or rendered back in full |
| Stored artifacts read from disk, a backup or the sandbox mount | every uploaded/fetched artifact is encrypted in chunks with AES-256-GCM under its own random key, which is wrapped by `APP_ENCRYPTION_KEY` (bound to org and artifact ID) and kept in the `artifacts` row, never on disk; a changed, truncated, reordered or swapped file fails authentication; deleting an artifact, or the asset/org it belongs to, removes that key, so a leftover file can't be decrypted; ciphertext lives in `ARTIFACT_STORE_ROOT`, which may not overlap the sandbox-mounted `SANDBOX_ARTIFACT_ROOT`; plaintext exists only while staged for one run (stale copies swept after 1 h); per-artifact size and per-org quota are enforced while reading; without the key storage refuses to store or read but still deletes; retention defaults to delete-after-analysis with a 24 h ceiling. Known gaps: `APP_ENCRYPTION_KEY` is not required at boot and artifact keys do not yet rotate via `APP_ENCRYPTION_OLD_KEYS` (org API keys do); prod runs `beat`/`worker-passive` (#174) so the purge runs there, while `worker-ai` is still missing; prod keeps ciphertext in the `artifact-store` volume, which has no backup yet (ADR 0028) |
| Malicious archive *(extractor implemented, not wired to a run until #87)* | `sandbox_tools.extract` runs only inside the sandbox, never in a worker: its own loop over zip and tar(.gz/.bz2/.xz) entries (format by magic bytes) that never creates links and writes files `0600`, directories `0700`, so setuid/setgid/sticky bits don't survive; symlinks, hard links, device nodes and FIFOs are skipped with a reason in the manifest; absolute paths, `..`, NUL, backslash or undecodable names, duplicate paths (including a file under an earlier link or file), corrupt or truncated archives, a tar that doesn't end in zero blocks up to the end of its stream, a zip entry whose deflate stream ends before or after its declared size, a zip directory entry that carries data, old-GNU sparse tar members, zip local headers that differ from the central directory, encrypted zip entries and compression methods other than stored/deflate reject the whole artifact and remove what was written, because a partial tree would read as clean; caps (512 MiB total, 64 MiB per file, 100,000 entries counting files, skipped entries and every directory created, depth 32, 200 bytes written per archive byte) count bytes as they are written, never declared sizes, and for tar the same size budget (plus 4 KiB of header room per entry) covers every decompressed byte the parser reads, including members it skips; a zip entry is a directory only if its name ends in `/`, so a directory mode can't hide a file; any other parser failure is a rejection; nested archives stay files. Known gaps: zip data not listed in the central directory is ignored; a tar extension header is held in memory up to that size budget and a huge zip central directory has no cap, so the sandbox memory limit is what stops them (ADR 0017) |
| Repository fetch abuse (SSRF, `git` transports) *(later)* | no `git` binary with network access: smart HTTP in Python over the pinned safe client; exact-match forge allowlist in code; URLs rebuilt from a validated `host/path`; no redirects; dumb HTTP refused; size and time caps; the pack is stored unparsed; analysis waits for ownership proof (ADR 0017) |
| Log injection | client `X-Request-ID` accepted only if it matches `[A-Za-z0-9-]{1,64}`, otherwise replaced; structured (JSON) logs |
| Malicious uploads *(later)* | never executed or built; static analysis only, in a fresh gVisor container per job started by `sandbox-launcher` through `sandbox-proxy`, the only holder of the Docker socket, which rejects any create request outside the sandbox policy, acts only on containers it created, and turns off container logging so tool output never lands on the host (ADR 0016); its only read call, `GET /info`, returns runtime names and nothing else from the daemon (ADR 0023); the Celery worker holding DB/Redis credentials never opens artifact bytes |
| Parser exploit in an analysis tool *(later)* | the sandbox has no network (`--network=none`), no credentials or Docker socket, a read-only root and input, non-root UID, all capabilities dropped, `no-new-privileges`; output is JSON on stdout, capped at 2 MiB (checked on each frame's declared size before the payload is read) and validated as `ScanOutput` before use; a cut-off or unknown frame fails the run, so partial output is never used; stderr is discarded (it can echo found secrets) |
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
sandbox analyzers it may name, none by default; and the #19 capabilities below), plus a
namespaced run cache and optional offline IP intel. DNS queries go to operator-configured
public resolvers only
(`DNS_RESOLVERS`, validated as public IPs), with no search domains; a query to a nameserver
found in an answer is never sent. The cache is not
network access and is not grant-controlled: it stores only public source data (CT names today,
RDAP later), never findings, evidence, tenant data or credentials; keys are namespaced beside
Celery's, values and TTLs are bounded, and every Redis error is a miss rather than a job failure
(ADR 0022). Declared
services are re-checked and resolved before the run starts; every DNS answer and HTTP host
(each request, including every redirect hop) is validated again when used. `lookup_many`
returns raw records as data and deliberately does not validate addresses, so private A/AAAA
answers can be reported by `dns.resolve`; the connection paths (`resolve_ipv4`/`resolve_name`)
still validate every address, and only those feed the pinned HTTP client. A scan profile's
`max_discovered_assets` caps what one root can add, counting against the scan root under a row
lock so overlapping scans can't each claim the full allowance and a check on a discovered
subdomain cannot claim a fresh one; a policy error fails only its job.

Active/analysis queues remain reserved and cannot be selected in a scan profile; active checks
run only on assets whose root domain proved ownership by DNS TXT (ADR 0014). CT discovery's
random-label wildcard probes use the same guarded DNS adapter and DNS budget; a wildcard marker
(`Asset.details["wildcard"] = true`) is data for later resolution, never a finding or a claim
that a name exists. `dns.resolve` records A/AAAA/CNAME/MX/NS/TXT/CAA/SOA in capped
`Asset.details`, creates IP assets/edges, and emits the info finding
`dns.records.private_ip_exposed` for private or special-purpose addresses; it never contacts
those addresses. A missing ip2asn file disables ASN/organisation enrichment only.
`dns.email` evaluates SPF/DMARC/DKIM/MTA-STS publication from TXT answers through the
same guarded DNS adapter and DNS budget; it performs no HTTP fetch (MTA-STS is the DNS
signal only) and emits findings with raw-record evidence, never new assets.

The #19 capabilities are separate, grant-declared adapters, never raw clients. The
authoritative adapter resolves a zone's nameservers through the guarded resolver, requires
every address to be public, and sends at most three read-only SOA/DNSKEY queries (2 s each,
64 KiB answers); unreachable servers are not reported as findings. `zone_transfer` is an active
check: the registry rejects it without `requires_verification`, the gate requires a verified
asset, and the adapter only attempts a transfer when the scanned name owns NS records itself
(so a parent zone is never transferred), reads only the first message and keeps only its record
count. RDAP resolves the TLD's base URL from the fixed `data.iana.org` bootstrap, requires
`https`, allows redirects only to the bootstrap/RDAP host, and may look up only the run's target
or its registrable domain; trimmed registration data (never findings, evidence or tenant data)
is cached for 24 hours (ADR 0026). Only the DS -> DNSKEY linkage is checked for DNSSEC, not
RRSIG signatures.

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

### Sandbox launcher

`sandbox-launcher` turns "run analyzer X on artifact Y" into one proxy-approved container
(ADR 0016). It is reachable only on the internal network and has no authentication, so the worker
must confirm the artifact belongs to the org before asking. What it guarantees:

- **Fixed menu.** The request is exactly `{analyzer, artifact_id}`; image, command, mount and
  limits come from the catalog and the artifact root. Malformed bodies are 400 before any sandbox
  exists; an unknown analyzer or artifact is the same 404.
- **Limits it enforces itself.** Wall time (at most 840 s, below the proxy's 900 s) is decided by
  the launcher's own deadline, then it kills; stdout over 2 MiB kills the run. Either way partial
  output is dropped. Stderr is never returned.
- **Cleanup on every path.** After a successful create the container is killed and removed before
  the call returns, falling back to a forced delete; `sandbox_cleanup_failed` (error level) means
  a container may be left behind and should alert.
- **No content in logs or errors.** One `sandbox_run` line per run with analyzer, runtime,
  duration, outcome, exit code and byte count; replies and request values never reach a log or
  an exception message.
- **Start-up rule.** In prod it exits unless `runsc` is a registered runtime; `runc` is allowed
  only outside prod with `SANDBOX_ALLOW_RUNC=true`, and logs `sandbox_launcher_runc_fallback`. If
  the proxy can't be asked, it exits rather than retry. Dev Compose defaults to
  `SANDBOX_ALLOW_RUNC=true` (weaker isolation than `runsc`); prod refuses it.
- **Dev topology (ADR 0029, prod has none yet).** Behind the opt-in `sandbox` profile, the
  `sandbox` network is `internal` (no route outside; Postgres and Redis are not on it). Only
  `sandbox-proxy` mounts the Docker socket. The launcher and proxy read the process environment
  only, so no `.env`, database URL or encryption key reaches them. `worker-analysis` is on both
  networks; the launcher mounts the staging folder read-only and the worker read-write.
- **Known limit: proxy trust.** The proxy has no caller authentication and the worker shares its
  network, so a compromised worker could ask Docker for any create the proxy policy allows. Dev
  accepts this; #92 must close it before prod.
- **Known limit.** A container that exits and is removed before Docker registers the removed-wait
  makes the wait fail, so the run fails (503) instead of reporting an unconfirmed exit code.

#### Worker-side client and tenant safety

The launcher knows nothing about orgs: any caller that can reach it can name any artifact ID. The
worker is the only barrier, so **the caller of `SandboxRunner.run` must confirm that the artifact
belongs to the job's org (`get_scoped`) before calling it.** `LauncherSandboxRunner` and the scope
guard don't check this (the guard only limits which analyzers a scanner may name); the analysis
scanner that first calls `run` must, with a tenant-isolation test.

- The launcher URL is operator config (`SANDBOX_LAUNCHER_URL`, a `SecretStr`, plain
  `http://host[:port]` only), so the client skips the SSRF guard that would refuse an internal
  address. It ignores proxy environment variables and `.netrc` and never follows a redirect.
- The reply is untrusted: size-capped at 3 MiB, never inflated, exact keys and types, strict
  decoding. No reply text, URL or artifact ID reaches a log line or a stored `JobError`.
- Unset, the workers refuse every sandbox request.

## Accounts

Signup is open by default (`ALLOW_SIGNUP=true`). With `ALLOW_SIGNUP=false` only the first user
can sign up (the instance admin); everyone else gets 404. The first-user check runs under a
Postgres advisory lock inside the signup transaction, so concurrent bootstrap signups can't both win. Signup reveals whether an email is
already registered (rate-limited); login never does.

## Data sent to LLM providers

Only normalized findings (rule, severity, asset name, trimmed evidence) and aggregate stats.
When an admin clicks "Test connection" on `/settings`, a minimal structured health-check probe
(`{"ok": true}`) is sent with no tenant data. Never sent: credentials, API keys, raw uploads.
Each AI feature documents its payload here as it is added. Orgs can disable AI or bring their own
provider key; monthly UTC token budgets (`LLM_MONTHLY_INSTANCE_TOKEN_BUDGET` for the instance key
and optional per-org caps) skip AI triage gracefully once reached.

What is stored about each call (`llm_usage`): provider, model, purpose, whose key paid, token
counts, estimated cost, latency, and on failure the error's class name. Never the prompt, the
reply, the error message, the API key or the base URL (which can embed credentials).

## Reporting a vulnerability

Open a private security advisory on GitHub rather than a public issue.
