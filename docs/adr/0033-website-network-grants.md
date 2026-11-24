# 0033. Network grants for website checks

- Status: accepted
- Date: 2026-11-23

## Context
ADR 0013 defines ScopeGuard as the single network choke point for scanners, classifies any HTTP
request to the target (`HttpPermission.TARGET`) as an active check requiring verified ownership,
and provides `GET`-only HTTP and budgeted DNS adapters. Epic #66 (the website module, issues
#70–#82) adds TLS certificate/protocol inspection, HTTP service discovery, technology
fingerprinting, security header/cookie/CORS checks, fixed-path sensitive-file and admin-panel
exposure checks, and WordPress exposure checks.

Before opening the `active` queue or adding any website scanner, we need an explicit, enforceable
contract for what website scanners may send, where they may connect, how they are throttled and
identified, and what they must never do.

## Decision

### 1. Verified hosts only (keep ADR 0013's rule)
- Nothing in the website module may touch an unverified host — neither HTTP requests nor TLS
  handshakes.
- Both `http=HttpPermission.TARGET` and `tls=True` are active checks: the scanner registry rejects
  plugins declaring either without `requires_verification=True`, and `ScopeGuard.check` requires an
  unexpired, verified DNS TXT ownership proof on the asset's root domain (ADRs 0014, 0015).
- `URL` assets inherit ownership verification from their verified root domain (same rule as
  subdomains).
- Unverified targets raise `ScopeError` and record `Job.status = skipped` with a user-facing
  reason.

### 2. Guarded TLS handshake adapter (`ctx.runtime.tls`) (#71, #76)
- `ScannerGrant` gains `tls: bool = False` and `tls_ports: frozenset[int] = frozenset({443})`.
- TLS inspection counts as target active traffic (requires verified ownership,
  `ACTIVE_SCANS_ENABLED=true`, and the `active` queue). When `tls` is `False`,
  `ScannerRuntime.tls` is `UnconfiguredTls`, whose `inspect(...)` raises `ScopePolicyError`.
- `ctx.runtime.tls.inspect(host, port=443)` enforces:
  - `host` matches the run's target scope (validated public hostname);
  - `port in grant.tls_ports`;
  - DNS resolution through the guarded resolver (`resolve_name`, rejecting private, loopback,
    link-local/metadata, multicast, and reserved ranges) and IP pinning of the dialed address;
  - SNI set to `host`, bounded handshake timeout (`5.0` s), and bounded certificate chain reading
    (max 10 certificates / 64 KiB DER);
  - draws from the same per-target `(org_id, host)` rate limit and concurrency lease as HTTP.
- `inspect` returns the negotiated TLS version and cipher, parsed chain metadata (subject, SANs,
  issuer, validity window, key type/size, signature algorithm), and a separate validation result
  (`trusted_chain`, `hostname_matches`) so expired, self-signed, or mismatched certificates are
  *reported* as findings rather than raised as transport errors.
- Legacy-protocol probing (TLS 1.0/1.1) is best-effort and capability-detected against the
  worker's OpenSSL build (documented in #71).
- The scanner static import-ban test is extended to forbid `import ssl` (and `from ssl import ...`)
  in `src/attacksurf/scanners/`.

### 3. HTTP grant extensions for `TARGET` traffic (#70, #72, #77, #78, #79)
- **Allowed methods**: `GET`, `HEAD`, and `OPTIONS` only (`POST`, `PUT`, `PATCH`, `DELETE`,
  `CONNECT`, `TRACE` are never allowed). `ScannerGrant` declares
  `http_methods: frozenset[str] = frozenset({"GET"})`, validated as a non-empty subset of
  `{"GET", "HEAD", "OPTIONS"}`. Request bodies are always empty (`b""`). `HEAD` is required for
  large or binary exposure probes (e.g. `/actuator/heapdump`, backup archives) so large files are
  never downloaded.
- **Allowed ports**: Default `http_ports: frozenset[int] = frozenset({80, 443})` and
  `tls_ports: frozenset[int] = frozenset({443})`. Explicit extra ports may be declared on a grant
  only from a curated web-port allowlist (`{80, 443, 8000, 8080, 8443, 8888}`), never arbitrary
  port ranges or non-HTTP services.
- **Path allowlists (`http_paths`)**: Analogous to `http_hosts` for `SERVICES`, `TARGET` HTTP
  grants declare `http_paths: frozenset[str] = frozenset({"/"})` — exact, normalized leading-`/`
  paths (no `..`, no query payloads, max 50 entries per plugin), reviewed in code and enforced by
  `ScopeGuard` on every request. When scanning a `URL` asset, the asset's own normalized base path
  is permitted when `"/"` is granted. Exposure (#78) and WordPress (#79) plugins declare their
  fixed request sets explicitly in `http_paths`.
- **Soft-404 calibration**: `ScannerGrant` may set `soft_404_probe: bool = False`. When `True`,
  the gate permits at most one randomly generated sentinel path matching
  `/attacksurf-not-found-<hex>` per target host so soft-404 baselines (#78) work without
  opening arbitrary-path requests.
- **Redirects**: Bounded by `MAX_REDIRECTS = 4`, re-validated at every hop against verified target
  scope, allowed ports, and pinned public IP addresses. Plugins declare `follow_redirects: bool`
  on their grant (enabled for `web.probe`, disabled for fixed-path exposure checks in #78 so an
  open redirect cannot turn a fixed-path probe into arbitrary requests).
- **Request headers**: Restricted to a narrow allowlist of safe read-only probe headers
  (specifically a fixed benign foreign `Origin` for the single CORS reflection probe in #77, plus
  standard `Accept`/`Accept-Encoding`). `Authorization`, `Cookie`, `Proxy-Authorization`, and
  arbitrary plugin-supplied headers are forbidden.
- **Response caps & HTTP TLS verification**: Retain the `1 MiB` (`MAX_BODY_BYTES`) decoded
  streaming cap in `infra/http.py`. HTTP requests never disable TLS certificate verification;
  broken or untrusted certificates are inspected only via `ctx.runtime.tls.inspect`.

### 4. Active queue, egress isolation, kill switch, rate limits, and `User-Agent` (#70)
- **Active queue & worker**: Open the `active` Celery queue (`active.*` task prefix in
  `infra/queue.py`) with a dedicated `worker-active` service in `compose.yaml` and
  `compose.prod.yaml` on its own isolated egress network (separate from `worker-passive`,
  `worker-ai`, and `sandbox`; no access to `sandbox-launcher` or the Docker socket).
- **Global kill switch**: `ACTIVE_SCANS_ENABLED` (`bool`, default `false`) in `Settings` and
  `.env.example`. When `false`, `ScopeGuard.check` denies active checks (`http=HttpPermission.TARGET`,
  `tls=True`, `zone_transfer=True`, or `queue="active"`) with `ScopeError`, marking those jobs
  `skipped` with a clear user-facing reason.
- **Per-target rate limit and concurrency**: Enforced inside the safe HTTP and TLS adapters via a
  Redis-backed token bucket and concurrency lease keyed by `(org_id, target_host)` (testable
  with a fake clock):
  - `ACTIVE_TARGET_RATE_LIMIT_RPS`: default `2.0` (hard ceiling `10.0`),
  - `ACTIVE_TARGET_RATE_LIMIT_BURST`: default `5` (hard ceiling `20`),
  - `ACTIVE_TARGET_MAX_CONCURRENCY`: default `2` (hard ceiling `5`).
  Every `TARGET` HTTP request (including redirect hops) and every TLS handshake draws from the
  same `(org_id, host)` limiter.
- **Identifying `User-Agent`**: Every `TARGET` HTTP request sends
  `attacksurf/<version> (+<contact_url>)`, where `<contact_url>` comes from `SCANNER_CONTACT_URL`
  (optional validated `http://` or `https://` URL, falling back to `APP_BASE_URL` or
  `https://github.com/cpt9m0/attacksurf`). Plugins cannot override `User-Agent`.

### 5. Hard "never" list (non-negotiable)
Website scanners must **never**:
1. Send exploit, injection, or canary payloads (XSS, SQLi, SSTI, SSRF callbacks, command injection,
   path traversal `../`, deserialization gadgets).
2. Fuzz parameters, headers, or paths, or use wordlists beyond code-reviewed `http_paths`
   (≤ 50 entries).
3. Crawl or spider links, forms, or JS routes beyond the target URL and bounded same-scope HTTP
   redirects (≤ 4 hops).
4. Attempt authentication, login forms, default credentials, brute forcing, or XML-RPC/API login
   calls.
5. Send state-changing HTTP methods (`POST`, `PUT`, `PATCH`, `DELETE`).
6. Download large or binary files (enforced by `HEAD`-only probes on archive/heapdump paths and
   the 1 MiB decoded streaming cap).
7. Probe unverified hosts (either HTTP or TLS) or disable TLS certificate verification during HTTP
   requests.
8. Store raw secret values from exposed files (e.g. `.env` evidence stores key *names* only, never
   values, across DB, evidence, and logs).

## Consequences
- Issues #70–#82 share one unambiguous grant, queue, rate-limit, and safety specification.
- Existing `dns.takeover.http` (`http=HttpPermission.TARGET`, path `/`, `GET`) and `dns.axfr`
  (`zone_transfer=True`) stay compatible under default `http_methods={"GET"}` and
  `http_paths={"/"}`; #70 will wire `ACTIVE_SCANS_ENABLED` and `active` queue routing cleanly.
- Self-hosted operators must explicitly set `ACTIVE_SCANS_ENABLED=true` before active web checks
  execute; when `false`, passive discovery and passive DNS checks still run normally.
- Fixed path allowlists intentionally trade breadth for safety, ensuring attacksurf remains a
  defensive exposure monitor and never becomes a fuzzer or crawler.
