# 0013. ScopeGuard and the scanner network boundary

- Status: accepted
- Date: 2026-10-27

## Context
Scanners turn user input (domains, later IPs and URLs) into outbound traffic. Without a single
choke point the app could be used as an SSRF proxy or an attack tool: internal names, cloud
metadata (`169.254.169.254`), private ranges, redirects to other hosts, DNS rebinding between a
check and the connect, and plain scanners talking to anything they like. #11 already gates every
run through `ScannerGate` but ships a closed gate; scanners also need passive access to public
data services (CT logs, RDAP) before ownership verification exists (#14).

## Decision
- **One gate**: `infra/scope_guard.ScopeGuard` implements `ScannerGate.check`, which validates
  the target and returns the run's adapters. The worker wires it in `workers.runtime`; there is
  no permissive default.
- **Validation is pure and layered**: `domain/scope.py` holds the rules (blocked address ranges,
  internal/single-label names, allowlist matching, Public Suffix classification *input*). The
  Public Suffix List is read from `tldextract`'s bundled snapshot by `infra/public_suffix.py`
  with fetching and disk caching disabled, so results don't depend on the worker's network or
  home directory.
- **Declared, enforced budget**: each plugin has a frozen `ScannerGrant` — `http` permission
  (`none`, `services` + allowlisted `http_hosts`, or `target` after ownership proof) and a DNS
  lookup budget. The gate checks grants at registration, resolves the allowlisted services and
  hands the plugin only `dns`/`http` adapters that re-check every call. A scanner can therefore
  query CT logs but never the scanned host unless it is an active check on a verified asset.
- **Ownership is an interface** (`OwnershipChecker`), unverified until #14; active checks stay
  denied. A `TARGET` HTTP grant is an active check: the gate requires ownership for it whatever
  the plugin's `requires_verification` flag says, and the registry rejects that combination at
  registration. No verification model or migration here.
- **Pinning without DNS rebinding**: the safe HTTP client resolves the host through the guarded
  resolver (every answer must be public), picks one address, and dials *that address* through an
  `httpcore` backend while keeping the original `Host` header, SNI and certificate checks. The
  gate's allowlist is the client's policy hook and is consulted *before the first request* and
  at every redirect hop, so the run-scoped client handed to scanners is as strict as the
  wrapper; timeouts, a redirect cap and a streaming size cap (`MAX_BODY_BYTES`, applied inside
  the client to the *decoded* body, so a gzip bomb can't expand past it) bound each request.
  Environment proxies are never used; TLS verification cannot be disabled through the client.
- **Passive checks only reach public data services**, through the same client (DNSSEC-less
  StubResolver, no search domains). No scanner contacts an arbitrary target.
- Denials are `ScopeError`s and are recorded on the `Job` as `skipped` with a message; policy
  bugs (bad grant, unsupported asset type) are `ScopePolicyError`s and fail only their job.
- **Discovery cap**: scan profiles may set `max_discovered_assets`; persistence keeps the
  root's discovered assets (existing + new) under it, so a huge zone can't flood a tenant or be
  crawled in chunks across runs. Dropped names are never used as relation/finding targets.

## Consequences
- New scanners must declare a grant and use `ctx.runtime`; a module-import test fails the build
  if scanner code imports raw network libraries (`requests`, `httpx`, sockets, `urllib.request`,
  dnspython resolvers). This is a check, not a sandbox: plugin code is trusted and runs in-process.
- Service answers are validated at request time (when the client pins), not when planning, so
  planning performs no I/O; a service that starts resolving privately fails its check.
- Active checks and target HTTP stay disabled until #14; the active queue remains locked.
- One connection is pooled per (host, pinned address); a changing answer opens a new pool.
- Scanners should stop at their own limits and report truncation; the persistence cap is a
  backstop that silently drops overflow.
- No UI or schema change here; #13 uses `domain/scope` validation when adding root domains.
