# 0022. CT discovery: sources, cache and wildcard markers

- Status: accepted
- Date: 2026-11-11

## Context
Issue #15 adds the first real scanner: passive subdomain discovery. crt.sh is the broadest free
Certificate Transparency source but is frequently slow or unavailable, while Cert Spotter offers
a paginated fallback with a lower rate limit. Both are public data services, so ScopeGuard's
service allowlist is the right boundary (ADR 0013). Discovery output feeds later DNS resolution
(#16), so wildcard zones need a durable marker: a wildcard DNS answer is not evidence that an
individual name is real. The scanner must also stay bounded against huge zones, and tests must
never touch the live services.

## Decision
- **Sources:** `dns.discovery.ct` queries crt.sh's JSON endpoint first and falls back to the Cert
  Spotter issuances API (at most five pages, following only `api.certspotter.com` next links) when
  crt.sh fails, times out or returns a truncated body. Both hosts are declared in the scanner's
  `ScannerGrant`; every request still goes through the pinned safe client. When both sources fail,
  the scanner raises `TransientJobError`; Celery's existing retry policy (max three attempts,
  exponential backoff with jitter) provides the retry/backoff behavior. There is no sleep loop
  inside the scanner.
- **Parsing:** response bodies are untrusted. `name_value` (and `common_name`) from crt.sh and
  `dns_names` from Cert Spotter are split, stripped of one leading `*.`, normalized with
  `normalize_hostname`, filtered to the scanned root, deduplicated and sorted shallow-first. The
  input root is never emitted as a discovered asset. Names that are malformed or outside the root
  are skipped, never fatal.
- **Cache:** scanners get a new `ctx.runtime.cache` port (`domain/cache.py`, no network access and
  not part of `ScannerGrant`). The production adapter is `infra.cache.RedisScanCache`, namespaced
  under `attacksurf:scan-cache:v1:` over the shared `REDIS_URL`. Complete CT name lists are cached
  per root for six hours; partial fallback pages and failed sources are not cached. Values are
  capped (256 KiB) and TTLs are clamped (seven days). Redis errors are misses, so a cache outage
  slows discovery but never fails a job. Only public CT names are cached: no findings, evidence,
  tenant data or secrets.
- **Wildcard markers:** the scanner checks the root and the wildcard-zone candidates mentioned by
  certificates by resolving one random 16-hex-character label under each (at most six checks,
  sharing the existing DNS budget). A non-empty answer marks that zone as a wildcard. Detected
  zones are returned in `ScanOutput.wildcard_zones`; persistence merges `{"wildcard": true}` into
  the existing `Asset.details` JSONB for the root and for discovered zone assets. Markers are
  only written for rows the persistence cap admitted, never guessed. A failed probe (NXDOMAIN,
  resolver error, blocked address, exhausted budget) means "not detected", not a failed scan.
  Markers are sticky until a later reconciliation (#16) updates them.
- **Cap:** the `dns_passive` profile sets `max_discovered_assets=1000`. The scanner receives the
  effective cap through `ScanContext.max_discovered_assets` and stops before producing more names
  than persistence would admit; persistence still enforces the cap as the backstop and counts
  existing children too.

## Consequences
- The first production plugin is registered explicitly in `scanners/__init__.py`, so both workers
  and any future web scan trigger see the same registry; profiles can no longer name a plugin
  that was never imported.
- The scanner contract grows in backward-compatible ways: an optional runtime cache, an optional
  discovery cap on the context, and a `wildcard_zones` output field. Existing scanners and tests
  need no changes beyond construction sites.
- Discovery is bounded end to end: source body size, page count, name count, wildcard checks and
  DNS/HTTP budgets. A huge zone is truncated deterministically (shallow names first).
- crt.sh latency can exceed the base client's five-second default; the worker's scanner HTTP
  client uses a 15-second timeout, and the scanner's own wall-time budget is 180 seconds.
- Tests use recorded/trimmed responses and fakes. There is no live CT access in CI; a real-domain
  scan is a manual dev acceptance step.
- No database migration is needed: `Asset.details` already exists. The marker is a documented
  key convention for later scanners; #16 can merge DNS records into the same bag.
