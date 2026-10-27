---
name: add-scanner
description: Add a new scanner plugin or security check (DNS, IP, web, code, binary) with its rules, fixtures and tests. Use when implementing any new check, detection rule, or discovery source.
---

# Add a scanner plugin

Read `docs/architecture.md` (scan pipeline section) first.

## Rules of the road
- A scanner **detects and returns normalized output**. It never touches the DB, never calls an
  LLM, and never imports a network library (`requests`, `httpx`, sockets, `urllib.request`,
  dnspython resolvers — a test enforces this). I/O goes through `ctx.runtime.dns` /
  `ctx.runtime.http`, which ScopeGuard already validated and bounded (ADR 0013).
- Passive vs active: if the check sends anything to the target beyond normal public lookups
  (zone transfer, port scan, probing payloads), it is **active** and must declare
  `requires_verification = True` and `ScannerGrant(http=HttpPermission.TARGET)`.
- Never exploit, brute force, or claim resources (e.g. takeover checks only *detect*).

## Steps
1. **Rules first:** add `Rule` entries to the catalog in `src/attacksurf/domain/rules/<target>.py`
   and list them in `_ALL_RULES` (`domain/rules/__init__.py`):
   - `id`: dotted, `<target>.<area>.<issue>` e.g. `dns.email.dmarc_missing`
   - `default_severity` (`info|low|medium|high|critical`), `title`, `description`,
     `remediation` (`$name` placeholders, filled by `render_remediation`), `references`
     (RFCs, vendor docs)
   - Findings carry a `location` when one rule can fire several times on one asset (e.g. the
     DKIM selector); it feeds `domain.findings.finding_fingerprint`, so it must not contain
     anything that changes between scans (TTLs, record order, timestamps).
2. **Plugin:** `src/attacksurf/scanners/<target>/<name>.py`
   - Implement the `Scanner` protocol, decorate with `@register_scanner`.
   - Set `asset_types`, `queue` (`passive` / `active` / `analysis`), `requires_verification`,
     timeout and `grant` (`ScannerGrant`: `http=NONE` for DNS-only, `SERVICES` + `http_hosts`
     for public data services such as `crt.sh`, each needing one `dns_lookups`; `TARGET` only
     for verified active checks). Ideas beyond the grant are denied at runtime.
   - Return `ScanOutput` (discovered assets, relations, raw findings with evidence).
   - Evidence must be what a human needs to confirm the issue: raw records, response snippets
     (size-capped). No secrets.
   - Contracts live in `domain/scanners.py`: `ScanOutput(assets, relations, findings)` uses
     tuples; `AssetRef(type, value)` is normalized and carries no DB ID. Relations/findings
     reference only the input or assets explicitly returned in that output. Findings use
     catalog `rule_id`, `location`, `confidence`, optional severity/remediation context, evidence.
   - Output <= 2 MiB, individual evidence JSON <= 64 KiB UTF-8; oversize output fails the job.
     Timeout must be > 0 and <= 240 seconds; threads cannot be killed, so guarded I/O adapters
     must enforce their own deadlines. No DB access from scanner threads, including on timeout.
   - Register via `scanners.registry.register_scanner` and import the module explicitly at
     worker startup. The production gate (`workers.runtime.scanner_gate()`) validates and
     authorizes every run; never bypass it or widen a grant to make a check work.
     `active`/`analysis` workers/profiles are not enabled yet (and #14 gates active checks).
3. **Profile:** add the scanner name to `scanners/profiles.py` (`ScanProfile.discover` for root
   discovery, `checks` for per-asset work; `max_discovered_assets` caps what a root can gain).
   The persistence barrier commits inside each scanner job before its chord receipt; plugins
   must not persist themselves. Test doubles belong only in `tests/scanner_fixtures.py`, never
   the production registry/profile.
4. **Fixtures:** record realistic responses into `tests/fixtures/<target>/<name>/`. No live
   network in tests.
5. **Tests:** `tests/unit/scanners/<target>/test_<name>.py`:
   - positive case per rule, negative case (clean config → no finding)
   - malformed/hostile input (huge records, weird encodings, HTML/JS in TXT records)
   - timeout/error → scanner fails gracefully
   - fingerprint stability (same input → same fingerprint)
6. **Docs:** add the rules to the scanner/rule list in `docs/`.
7. Run `pre-pr-check`.
