# 0026. DNS hygiene: authoritative probes, RDAP and zone-transfer grants

- Status: accepted
- Date: 2026-11-13

## Context
Issue #19 adds the remaining MVP DNS hygiene checks: DNSSEC (DS/DNSKEY linkage), nameserver
hygiene (single NS, lame delegation, inconsistent SOA), MX target hygiene, CAA publication,
registration expiry/registrar lock via RDAP, and zone-transfer exposure. Three of them need
network access the existing grant model cannot express:

- comparing each authoritative server's answer needs direct queries to the zone's nameservers,
  because the stub resolver returns one merged answer;
- RDAP servers live on per-TLD hosts resolved from IANA's bootstrap registry, so a fixed
  `http_hosts` allowlist cannot name them;
- an AXFR is a TCP request to a nameserver, not HTTP, and is an active check.

ADR 0013 defined the grant model (`http`, `http_hosts`, `dns_lookups`) and ADR 0014 already
talks to authoritative servers for the ownership proof.

## Decision
- **Three capability flags on `ScannerGrant`**: `authoritative_dns`, `rdap`, `zone_transfer`.
  The gate builds one guarded adapter per granted capability; a plugin without the flag gets a
  null adapter that raises `ScopePolicyError` (a plugin bug, not a skip).
- **Authoritative adapter**: `AuthoritativeLookup` (in `infra/authoritative_dns.py`, beside the
  ownership TXT lookup) discovers the zone with an owner-checked NS lookup (the asset itself
  when it owns NS data, else its registrable domain), resolves each nameserver through the
  guarded DNS resolver, and queries at most three servers, one validated public address each,
  UDP then TCP on truncation, 2 s each, 64 KiB responses. It reads SOA/DNSKEY answers only; an
  unreachable server is reported as such, never as a finding.
- **Zone transfer**: the same adapter attempts one AXFR per nameserver of a name that owns NS
  records itself, so a non-apex root can never cause a parent zone to be transferred. Only the
  first message is read and only its record count is kept; zone content is never stored or
  returned. `zone_transfer` requires `requires_verification` at registration and ownership at
  the gate, whatever the flag says. It runs on the `passive` queue because the `active` queue is
  still reserved (#70).
- **RDAP**: `RdapClient` (`infra/rdap.py`) resolves the TLD's base URL from
  `https://data.iana.org/rdap/dns.json`, requires an `https` base URL, and only requests
  `{base}/domain/{domain}` for the run's target or its registrable domain. Both requests use the
  safe client (pinned, address-validated); redirects stay on the bootstrap/RDAP host. The
  trimmed result (registrar, expiration, statuses) and the bootstrap JSON are cached for 24
  hours as public data; failures are not cached and are fail-open.
- **DNSSEC depth**: the check verifies the DS -> DNSKEY linkage (key tag, algorithm and digest
  per RFC 4034 section 5.1.4, digest types SHA-1/256/384), not RRSIG signature validity.
  Unsupported digests or algorithms leave the zone unjudged.
- **Scope**: the zone-level checks (`dns.ns`, `dns.dnssec`, `dns.axfr`) run only on a zone apex;
  MX/CAA/RDAP use the asset's own data with the registrable domain as fallback. All six are
  `DOMAIN`-only, so they run once per scan root rather than per discovered subdomain.

## Consequences
- The grant contract grows in a backward-compatible way; existing scanners need no changes.
- New outbound paths are bounded and documented in `docs/security.md`: authoritative probes are
  read-only single queries to the zone's own servers; AXFR runs only on verified zone apexes;
  RDAP is limited to the scanned domain through the IANA bootstrap.
- `ScannerRuntime` gains three optional adapters; the null versions fail the job as a policy bug.
- No database migration, setting or dependency.
- Follow-ups: full DNSSEC RRSIG validation; a dedicated `active` queue with egress isolation
  (#70); provider-specific unclaimed-zone probing (a STATE open thread).
