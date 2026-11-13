# STATE

> Handoff for the next session. Overwritten at the end of every task; not a history log.

**Updated:** 2026-11-13 · **Branch:** `19-dns-hygiene-checks` · **Issue:** #19 (DNS hygiene: DNSSEC, NS/MX, CAA, RDAP expiry, AXFR)

## Status
PR #165 (`feat(scanners): add DNS hygiene checks (#19)`, `Closes #19`) is open, mergeable and
green: CI (lint, compose, secrets, test 3.12/3.13/3.15, web-e2e, pr-title) passes and the Codex
review passed on `eaee255` ("Didn't find any major issues"). Local checks: ruff check/format,
lint-imports (6 kept), pyright, pytest 1864 passed / 19 skipped, coverage above the 80% gate.

## Last task
- Implemented #19: six check-only plugins in `dns_passive` (`dns.dnssec`, `dns.ns`, `dns.mx`,
  `dns.caa`, `dns.whois`, `dns.axfr`; 11 rules), all `DOMAIN`-only; the zone-level checks run
  only when the asset is itself a zone apex.
- New grant capabilities `authoritative_dns`, `rdap`, `zone_transfer` (ADR 0026), with grant-gated
  `AuthoritativeLookup` (owner-checked zone discovery, validated nameserver addresses, read-only
  SOA/DNSKEY probes, one AXFR per server when the name owns NS) and `RdapClient` (IANA bootstrap,
  https-only, target/registrable domain only, 24 h cache of trimmed public data).
- Addressed the Codex review findings on #165: chunked DNSKEY presentation (`3fa1650`), CD
  diagnostic zone discovery so a bogus zone still reveals its authorities (`db1caba`), every CAA
  ancestor within the lookup budget (`d8a30e9`), and fallback MX evidence attributed to the name
  that publishes the RRset (`eaee255`).
- Tests: 6 scanner suites + RDAP/authoritative/gate/registry tests + RDAP fixtures; no live
  network.
- Docs synced: ADR 0026, architecture, security, AGENTS rule 6, `add-scanner` skill, CHANGELOG.
  No migration, setting or dependency.

## Next step
1. Merge PR #165 (squash; `Closes #19` closes the issue), then delete the branch.
2. Pick the next unblocked issue in epic #31 (check #21/#22 first; #20 dedupe follows).

## Open threads
- DNSSEC validates only the DS↔DNSKEY linkage; RRSIG signature validation is a follow-up.
- A subdomain root that is not a delegated zone gets no `dns.ns`/`dns.dnssec`/`dns.axfr` findings
  (they belong to its registrable domain); add that domain as a root to see them.
- RDAP failures are fail-open (no finding), so a transient outage looks like "no issue" to #20's
  diffing until a later scan succeeds.
- `dns.axfr` runs on the `passive` queue because the `active` queue is reserved (#70).
- Zone-level findings on two roots in one zone are not deduplicated across assets (#20).

## Notes for the next agent
- `uv run` fails on the uv cache here (`/home/ubuntu/.cache`); use `.venv/bin/<tool>` directly.
- Git hooks need caches redirected (`UV_CACHE_DIR`, `PRE_COMMIT_HOME`, `GOCACHE`, `GOPATH` under
  /tmp) and the pre-push hook needs `TEST_DATABASE_URL` in the same command.
- DB tests: `TEST_DATABASE_URL='postgresql+psycopg://attacksurf:attacksurf@127.0.0.1:5432/attacksurf_test'`
  and `PATH="$PWD/.venv/bin:$PATH"` (the alembic CLI test shells out to `alembic`).
