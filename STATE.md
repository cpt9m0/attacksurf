# STATE

> Handoff for the next session. Overwritten at the end of every task; not a history log.

**Updated:** 2026-11-13 · **Branch:** `19-dns-hygiene-checks` · **Issue:** #19 (DNS hygiene: DNSSEC, NS/MX, CAA, RDAP expiry, AXFR)

## Status
#19 is implemented and verified on the branch; the commits are ready to push as a draft PR with
`Closes #19`. Local checks: ruff check/format, lint-imports (6 kept), pyright, pytest 1858 passed /
19 skipped, coverage 95.14%.

## Last task
- Six new check-only plugins in the `dns_passive` profile: `dns.dnssec`, `dns.ns`, `dns.mx`,
  `dns.caa`, `dns.whois`, `dns.axfr` (11 new rules), all `DOMAIN`-only; the zone-level checks run
  only when the asset is itself a zone apex.
- New grant capabilities `authoritative_dns`, `rdap`, `zone_transfer` (ADR 0026). ScopeGuard
  builds grant-gated adapters: `AuthoritativeLookup` (owner-checked zone discovery, validated
  nameserver addresses, ≤3 read-only SOA/DNSKEY probes, one AXFR per server when the name owns
  NS), and `RdapClient` (IANA bootstrap, https-only, target/registrable domain only, 24 h cache
  of trimmed public data).
- DNSSEC verifies the DS↔DNSKEY linkage (key tag/algorithm/digest, SHA-1/256/384), not RRSIG
  signatures. AXFR is active: the registry and the gate require verification for
  `zone_transfer`, and only the first message's record count is kept.
- Tests: 6 scanner suites + RDAP/authoritative/gate/registry tests + RDAP fixtures; no live
  network.
- Docs synced: ADR 0026, architecture, security, AGENTS rule 6, `add-scanner` skill, CHANGELOG.
  No migration, setting or dependency.

## Next step
1. Commit (split: infra+grants, DNSSEC/NS, MX/CAA, RDAP, AXFR, profile wiring, docs), push, open
   the draft PR titled `feat(scanners): add DNS hygiene checks (#19)`, confirm CI, merge.
2. Then pick the next unblocked issue in epic #31 (check #21/#22 first; #20 dedupe follows).

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
