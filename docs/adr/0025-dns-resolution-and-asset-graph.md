# 0025. DNS resolution: record data, IP/CNAME graph and lifecycle

- Status: accepted
- Date: 2026-11-12

## Context
Issue #16 resolves every discovered (sub)domain and builds the graph later IP and web modules
consume. ADR 0013 makes ScopeGuard the only network boundary; ADR 0022 marks wildcard zones but
deliberately leaves resolution to this issue. DNS answers are untrusted, can be large, and may
contain private addresses that are interesting to report but must never be contacted. The
scanner also needs to mark a discovered subdomain inactive when it no longer resolves, without
ever deactivating a root the org added itself.

## Decision
- **Resolver configuration:** `DnsPythonResolver` uses configurable public recursive resolvers
  (`DNS_RESOLVERS`, public IPs only), per-query and overall timeouts, and a concurrency limit
  (`DNS_TIMEOUT_SECONDS`, `DNS_LIFETIME_SECONDS`, `DNS_MAX_CONCURRENCY`). It keeps the sync
  resolver for HTTP/ownership paths and uses `dns.asyncresolver` for `lookup_many`, which runs
  queries concurrently under a semaphore. Search domains and SERVFAIL retries stay disabled.
- **Two DNS views, one gate:** `DnsResolver` gains `lookup_many(queries)` returning raw record
  values plus an `OK`/`NXDOMAIN`/`NO_ANSWER`/`ERROR` status. `_GuardedDns` charges the plugin's
  DNS budget for each query but does not run `check_addresses` on raw records: they are data, not
  connection targets. `resolve_ipv4`/`resolve_name` still validate every address, and the safe
  HTTP client only connects through those. A private A/AAAA answer can therefore be reported
  without weakening SSRF protection.
- **Scanner:** `dns.resolve` is a passive check on domains/subdomains with a 40-lookup grant and
  a 60-second budget. It queries A, AAAA, CNAME, MX, NS, TXT, CAA and SOA, follows CNAMEs up to
  five hops, asks for the terminal A/AAAA, performs reverse DNS for the first ten addresses and
  looks up ASN/organisation in an optional offline ip2asn TSV (`IP_ASN_DB_PATH`). No new
  dependency and no network download: a missing database simply disables enrichment.
- **Asset details:** scanners can return `ScanOutput.observations` (`AssetObservation`). An
  observation carries a capped JSON `details` bag and an optional `active` claim. Persistence
  merges details top-level, so a scanner replaces its own `dns`/`ip` subtree without clobbering
  another scanner's keys. DNS records live under `details["dns"]` (`a`, `aaaa`, `cname`, `mx`,
  `ns`, `txt`, `caa`, `soa`, `cname_chain`, `private_ips`); IP enrichment lives under
  `details["ip"]` (`ptr`, `asn`, `org`, `country`). Values are normalized, deduplicated and
  capped (5 records/type, 256 characters, 16 KiB per observation). Details carry a top-level
  `observed_at` marker: only an observation at least as new may replace them, so a delayed
  older scan cannot erase newer records. A partial lookup failure withholds the whole `dns`
  replacement (a top-level merge would otherwise drop the failed record type); a confirmed
  empty answer does replace it with an empty subtree. Reverse DNS failures likewise withhold
  that IP's `ip` subtree instead of erasing a known PTR. NUL bytes in DNS character-strings
  are stored as a visible `\0`, because PostgreSQL JSONB cannot represent U+0000.
- **Graph:** A/AAAA answers create `ip` assets and `resolves_to` edges from the scanned asset to
  each address (effective resolution). CNAME hops create assets and `cname_to` edges only for
  names at or under the scan root; external targets stay in `cname_chain` and are neither tenant
  assets nor scanned. Assets and relations are emitted in a stable type/value order, so
  concurrent scans that share IP rows take their upsert locks in the same order. The asset
  detail page renders the chain and the records, so the acceptance criterion is visible even
  when the terminal CNAME target is external.
- **Lifecycle:** a discovered subdomain with no records at all becomes `is_active=false` with
  `deactivated_at` set to the scan's sighting time; a name with only MX/TXT/NS stays active.
  Only rows with a parent can be deactivated, so roots/user assets never are. Out-of-order
  results never move lifecycle backwards: repeated negative observations advance
  `deactivated_at` even while the row is already inactive, so a delayed positive result cannot
  reactivate it. Persistence refreshes the input row as part of the same stable asset-lock
  order it uses for discovered assets, so a transaction that waited on the root lock cannot
  use a stale copy and overlapping roots cannot deadlock. A wildcard-marked zone
  (`target_is_wildcard`) is never deactivated on an empty answer. CT rediscovery can reactivate a name later; a full
  reconciliation policy belongs to #20.
- **Exposure finding:** each private, loopback, link-local or special-purpose address found in
  public A/AAAA data emits `dns.records.private_ip_exposed` at info severity, with the address
  as `location` and the CNAME chain as DNS evidence. The IP asset is still recorded and linked;
  no connection is attempted.
- **UI/API:** `AssetDetail` gains parsed `dns`/`ip` view models; `GET /api/v1/assets/<id>` gains
  the same additive fields. Scan-derived values are escaped and display-capped.

## Consequences
- No migration: `Asset.details` JSONB and the existing relation kinds cover everything.
- IP assets discovered through DNS count toward the profile's `max_discovered_assets` cap, like
  other discovered assets; cap-dropped observations/relations are skipped, never guessed.
- External CNAME targets are metadata only. Later checks that need to test the target (e.g.
  takeover, #18) can read `cname_chain`; turning them into assets would require a hostname asset
  type and a deliberate ownership decision.
- A non-resolving subdomain is excluded from future check fan-out until CT or a later
  reconciliation sees it again. This is intentional history-preserving behavior, not a promise
  to keep probing a dead name.
- Raw DNS records are untrusted and never used to choose a connection address. Private-address
  detection is observational; it does not make private targets scannable.
- The ASN database is operator-supplied public data; no paid API and no runtime fetch. A missing
  file degrades enrichment only.
