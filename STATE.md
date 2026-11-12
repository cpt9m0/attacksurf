# STATE

> Handoff for the next session. Overwritten at the end of every task; not a history log.

**Updated:** 2026-11-12 · **Branch:** `16-dns-resolution` · **Issue:** #16 (DNS resolution)

## Status
Implementation is complete in the worktree `.worktrees/16-dns-resolution` (branch
`16-dns-resolution`, from `origin/main` `917e2b4`). The branch adds `dns.resolve` to the
`dns_passive` profile, configurable public resolvers with async bounded lookups, per-asset DNS/IP
details, IP/CNAME graph edges, inactive non-resolving subdomains, offline ip2asn enrichment, the
`dns.records.private_ip_exposed` info finding, and the asset-detail DNS/IP cards. ADR 0025 records
the decisions. No migration and no new dependency. Local checks (ruff, format, pyright,
pytest/coverage, import-linter) pass. The work is committed in four logical commits and pushed
as draft PR #161 (https://github.com/cpt9m0/attacksurf/pull/161).

## Last task
- Added `DnsResolver.lookup_many`/`DnsQuery`/`DnsLookup`/`IpIntel` ports and the async
  `DnsPythonResolver` (public resolvers, timeouts, concurrency).
- Added `AssetObservation` to `ScanOutput`; persistence merges capped details and applies
  lifecycle only to discovered assets.
- Added `scanners/dns/resolve.py`, registered it in both entry points and the profile.
- Added `infra/ip_intel.py` (offline ip2asn TSV), the DNS rule module, asset-detail view models,
  template/CSS cards, config/env/compose entries, tests, ADR 0025 and docs updates.

## Next step
1. From the worktree run the full gate again:
   `ruff check`, `ruff format --check`, `pyright`, `pytest` (with `TEST_DATABASE_URL`),
   `lint-imports`, `pre-commit run --all-files`.
2. Wait for CI on draft PR #161; fix any failures.
3. Manual acceptance: `make up`, add a real domain, start a scan through `scans.start_scan`
   (scan trigger UI is still #21), then open `/assets/<id>` and verify the CNAME → IP chain and
   records. Capture light/dark screenshots for the PR.
4. Before pushing, re-check the next free ADR number; 0025 is used here.

## Open threads
- #16's PR is likely above the ~400-line guideline because it bundles resolver, scanner, graph,
  enrichment and UI. If review size is a problem, split from commit 3 into a stacked
  `16-ip-intel-ui` PR; the commit boundaries support that.
- Wildcard ancestry: `dns.resolve` avoids deactivating a directly marked zone, but a subdomain
  under a marked wildcard zone is not tracked yet. A full reconciliation policy belongs to #20.
- `IP_ASN_DB_PATH` is operator-supplied; no ip2asn data ships in the repo. Without it, ASN/org
  enrichment is empty but scans succeed.
- External CNAME targets stay in `details["dns"]["cname_chain"]`; they are not tenant assets or
  scanned. #18 can consume the chain.

## Notes for the next agent
- Worktree `.venv` is a symlink to the main checkout's venv; run tools as
  `PATH=<repo>/.venv/bin:$PATH PYTHONPATH=<worktree>/src .venv/bin/python -m pytest`.
- DB tests need `TEST_DATABASE_URL=postgresql+psycopg://attacksurf:attacksurf@localhost:5432/attacksurf_test`.
- The scanner persists `Asset.details["dns"]` and `["ip"]`; `_observe` merges top-level keys and
  never deactivates a root/user asset.
- `dns.resolve` uses 40 DNS lookups per run; `MAX_DNS_LOOKUPS` is now 40 (CT still declares 20).
- Raw `lookup_many` records are deliberately not address-validated; connection paths still are.
- Production plugins need imports in both `app.py` and `workers/app.py`.
- The ruff format hook strips unused imports; add imports with their first use.
