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
pytest/coverage, import-linter) pass. The work is committed and pushed on PR #161
(https://github.com/cpt9m0/attacksurf/pull/161), which is ready (not draft), mergeable, and has
green CI (lint, tests 3.12/3.13/3.15, web-e2e, secrets, compose, pr-title). Codex completed its
review at `f1eff1c` with no findings and reacted 👍.

## Last task
- Added `DnsResolver.lookup_many`/`DnsQuery`/`DnsLookup`/`IpIntel` ports and the async
  `DnsPythonResolver` (public resolvers, timeouts, concurrency).
- Added `AssetObservation` to `ScanOutput`; persistence merges capped details, records
  `observed_at`, refreshes the input under the root lock, and locks input/discovered assets in a
  stable type/value order.
- Added `scanners/dns/resolve.py`, registered it in both entry points and the profile.
- Added `infra/ip_intel.py` (offline ip2asn TSV), the DNS rule module, asset-detail view models,
  template/CSS cards, config/env/compose entries, tests, ADR 0025 and docs updates.
- Addressed five rounds of Codex findings: partial-record errors, partial details, stale
  observations, failed PTRs, NUL TXT bytes, repeated negative ordering, shared-IP lock order and
  stale input rows.

## Next step
1. Human review/merge of PR #161. Codex is clean; no further automated review round is needed.
2. Optional acceptance polish: light/dark screenshots and a manual real-scan check. Start a scan
   through `scans.start_scan` (scan trigger UI is still #21), then open `/assets/<id>` and verify
   the CNAME → IP chain and records.
3. Before any future ADR, re-check the next free number; 0025 is used here.

## Open threads
- #16's PR is above the ~400-line guideline because it bundles resolver, scanner, graph,
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
- The scanner persists `Asset.details["dns"]` and `["ip"]`; `Asset.details["observed_at"]` orders
  replacements and `_observe` never deactivates a root/user asset.
- `persist_scan_output` locks the scan root, then the input and discovered assets in stable
  type/value order; keep that order when adding persistence paths.
- `dns.resolve` uses 40 DNS lookups per run; `MAX_DNS_LOOKUPS` is now 40 (CT still declares 20).
- Raw `lookup_many` records are deliberately not address-validated; connection paths still are.
- Production plugins need imports in both `app.py` and `workers/app.py`.
- The ruff format hook strips unused imports; add imports with their first use.
