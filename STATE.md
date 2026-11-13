# STATE

> Handoff for the next session. Overwritten at the end of every task; not a history log.

**Updated:** 2026-11-13 · **Branch:** `18-dns-subdomain-takeover` · **Issue:** #18 (DNS check: dangling CNAME / subdomain takeover candidates)

## Status
#18 is **implemented, verified, and open as PR #164** (draft; branch pushed; pre-push pyright +
pytest passed). Issue stays open until the PR merges (`Closes #18`).

## Last task
- Split design (user-approved): a `TARGET` HTTP grant makes ScopeGuard skip unverified assets
  before a plugin runs, so the passive DNS findings and the HTTP confirmation are two plugins.
  `dns.takeover` (passive, DNS-only, domains + subdomains) follows the CNAME chain ≤5 hops and
  fires `dns.takeover.dangling_cname` (high) when the terminal name suffix-matches a
  known-claimable NXDOMAIN-type service and returns NXDOMAIN, plus `dns.takeover.dangling_ns`
  (critical, medium confidence, per-host `location`) for NS hosts that are NXDOMAIN.
  `dns.takeover.http` (passive queue, `requires_verification` + `TARGET` grant) re-walks the
  chain and makes one plain-HTTP GET of the asset only when the terminal matches a resolving
  claimable service; body/status signature ⇒ `dns.takeover.fingerprint_match` (high) with
  CNAME chain + response snippet evidence.
- Dataset: pinned subset of can-i-take-over-xyz @ `5bd4e12` (CC-BY-4.0) in
  `scanners/dns/fingerprints.json` — the 24 vulnerable entries with a CNAME pattern and a
  usable signal; validating literal-substring loader (`fingerprints.py`, never regex) and
  `fingerprints-NOTICE.md` attribution/transform note. `uv build` verified the JSON ships.
- Tests: 28 new tests (`test_takeover.py`, `test_takeover_http.py`, S3 `NoSuchBucket` fixture
  proves the acceptance criterion) + profile assertion. Codex review follow-up: NS attribution
  is withheld for aliased names (RFC 1034 §3.6.2 — a CNAME owner holds no other data, so the
  NS answer is the target's), and redirect-status fingerprints are dropped (Helprace 301: the
  client follows redirects, and a redirect alone does not prove an unclaimed instance) with a
  loader invariant (`REDIRECT_STATUSES`) so they cannot return. Checks: ruff check/format,
  lint-imports (6 kept), pyright, pre-commit all hooks, full pytest 1749 passed / 19 skipped,
  coverage 95.71%.
- Docs synced: `CHANGELOG.md` [Unreleased], `docs/architecture.md` (profile + takeover
  bullet), `docs/security.md`. README already listed takeover detection; no ADR (applies
  ADR 0013/0014 as-is), no migration, no new dependency or setting.

## Next step
1. Watch PR #164 CI (`lint`, `test (3.12/3.13/3.15)`, `secrets`, `compose`, `pr-title`) and
   merge when green; then start #19 (DNSSEC / NS / MX / CAA / RDAP / AXFR; depends on
   #16/#17/#18 per epic #31).

## Open threads
- "Dangling NS" is scoped to *NS target hostname is NXDOMAIN*; detecting an unclaimed zone on
  a resolving provider nameserver (e.g. DigitalOcean-style) needs provider-specific probing
  and is a follow-up candidate, not built.
- A few upstream fingerprints contain regex-style artifacts (`.*`, HTML entities) and are
  inert under literal matching until upstream publishes plain text (see fingerprints-NOTICE).
- Helprace (`HTTP_STATUS=301`) is not detected: see the notice. Revisit only with
  Location-header-aware logic that distinguishes a same-host https redirect from a redirect
  to the vendor's error page.
- Fingerprint entries with no CNAME pattern are not matched by body alone (false-positive
  risk on ordinary 404 pages); deliberate.

## Notes for the next agent
- `.venv/bin/<tool>` works; git hooks need caches redirected or they fail on
  `/home/ubuntu/.cache` (`UV_CACHE_DIR`, `PRE_COMMIT_HOME`, `GOCACHE`, `GOPATH` under /tmp),
  and the pre-push hook needs `TEST_DATABASE_URL` set in the same command.
- DB tests from the host: `TEST_DATABASE_URL='postgresql+psycopg://attacksurf:attacksurf@127.0.0.1:5432/attacksurf_test'`
  and `PATH="$PWD/.venv/bin:$PATH"` (the alembic CLI test shells out to `alembic`).
