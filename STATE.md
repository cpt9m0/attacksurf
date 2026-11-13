# STATE

> Handoff for the next session. Overwritten at the end of every task; not a history log.

**Updated:** 2026-11-13 · **Branch:** `17-dns-email-security` · **Issue:** #17 (DNS check: email security (SPF, DMARC, DKIM, MTA-STS))

## Status
#17 is **implemented and verified on this branch**, not yet pushed or PR'd. Issue stays open
until the PR merges (`Closes #17`).

## Last task
- Added the `dns.email` passive scanner (root domains only): one `lookup_many` round reads TXT
  at the apex, `_dmarc`, `_mta-sts` and six common `<selector>._domainkey` names; evaluates SPF
  (missing / multiple / permissive incl. implicit `?all`, `redirect=` suppresses `all` /
  >10 DNS-querying terms), DMARC (missing incl. multiple or policy-less records / `p=none` /
  no reporting / `pct<100`, fired independently), DKIM (no usable key on any probed selector,
  low confidence; `v=` optional, empty `p=` is revoked) and MTA-STS (missing, info). Findings
  only, raw TXT as `dns_record` evidence. Partial DNS errors fail open per check; an all-error
  run raises `TransientJobError`.
- Added all ten `dns.email.*` rules to `domain/rules/dns.py` with remediation + RFC references;
  wired `dns.email` into `dns_passive` checks and both plugin-import lists (web + worker).
- Tests: 26 new tests in `tests/unit/scanners/dns/test_email.py` plus profile assertion.
  Checks: ruff check + format, lint-imports (6 kept), pyright, pre-commit (all hooks, caches
  redirected to /tmp), full pytest 1704 passed / 19 skipped, coverage 97%.
- Docs synced: `CHANGELOG.md` [Unreleased], `docs/architecture.md` (profile + email bullet),
  `docs/security.md`. README already listed email security; no ADR (no new architectural
  choice: check-only plugin on existing ports), no migration, no new dependency (`checkdmarc`
  rejected in favour of a stdlib parser).

## Next step
1. Push `17-dns-email-security` and open the PR (`feat(scanners): add email security check
   (#17)`, `Closes #17`), then start #18 (subdomain takeover; depends on #16, now unblocked).

## Open threads
- SPF lookup counting is per published record (top-level DNS-querying terms); recursive
  `include:` expansion is not fetched, so a record can exceed 10 lookups via nested includes
  without a finding. Deliberate for the DNS budget; revisit if #19/#20 want deeper evaluation.
- DKIM probing covers six common selectors only, hence low confidence by design.

## Notes for the next agent
- `.venv/bin/<tool>` works; bare `uv run` / pre-commit need caches redirected
  (`UV_CACHE_DIR`, `PRE_COMMIT_HOME`, `GOCACHE`, `GOPATH` under /tmp).
- DB tests from the host: `TEST_DATABASE_URL='postgresql+psycopg://attacksurf:attacksurf@127.0.0.1:5432/attacksurf_test'`
  and `PATH="$PWD/.venv/bin:$PATH"` (the alembic CLI test shells out to `alembic`).
