# STATE

> Handoff for the next session. Overwritten at the end of every task; not a history log.

**Updated:** 2026-10-27 · **Branch:** `main` · **Merged:** PR #58 · **Next:** #13 or #14

## Status
#12 (ScopeGuard) merged to `main` as `de832bb`; CI green on main, branch deleted, local main
fast-forwarded. Nothing in flight.

## Last task
ScopeGuard and the guarded network clients (ADR 0013) landed through PR #58 after five Codex
review rounds (12 findings, all fixed and each regression-tested):
- Round 1: grant not enforced before the first HTTP request (P1); body cap bypassed on the
  runtime path; discovery cap counted the input asset instead of the scan root; `ScopePolicyError`
  failed the whole scan.
- Round 2: `TARGET` HTTP grant skipped ownership unless the plugin set `requires_verification`
  (P1, now tied in gate + registry); gzip decompression bomb; `//` path truncated to `/`;
  concurrent scans of one root each spending the full discovery allowance.
- Rounds 3-5: decoder fallbacks returned the uncapped wire buffer; concatenated gzip members
  dropped; incomplete streams reported as intact; unread slices dropped between members.
- Decoder now splits into `_decoded` (policy) and `_inflate` (member loop) with a 22-row table
  in `_DECODE_CASES`. Merge note: ~1,400 lines excl. tests, over the 400-line guideline.

## Next step
Pick up #13 (assets UI: root domain, asset list, detail with relations; `needs-design`, so read
`DESIGN.md` first) or #14 (DNS TXT ownership verification, which unblocks active checks). Both
are part of epic #31.

## Open threads
- Active checks and target HTTP stay denied until #14 plugs a real `OwnershipChecker` into
  `workers.runtime.scanner_gate()`. The TARGET/verification invariant lives in two places (gate
  and registry) and must stay consistent when #14 lands.
- Five straight review rounds landed in HTTP response decoding. If decoding is touched again and
  another edge case appears, stop patching: either cap compressed bodies only (no transparent
  decoding) or use a vetted library.
- `make test-worker` / e2e Compose tests were never run for #12.
- `.env.example` still needs auth settings (ALLOW_SIGNUP, SESSION_LIFETIME_HOURS, PROXY_COUNT).
- The pre-push hook runs `pytest` without `TEST_DATABASE_URL`, so 170 DB tests skip and coverage
  fails the gate unless you export it before `git push`. Worth fixing in the hook itself.

## Notes for the next agent
- New deps: httpx (httpcore transport), dnspython (stub resolver), tldextract (bundled PSL;
  pulling in requests, pinned by uv.lock). Never enable tldextract fetching or caching.
- `scoped()` returns an order-by query: use `select(func.count()).select_from(Model)` for counts.
- Fake plugins/gates live only in `tests/scanner_fixtures.py`; pipeline fixtures monkeypatch
  `pipeline.registry`/`PROFILES` (a check job resolves plugins through the task module globals).
- Response decoding: `_decoded` is the policy entry point, `_inflate` the member loop; cases live
  in `_DECODE_CASES` in `tests/unit/infra/test_http.py`. `zlib` does not raise on a stream that
  ends early, so completeness needs `decoder.eof`. When switching gzip members keep
  `decoder.unused_data + pending`. Test payloads must be incompressible, or a member never spans
  a slice and bugs hide.
- A `SafeHttpClient` built without `redirect_allowed` has *no* policy hook (bare transport, used
  by `test_http.py`); one built via `with_redirect_policy` enforces the hook on every hop.
  `with_redirect_policy` returns a plain `SafeHttpClient`, so a subclass's `_request` override is
  lost: fake the transport by overriding `with_redirect_policy` too.
- Tests needing a real second connection commit to `db_engine`; delete their rows in `finally` or
  later tests collide on `uq_orgs_slug` (`make_scan` always uses slug "acme").
- DB tests: `TEST_DATABASE_URL=postgresql+psycopg://attacksurf:attacksurf@localhost:5432/attacksurf_test uv run pytest`
  (dev Compose publishes Postgres on 5432).
- Stale shell groups: use `sg docker -c 'make up'`. Never chmod the Docker socket.
