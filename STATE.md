# STATE

> Handoff for the next session. Overwritten at the end of every task; not a history log.

**Updated:** 2026-10-27 · **Branch:** `12-scopeguard-safe-clients` · **PR/Issue:** #58 / #12

## Status
PR #58 open; third round of Codex findings addressed, awaiting re-review and CI on the new head.

## Last task
Round 3 on `d11ee95` — two more P2s, both in the round-2 decoder, both reproduced first:
- `_decoded`'s raw-body fallbacks (corrupt gzip, unknown encoding, `zlib.error`) returned the
  whole retained wire buffer, which may be `min(limit*20, 2 MiB)`: `_decoded(b'not gzip'*250_000,
  'gzip', 1 MiB)` returned 2,000,000 bytes. All returns now go through `_clamped()`, which slices
  to `limit` and flags truncation, so no path can exceed the ceiling.
- Concatenated gzip members were silently dropped after the first (`decoder.unused_data` was
  ignored): `gzip.compress(b'first') + gzip.compress(b'second')` returned only `b'first'`. The
  decoder now loops over members under one cumulative output budget.
- 4 new tests, each confirmed red first. ADR 0013 and CHANGELOG updated.

Rounds 1 and 2 (earlier commits on this branch): grant enforcement before the first request and
inside the client, TARGET HTTP requiring ownership, root-scoped admission count under a row lock,
`ScopePolicyError` failing only its job, decoded-body ceiling, `//` path preservation.

## Next step
Push and re-trigger Codex (`gh pr comment 58 -b "@codex review"`); confirm CI green on the new
head, then merge. Next issue per epic #31: #13 (assets UI) or #14 (verification).

## Open threads
- Active checks and target HTTP stay denied until #14 plugs a real `OwnershipChecker` into
  `workers.runtime.scanner_gate()`. The TARGET/verification invariant is enforced in two places
  (gate + registry) should #14 change the rules.
- The decoder grows with each review round; if round 4 lands here again, consider moving
  response decoding into its own module with a table of tests instead of patching it further.
- `make test-worker` / e2e Compose tests were not rerun for this branch.
- `.env.example` still needs auth settings (ALLOW_SIGNUP, SESSION_LIFETIME_HOURS, PROXY_COUNT).

## Notes for the next agent
- New deps: httpx (httpcore transport), dnspython (stub resolver), tldextract (bundled PSL;
  pulling in requests, pinned by uv.lock). Never enable tldextract fetching or caching.
- `scoped()` returns an order-by query: use `select(func.count()).select_from(Model)` for counts.
- Fake plugins/gates live only in `tests/scanner_fixtures.py`; pipeline fixtures monkeypatch
  `pipeline.registry`/`PROFILES` (a check job resolves plugins through the task module globals).
- A `SafeHttpClient` built without `redirect_allowed` has *no* policy hook (bare transport, used
  by `test_http.py`); one built via `with_redirect_policy` enforces the hook on every hop.
- `with_redirect_policy` returns a plain `SafeHttpClient`, so a subclass override of `_request`
  is lost: fake the transport by overriding `with_redirect_policy` too.
- Tests that need a real second connection commit to `db_engine`; delete their rows in `finally`
  or later tests collide on `uq_orgs_slug` (`make_scan` always uses slug "acme").
- DB tests: `TEST_DATABASE_URL=postgresql+psycopg://attacksurf:attacksurf@localhost:5432/attacksurf_test uv run pytest`
  (dev Compose publishes Postgres on 5432). The pre-push hook runs pytest *without* this, so
  export it before `git push`.
- Stale shell groups: use `sg docker -c 'make up'`. Never chmod the Docker socket.
