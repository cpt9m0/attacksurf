# STATE

> Handoff for the next session. Overwritten at the end of every task; not a history log.

**Updated:** 2026-10-27 · **Branch:** `12-scopeguard-safe-clients` · **PR/Issue:** #58 / #12

## Status
PR #58 open; fifth round of Codex findings addressed, awaiting re-review and CI on the new head.

## Last task
Round 5 on `b5bcfc3` — one P2, and it exposed a flaw in how the round-4 tests were written:
- `_inflate` advanced to the next gzip member with `unused_data` alone, which holds only the
  tail of the *current* 64 KiB slice. A member ending mid-body therefore dropped the unread
  slices of the following member: a small member plus a 100 KB incompressible one decoded to
  ~64 KB, and when the first member ended on a slice boundary the second vanished with
  `truncated=False` (silent data loss). The buffer is now rebuilt from `unused_data + pending`,
  so both the unconsumed tail and the unseen slices survive the member switch.
- The round-4 table rows passed against the *broken* code because they used highly
  compressible payloads (`b'b' * 100_000`), whose wire bytes fit in one slice. Rows now use
  deterministic incompressible data (`hashlib`-derived, no `random`) so a member really spans
  slices. The bug only reproduces with incompressible input — worth remembering.
- 2 rows confirmed red on the old code. A third row (800 small members) passes both ways and is
  kept as a plain protocol case.

## Next step
Push and re-trigger Codex (`gh pr comment 58 -b "@codex review"`); confirm CI green on the new
head, then merge. Next issue per epic #31: #13 (assets UI) or #14 (verification).

## Open threads
- Active checks and target HTTP stay denied until #14 plugs a real `OwnershipChecker` into
  `workers.runtime.scanner_gate()`. The TARGET/verification invariant is enforced in two places
  (gate + registry) should #14 change the rules.
- Five review rounds have all landed in HTTP response decoding, three of them in code written to
  fix the previous round. If a sixth round lands here, stop patching: the next step is to drop
  streaming decompression and either cap compressed bodies only or use a vetted library.
- `make test-worker` / e2e Compose tests were not rerun for this branch.
- `.env.example` still needs auth settings (ALLOW_SIGNUP, SESSION_LIFETIME_HOURS, PROXY_COUNT).

## Notes for the next agent
- New deps: httpx (httpcore transport), dnspython (stub resolver), tldextract (bundled PSL;
  pulling in requests, pinned by uv.lock). Never enable tldextract fetching or caching.
- `scoped()` returns an order-by query: use `select(func.count()).select_from(Model)` for counts.
- Fake plugins/gates live only in `tests/scanner_fixtures.py`; pipeline fixtures monkeypatch
  `pipeline.registry`/`PROFILES` (a check job resolves plugins through the task module globals).
- Response decoding: `_decoded` is the policy entry point, `_inflate` the member loop; test cases
  live in `_DECODE_CASES` in `tests/unit/infra/test_http.py`. `zlib` does not raise on a stream
  that ends early, so completeness must be checked with `decoder.eof`. When switching gzip
  members, keep `decoder.unused_data + pending`: `unused_data` is only the tail of the current
  slice. Test payloads must be incompressible, or a member never spans a slice and bugs hide.
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
