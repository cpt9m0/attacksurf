# STATE

> Handoff for the next session. Overwritten at the end of every task; not a history log.

**Updated:** 2026-10-27 · **Branch:** `12-scopeguard-safe-clients` · **PR/Issue:** #58 / #12

## Status
PR #58 open; fourth round of Codex findings addressed, awaiting re-review and CI on the new head.

## Last task
Round 4 on `953e6b6` — one P2, and the point where the decoder was restructured instead of
patched again:
- A gzip/deflate stream that ends before its final block does **not** raise in `zlib`: partial
  output comes back and the old code returned `truncated=False`. `_decoded` now checks
  `decoder.eof` after each member and reports incomplete streams as truncated.
- Decoding was split into `_decoded` (policy: encoding -> raw/clamped/truncated) and `_inflate`
  (the member loop), and the scattered tests were replaced by one 19-row table
  (`_DECODE_CASES`) covering every case from all four rounds.
- 3 new rows confirmed red on the old code; the 16 existing rows still pass.

Rounds 1-3 (earlier commits): grant enforcement before the first request and inside the client,
TARGET HTTP requiring ownership, root-scoped admission count under a row lock, `ScopePolicyError`
failing only its job, decoded-body ceiling, `//` path preservation, clamped fallbacks,
concatenated gzip members.

## Next step
Push and re-trigger Codex (`gh pr comment 58 -b "@codex review"`); confirm CI green on the new
head, then merge. Next issue per epic #31: #13 (assets UI) or #14 (verification).

## Open threads
- Active checks and target HTTP stay denied until #14 plugs a real `OwnershipChecker` into
  `workers.runtime.scanner_gate()`. The TARGET/verification invariant is enforced in two places
  (gate + registry) should #14 change the rules.
- Four review rounds have all landed in HTTP response decoding. Adding a case should now mean
  adding a row to `_DECODE_CASES`, not a branch in `_inflate`; if a fifth round needs a new
  branch, the design is wrong, not the edge case.
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
  that ends early, so completeness must be checked with `decoder.eof`.
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
