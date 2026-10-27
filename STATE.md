# STATE

> Handoff for the next session. Overwritten at the end of every task; not a history log.

**Updated:** 2026-10-27 · **Branch:** `12-scopeguard-safe-clients` · **PR/Issue:** #58 / #12

## Status
PR #58 open; second round of Codex findings addressed, awaiting re-review and CI on the new head.

## Last task
Round 2 of Codex review on `4db6396` — four more findings, all reproduced first, all fixed:
- **P1** `infra/scope_guard.py` + `scanners/registry.py`: nothing tied `HttpPermission.TARGET` to
  `requires_verification`, so a plugin declaring target HTTP with the flag `False` skipped the
  ownership check entirely (`is_verified` was never called) and got a client for the scanned
  host. The gate now requires ownership for any TARGET grant regardless of the flag, and the
  registry rejects the inconsistent metadata at registration.
- **P2** `infra/http.py`: `_read_capped` capped *wire* bytes, then `httpx.Response(content=...)`
  decompressed unbounded (8,175 bytes of gzip -> 8 MiB). The client now decodes gzip/deflate
  itself via incremental `zlib` with the cap on decoded output, drops `Content-Encoding`, and
  only allows the `MAX_EXPANSION` wire headroom for encoded responses.
- **P2** `infra/http.py`: `_target` parsed `parts.path` alone, so `//api/v1` was read as an
  authority and sent as `/v1`. It now uses the full URL's `raw_path`.
- **P2** `services/scan_results.py`: overlapping scans of one root could each read the same
  count and admit the full allowance (`start_scan` allows overlap; each holds only its own
  `Scan` lock). `_admit` now takes `FOR NO KEY UPDATE` on the root before counting.
- Round 1 (previous commit): grant enforcement before the first request, body ceiling inside the
  client, root-scoped admission count, `ScopePolicyError` failing only its job.
- Each regression test was confirmed failing on the pre-fix code. ADR 0013, `docs/security.md`,
  CHANGELOG and STATE updated.

## Next step
Push and re-trigger Codex (`gh pr comment 58 -b "@codex review"`); confirm CI green on the new
head, then merge. Next issue per epic #31: #13 (assets UI) or #14 (verification).

## Open threads
- Active checks and target HTTP stay denied until #14 plugs a real `OwnershipChecker` into
  `workers.runtime.scanner_gate()`. The TARGET/verification invariant is now enforced in two
  places (gate + registry) should #14 change the rules.
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
