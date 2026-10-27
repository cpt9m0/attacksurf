# STATE

> Handoff for the next session. Overwritten at the end of every task; not a history log.

**Updated:** 2026-10-27 · **Branch:** `12-scopeguard-safe-clients` · **PR/Issue:** #58 / #12

## Status
PR #58 open; Codex review findings addressed in a follow-up commit, awaiting re-review. CI was
green before the fix commit and must be re-checked on the new head.

## Last task
Addressed all four Codex review findings on PR #58:
- **P1** `infra/http.py`: `SafeHttpClient.get()` now consults its policy hook before the *first*
  request, not only on redirects. The run-scoped client from `client_for()` is the inner client,
  so it previously bypassed `_GuardedHttp.get()` and could reach unlisted hosts (or make HTTP
  requests under a DNS-only grant).
- **P2** `infra/http.py`: the 1 MiB body ceiling moved into the client as `MAX_BODY_BYTES` /
  `bounded_limit()`, so a plugin-supplied `limit` can no longer exceed it. `MAX_HTTP_BYTES` in
  `scope_guard.py` is gone; both paths share the one clamp.
- **P2** `services/scan_results.py`: `_admit()` takes the scan root id and counts/looks up
  children of the root, matching the `parent_id=scan.root_asset_id` rows it writes. Subdomain
  checks no longer get a fresh discovered-asset allowance each.
- **P2** `services/scanner_jobs.py`: `ScopePolicyError` is caught with `ScopeError` and routed
  through `_gate_denied()`, which fails only that job (ADR 0013); previously it escaped and
  failed the whole scan.
- Tests: the review exposed that `tests/unit/infra/test_scope_guard.py`'s `_RunHttp` fake was
  *stricter* than production and hid the bypass. The fake now mirrors the real client, and new
  tests use a `SafeHttpClient` subclass with a recording transport. Added
  `tests/integration/services/test_scanner_jobs.py` (first tests for `run_check`). Each new test
  was confirmed red on the pre-fix code.
- ADR 0013 and CHANGELOG updated.

## Next step
Push the fix commit and re-trigger Codex (`gh pr comment 58 -b "@codex review"`); confirm CI is
green on the new head, then merge. Next issue per epic #31: #13 (assets UI) or #14 (verification).

## Open threads
- Active checks and target HTTP stay denied until #14 plugs a real `OwnershipChecker` into
  `workers.runtime.scanner_gate()`.
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
- DB tests: `TEST_DATABASE_URL=postgresql+psycopg://attacksurf:attacksurf@localhost:5432/attacksurf_test uv run pytest`
  (dev Compose publishes Postgres on 5432).
- Stale shell groups: use `sg docker -c 'make up'`. Never chmod the Docker socket.
