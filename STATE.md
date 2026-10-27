# STATE

> Handoff for the next session. Overwritten at the end of every task; not a history log.

**Updated:** 2026-10-27 · **Branch:** `12-scopeguard-safe-clients` · **Issue:** #12 (ScopeGuard)

## Status
Implementation complete on the branch, committed; no PR opened yet.

## Last task
- Added `domain/scope.py` (pure rules: blocked IPv4/IPv6 ranges, internal/single-label names,
  allowlist matching), `domain/net.py` (DNS/HTTP/runtime ports), `infra/public_suffix.py`
  (bundled PSL, no fetch), `infra/dns.py`, `infra/http.py` (pinned IP, Host/SNI kept, redirect
  allowlist, time/size caps, env proxies off), `infra/scope_guard.py` (ScopeGuard + per-run
  granted adapters, `UnverifiedOwnership`).
- Scanners declare a frozen `ScannerGrant`; the registry validates it. `run_check` builds
  `ScanContext.runtime` after the gate approves. `workers.runtime.scanner_gate()` now returns the
  real guard. Profiles may set `max_discovered_assets` (enforced at persistence).
- ADR 0013, security/architecture docs, CHANGELOG, AGENTS.md and the add-scanner skill updated.
- Ruff, format, import-linter, pre-commit, pyright and the DB-backed pytest suite pass
  (648 passed, 3 opt-in skipped, coverage 97%); module-import test blocks raw network libs in
  `scanners/`.

## Next step
Open a draft PR for this branch (`Closes #12`, title `feat(security): add ScopeGuard and
guarded network clients`), then implement #13 (assets UI) or #14 — check epic #31 for what is
unblocked.

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
- DB tests: `TEST_DATABASE_URL=postgresql+psycopg://attacksurf:attacksurf@localhost:5433/attacksurf_test uv run pytest`.
- Stale shell groups: use `sg docker -c 'make up'`. Never chmod the Docker socket.
