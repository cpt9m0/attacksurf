# STATE

> Handoff for the next session. Overwritten at the end of every task; not a history log.

**Updated:** 2026-11-23 · **Branch:** `72-web-probe-discovery` · **Issue:** #72 (Discover HTTP services on verified hosts and record URL assets)

## Status
Implemented and tested on branch `72-web-probe-discovery`; verifying full checks and opening PR #72.

## Last task
- Extended `SafeHttpClient`, `domain.net.HttpBody`, `ScannerGrant` (`http_ports`, `follow_redirects`), `ScopeGuard` (`AssetType.URL` validation, verified-root same-scope redirects, `stop_on_out_of_scope_redirect`), and `DbOwnershipChecker` (`URL` host-containment verification) (#72).
- Implemented `web.probe` (`scanners/web/probe.py`) and added the `web_active` profile (`PROFILES`, UI scan selector on `/scans` and `/assets/<id>`) (#72).
- Added unit tests (`test_probe.py`, `test_http.py`, `test_scope_guard.py`, `test_profiles.py`) and DB integration tests (`test_ownership.py`, `test_web_probe.py`, `test_scans_ui.py`, `test_scans_api.py`), and synced `docs/scanners.md`, `docs/architecture.md`, `docs/security.md`, and `CHANGELOG.md` (#72).

## Next step
Implement #73: Fingerprint web technologies and versions on URL assets (start after #72 PR is merged).

## Open threads
- **Proxy trust:** the proxy has no caller authentication and `worker-analysis` shares the `sandbox` network with it (`docs/security.md`; #92 must close it before prod).
- **Dropped dev jobs:** `worker-analysis` drops `analysis.*` messages until #87/#101 register tasks; the job rows stay `queued`.
- **#92 prerequisites:** proxy, launcher and worker in `compose.prod.yaml`, `runsc` on the VPS, and the profile guard test in `tests/unit/scanners/test_profiles.py` removed or changed.
- Follow-up issues to file (before #92): stray `attacksurf-*` container cleanup after proxy restart; `/tmp/attacksurf-sandbox` symlink hardening.
- First analysis scanner calling `SandboxRunner.run` must `get_scoped` the artifact first with a tenant-isolation test.
- From AI summary (#26): prioritize assets in the 200-asset summary input, live eval results, and Claude list prices in `ai/pricing.py`.

## Notes for the next agent
- Production plugins are registered in `src/attacksurf/app.py` and `src/attacksurf/workers/app.py`.
- DB tests need `TEST_DATABASE_URL`; the dev stack exposes PostgreSQL on `127.0.0.1:5432` with `attacksurf_test`.
- `ScopeGuard` defaults `active_scans_enabled=False`; tests exercising active checks with `ScopeGuard` directly must pass `active_scans_enabled=True`.
