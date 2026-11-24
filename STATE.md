# STATE

> Handoff for the next session. Overwritten at the end of every task; not a history log.

**Updated:** 2026-11-23 · **Branch:** `73-web-fingerprint` · **Issue:** #73 (Fingerprint web technologies and versions on URL assets)

## Status
Implemented and tested on branch `73-web-fingerprint`; running full verification and opening PR #73.

## Last task
- Added `web.disclosure.version_banner` rule in `src/attacksurf/domain/rules/web.py` and registered `WEB_RULES` in `domain.rules` (#73).
- Vendored a curated 66-technology signature subset from `enthec/webappanalyzer` (`GPL-3.0`, pinned commit `7dba7bf3e8b4f25c6a5b4b2c9f5e7a0e73e6a1bf`) in `src/attacksurf/scanners/web/fingerprints.json` with attribution in `fingerprints-NOTICE.md`, keeping passive channels only (`headers`, cookie names only, `meta`, `script_src`, `html`) and dropping unsafe/nested-quantifier regexes (#73).
- Implemented `src/attacksurf/scanners/web/fingerprint.py` and integrated it into `web.probe` (`scanners/web/probe.py`) with zero extra HTTP requests, storing `Asset.details["technologies"]` and reporting `web.disclosure.version_banner` with `HTTP_RESPONSE` evidence (#73).
- Added unit tests (`tests/unit/scanners/web/test_fingerprint.py`, `test_probe.py`) and DB integration assertions (`tests/integration/workers/test_web_probe.py`), and updated `docs/scanners.md`, `docs/security.md`, and `CHANGELOG.md` (#73).

## Next step
Implement #75: Flag known-vulnerable web components from fingerprints (start after #73 PR is merged).

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
