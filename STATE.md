# STATE

> Handoff for the next session. Overwritten at the end of every task; not a history log.

**Updated:** 2026-11-24 · **Branch:** `75-web-components` · **Issue:** #75 (Flag known-vulnerable web components from fingerprints)

## Status
Implemented and tested on branch `75-web-components`; running full verification and opening PR #75.

## Last task
- Added `web.components.known_vulnerable` rule in `src/attacksurf/domain/rules/web.py` (#75).
- Exposed read-only `VulnIntelLookup` (`domain.net`), `DbVulnIntelLookup` (`services.vulnintel`), `ScopeGuard(vuln_intel=...)`, `workers/runtime.py` wiring, and `ScanContext.target_details` (`scanner_jobs.py`), plus volatile EPSS/description stripping in `_digest_json` (`scan_results.py`) (#75).
- Implemented `web.components` (`scanners/web/components.py`) with curated technology → CPE mapping, CVSS severity + CISA KEV severity bump, `Confidence.MEDIUM`, and capped CVE/KEV/EPSS evidence, and wired it into `web_active.checks`, `app.py`, and `workers/app.py` (#75).
- Added unit tests (`tests/unit/scanners/web/test_components.py`, `test_profiles.py`) and Postgres integration tests (`tests/integration/workers/test_web_components.py`), and updated `docs/scanners.md`, `docs/security.md`, and `CHANGELOG.md` (#75).

## Next step
Implement #76: Check TLS certificates and configuration of web hosts (start after #75 PR is merged).

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
