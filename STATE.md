# STATE

> Handoff for the next session. Overwritten at the end of every task; not a history log.

**Updated:** 2026-11-24 · **Branch:** `76-web-tls-checks` · **Issue:** #76 (Check TLS certificates and configuration of web hosts)

## Status
Implemented and tested on branch `76-web-tls-checks`; verifying full suite and opening PR #76.

## Last task
- Added 7 TLS rules (`web.tls.cert_expired`, `cert_expiring`, `hostname_mismatch`, `untrusted_chain`, `weak_key`, `weak_signature`, `legacy_protocol`) in `src/attacksurf/domain/rules/web.py` (#76).
- Implemented `web.tls` (`src/attacksurf/scanners/web/tls.py`) using `ctx.runtime.tls.inspect`, recording capped `Asset.details["tls"]` and deterministic parsed-chain-summary evidence, and registered it in `web_active.checks`, `app.py`, and `workers/app.py` (#76).
- Added unit tests (`tests/unit/scanners/web/test_tls.py`, `test_profiles.py`) and Postgres integration tests (`tests/integration/workers/test_web_tls.py`), and synced `docs/scanners.md`, `docs/security.md`, and `CHANGELOG.md` (#76).

## Next step
Implement #77: Check HTTP security headers, cookies and HTTPS redirects (start after #76 PR is merged).

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
