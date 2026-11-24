# STATE

> Handoff for the next session. Overwritten at the end of every task; not a history log.

**Updated:** 2026-11-23 · **Branch:** `74-vuln-intel-sync` · **Issue:** #74 (Sync vulnerability intelligence into a local store)

## Status
Implemented and tested on branch `74-vuln-intel-sync`; verifying full checks and opening PR #74.

## Last task
- Added `NVD_API_KEY` (`SecretStr`, `.env.example`) and extended `SafeHttpClient` (`headers`, `max_body_bytes`, `Host` protection, cross-origin sensitive-header stripping) (#74).
- Added pure `domain.vulnintel` contracts, CPE 2.3 parser, SemVer/vendor-suffix `compare_versions`, and `version_matches_range` evaluator, plus global read-only DB tables (`vuln_cves`, `vuln_cpe_ranges`, `vuln_sync_state`) via Alembic migration `0015` (#74).
- Added NVD/KEV/EPSS feed parsers & allowlisted client (`infra.vulnintel`), incremental/idempotent `sync_vuln_intel` + `match_product` (`services.vulnintel`), and the daily `passive.vulnintel_sync` Celery Beat task (#74).
- Added domain, infra, worker/beat, and DB integration tests, and synced `docs/architecture.md`, `docs/security.md`, `AGENTS.md`, `README.md`, and `CHANGELOG.md` (#74).

## Next step
Implement #72: Discover HTTP services on verified hosts and record URL assets (start after #74 PR is merged).

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
