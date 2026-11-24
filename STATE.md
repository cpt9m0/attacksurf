# STATE

> Handoff for the next session. Overwritten at the end of every task; not a history log.

**Updated:** 2026-11-23 · **Branch:** `70-active-queue-rate-limits` · **Issue:** #70 (Open the active queue with egress isolation and per-target rate limits)

## Status
Done on branch `70-active-queue-rate-limits`; PR open for review.

## Last task
- Opened the `active` queue (`infra/queue.py`, `workers/tasks/pipeline.py` `active.scan`), moved `dns.takeover.http` and `dns.axfr` to `active`, and enforced active-queue routing in `ScannerRegistry` (#70).
- Added `worker-active` on isolated `active-egress` networks in `compose.yaml` and `compose.prod.yaml`.
- Added `ACTIVE_SCANS_ENABLED` (default `false`), `ACTIVE_TARGET_RATE_LIMIT_*`, `SCANNER_CONTACT_URL` / `scanner_user_agent` (`config.py`, `.env.example`), `RedisTargetRateLimiter` / `InMemoryTargetRateLimiter` (`infra/rate_limit.py`), and enforcement in `SafeHttpClient` and `ScopeGuard`.

## Next step
Implement #71: Add a guarded TLS handshake adapter for scanners (start after #70 PR is merged).

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
- `ScopeGuard` now defaults `active_scans_enabled=False`; tests exercising active checks with `ScopeGuard` directly must pass `active_scans_enabled=True`.
