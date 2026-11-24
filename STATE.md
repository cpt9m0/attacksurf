# STATE

> Handoff for the next session. Overwritten at the end of every task; not a history log.

**Updated:** 2026-11-23 · **Branch:** `71-guarded-tls-adapter` · **Issue:** #71 (Add a guarded TLS handshake adapter for scanners)

## Status
Done on branch `71-guarded-tls-adapter`; running verification and opening PR for #71.

## Last task
- Added `TlsInspection`, `TlsCertificate`, `TlsValidation`, `TlsInspector`, `UnconfiguredTls`, and `TlsError` in `domain/net.py`, and `tls` / `tls_ports` (`ALLOWED_WEB_PORTS`) in `domain/scanners.py` + `ScannerRegistry` active-queue/verification enforcement (#71).
- Implemented `SafeTlsClient` and `SocketTlsConnector` in `infra/tls.py` (IP pinning, SNI, 5 s timeout, 10-cert / 64 KiB DER chain cap, non-raising validation reporting, per-target rate limiter integration, best-effort legacy TLS probing) and wired `_GuardedTls` into `ScopeGuard`.
- Extended `tests/unit/scanners/test_network_boundary.py` to ban `ssl`, added `tests/unit/infra/test_tls.py` and ScopeGuard/registry tests, and synced `docs/security.md`, `docs/architecture.md`, and `CHANGELOG.md`.

## Next step
Implement #74: Sync vulnerability intelligence (NVD, CISA KEV, EPSS) into a local store (start after #71 PR is merged).

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
