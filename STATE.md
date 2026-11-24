# STATE

> Handoff for the next session. Overwritten at the end of every task; not a history log.

**Updated:** 2026-11-23 · **Branch:** `69-website-network-grants-adr` · **Issue:** #69 (ADR: network grants for website checks)

## Status
Done on branch `69-website-network-grants-adr`; running verification and opening PR for #69.

## Last task
- Added [ADR 0033](docs/adr/0033-website-network-grants.md) specifying website network grants (`tls`, `tls_ports`, `http_methods`, `http_ports`, `http_paths`, `soft_404_probe`, `follow_redirects`), verified-only target rules, `active` queue isolation, `ACTIVE_SCANS_ENABLED=false` kill switch, per-target Redis rate/concurrency limits, identifying `User-Agent`, `ssl` import ban, and the hard "never" list (#69).
- Updated `docs/security.md`, `docs/architecture.md`, and `CHANGELOG.md` (`[Unreleased]`).

## Next step
Implement #70: Open the active queue with egress isolation and per-target rate limits (start after #69 PR is merged).

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
- `tests/unit/scanners/test_docs_sync.py` checks every relative link in `docs/security.md`, `docs/architecture.md`, and other top-level docs.
