# STATE

> Handoff for the next session. Overwritten at the end of every task; not a history log.

**Updated:** 2026-11-23 · **Branch:** `30-mvp-acceptance` · **Task:** MVP acceptance: end-to-end test, security review, docs & `v0.1.0` prep (#30)

## Status
Completed GitHub issue #30 across PR #192 (`30-mvp-acceptance`) and cut `0.1.0` in `CHANGELOG.md`:
- Full-stack Chromium Playwright E2E test (`tests/e2e/test_mvp_e2e.py`) passing against real PostgreSQL, Flask/CSRF/CSP/HTMX/Alpine, ScopeGuard, DNS passive + verified-active plugins, AI triage/summary fakes, false-positive suppression, and rescan diffing.
- Exhaustive route-by-route security suite (`tests/integration/web/test_route_security.py`), static CSP/autoescape/settings AST guards (`tests/unit/web/test_security.py`), tenant-scoped `artifacts._defer_retry`, and `make audit` / CI `audit` (`pip-audit==2.10.1`) with remediated `uv.lock` advisories (`dnspython 2.9.2`, `filelock 4.2.9`, `opentelemetry-api 1.45.2`, `virtualenv 21.15.6`).
- Performance & scan-detail scaling (`tests/integration/workers/test_scale_1k.py`): batched job creation in `services.scans.dispatch_stage`, batched asset/relation upserts (`services.assets.record_assets` / `record_relations` in `persist_scan_output`), single-SELECT `run_check` pre-read, `MAX_DETAIL_JOBS = 200` UI cap with exact SQL `GROUP BY` status counts in `services.scan_views`, and `mark_completed = False` on `passive.scan`.
- Documentation suite (`README.md`, `docs/architecture.md`, `docs/scanners.md`, `docs/writing-a-scanner.md`, `docs/self-hosting.md`, `docs/responsible-use.md`) verified by `tests/unit/scanners/test_docs_sync.py`.

## Last task
- Added `tests/dns_fakes.py` (`MutableDnsZone`, `FakeWireTransport`, `patch_dnspython_wire`, `FakeScopeHttp`) and `tests/e2e/test_mvp_e2e.py`.
- Added `tests/integration/web/test_route_security.py` covering every registered route in `ROUTE_MATRIX` for classification, authentication, CSRF, admin-only RBAC, tenant isolation, and encrypted API key non-disclosure.
- Hardened `services/artifacts.py` (`_defer_retry` includes `Artifact.org_id == org_id`), added `make audit` + CI `audit` job + PostgreSQL-backed `web-e2e` CI job, and updated dependencies cleanly in `pyproject.toml` / `uv.lock`.
- Updated `services/scans.py` (`_plan_tasks`), `services/assets.py` (`record_assets`, `record_relations`), `services/scan_results.py`, `services/scanner_jobs.py`, `workers/base.py` (`mark_completed`), `workers/tasks/pipeline.py` (`passive.scan`), `services/scan_views.py` (`MAX_DETAIL_JOBS = 200`), and `web/templates/pages/_scan_progress.html`.
- Added/updated docs (`README.md`, `docs/architecture.md`, `docs/scanners.md`, `docs/writing-a-scanner.md`, `docs/self-hosting.md`, `docs/responsible-use.md`, `docs/README.md`, `docs/development.md`, `docs/security.md`, `CONTRIBUTING.md`, `AGENTS.md`, `CHANGELOG.md`).

## Next step
Wait for CI on PR #192 (`30-mvp-acceptance`), review and merge to `main`. Once CI is green on `main`, create and push annotated git tag `v0.1.0` (`git tag -a v0.1.0 -m "Release v0.1.0" && git push origin v0.1.0`) to trigger `.github/workflows/release.yml`, complete the manual VPS hardening/backup steps in `docs/deployment.md`, and close #30 and #31. On the sandbox track, PR 5 (`84-sandbox-ci`) remains next.

## Open threads
- **Proxy trust:** the proxy has no caller authentication and `worker-analysis` shares the
  `sandbox` network with it. Written up in `docs/security.md`; #92 must close it before prod.
- **Dropped dev jobs:** `worker-analysis` drops `analysis.*` messages until #87/#101 register
  tasks; the job rows stay `queued`.
- **#92 prerequisites:** proxy, launcher and worker in `compose.prod.yaml`, `runsc` on the VPS,
  and the profile guard test in `tests/unit/scanners/test_profiles.py` removed or changed.
- Follow-up issue to file (before #92): after a proxy restart a stray `attacksurf-*` container
  is alerted on but not removed.
- The `/tmp/attacksurf-sandbox` default can be claimed first by another local user on a shared
  host (symlink risk, `sandbox_launcher/artifacts.py`). Accepted in dev; revisit before #92.
- Nothing enforces "the artifact belongs to the job's org" before `SandboxRunner.run`: the first
  analysis scanner must `get_scoped` the artifact first, with a tenant-isolation test.
- From the AI summary work (#26): human-review requests remain (prioritize assets in the
  200-asset summary input, live eval results); `ai/pricing.py` still has no Claude list prices.

## Notes for the next agent
- Run `make screenshots` (or `uv run python scripts/capture_screenshots.py --out screenshots/latest`)
  after any template/CSS change to inspect all 20 views in light/dark at 1440px and 390px.
- Do not use `db_session` (`create_savepoint`) for multi-thousand-job tests like `test_scale_1k.py`;
  use `db_engine` + `create_session_factory(db_engine)` with org cleanup in `finally:` so Postgres
  subtransaction caches don't distort timing.
- The launcher copies proxy constants and `domain.scanners.MAX_OUTPUT_BYTES` on purpose (it may
  not import them); a parity test guards each copy. Don't "fix" that by importing.
- `sandbox-images.lock` is `{}`: the catalog is empty, so every `POST /runs` is a 404.
- Compose sandbox services have no `curl`; healthchecks use `python -c`.
- ADR numbers move fast: check `origin/main` and open branches for the next free number first.
- Production plugins are registered in `src/attacksurf/app.py` and `src/attacksurf/workers/app.py`.
- DB tests need `TEST_DATABASE_URL`; the dev stack exposes PostgreSQL on `127.0.0.1:5432` with an
  `attacksurf_test` database (`make test` runs them in `web`).
- The ruff format hook strips imports that aren't used yet: add imports with their first use.
- Keep `(created_at, id)` summary recency identical to `services.summary_views`.
