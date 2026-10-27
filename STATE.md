# STATE

> Handoff for the next session. Overwritten at the end of every task; not a history log.

**Updated:** 2026-10-27 · **Branch:** `11-scanner-pipeline` · **Issue:** #11

## Status
#11 implementation complete; CI and review must pass before merge.

## Last task
- Added validated scanner contracts, registry/profiles, discovery/check Celery chords and
  continuation stages, tenant-scoped scan services, atomic fingerprint/evidence persistence,
  bounded scanner execution, sanitized failures and best-effort post-commit events (ADR 0011).
- No schema/UI changes. Production execution is denied pending ScopeGuard (#12); fake plugins
  and the permissive fixture-only gate live in tests. `dns_passive` has no real scanners yet.
- `diff`/`triage` remain no-op seams (#20/#25); no lifecycle transitions or stats are inferred.
- Full suites: 513 passed on Python 3.12/3.13, coverage 98.09%; the two worker tests pass separately.
  Ruff, pyright, import-linter, pre-commit and changed-file secret scanning pass.
- Updated architecture/security/development docs, README, changelog, AGENTS and scanner skill.

## Next step
Review/merge the #11 PR from `11-scanner-pipeline` after CI passes. Then implement #12:
replace `workers.runtime.scanner_gate()` with ScopeGuard and add safe network adapters.

## Open threads
- #53 tracks an existing clock-boundary CSRF test flake; the unchanged suite passes on rerun.
- #20 owns finding fixed/regressed/suppression semantics, per-scan observations and stats;
  `FindingFixed` is defined but not emitted until actual fixed transitions exist.
- #21 owns the stale-job sweeper, concurrent scan limit and cancellation UI/API. Publication
  and event delivery are not exactly-once; see ADR 0011 for thread/publication limitations.
- `.env.example` still needs auth settings (ALLOW_SIGNUP, SESSION_LIFETIME_HOURS, PROXY_COUNT).

## Notes for the next agent
- Test Postgres/Redis containers: `attacksurf-issue11-pg` / `attacksurf-issue11-redis` (stopped).
  Start with `sudo docker start attacksurf-issue11-pg attacksurf-issue11-redis`.
- DB tests: `TEST_DATABASE_URL=postgresql+psycopg://attacksurf:attacksurf@localhost:5433/attacksurf_test uv run pytest`.
- Scanner outputs never go through Redis. Threads never access DB; timed-out threads cannot be
  killed, so four unfinished threads exhaust a child until it recycles (100 tasks).
- All fake-worker tests remain in the existing `make test-worker` / CI e2e path; no workflow edits.
