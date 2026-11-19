# STATE

> Handoff for the next session. Overwritten at the end of every task; not a history log.

**Updated:** 2026-11-19 · **Branch:** `27-scheduled-rescans` · **Issue:** #27 (scheduled rescans)

## Status
Implemented and open as PR #185 (`Closes #27`), branched from `origin/main` `db663bd`. Local
checks are green: pytest 2994 passed / 20 optional skips (95.9% coverage), web-e2e 14 passed,
ruff, ruff format, pyright, import-linter (8 kept), pre-commit and the pre-push pytest hook.

## Last task
- `0012_add_scan_schedules` + `ScanSchedule` (one per root, same-org FK, unique, enabled/due
  CHECK, partial due index).
- `services.scan_schedules`: registration seeding (`SCAN_DEFAULT_FREQUENCY`, weekly by default;
  restored roots keep their row), tenant-scoped `get_schedule`/`save_schedule` (a same-preference
  save keeps the clock), and `enqueue_due_scans` (per-org due reads, root-then-schedule
  `FOR UPDATE SKIP LOCKED`, one attempt per slot, active scans consume it, quota defers 1 h).
- `dns_scheduled` in `WORKER_PROFILES` only (`dns.resolve`, `dns.email`, `dns.dnssec`).
- `passive.enqueue_due_scans` every minute (`expires: 60`); admin/member root-overview card and
  `POST /assets/<id>/schedule`; docs, DESIGN, README, CHANGELOG.

## Next step
Review and merge PR #185; no other issue work is in progress on this branch.

## Open threads
- Existing roots have no `ScanSchedule` row until an admin saves the card (shown as off); no
  backfill migration on purpose. Re-adding a restored root can run an overdue saved schedule on
  the next tick.
- Scheduled runs use only the three read-only DNS checks; discovery, takeover, AXFR and active
  HTTP stay manual. Omitted scanners never auto-fix their findings (`scan_diff` is per scanner).
- Candidate reads issue one due query per org each minute (tenant boundary); the oldest 20 go
  per delivery. Measure before adding pagination or a system-level index.
- Broker failure marks the scan/job failed and consumes the slot; no outbox.
- No email alerts (the README previously implied them); they are not part of #27.

## Notes for the next agent
- DB tests need `TEST_DATABASE_URL`; this session used the existing `attacksurf-test-db` on
  `127.0.0.1:5433` with database `attacksurf27_test`.
- The plan is at `../attacksurf/.hermes/plans/2026-11-19_180451-27-scheduled-rescans.md`.
- `tests/integration/services/test_scan_schedules.py` imports the worker app to register the
  production DNS plugins; without it, `registry.validate` fails.
- The beat tick freezes time by patching `workers.tasks.system.datetime` in
  `tests/integration/workers/test_scan_schedule_task.py`; no new test dependency.
