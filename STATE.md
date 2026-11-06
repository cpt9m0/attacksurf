# STATE

> Handoff for the next session. Overwritten at the end of every task; not a history log.

**Updated:** 2026-11-05 · **Branch:** `14-ownership-verification-single` · **Issue:** #14 (DNS TXT ownership)

## Status
PR [#123](https://github.com/cpt9m0/attacksurf/pull/123) is open into `main`.
Three review fixes are implemented and validated; the user has authorized commit and push.

## Last task
- Separate renewal (`recheck_at`, 20 hours) from authorization expiry (24 hours); migration
  `0007` backfills existing deadlines without extending authorization. ADR 0015 records it.
- Poll the viewed asset so inherited subdomain cards remain read-only after HTMX refresh.
- Propagate NS discovery errors as transient failures instead of querying an unconfirmed parent.
- Add regressions for early renewal, inherited polling, migration backfill, and expired-proof
  failure handling. Update architecture/security docs, DESIGN.md, and CHANGELOG.md.
- Validation: pytest 922 passed / 3 worker E2E tests skipped, 97.66% coverage; ruff check/format,
  pyright (0 errors), and all pre-commit hooks pass. No live browser check in this task.

## Next step
Check PR #123 CI and review the three addressed threads. Human security review precedes merge.

## Open threads
- Dev DB needs migration `0007` before running this code; migration `0006` is unchanged.
- Worker-less verification stays queued and polls indefinitely.
- Follow-ups: #114 shell overflow, #115 tag editing, #116 cancel scans on archive,
  #117 overlapping roots. `.env.example` lacks ALLOW_SIGNUP, SESSION_LIFETIME_HOURS, PROXY_COUNT.

## Notes for the next agent
- Keep #14 in one PR into `main`; stale branches and PRs #121/#122 are not authoritative.
- DB tests use `TEST_DATABASE_URL=postgresql+psycopg://attacksurf:attacksurf@localhost:5432/attacksurf_test`.
- Next feature work after #14 merges: website module (#69 ADR, #70 active queue, #71 TLS adapter).
