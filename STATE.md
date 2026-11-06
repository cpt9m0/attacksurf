# STATE

> Handoff for the next session. Overwritten at the end of every task; not a history log.

**Updated:** 2026-11-05 · **Branch:** `test/126-hermetic-worker-settings` · **Issue:** #126

## Status
PR [#127](https://github.com/cpt9m0/attacksurf/pull/127) fixes test settings leaking during collection.
User authorized merging; conflicts with current main are resolved and locally verified.
PRs #123–#125 are merged; ownership verification is on main.

## Last task
- Keep both changelog entries when merging current main into PR #127; refresh this handoff.
- Preserve main's database ownership gate test alongside the collection-time regression.
- Hermetic worker settings are installed in `pytest_configure` before task proxies finalize
  Celery configuration; cleanup restores the original settings accessor.
- Validation: 923 passed, 3 worker E2E tests skipped; ruff check/format, pyright, and all
  pre-commit hooks pass. Full suite runs with a deliberately non-default Redis URL.

## Next step
Verify PR #127 CI after the conflict-resolution push, then squash-merge and update main.

## Open threads
- The previous local main handoff is preserved in a Git stash named
  `codex: preserve local handoff before PR 127`.
- #83 has separate sandbox/fetcher/tool ADR branches. Their planned ADR numbers 0014/0015 now
  collide with merged ownership ADRs; recheck and renumber those drafts before publishing.
- Dev DB needs migration `0007` before running the merged ownership code.
- Worker-less verification stays queued and polls indefinitely.
- Follow-ups: #114, #115, #116, #117. `.env.example` lacks ALLOW_SIGNUP,
  SESSION_LIFETIME_HOURS, PROXY_COUNT.

## Notes for the next agent
- Worker settings used by module-level Celery tasks must be installed before pytest collection.
- Ownership renewals are due after 20 hours; authorization expires after 24 hours (ADR 0015).
- Website roadmap starts with #69 ADR, #70 active queue, and #71 TLS adapter; verify dependencies.
