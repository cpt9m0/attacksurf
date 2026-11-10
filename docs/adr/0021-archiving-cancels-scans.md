# 0021. Archiving a root domain cancels its in-flight scans in the database

- Status: accepted
- Date: 2026-11-10

## Context
Archiving a root domain (#13) deactivates the root and its discovered assets and `start_scan`
refuses inactive roots. A scan that was already queued or running kept going (#116): discovery
kept inserting subdomains under the archived root as *active* assets (a fresh insert never
consults `deactivated_at`), checks kept recording findings, and the scan showed as `running`.
ADR 0010 makes the `Job` row the source of truth for task state; ADR 0011 makes persistence the
last step before a chord receipt. The issue asked whether the archive should wait for or revoke
Celery tasks (ADR 0010/0011).

## Decision
- **Cancel in the database, in the archive's own transaction.** `archive_root_domain` moves the
  root's `queued`/`running` scans to `ScanStatus.CANCELLED` (with `finished_at`, and `started_at`
  from the database clock when the scan never started, so `finished_at >= started_at` holds),
  cancels their `queued`/`running` jobs, and audits one `scan.cancelled` per scan next to the
  `asset.root_archived` entry. Completed scans and finished jobs are untouched.
- **Neither wait nor revoke.** Celery holds no cancellation that fits this. `revoke` by
  `celery_task_id` misses every task that has not started yet (the id is only recorded once a
  task runs) and cannot cover tasks inside a chord header; re-sending revokes is unreliable and
  still not a guarantee. Waiting would block a web request on scanner I/O. Workers therefore run
  tasks normally, and the database decides what they may write. This supersedes the implicit
  "cancellation is only what `fail_scan` does" reading of ADR 0010.
- **Persistence refuses cancelled scans and archived roots.** `persist_scan_output` raises
  `ScanCancelled` for a terminal scan and `AssetNotFound` when the scan's root is inactive;
  `run_check` maps both onto its job (failed with the type name, chord receipt still returned), so
  a cancelled scan never writes assets, relations, findings or evidence. Orchestration checks the
  root too: `dispatch_stage` and `finalize_scan` do nothing for an inactive root, so an archived
  scan neither fans out checks nor completes.
- **One lock orders archive and persistence.** `persist_scan_output` locks the scan's root row
  `FOR UPDATE` before writing anything, and `archive_root_domain` takes the same lock first.
  Either the archive commits first and the persist drops its output, or persistence commits first
  and the archive's update deactivates everything it created. `_admit`'s cap counting relies on
  that same lock instead of taking its own.
- **New scans never race the archive.** `start_scan` reads the root with `populate_existing`, so a
  committed archive is never hidden by a stale copy in the session.

## Consequences
- Archiving is the only cancellation path for now; a user-facing "cancel scan" would reuse
  `_cancel_scans` and the same persistence guards.
- Queued tasks still run once and no-op (`TrackedTask` skips finished jobs, `dispatch_stage` and
  `run_check` see the terminal scan), so cancellation costs a few wasted deliveries, not work.
- A task killed between `mark_job_running` and its persist leaves a `running` row; that is the
  stale-job sweeper's job (#21), unchanged here.
- Sights from a cancelled scan are never written, so the live/fixed inference of #20 sees no
  sightings for a cancelled run: absence still means "unknown", never "fixed".
