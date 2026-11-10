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
- **One lock order, and the root lock is taken once.** Every path that can touch a root's scans
  locks the scan rows first and the root second; that is the order `run_check` already had
  (`load_job_scan`, then persistence). `archive_root_domain` validates with a plain read, cancels
  the scans, and only then locks the root `FOR UPDATE`. `persist_scan_output` reads the root
  `FOR KEY SHARE`, or takes `FOR UPDATE` from the start when the discovery cap needs it. No path
  reads the root under one lock and later upgrades it: two transactions doing that wait on each
  other's shared lock and Postgres aborts one, whether the two are persists, archives, or an
  archive and a persist (all three found in review, #148). Either persistence commits first and
  the archive's update deactivates everything it created, or the archive commits first and the
  persist drops its output.
- **Nothing is left `queued` when the archive misses a scan.** `start_scan` can insert a scan
  after the archive's cancellation ran (it read an active root, then the archive committed).
  `dispatch_stage` therefore cancels a non-terminal scan it finds under an inactive root instead
  of returning quietly; otherwise the kickoff job completes and the scan never leaves `queued`.
  The stage's own job is skipped so `finalize` can still complete the scan.
- **Timestamps never move backwards.** Cancellation writes `clock_timestamp()`, the real time of
  the update, never `now()`: `now()` is the archive transaction's start, so a worker that
  committed `started_at` after the request began would otherwise trip `finished_after_started`
  and roll back the whole archive (also found in review, #148). Jobs use
  `greatest(started_at, clock_timestamp())` for the same reason.
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
