# 0010. Celery worker runtime: sessions, job lifecycle, failure handling

- Status: accepted (supersedes the worker-session line of ADR 0008)
- Date: 2026-10-15

## Context
ADR 0003 picked Celery + Redis and ADR 0008 said tasks would use `sessionmaker.begin()`. Building
the workers (#10) showed that doesn't fit: services commit themselves, one per use case, and a
task's lifecycle (start, finish, retry) is several separate commits that must survive the task
body failing. Workers also must not depend on Flask, and importing task code (tests, tooling) must
not read the environment.

## Decision
- **Sessions:** each worker process owns one session factory (`workers.runtime.session_factory`,
  rebuilt after fork). Tasks and `TrackedTask` open short sessions with
  `with runtime.session_factory()() as session:` and call services, which commit.
  No Flask app (context) in workers.
- **Configuration:** the worker Celery app reads `Settings` lazily on first use
  (`app.add_defaults`), never at import.
- **Job lifecycle:** every tracked task has a `Job` row, which is the source of truth (results are
  ignored). `services.jobs.create_job` commits the row before sending the task. `TrackedTask`
  records `running → completed / failed` (`queued` again on retry), skips redelivered tasks of
  finished jobs, and never overwrites a cancellation (row lock, fresh read).
- **Failures:** only `TransientJobError` is retried by Celery; a database outage around the
  lifecycle writes is retried too. `Job.attempts` counts deliveries and caps them at
  `max_retries + 2`, so a task that keeps killing its worker (`acks_late` +
  `reject_on_worker_lost` redeliver it) ends `failed` instead of looping.
- **Error data:** `Job.error` stores the exception type, plus the message only for our own
  `JobError`s (written to be safe). Logs get the same sanitized error and the stack frames, never
  the raw exception; Celery's own tracer logger is silenced in workers for that reason.
- **Routing:** a task's name prefix is its queue, each queue has its own direct exchange and
  routing key, and unknown prefixes are rejected.

## Consequences
- Lifecycle writes are extra round trips per task: fine at our volume.
- A web process killed between commit and enqueue leaves a `queued` job without a message, and
  a hard time-limit kill leaves one `running`; the stale-job sweeper (#21) re-dispatches or fails
  them. No transactional outbox for now.
- Exception messages from third-party code are not stored or logged; debugging relies on the
  error type and stack frames.
