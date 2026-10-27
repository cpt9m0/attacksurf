# 0011. Scanner contracts, pipeline receipts and bounded execution

- Status: accepted
- Date: 2026-10-26

## Context
Issue #11 needs composable plugins and Celery orchestration without coupling plugins to the
database, putting evidence in Redis, or letting an ordinary scanner error break a chord.
Discovery must persist its assets before per-asset checks can be planned. ScopeGuard, lifecycle
diffing and AI triage belong to later issues (#12, #20, #25).

## Decision
- Put the `Scanner` protocol and pydantic `ScanOutput` in `domain/scanners.py`. Pydantic is an
  I/O-free validation dependency (MIT); the domain still imports no infrastructure or SDKs.
  Plugins return typed, normalized asset references (type + value), relations and catalog rule
  IDs with evidence. Services, not plugins, choose tenant IDs, row IDs and lifecycle states.
- Register plugin classes explicitly with `@register_scanner`; profiles name discovery and
  check plugins. Currently only `passive` workers are supported. `requires_verification` names
  the active-check flag unambiguously. No real plugins ship here; the default gate denies all
  execution until #12, and the fake plugins/gate live exclusively in tests.
- Use Redis-backed chords for discovery/check groups and immutable chains for continuation
  stages. Commit each batch of `Job` rows before publication via the `PipelineQueue` port;
  reuse rows under a scan lock on orchestration redelivery. Retain the existing `TaskQueue`
  port for the kickoff job. No DB dependency table or migration is needed.
- Normalize/persist each scanner result **before** returning its chord receipt; `persist` is
  the subsequent barrier. This refines the target stage diagram: discovery becomes visible
  before fan-out, and Redis only stores `None` receipts, never findings or evidence. Persist
  data and the scanner job's terminal status atomically, with fingerprint upserts and
  deterministic per-scan evidence IDs to make replay safe.
- Scanner jobs use a daemon thread with their declared wall-time budget. Threads have **no DB
  access**. Ignore late results; cap unfinished threads at four per prefork child. Python cannot
  kill a thread: adapters still need I/O deadlines, and children recycle after 100 tasks to
  reclaim abandoned work. Celery retains its 300/330-second soft/hard outer limits.
- Retry `TransientJobError` as before. Exhausted retries, ordinary exceptions and scanner
  budget exhaustion fail only the scanner's `Job`, then return a successful receipt so the
  chord continues. Guard denials skip the job. Unexpected orchestration/persistence failures
  fail the scan; callbacks and the task failure hook make this idempotent. Sanitize exceptions
  before they reach Celery's result backend, including retry exceptions.
- Leave `diff` and `triage` as explicit no-op jobs. Never mark absent findings fixed or reopen
  suppressed/fixed findings here. `FindingFixed` is defined, but emitted only when #20 adds a
  real fixed transition. `Scan.stats` stays empty until then.
- Dispatch identifier-only `FindingCreated` and `ScanCompleted` events after commit, through
  an in-process dispatcher. Handler failures are isolated and sanitized.

## Consequences
- A completed scan can contain failed/skipped checks; inspect its jobs for coverage. Check
  targets are the active root and its known direct children, not an unbounded recursive crawl.
- Findings retain first/last scan IDs and monotonic timestamps across out-of-order results;
  evidence deduplicates within a scan but remains available across distinct scans.
- The dispatcher is best-effort, not exactly-once: a process crash after commit can lose an
  event. Durable delivery/outbox is deliberately not introduced yet.
- The commit/publish gap, hard-killed tasks and duplicate orchestration publication still need
  #21's stale-job sweeper. Idempotent SQL prevents duplicate results; it is not exactly-once
  execution or publication. Permanently hung threads can exhaust a child until it recycles.
- No UI/API endpoints, network-enabled checks, diff engine or LLM integration are added here.
