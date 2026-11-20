# 0029. AI triage stage

- Status: accepted
- Date: 2026-11-19

## Context
Issue #25 adds the first AI feature that runs inside the scan pipeline: an LLM judges each
normalized finding (adjusted severity, false-positive likelihood, priority, remediation).
AGENTS.md rule 7 sets the boundary: scanners detect, the LLM judges, and it never creates or
closes findings. The pieces it builds on:

- ADR 0019 and ADR 0024: one `LLMProvider.complete()` contract with schema validation and one
  corrective retry, no sampling settings, no SDK retries (Celery retries the task), and a
  240 s deadline per call (`CALL_DEADLINE_SECONDS`).
- #24: org settings and monthly token budgets; `enforce_triage_budget` skips the triage job
  with a notice when AI is off or the budget is spent.
- ADR 0027: findings carry a stable fingerprint and an `evidence_digest`, and a scan's own
  observations are its `finding_observations` rows.
- ADR 0011: the chain ends `persist`, `diff`, `triage`, `finalize`; `triage` is an empty
  `PipelineTask`.

The forces:

- A failing `PipelineTask` fails the whole scan, but an LLM outage, a rate limit or a spent
  budget must never fail or delay a scan.
- `TrackedTask` stops a task after 300 s. One call can take 240 s, so a task that loops over
  many calls would be killed on any sizable scan.
- Scan data is attacker-influenced (TXT records, HTTP bodies, hostnames) and goes into prompts:
  prompt injection is the main threat (AGENTS.md rule 8).
- Tokens cost the org (its own key) or the operator (the capped instance key). Re-triaging
  unchanged findings on every scan wastes both.
- #26 (exposure summary) reuses the same prompt files, data wrapper and job pattern.

## Decision
- **Triage runs after the scan completes.** The chain becomes `persist`, `diff`, `finalize`.
  After `finalize_scan` commits the scan as `completed`, it creates one `triage` job for
  `ai.triage` on the `ai` queue through `jobs.create_job`. A broker failure fails only that job;
  `finalize_scan` logs it and returns. It is not a `ScanCompleted` handler: the in-process
  dispatcher is best effort. The job is created even when AI is off, so its skip carries the
  notice #24 asks for. `passive.triage` stays one release as a no-op that completes its job, so
  chains published before the deploy still finish.
- **AI tasks use `TrackedTask`, never `PipelineTask`.** Their failures mark their own job and
  never the scan.
- **One LLM call per job.** `ai.triage` coordinates: it runs the budget gate
  (`enforce_triage_budget`, which returns the resolved `LLMConfig`, or `None` after skipping
  the job), lists the assets with untriaged findings, and starts a workflow
  (`jobs.enqueue_workflow`) of one `ai.triage_batch` job per asset with an `ai.triage_done`
  tail. Each batch job makes one `complete()` call, so it fits the task time limit, and a
  Celery retry repeats only that call. Batch jobs return a chord receipt even when they fail, as
  scanner jobs do, so one failed batch never blocks the tail. Redis carries IDs only
  (ADR 0011): a batch job names its asset in `Job.asset_id` and loads the findings from the
  database. Batch and tail tasks are `ChordTask`s: Celery keeps their results, and errors reach
  the backend sanitized. If a batch task crashes anyway, the workflow's error callback
  `ai.triage_failed` closes the run's queued jobs; otherwise `ai.triage_done` skips that unused
  failure job. A domain archived after its scan is skipped with a notice.
- **One batch per asset per scan.** A batch holds one asset's most severe untriaged findings,
  at most `MAX_FINDINGS_PER_BATCH = 20`. Findings past the cap are sent by a later scan, when
  the ones judged now are cache hits; a job has no field to name a chunk, and with 25 DNS rules
  an asset rarely has more than 20 findings. Triage selects the active findings
  (`open`, `regressed`) this scan observed, from its `finding_observations` rows and never from
  `Finding.last_seen_scan_id`. `info` findings are included only when the instance setting
  `LLM_TRIAGE_INCLUDE_INFO` is true (default false).
- **The cache lives on the finding.** `Finding.ai_triage` holds a `StoredTriage` whose
  `cache_key` is the SHA-256 of the prompt version, model, fingerprint, evidence digest and
  every other finding field the prompt shows that can change under the same fingerprint and
  evidence: scanner severity, confidence, title and description (`TriageCacheInput`). A
  finding whose stored key still matches is not sent again; a change to any part triggers a new
  judgment. All parts are finding columns, so checking the cache loads no evidence. There is no
  cache table. Results are committed per batch. A judgment whose finding changed since (its key,
  rebuilt with its own prompt version and model, no longer matches) stays visible but is marked
  "Outdated" until a new run replaces it, since that run may be skipped or fail; a newer prompt
  or model alone doesn't mark it.
- **The budget is checked before every call.** Once it runs out, the remaining batch jobs are
  skipped with the notice. Batches running in parallel can each start one call after the cap
  is reached; the overshoot is bounded by one batch per `ai` worker.
- **What is sent.** Per batch: the asset's name and type. Per finding: a batch-local reference
  (`F1`, `F2`, ...), the rule ID, title, description, scanner severity and confidence, the
  location, and up to 5 evidence items, each string in them capped at 2,000 characters. Never
  sent: database IDs, org or user data, other assets' or other orgs' data, credentials, API keys
  or base URLs.
- **Scan data is delimited, escaped and capped.** Everything scan-derived is serialized as one
  JSON object inside a `<scan_data>` block, with `<` and `>` escaped as `<` and `>`, so
  no value can close the block. Capped fields carry a truncation marker. The system prompt says
  the block is data and that instructions inside it are never followed.
- **The output contract.** `TriageReply` (pydantic, `extra="forbid"`) holds one `FindingTriage`
  per reference: `adjusted_severity`, `confidence`, `false_positive_likelihood` (low, medium,
  high), `priority` (P1 to P4), `rationale`, `exploitability` and up to 5 `remediation_steps`,
  all length-capped. Unknown and duplicate references are dropped; findings missing from a reply
  stay untriaged. Priority is P1 to P4 rather than a rank: ranks from separate per-asset calls
  cannot be compared, while P1 to P4 plus adjusted severity orders a whole scan.
- **The AI never changes a finding.** Triage writes only `Finding.ai_triage`; `status`,
  `severity` and `confidence` stay the scanner's and the user's. The UI shows the adjusted
  severity next to the scanner's, labeled as AI-generated with the model and prompt version.
- **Prompts are versioned files.** `ai/prompts/<purpose>/v<N>.md`: plain text with
  `$placeholders`, no Jinja (there is no HTML to escape). A released version is never edited: a
  test pins each released file's SHA-256, and a change adds `v<N+1>`. The prompt version is
  stored with every result.
- **Code layout and the signatures the stage relies on.** `ai/schemas.py` holds the output
  models, `ai/untrusted.py` the scan-data block, `ai/triage.py` the input types and:
  - `build_triage_messages(batch: TriageBatch) -> list[Message]`
  - `triage_batch(provider: LLMProvider, batch: TriageBatch) -> LLMResult[TriageReply]`
  - `match_results(batch: TriageBatch, reply: TriageReply) -> dict[str, FindingTriage]`

  `services/triage.py` holds selection, storage and the job use cases; the tasks in
  `workers/tasks/ai.py` stay thin.
- **Usage and errors.** Every call is recorded with `record_llm_usage` (purpose `triage`) and
  committed before an error is re-raised. `LLMUnavailable` retries the batch through Celery.
  `LLMOutputError`, `LLMAuthError` and `LLMRequestError` fail the batch job with the error's safe
  message. None of them changes the scan.
- **Evals are opt-in.** `make eval` runs fixture batches against the provider configured in
  `.env` (`llm_live`, never in CI). CI runs only the eval harness, with `FakeLLMProvider`.

## Consequences
- Scans finish as fast as before; triage results appear afterwards, and the scan page polls
  its AI section on its own. The scan's progress count leaves AI jobs out.
- An LLM outage or a spent budget leaves findings untriaged but never blocks or fails a scan.
- A scan gets more job rows: the coordinator, one per batch and the tail.
- A crash between `finalize_scan`'s commit and the job's creation loses that scan's triage. The
  next scan picks the findings up, since nothing was cached.
- Eval results depend on the model; PRs that change a prompt record the model and the results.
- Rejected alternatives: triage inside the chain before `finalize` (delays scans, and its
  failures fail them); one long task with a raised time limit (still capped, and it holds one of
  the two `ai` workers for the whole run); a cache table (duplicates the finding row); a global
  priority rank; Jinja templates; a `ScanCompleted` handler.
- Follow-ups: delete `passive.triage` one release after the deploy; a per-org `info` toggle; a
  "triage again" action; #22 mounts the AI panel on the finding page; #26 queues `ai.summarize`
  from `ai.triage_done` and reuses the prompt files and the scan-data block.
