# 0030. AI exposure summary and notable assets

- Status: accepted
- Date: 2026-11-20

## Context
Issue #26 adds a post-scan AI exposure summary on top of the AI triage stage (#25, ADR 0029).
After a scan's findings are triaged, the security team wants one short, plain-language brief of
the domain's exposure: a headline, the top risks linked to real findings, which hosts look
sensitive and why (`admin.`, `jenkins.`, `vpn.`, `staging.`, `old.`), what changed since the last
scan, and what to do next. Hosts the AI flags also receive a `notable` tag so future active
scanners (such as the website module, #66) can inspect them first.

The forces mirror ADR 0029, plus two specific to whole-scan summaries:

- **One whole-scan view without flooding the prompt.** A scan can observe hundreds of assets and
  dozens of findings, and raw evidence has already been judged per finding during triage. Sending
  raw evidence again wastes tokens and widens the prompt-injection surface.
- **No hallucinated links.** The summary is shown on the scan page and dashboard with clickable
  links to findings and assets. A model must never invent finding or asset IDs, and database UUIDs
  must stay out of prompts (ADR 0029).
- **Failures must stay contained.** An LLM outage, rate limit, or spent budget must never fail or
  delay the scan or disturb its triage results, and a redelivered job must not pay twice.
- **Safe tagging.** The AI owns flagging notable hosts, but it must never disturb any other tag
  value, another root domain's assets, or another organization's assets.

## Decision
1. **When it runs.** Once per completed scan, as its own `ai.summarize` job (`TrackedTask`, one
   LLM call) on the `ai` queue. It is queued when triage ends: from `finish_triage` (the
   `ai.triage_done` job) when triage batches ran, and from `run_triage` when there was nothing new
   to triage, so an unchanged scan still produces a "changes since last scan" summary. It is not
   queued when triage was skipped (AI off, budget spent, domain archived); the UI card then shows
   that notice.
2. **Failures stay contained.** `run_summary` gates with `enforce_triage_budget` and records usage
   with `record_llm_usage` (purpose `"summary"`) on both success and failure, committing before
   re-raising. `LLMUnavailable` retries through Celery; `LLMOutputError`, `LLMAuthError`, and
   `LLMRequestError` fail only the `ai.summarize` job with the error's safe message. The scan and
   its triage results are never touched.
3. **What the model sees (`SummaryInput` in `ai/summary.py`).** No raw evidence. Everything
   scan-derived goes through `ai/untrusted.scan_data_block` as escaped, capped JSON inside
   `<scan_data>`, under batch-local references and never database IDs:
   - **Root domain** and **change stats** from `services.scan_views.parse_diff(scan.stats)` (new,
     fixed, regressed, and total findings by severity; new and disappeared asset counts and names).
   - **Findings:** up to 25 active findings this scan observed (from its `finding_observations`
     rows), referenced as `F1`..`F25`. Findings with a current (non-stale) triage come first,
     ordered by priority then adjusted severity; untriaged or stale findings follow by scanner
     severity. Each carries its ref, rule ID, title, scanner severity, and asset name; a current
     triage also adds priority, adjusted severity, false-positive likelihood, and a rationale
     capped at 300 characters.
   - **Assets:** up to 200 active assets under the scan's root (the root itself and its active
     discovered children), sorted deterministically by name, with their type, referenced as
     `A1`..`A200`.
4. **What the model returns (`ExposureSummary` in `ai/schemas.py`).** Strict pydantic model
   (`extra="forbid"`) whose docstrings and field descriptions speak to the model, with a pinned
   JSON-schema snapshot:
   - `headline`: non-empty string, at most 200 characters.
   - `key_risks`: at most 5 ranked items of `{finding_ref, why}` (`finding_ref` matches
     `^F[1-9][0-9]?$`, `why` non-empty and at most 300 characters).
   - `notable_assets`: at most 10 items of `{asset_ref, reason}` (`asset_ref` matches
     `^A[1-9][0-9]{0,2}$`, `reason` non-empty and at most 200 characters).
   - `changes`: non-empty string, at most 600 characters.
   - `next_actions`: at most 5 non-empty strings of at most 200 characters each.
5. **No invented references.** `validate_summary(summary_input, reply)` maps `finding_ref` and
   `asset_ref` back to real finding and asset UUIDs from the input, dropping any ref not present in
   the input and any duplicate ref (keeping the first occurrence in ranked order). `StoredSummary`
   stores the validated content with real finding/asset UUIDs plus `prompt_version`, `provider`,
   `model`, and `generated_at`.
6. **Storage.** Migration `0013` adds a nullable JSONB column `Scan.ai_summary` holding a
   `StoredSummary`. There is one summary per scan: if a redelivered `ai.summarize` job finds
   `Scan.ai_summary` already present (and valid), it returns without calling the LLM (no second
   payment).
7. **Notable tag.** Nothing writes `Asset.tags` today, so the AI owns the tag value `"notable"`.
   When a summary is stored, the root asset row is locked `FOR UPDATE` until commit to serialize
   publication for that root. Tags are synchronized only if this is the newest completed scan
   with a stored summary, ordered by `created_at` then `id` (the dashboard's order). An older
   scan keeps its historical summary and usage, but cannot replace newer tags; a newer scan
   without a summary does not block tagging. The lock is acquired only after the LLM returns,
   before adding the usage row (whose foreign-key autoflush would invert scan startup's
   root-before-organization lock order).
   `"notable"` is added to the active assets under the scan's root that the validated summary
   flagged, and removed from that root's other assets. No other tag value and no asset outside
   that root or organization is ever modified. Every query is tenant-scoped. If manual tagging
   is added later, `"notable"` must be reserved for the AI.
8. **Scan progress.** `SUMMARY_STAGE = "summary"` is added to `TRIAGE_STAGES` in
   `services/triage.py`, keeping the summary job out of the scan's own progress counts just like
   triage jobs.

## Consequences
- Every completed scan with AI enabled gets one concise exposure brief and up-to-date `notable`
  tags without delaying scan completion or adding raw evidence to another prompt.
- Every finding and asset link rendered from a summary is guaranteed to point at a real row from
  that scan's org and root; hallucinated refs are dropped before storage.
- Re-running or redelivering `ai.summarize` after it has already stored a summary costs zero
  tokens.
- A summary sees at most 25 findings and 200 active assets; larger scans still highlight the
  highest-priority issues first, while remaining findings are browsable on the findings page.
- Rejected alternatives: summarizing inside `ai.triage_done` (would turn the chord tail into an
  LLM call that could time out or fail the triage run); storing summaries in a separate table
  (there is strictly one summary per scan, so a JSONB column on `scans` mirrors
  `Finding.ai_triage`); letting the model output raw hostnames or UUIDs (invites hallucinated
  links).
- Follow-ups: future website and active scanners (#66) can prioritize assets carrying the
  `notable` tag; if user-editable tags are added later, reserve `"notable"` so user edits and AI
  updates cannot overwrite each other.
