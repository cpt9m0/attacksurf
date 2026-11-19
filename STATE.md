# STATE

> Handoff for the next session. Overwritten at the end of every task; not a history log.

**Updated:** 2026-11-19 · **Branch:** `25-ai-triage` · **Issue:** #25 (AI triage stage)

## Status
In progress: commits 1-7 of 9 on draft PR #186; triage now runs end to end (no UI yet).

## Last task
- Plan: one PR per issue (Angela: #25 now; sten-ctrl: #26 after #25 merges), kept in the Claude
  Doc "#25 + #26: one PR per issue" (not in the repo). cpt9m0 approved the oversized PR.
- Commits 1-4: ADR 0029; the contract (`ai/schemas.py`, `ai/triage.py`); `ai/prompts`
  (`load_prompt`, pinned hashes) and `ai/untrusted.scan_data_block`; prompt `triage/v1` with
  `build_triage_messages`, `triage_batch`, `match_results` (5 evidence items per finding, strings
  capped at 2,000 characters; `docs/security.md` lists what's sent).
- Commit 5: the chain tail is `persist`, `diff`, `finalize`; `finalize_scan(session, queue,
  ...)` queues an `ai.triage` job (`TrackedTask`) after the scan's completion commits;
  `passive.triage` is a no-op for one release.
- Commit 6: `services/triage.py` (`assets_to_triage`, `build_asset_batch` returning
  `AssetTriage`, `store_triage`, `stored_triage`) and the `LLM_TRIAGE_INCLUDE_INFO` setting. One
  batch per asset per scan (at most 20 findings, most severe first; the rest come with a later
  scan as cache hits pile up): ADR 0029 updated.
- Commit 7: `run_triage` (coordinator: gate, skip archived domains, one `ai.triage_batch` job
  per asset + `ai.triage_done` tail + `ai.triage_failed` error callback, rows reused on
  redelivery), `run_triage_batch` (one call; usage on success and failure; raises only
  `LLMUnavailable` while retries remain), `finish_triage`, `fail_triage`.
  `enforce_triage_budget` returns `LLMConfig | None`. `workers.base.ChordTask` now holds the
  chord-member behavior `PipelineTask` had (kept results, sanitized errors).

## Next step
Commit 8: the AI panel. A `components/ai_panel.html` macro (AI-generated label, model + prompt
version, adjusted next to scanner severity, FP likelihood, priority, rationale, exploitability,
remediation; autoescaped, CSP-safe styles) replacing #22's raw-JSON placeholder in
`finding_detail.html`; a polled "AI triage" section on the scan page (`get_scan_triage`: job
states, triaged findings sorted by priority, 100-row cap); the scan's own job count leaves the
`triage*` stages out. Tests: XSS payload escaped, tenant isolation, polling stops.

## Open threads
- #22 shipped an "AI triage" placeholder on the finding page (`finding_detail.html`, raw JSON of
  `ai_triage`): commit 8 replaces it with the AI panel and adds the scan page section.
- #27 took migration `0012`: #26's `Scan.ai_summary` migration is `0013`.

## Notes for the next agent
- Pydantic puts a reply model's docstring and field descriptions into the JSON schema the model
  sees: keep them model-facing, put developer notes in comments. A change to them changes the
  snapshot and needs a new prompt version.
- `anthropic.transform_schema` moves unsupported limits (`maxLength`, `pattern`) into
  descriptions; pydantic still enforces them locally, and the corrective retry covers misses.
- Write invisible or non-ASCII test characters with `chr(...)`: ruff rejects them raw (PLE2515).
- Integration tests that need the production DNS plugins import the worker app first (see
  `tests/integration/services/test_scan_schedules.py`), or `registry.validate` fails.
- On this laptop Postgres listens on `127.0.0.1:5433` (local `compose.override.yaml`, excluded
  from git): start Docker Desktop, `docker compose up -d --wait postgres`, then
  `TEST_DATABASE_URL=postgresql+psycopg://attacksurf:attacksurf@127.0.0.1:5433/attacksurf_test`.
- Commits here need `UV_CACHE_DIR=/tmp/uv-cache-ubuntu PRE_COMMIT_HOME=/tmp/pre-commit-cache`;
  git identity is set repo-locally (GitHub no-reply address).
- ADR numbers move fast: check `origin/main` and open branches before taking the next number.
