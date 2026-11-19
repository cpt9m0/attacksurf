# STATE

> Handoff for the next session. Overwritten at the end of every task; not a history log.

**Updated:** 2026-11-19 · **Branch:** `25-ai-triage` · **Issue:** #25 (AI triage stage)

## Status
In progress: commits 1-5 of 9 on draft PR #186 (CI green through commit 4 and the merge of
`origin/main` with #22 findings UI and #27 scheduled rescans).

## Last task
- Plan: one PR per issue (Angela: #25 now; sten-ctrl: #26 after #25 merges), kept in the Claude
  Doc "#25 + #26: one PR per issue" (not in the repo). cpt9m0 approved the oversized PR.
- Commits 1-4: ADR 0029; the contract (`ai/schemas.py`, `ai/triage.py`); `ai/prompts`
  (`load_prompt`, pinned hashes) and `ai/untrusted.scan_data_block`; prompt `triage/v1` with
  `build_triage_messages`, `triage_batch`, `match_results` (5 evidence items per finding, strings
  capped at 2,000 characters; `docs/security.md` lists what's sent).

- Commit 5: the chain tail is `persist`, `diff`, `finalize`;
  `finalize_scan(session, queue, ...)` queues an `ai.triage` job (`TrackedTask`) after the scan's
  completion commits (broker errors only fail that job); `passive.triage` is a no-op for one
  release. Tests: `test_pipeline.py` (finalize + `RecordingQueue` in `pipeline_env`) and
  `test_ai_task.py` (`ai.triage` skip, budget, completion, failure, tenant isolation).

## Next step
Commit 6: `services/triage.py` with `select_triage_batches` (active findings this scan
observed, from `finding_observations`; `info` only with the new `LLM_TRIAGE_INCLUDE_INFO`
setting; cache hits skipped; per asset, split at 20) and `store_triage` (writes
`StoredTriage` JSON to `Finding.ai_triage`, never `status` or `severity`).
`enforce_triage_budget` changes to return `LLMConfig | None` in commit 7, where it's used.

## Open threads
- How a batch job finds its chunk when an asset has more than 20 findings (`Job` has no
  parameters column): decide in commit 7.
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
