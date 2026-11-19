# STATE

> Handoff for the next session. Overwritten at the end of every task; not a history log.

**Updated:** 2026-11-19 · **Branch:** `25-ai-triage` · **Issue:** #25 (AI triage stage)

## Status
In progress: commits 1 and 2 of 9 are on `25-ai-triage`, not pushed; no PR yet.

## Last task
- Plan: one PR per issue (Angela: #25 now; sten-ctrl: #26 after #25 merges), kept in the Claude
  Doc "#25 + #26: one PR per issue" (not in the repo). cpt9m0 approved going over the ~400-line
  PR guideline.
- `docs/adr/0029-ai-triage-stage.md`: triage runs after the scan as `ai.*` jobs, one LLM call
  per job; cache on `Finding.ai_triage`; what is and isn't sent; prompt files; opt-in evals.
- `ai/schemas.py` (`FindingTriage`, `TriageReply`, `StoredTriage`, `TriagePriority`) and
  `ai/triage.py` (`TriageBatch`, `triage_cache_key`), tested in
  `tests/unit/ai/test_triage_contract.py` with the snapshot `tests/fixtures/ai/triage_reply_schema.json`.

## Next step
Push `25-ai-triage`, open the draft PR (`feat(ai): add the ai triage stage`, `Closes #25`,
oversized-PR note under "Notable"), then commit 3: `ai/prompts/__init__.py` (`load_prompt`,
pinned file hashes) and `ai/untrusted.py` (`scan_data_block`).

## Open threads
- How a batch job finds its chunk when an asset has more than 20 findings (`Job` has no
  parameters column): decide in commit 7.
- Evidence cap per finding (proposed: 5 items of 2,000 characters) lands in commit 4.
- #22 (findings UI) is unowned; the AI panel goes on the scan page first.

## Notes for the next agent
- Pydantic puts a reply model's docstring and field descriptions into the JSON schema the model
  sees: keep them model-facing, put developer notes in comments. A change to them changes the
  snapshot and needs a new prompt version.
- `anthropic.transform_schema` moves unsupported limits (`maxLength`, `pattern`) into
  descriptions; pydantic still enforces them locally, and the corrective retry covers misses.
- On this laptop Postgres listens on `127.0.0.1:5433` (local `compose.override.yaml`, excluded
  from git): `docker compose up -d --wait postgres`, then
  `TEST_DATABASE_URL=postgresql+psycopg://attacksurf:attacksurf@127.0.0.1:5433/attacksurf_test`.
- Commits here need `UV_CACHE_DIR=/tmp/uv-cache-ubuntu PRE_COMMIT_HOME=/tmp/pre-commit-cache`;
  git identity is set repo-locally (GitHub no-reply address).
- ADR numbers move fast: check `origin/main` and open branches before taking the next number.
- The ruff format hook strips imports that aren't used yet: add imports with their first use.
