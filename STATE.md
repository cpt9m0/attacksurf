# STATE

> Handoff for the next session. Overwritten at the end of every task; not a history log.

**Updated:** 2026-11-19 · **Branch:** `25-ai-triage` · **Issue:** #25 (AI triage stage)

## Status
In progress: commit 4 of 9 on `25-ai-triage`; draft PR #186 (commits 1-3 pushed).

## Last task
- Plan: one PR per issue (Angela: #25 now; sten-ctrl: #26 after #25 merges), kept in the Claude
  Doc "#25 + #26: one PR per issue" (not in the repo). cpt9m0 approved the oversized PR.
- Commits 1-2: ADR 0029 (triage design) and the contract (`ai/schemas.py`, `ai/triage.py`).
- Commit 3: `ai/prompts/__init__.py` (`load_prompt`, `parse_prompt`, `Prompt.messages`; files
  are `<!-- system -->` + `<!-- user -->` parts) and `ai/untrusted.py` (`scan_data_block`,
  `cap`). AGENTS.md rule 8, the `llm-prompt` skill, `docs/security.md` and
  `docs/architecture.md` now name both.
- Commit 4: prompt `ai/prompts/triage/v1.md` (hash pinned in `tests/unit/ai/test_prompts.py`)
  and `build_triage_messages`, `triage_batch`, `match_results` in `ai/triage.py` (5 evidence
  items per finding, strings capped at 2,000 characters; `docs/security.md` lists what's sent).

## Next step
Commit 5: triage runs after the scan finishes. `dispatch_stage`'s tail drops `triage`;
`finalize_scan` queues an `ai.triage` job (`TrackedTask`, `workers/tasks/ai.py`) after its
commit; `passive.triage` becomes a no-op for one release; `enforce_triage_budget` returns
`LLMConfig | None`. Test list: the old plan's "B1 commits" tab.

## Open threads
- How a batch job finds its chunk when an asset has more than 20 findings (`Job` has no
  parameters column): decide in commit 7.
- #22 (findings UI) is unowned; the AI panel goes on the scan page first.

## Notes for the next agent
- Pydantic puts a reply model's docstring and field descriptions into the JSON schema the model
  sees: keep them model-facing, put developer notes in comments. A change to them changes the
  snapshot and needs a new prompt version.
- `anthropic.transform_schema` moves unsupported limits (`maxLength`, `pattern`) into
  descriptions; pydantic still enforces them locally, and the corrective retry covers misses.
- Write invisible or non-ASCII test characters with `chr(...)`: ruff rejects them raw (PLE2515).
- On this laptop Postgres listens on `127.0.0.1:5433` (local `compose.override.yaml`, excluded
  from git): start Docker Desktop, `docker compose up -d --wait postgres`, then
  `TEST_DATABASE_URL=postgresql+psycopg://attacksurf:attacksurf@127.0.0.1:5433/attacksurf_test`.
- Commits here need `UV_CACHE_DIR=/tmp/uv-cache-ubuntu PRE_COMMIT_HOME=/tmp/pre-commit-cache`;
  git identity is set repo-locally (GitHub no-reply address).
- ADR numbers move fast: check `origin/main` and open branches before taking the next number.
