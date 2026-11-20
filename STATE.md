# STATE

> Handoff for the next session. Overwritten at the end of every task; not a history log.

**Updated:** 2026-11-19 · **Branch:** `25-ai-triage` · **Issue:** #25 (AI triage stage)

## Status
Done: all 9 commits on draft PR #186; the live eval passes 5 of 5 on `claude-sonnet-5-5`.

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
- Commit 8: `components/ai_panel.html` (`ai_triage_panel`, `priority_pill`) replaces #22's
  raw-JSON placeholder on the finding page; `pages/_scan_triage.html` + `ui.scan_triage` is the
  scan page's polled AI section, fed by `services/triage_views.get_scan_triage`; scan job
  counts leave `TRIAGE_STAGES` out. `DESIGN.md` AI panel row filled in.
- Commit 9: the eval set (5 cases in `tests/fixtures/ai/triage_eval/`, harness
  `tests/eval/triage_cases.py`, live runner `tests/eval/test_triage_eval.py`, offline checks
  `tests/unit/ai/test_eval_harness.py`) and `make eval`; README, CHANGELOG, AGENTS.md commands
  and `docs/development.md` synced.

## Next step
Mark #186 ready for review once CI is green (Angela ticks the PR's AI-assistance box), then
address review comments from sten-ctrl and cpt9m0. A future prompt change is `triage/v2` (new
file, new pinned hash), compared against v1 with `make eval`.

## Open threads
- `make eval` on 2026-11-19: 5 of 5 pass with `claude-sonnet-5-5` and `triage/v1`. The Meta
  development key returned HTTP 401 that day, so `.env` now points at Anthropic.
- `ai/pricing.py` has no Claude prices: Claude usage rows record tokens but no cost estimate.
  Add list prices from Anthropic's pricing page in a follow-up.
- Two tests unrelated to #25 flake on a loaded machine and pass alone:
  `test_artifact_purge_task.py::test_purge_task_deletes_expired_artifacts_even_without_a_key`
  (its `NOW` is fixed at import while the task reads the real clock) and
  `test_deadline.py::test_stalled_tls_handshake_is_cut_off_at_the_deadline` (timing). Worth an
  issue of their own.
- #27 took migration `0012`: #26's `Scan.ai_summary` migration is `0013`.
- sten-ctrl may start #26 on a branch stacked on `25-ai-triage` (see the plan doc).

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
