# STATE

> Handoff for the next session. Overwritten at the end of every task; not a history log.

**Updated:** 2026-11-17 · **Branch:** `23-llm-factory` · **Issue:** #23 (LLM providers, PR 4b)

## Status
PR 4b (provider factory) is committed on `23-llm-factory`, stacked on PR 3
(`23-openai-compat-provider`, not merged yet). Both `llm_live` tests pass against Meta
(`muse-spark-1.3-contributor`, both formats). Not pushed; DB tests not run locally.

## Last task
- `ai/factory.build_provider(config)`: `match` on `config.provider` → `AnthropicProvider` /
  `OpenAICompatProvider`, ending in `assert_never` (pyright flags a `ProviderKind` without a case).
- `tests/unit/ai/test_factory.py`: each kind gets its adapter, the whole config is handed over,
  building makes no network call, the key isn't in the `repr`.
- Docs: call path in `architecture.md` (AI layer) and the `llm-prompt` skill, CHANGELOG.

## Next step
Push `23-llm-factory` (the pre-push hook needs Postgres) and open a draft PR based on
`23-openai-compat-provider`: title `feat(ai): build llm providers from config (#23)`,
`Closes #23`, and both live results in "How was this tested?".

## Open threads
- PR 3 must merge first. When it does, GitHub retargets this PR to `main`; then
  `git merge origin/main` (PR 3 is squash-merged) and mark it ready. The partner reviews it.
- Full `pytest` with Postgres not run here: Docker isn't reachable from WSL on this laptop.
- After #23: #24 (org keys, instance-key cap, usage page). Waiting on the repo owner: default
  monthly cap per org. Meta prices in `ai/pricing.py` still need a check on developer.meta.com.
- Org-supplied base URLs still need ScopeGuard (SSRF) validation in #24 before use.

## Notes for the next agent
- Review fixes on PR 3: pull them with `git merge origin/23-openai-compat-provider`; never push
  to the partner's branch.
- `openai.APIStatusError` unwraps the top-level `"error"` object into `exc.body` and sets
  `exc.type`; format fallback only triggers on HTTP 400 before a format has succeeded.
- Git has no identity set in WSL here: set `user.name` / `user.email` before committing.
