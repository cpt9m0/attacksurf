# STATE

> Handoff for the next session. Overwritten at the end of every task; not a history log.

**Updated:** 2026-11-18 · **Branch:** `24-org-llm-settings` · **Issue:** #24 (Org AI settings)

## Status
Issue #24 and all code-review fixes are complete and verified on `24-org-llm-settings`; ready to open the PR.

## Last task
- Added `OrgSettings` (`0011_add_org_settings`), `SecretCipher` (`APP_ENCRYPTION_KEY` + `APP_ENCRYPTION_OLD_KEYS` rotation), `validate_llm_base_url`, and expanded `redact_secrets` (`api[-_]?key`, `base[-_]?url`, URL credentials).
- Hardened `AnthropicProvider`, `OpenAICompatProvider`, and `_DeadlineBackend` (`follow_redirects=False`, `trust_env=False`, dial-time `check_addresses` unless `allow_private_base_url=True`), single-query `resolve_org_llm_config`, and monthly UTC token caps (`LLM_MONTHLY_INSTANCE_TOKEN_BUDGET`).
- Added `/settings` UI + async `ai.test_connection` Celery task (`_ai_test_status.html` 2 s polling, `aiSettingsForm` replace modal, `confirm_dialog`, `.notice-list`, monthly `data_table`).

## Next step
Open PR for `#24` (`feat(ai): add org LLM settings, encrypted keys and budget enforcement`), wait for CI green, then start `#25` (versioned prompts + AI triage) per epic `#31`.

## Open threads
- Deadline layer wraps `httpx2.HTTPTransport._pool`; Meta prices in `ai/pricing.py` need a check on developer.meta.com.
- After CD deploys `cb7c061` (#178): confirm `docker compose -f compose.prod.yaml logs --tail=20 cloudflared | grep -c Registered` is non-zero.

## Notes for the next agent
- Integration tests require `TEST_DATABASE_URL` ending in `_test` (e.g. `attacksurf_24_test`); `ai.test_connection` runs on the `ai` queue.
