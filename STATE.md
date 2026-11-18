# STATE

> Handoff for the next session. Overwritten at the end of every task; not a history log.

**Updated:** 2026-11-18 · **Branch:** `24-org-llm-settings` · **Issue:** #24 (Org AI settings, BYO keys, usage view)

## Status

Issue #24 is implemented and locally verified on `24-org-llm-settings`:

- `OrgSettings` model + `0011_add_org_settings` migration (encrypted API key ciphertext + `last4`, provider, model, `base_url`, `ai_enabled`, `monthly_token_budget`).
- `SecretCipher` (`infra/crypto.py`) with `APP_ENCRYPTION_KEY` + `APP_ENCRYPTION_OLD_KEYS` rotation decryption, `LLM_MONTHLY_INSTANCE_TOKEN_BUDGET` (`500_000` default), `LLM_ALLOWED_BASE_HOSTS`, and expanded `redact_secrets`.
- `validate_llm_base_url` (`infra/scope_guard.py`) enforcing SSRF checks on save and load; `services/org_settings.py` + `services/llm_usage.py` handling resolution, budget caps, connection probes, and usage breakdown; `workers/tasks/pipeline.py` skipping `passive.triage` on disabled/over-budget AI.
- `/settings`, `POST /settings/ai`, `POST /settings/ai/clear-key`, `POST /settings/ai/test` with admin RBAC, CSRF, CSP-clean HTMX inline validation, masked keys, `confirm_dialog`, data-sharing notice, and monthly usage table.

## Next

Open PR for `#24` (`feat(ai): add org LLM settings, encrypted keys and budget enforcement`), confirm CI passes on GitHub, then proceed to `#25` (prompt templates / AI triage implementation) per epic `#31`.
