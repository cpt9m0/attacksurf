# STATE

> Handoff for the next session. Overwritten at the end of every task; not a history log.

**Updated:** 2026-10-31 · **Branch:** `13-asset-services-api` · **Issue:** #13 (Assets UI)

## Status
#13 ships as two PRs. PR 1 (services + `/api/v1/assets`, Refs #13) is done and green
locally; PR 2 (UI, Closes #13) is not started. Plan: `~/.claude/plans/greedy-swinging-cascade.md`.

## Last task
- `services/assets.py`: `add_root_domain` (ScopeGuard name rules; registrable **or** subdomain
  roots, per the user; re-adding an archived root restores it) and `archive_root_domain`
  (root + discovered children inactive, findings/scans kept, admin only). Both audited.
- `services/asset_views.py`: list (filters, pagination, open count + max severity), detail
  with relations both ways, findings, scans of the root, root options. Frozen dataclasses.
- `web/asset_params.py` + `web/api/v1.py`: the JSON endpoints (see `docs/architecture.md`).
- `domain/findings.py`: `SEVERITY_RANK` / `severity_from_rank`; `domain/assets.py`: `DomainAlreadyAdded`.

## Next step
After PR 1 merges: branch `13-assets-ui` from `main` and build PR 2 from the plan: routes in
`web/ui.py` (`/assets`, `POST /assets`, `/assets/<id>?tab=`, `POST /assets/<id>/archive`),
`pages/assets.html` + `_add_domain_form.html` + `asset_detail.html`, `data_table` caller cells,
`confirm_dialog` (`<dialog>` + `Alpine.data`), `relative_time`; then DESIGN.md, README, and a
Playwright pass.

## Open threads
- PR 1 is ~615 source lines (over the ~400 guideline even after the split); noted in the PR.
- Follow-ups to file: tag editing UI; a scan in flight when a root is archived can still
  reactivate children; overlapping roots (`example.com` + `eng.example.com`) duplicate
  discovered subdomains across trees.
- From before: #14 must plug a real `OwnershipChecker` into `workers.runtime.scanner_gate()`;
  `.env.example` still lacks ALLOW_SIGNUP, SESSION_LIFETIME_HOURS, PROXY_COUNT.

## Notes for the next agent
- `web/` can't import SQLAlchemy (import-linter): add read models to `asset_views.py`, not ORM rows.
- Counts: `scoped(Model, org_id).where(...).with_only_columns(func.count())`.
- URL asset values are normalized: `%c` becomes `%25c`, so test fixtures must use normalized forms.
- API tests sign up through `/signup` and send `X-CSRFToken` taken from `/` (see
  `tests/integration/web/test_assets_api.py`); change roles by editing `Membership` + commit.
- DB tests: `TEST_DATABASE_URL=postgresql+psycopg://attacksurf:attacksurf@localhost:5432/attacksurf_test`.
- Flask-WTF CSRF tokens differ across a second boundary: assert acceptance, never string equality.
- Stale shell groups: use `sg docker -c 'make up'`. Never chmod the Docker socket.
