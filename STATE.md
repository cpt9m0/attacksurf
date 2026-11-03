# STATE

> Handoff for the next session. Overwritten at the end of every task; not a history log.

**Updated:** 2026-11-03 (after Codex review) · **Branches:** `14-ownership-verification-part1` /
`14-ownership-verification` · **Issue:** #14 (DNS TXT ownership)

## Status
#14 is implemented in two stacked commits on `14-ownership-verification`; two PRs are open
against `main` (neither closes #14 alone — the one that merges last takes `Closes #14`):
`4cda8e7` (PR 1: model, services, authoritative lookup, gate wiring) then
`e35061a` (PR 2: worker task, hourly beat, ownership card).
All checks green locally: ruff, pyright (0), import-linter, pytest 891 passed / 97.9%.

## Last task
- `verifications` table (migration `0005`), `jobs.scan_id` now nullable (`SET NULL`; a pruned
  scan keeps its jobs). A revoked proof may carry `verified_at`; a pending one may not.
- `domain/verification.py` (token, record name/value, chunk-tolerant `matches`),
  `infra/authoritative_dns.py` (`AuthoritativeTxtLookup`: NS from the stub, every NS address
  validated with the scan-target policy, no referrals, TXT chunks joined),
  `services/ownership.py` (`DbOwnershipChecker`, `check_ownership`, `VerificationNotFound`),
  `services/verifications.py` (`start_verification`, `read_verification`, `record_check`,
  `due_verifications`, `enqueue_due_checks`).
- `passive.verify_ownership` + hourly `passive.reverify_ownership` (beat, minute 17);
  `POST /assets/<id>/verify` (admin, `action=start|check`, rotate = default) and
  `GET /assets/<id>/ownership` for the HTMX card.
- Checked in Chromium (light + dark): card, HTMX swap, copy button, rotate dialog
  (Escape closes), "Verify now" now issues a real POST.

## Review history
Codex left five findings on the first push; all are fixed and answered inline:
`3ad8762` (P2s: `DnsError` not translated, subdomain roots found no zone, failure rcodes read as
"absent"), `b3128a4` + `dfdbfc0` (P1s: "Verify now" queued nothing, inline Alpine ternaries in
the copy button). The subdomain-root fix was a design change approved by the user: the zone is
the closest ancestor with an NS RRset up to the registrable domain (ADR 0014).

## Next step
Get both PRs reviewed and merged (security-sensitive: DNS lookups and the gate), then
unblock the website module (#69 ADR, #70 active queue, #71 TLS adapter), which depends on
this.

## Open threads
- Dev DB needs `uv run alembic upgrade head` (done locally; `make migrate` in compose).
- Verification jobs currently just stay `queued` in a dev stack without a worker; expected.
- `due_verifications` is the only deliberately cross-tenant query (ids only, system work).
- Follow-ups filed earlier still open: #114 shell overflow at 390px, #115 tag editing,
  #116 cancel scans on archive, #117 overlapping roots.
- `.env.example` still lacks ALLOW_SIGNUP, SESSION_LIFETIME_HOURS, PROXY_COUNT.

## Notes for the next agent
- Signup, login and `/assets` POST are rate limited per IP (5/hour; also in dev). Reuse an
  existing account; the dev DB has `dana845461@example.com` (password `correct horse battery`).
- `pkill -f serve14.py` kills the shell that ran it; start the scratch server with
  `setsid nohup uv run python … &` in a separate command.
- `.example`/`.test` values are rejected (not in the PSL) — use `*.com` for manual demos.
- Playwright: `uv run --no-project --with playwright==1.55.0 python …` (Chromium in
  `~/.cache/ms-playwright`).
- `op.f("ck_...")` in a migration is **not** what the models' naming convention produces for an
  unnamed `CheckConstraint`: the metadata expands a short name to `ck_<table>_<name>`. Passing
  the full name in the model (or a `op.f` full name in the migration) creates a constraint that
  the model's metadata never matches; keep the when in the model and `alembic check` in the
  migration test catch this, but only after a fresh schema.
- DB tests: `TEST_DATABASE_URL=postgresql+psycopg://attacksurf:attacksurf@localhost:5432/attacksurf_test`.
