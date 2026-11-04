# STATE

> Handoff for the next session. Overwritten at the end of every task; not a history log.

**Updated:** 2026-11-04 · **Branch:** `14-ownership-verification-single` · **Issue:** #14 (DNS TXT ownership)

## Status
#14 is complete in **one PR into `main`** (`14-ownership-verification-single`, closes #14). The
earlier two-PR stack was abandoned: #122 was merged into the part‑1 branch rather than `main`,
and that branch was later force-pushed, so nothing from #14 is on `main` yet and none of the
old branches is authoritative. This branch is `main` + the full implementation + every review
fix. Locally green: ruff, pyright (0), import-linter, pytest 916 passed / 98%.

## Last task
- Schema (migration `0005`): `verifications` table (unique per `(org_id, asset_id)`; a revoked
  proof keeps `verified_at`, a pending one may not); `jobs.scan_id` nullable with `SET NULL`,
  so a pruned scan keeps its jobs and work outside a scan can be tracked.
- `domain/verification.py` (token, record name/value, chunk-tolerant `matches`,
  `RECHECK_AFTER`/`GRACE_AFTER_FAILURE`), `infra/authoritative_dns.py`
  (`AuthoritativeTxtLookup`: NS from the stub, **enclosing-zone discovery** up to the
  registrable domain, every NS address validated with the scan-target policy, no referrals,
  failure rcodes mean "try another server", TXT chunks joined, bounded),
  `services/ownership.py` (`DbOwnershipChecker`, `check_ownership`),
  `services/verifications.py` (`start_verification`, `queue_check`, `read_verification`,
  `check_in_flight`, `record_check`, `due_verifications`, `enqueue_due_checks`).
- Workers: `passive.verify_ownership` (tracked) + hourly `passive.reverify_ownership` (beat,
  minute 17), registered in `workers/app.TASK_MODULES`.
- Web: `POST /assets/<id>/verify` (admin; `start` / `check` / rotate), `GET /assets/<id>/ownership`
  (the HTMX card). The card shows the record with a copy button, polls itself while a check
  runs, and subdomains show their root's proof read-only.

## Review history (all fixed)
- `DnsError` from the stub adapter wasn't translated → NS/A failures escaped the handler.
- Subdomain roots had no NS of their own → enclosing-zone walk (approved by the user; ADR 0014).
- SERVFAIL/REFUSED were read as "record absent" → would revoke a live proof.
- "Verify now" queued nothing → `queue_check` (keeps the token).
- Inline Alpine ternaries in the copy button → `label`/`pressed` on the component, plus a test.
- **IPs/URLs inherited a domain's proof** (real security hole: `parent_id` is provenance) →
  inheritance restricted to domain/subdomain.
- The async result never appeared → the card polls until the check finishes.
- **CNAME bypass**: the stub follows CNAMEs, so an aliasing name borrowed the target
  zone's nameservers and could have forged the proof → `lookup_records` returns the answered
  owner and only an NS RRset owned by the queried name counts.
- Re-check batch starvation: failing proofs sorted first forever → `failed_attempts` +
  `retry_after` backoff (migration 0006).
- Expired proofs still showed as Verified while the gate denied them → `ownership_state`
  (verified past expiry is `expired`), shared by gate, list and card.

## Next step
Open the PR (`Closes #14`), review, merge. Then close #121 and #122 with a note pointing at it
and delete the stale branches (`14-ownership-verification`, `14-ownership-verification-part1`).
The website module (#69 ADR, #70 active queue, #71 TLS adapter) is what this unblocks.

## Open threads
- Dev DB needs `uv run alembic upgrade head` (`make migrate` in compose).
- Verification without a running worker stays `queued`; the card then polls indefinitely —
  expected in a worker-less dev stack, though a timeout on the "Checking…" state may be worth
  adding later.
- Earlier follow-ups still open: #114 shell overflow at 390px, #115 tag editing,
  #116 cancel scans on archive, #117 overlapping roots.
- `.env.example` still lacks ALLOW_SIGNUP, SESSION_LIFETIME_HOURS, PROXY_COUNT.

## Notes for the next agent
- **Do not stack PRs that one depends on**: #122 merged into its base branch instead of `main`,
  and a later force-push lost the merged commit. One branch, one PR, base `main`.
- Signup, login and `/assets` POST are rate limited per IP (5/hour signups, 20/hour logins,
  also in dev). Reuse `dana845461@example.com` (password `correct horse battery`) in the dev DB;
  logs and codes live in Redis, so a fresh `REDIS_URL` database resets the counters.
- `pkill -f <script>.py` kills the shell that ran it; start scratch servers with
  `setsid nohup uv run python … &` **in a separate command**.
- `.example`/`.test` values are rejected (not in the PSL) — use `*.com` for manual demos.
- Playwright: `uv run --no-project --with playwright==1.55.0 python …` (Chromium in
  `~/.cache/ms-playwright`).
- A model `CheckConstraint` gets the convention name from a *short* name; passing the fully
  prefixed name creates a constraint the metadata never matches.
- DB tests: `TEST_DATABASE_URL=postgresql+psycopg://attacksurf:attacksurf@localhost:5432/attacksurf_test`.
