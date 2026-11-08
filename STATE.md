# STATE

> Handoff for the next session. Overwritten at the end of every task; not a history log.

**Updated:** 2026-11-08 · **Branch:** `132-cloudflare-caddy-tls` (PR #133, draft) · **Issue:** #132

## Status
`https://attacksurf.dev` is **live** from the shared `lili` host (Oracle ARM, Ubuntu 24.04) via a
Cloudflare Tunnel. PR [#133](https://github.com/cpt9m0/attacksurf/pull/133) implements it; CI was
pending at handoff. Verified on the host: `/healthz` 200, `/` → `/login`, `www` → apex 301,
signup 200, 4 tunnel connections, and Caddy's access log resolves the visitor IP.

## Last task
- Added `compose.prod.yaml` (cloudflared, caddy, web/gunicorn, postgres, redis, migrate), a plain-
  HTTP Caddyfile behind the tunnel, and `docs/deployment.md`; ADR 0020 records moving public TLS
  to Cloudflare (SSL mode **Full**, not strict — there is no origin certificate).
- Fixed rate limiting: it keyed on `get_remote_address` (first hop). Now `CF-Connecting-IP`, else
  the leftmost `X-Forwarded-For`, which is safe only because the origin has no public port.
- Fixed a date-dependent test in `test_verifications.py` that failed after its fixed `NOW` passed
  the grace window; it blocked the pre-push hook and would have broken CI for a week.
- **Host layout:** source at `/opt/attacksurf` (plain files, not a git clone — GitHub needs creds
  there); secrets in `/etc/attacksurf/` (`tunnel.token` 640 client:65532, `postgres_password`,
  `redis_password` 640 client:10001, `attacksurf.env` 640 client; `cloudflare-dns-token` is now
  unused). Deploy: upload a `git archive` tarball, extract, `docker compose -f compose.prod.yaml
  up -d --build`.

## Next step
1. Watch PR #133 CI; mark ready and merge when green (commits/pushes are authorized in this chat;
   merge only when asked).
2. After merge, replace `/opt/attacksurf` with a `git clone` on the host and deploy from `main`
   (needs a deploy key or the repo made accessible to the `ubuntu` user).

## Open threads
- **Rotate secrets pasted in chat:** the tunnel token is being rotated now; the `cfat_` API token
  is no longer used by the stack and should be deleted in Cloudflare.
- **No workers/beat in the prod stack** (#29): scans, ownership checks and AI jobs stay queued on
  the live instance. Stacks on the same host keep Postgres/Redis; this one uses its own.
- **Backups, Sentry, log rotation, host hardening** remain in #29. The host is shared with
  jellyfin, uptime-kuma, `csday-prod` and an unrelated MetaHack `attacksurf-postgres/redis` pair;
  a dedicated VPS is an open question.
- `ALLOW_SIGNUP=true` on the public instance — close it until backups exist.
- The local `STATE.md` edit present at session start (someone else's handoff refresh) was left
  untracked outside this branch's commits.

## Notes for the next agent
- Behaviour change to remember: `PROXY_COUNT` counts proxy **hops**; behind the tunnel it is 1.
- Never put the tunnel/API tokens or DB passwords in the repo, the image, or a compose file; they
  belong in `/etc/attacksurf/` with the uid/gid noted above.
- Validate the Caddyfile with `caddy validate` in the built image before `up -d`; a bad config
  makes caddy restart-loop and the site return 502 (happened twice during this task).
- Validation: ruff, pyright, import-linter clean; 1005 passed, 3 skipped (worker E2E).
