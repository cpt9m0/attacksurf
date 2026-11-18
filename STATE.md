# STATE

> Handoff for the next session. Overwritten at the end of every task; not a history log.

**Updated:** 2026-11-18 · **Branch:** `main` · **Issue:** Dependabot #177 + #178 merged

## Status
Done: merged `c1e236a build(deps): bump postgres from 18 to 18 (#177)` and `cb7c061
build(deps): bump cloudflare/cloudflared from 2026.10.7 to 2026.11.0 (#178)` via
squash-merge (both `CLEAN`/`MERGEABLE`, all CI green before merge). Local `main` is synced
with `origin/main` at `cb7c061` plus this handoff. Dev `postgres` is running the new digest
and healthy with data intact.

## Last task
- #177 (postgres digest-only refresh `e3d24f6…` → `2ea8630d…`, tag stays `18`): updated in
  **both** `compose.yaml:46` and `compose.prod.yaml:135` (Dependabot PR did both; verified
  consistent). No migration: major stays 18, `pgdata` parent-volume mount unchanged.
- #178 (cloudflared `2026.10.7` → `2026.11.0`, digest `4955524a…` → `b94b96ed…`):
  `compose.prod.yaml:57` only (cloudflared is prod-only by design). Tunnel command untouched.
- Verified after merge: both digests resolve upstream with `linux/amd64`
  (`imagetools inspect`); `docker compose config --quiet` passes for dev and prod (prod with
  a temp `deploy/attacksurf.env` from `.example`, deleted after); `docker compose pull
  postgres && up -d --wait postgres` → recreated on the new digest, `Healthy`, `pg_isready`
  accepting connections, `alembic_version`/`attacksurf_test` reachable (dev `orgs` empty, as
  before). Full PR CI (lint, secrets, compose, test 3.12/3.13/3.15, web-e2e, pr-title) was
  green on both heads, so no local pytest re-run (no app code changed).
- Rebase note: the previous session's unpushed `880c039` handoff (#174) was dropped
  (`rebase --skip`) because `origin/main` had moved on (#176, #180, #177, #178) and its
  STATE.md content was superseded; this file replaces it.

## Next step
1. Next unblocked issue in epic #31. Note `origin` also merged since the last handoff:
   `b70587d feat(ai): add openai-compatible provider (#23) (#176)` and `bebfa32 docs(agents):
   add issue 84 implementation plans (#180)`; remote branch `23-llm-factory` exists (PR 4b
   factory work for #23). `worker-ai`, backups, monitoring stay #29.
2. After the CD timer deploys `cb7c061`: `docker compose -f compose.prod.yaml logs --tail=20
   cloudflared | grep -c Registered` should be non-zero (new `2026.11.0` image), and dev
   `postgres` is already on `2ea8630d…` (this box).

## Open threads
- None from #177/#178. No rebase needed (different hunks); no `@dependabot` commands used.

## Notes for the next agent
- Shell env needed here: `UV_CACHE_DIR=/tmp/uv-cache-ubuntu`,
  `PRE_COMMIT_HOME=/tmp/pre-commit-cache` (home cache is not writable),
  `TEST_DATABASE_URL='postgresql+psycopg://attacksurf:attacksurf@127.0.0.1:5432/attacksurf_test'`.
  Chromium: `PLAYWRIGHT_BROWSERS_PATH=/tmp/ms-playwright` (installed there).
- Hooks are authoritative: always export the env above for commits/pushes, or the commit and
  pre-push hooks fail on cache permissions.
- `compose.prod.yaml config` needs a temp `deploy/attacksurf.env` (copy from `.example`,
  delete after) plus stub secret files via `SECRETS_DIR`; `docker compose config` output
  re-escapes `$` as `$$`.
- Author/committer identity for this repo: `Ali Ayati <seyyedaliayati@gmail.com>`.
