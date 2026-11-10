# STATE

> Handoff for the next session. Overwritten at the end of every task; not a history log.

**Updated:** 2026-11-10 · **Branch:** `114-mobile-shell-overflow` · **Issue:** #114 (PR pending)

## Status
The app shell no longer overflows a phone viewport. `.topbar` wraps (`flex-wrap`) and carries a
`min-width: 0` grid-item guard; `.user-menu` shrinks and ellipsizes with the full `email · org`
in its `title` attribute, floored by the new `--user-menu-min-width` token so the bar wraps
instead of squeezing the email to nothing; `.sidenav` and its `ul` get the same `min-width: 0`
guard and its links `flex-shrink: 0`, so the mobile nav row scrolls inside itself. Measured
618px → 390px at a 390px viewport on all five nav pages in both themes; 320px and 1280px
unchanged.

Regression coverage is the new hermetic browser suite `tests/e2e/web/` (marker `web_e2e`): it
renders the real pages with `phone_client` (40-char email), writes them next to a copy of
`static/` and measures them in Chromium — no server, no database. 12/12 fail before the fix,
12/12 pass after. `login_as`/`make_session_user`/`LoginAs` moved from `tests/unit/web/conftest.py`
to `tests/conftest.py` so `tests/e2e/` can use them. `playwright` is a dev dependency and CI has
a `web-e2e` job. Docs synced (`CHANGELOG.md`, `DESIGN.md`, `docs/development.md`, `AGENTS.md`).

`main` also carries the Cloudflare Tunnel production stack (ADR 0020, #133), the pull-based CD
units and `scripts/deploy.sh`/`make deploy` (#136–#139, #141, #142) — see `docs/deployment.md`.

## Next step
Open the PR for this branch (`Closes #114`), attach the before/after 390px screenshots from
`/home/ubuntu/data/attacksurf-plans/issue-114/`, and drive it through review.

## Open threads
- #84: PR 3 (`84-sandbox-launcher`) is next; merge order port → proxy → launcher → analysis
  worker → CI. The launcher must send exactly what `sandbox_proxy/policy.py` accepts (user
  `65532:65532`, `LogConfig` none, `AutoRemove`, binds under the artifact root; attach before
  start, stdout only), and deployment must pass the proxy settings as environment variables
  (the proxy never reads `.env`).
- The scanner registry caps `timeout_seconds` at 240 s, but ADR 0016 allows 600 s sandbox runs.
  Resolve before the first analysis scanner; the runner client deadline is affected too.
- PR 4 adds a new ADR for consuming the `analysis` queue before a real analyzer exists, and
  names the OSV volume `attacksurf_osv` to match the proxy. `runsc` must be registered on the
  VPS before the proxy is deployed to prod.
- #23: Anthropic and OpenAI-compatible adapters and the factory remain; each must enforce the
  240 s deadline, and org base URLs need ScopeGuard validation (#24).
- #29: backups, monitoring and hardening remain; signup is enabled and should be closed until
  backups exist. The exposed tunnel/API credentials recorded in #133 still need rotation.
- `.env.example` lacks ALLOW_SIGNUP, SESSION_LIFETIME_HOURS, PROXY_COUNT.
- Follow-ups: #115–#117.

## Notes for the next agent
- Browser layout tests: `RUN_WEB_E2E=1 uv run pytest tests/e2e/web -m web_e2e --no-cov` after
  `uv run playwright install chromium`; they skip by default, so `uv run pytest` stays fast.
- Deployment: `docs/deployment.md` (pull-based CD); secrets stay in `/etc/attacksurf/`, never git
  or images. `PROXY_COUNT` counts hops (1 behind the tunnel); validate Caddy before deploying.
- `docs/plans/` holds the user's temporary plan copy: never stage it.
- Commits and pushes are authorized for this branch; merge only when requested.
- The due-verifications test is clock-pinned on `main` (explicit `NOW`); keep it that way.
