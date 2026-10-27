# STATE

> Handoff for the next session. Overwritten at the end of every task; not a history log.

**Updated:** 2026-10-27 · **Branch:** `main` · **Merged:** #61, #62 · **Next:** #13 or #14

## Status
`main` is green at `ffbf917`. Nothing in flight. #12 (ScopeGuard, PR #58), #59 (PR #61) and
#53 (PR #62) are all merged and their issues closed.

## Last task
Two bug fixes raised while working on #58:
- **#59 (PR #61)**: the pre-push hook ran bare `pytest`, so DB tests skipped without
  `TEST_DATABASE_URL`, coverage fell under the gate and every push failed. The hook now resolves
  the URL itself (`.github/scripts/test_database.py`: shell, then `.env`, then `.env`'s
  `DATABASE_URL` with a `_test` suffix, then the local default), refuses any non-`*_test`
  database, and stops with one message if the database is unreachable. Verified by pushing with
  no `TEST_DATABASE_URL` set — hook passes, no `--no-verify`.
- **#53 (PR #62)**: `test_shell_sends_csrf_token_header_for_htmx` compared a header token to one
  from a second GET; Flask-WTF stamps tokens with `int(time.time())`, so it failed whenever the
  two requests straddled a second. It now validates the header token through a real POST probe.
  Confirmed the guard still bites: removing `hx-headers` from `base.html` fails 3 tests, and a
  bogus token in it fails with 400.

## Next step
Pick up #13 (assets UI: root domain, asset list, detail with relations; `needs-design`, so read
`DESIGN.md` first) or #14 (DNS TXT ownership verification, which unblocks active checks). Both
are part of epic #31.

## Notes from #58 work (still current)
ScopeGuard landed after five Codex rounds; the decoder is now `_decoded` (policy) + `_inflate`
(member loop) with a 22-row case table. Merge note: ~1,400 lines excl. tests, over the guideline.

## Open threads
- Active checks and target HTTP stay denied until #14 plugs a real `OwnershipChecker` into
  `workers.runtime.scanner_gate()`. The TARGET/verification invariant lives in two places (gate
  and registry) and must stay consistent when #14 lands.
- Five straight review rounds landed in HTTP response decoding. If decoding is touched again and
  another edge case appears, stop patching: either cap compressed bodies only (no transparent
  decoding) or use a vetted library.
- `make test-worker` / e2e Compose tests were never run for #12.
- `.env.example` still needs auth settings (ALLOW_SIGNUP, SESSION_LIFETIME_HOURS, PROXY_COUNT).

## Notes for the next agent
- New deps: httpx (httpcore transport), dnspython (stub resolver), tldextract (bundled PSL;
  pulling in requests, pinned by uv.lock). Never enable tldextract fetching or caching.
- `scoped()` returns an order-by query: use `select(func.count()).select_from(Model)` for counts.
- Fake plugins/gates live only in `tests/scanner_fixtures.py`; pipeline fixtures monkeypatch
  `pipeline.registry`/`PROFILES` (a check job resolves plugins through the task module globals).
- Response decoding: `_decoded` is the policy entry point, `_inflate` the member loop; cases live
  in `_DECODE_CASES` in `tests/unit/infra/test_http.py`. `zlib` does not raise on a stream that
  ends early, so completeness needs `decoder.eof`. When switching gzip members keep
  `decoder.unused_data + pending`. Test payloads must be incompressible, or a member never spans
  a slice and bugs hide.
- A `SafeHttpClient` built without `redirect_allowed` has *no* policy hook (bare transport, used
  by `test_http.py`); one built via `with_redirect_policy` enforces the hook on every hop.
  `with_redirect_policy` returns a plain `SafeHttpClient`, so a subclass's `_request` override is
  lost: fake the transport by overriding `with_redirect_policy` too.
- Tests needing a real second connection commit to `db_engine`; delete their rows in `finally` or
  later tests collide on `uq_orgs_slug` (`make_scan` always uses slug "acme").
- DB tests: `TEST_DATABASE_URL=postgresql+psycopg://attacksurf:attacksurf@localhost:5432/attacksurf_test uv run pytest`
  (dev Compose publishes Postgres on 5432). The pre-push hook now sets this itself; export it
  only to point at a different test database.
- CSRF tests: assert a token is *accepted* (POST with `X-CSRFToken`, see `assert_csrf_valid` in
  `tests/unit/web/test_auth.py`), never that two responses' token strings are equal — Flask-WTF
  stamps the time, so strings legitimately differ across a second boundary. Routes must be
  registered before the first request (`add_csrf_probe_route` takes `app`).
- Stale shell groups: use `sg docker -c 'make up'`. Never chmod the Docker socket.
