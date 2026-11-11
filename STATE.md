# STATE

> Handoff for the next session. Overwritten at the end of every task; not a history log.

**Updated:** 2026-11-11 · **Branch:** `main` · **Issue:** #15 · **PR:** #155 (merged)

## Status
Issue #15 is merged into `main` as `dfc8111` (PR #155). The Cert Spotter pagination review
comment is addressed: the source follows the last issuance id as `after`, repeats until an empty
page, and never caches a partial result. All local checks are green: ruff, pyright,
import-linter, pre-commit, `uv lock --check`, and `pytest` with Postgres (1333 passed, 18 skipped,
coverage 97.24%); all PR CI checks passed. A real `dns_passive` scan of `example.com` in the dev
Compose stack completed and persisted `dev`, `m`, `products`, `support` and `www` subdomains with
five `subdomain_of` relations. The test org was removed afterwards.

## Last task
- Added the `dns.discovery.ct` scanner (crt.sh + Cert Spotter fallback), the namespaced
  fail-open Redis source cache (`ctx.runtime.cache`), wildcard-zone detection and
  `Asset.details["wildcard"]` persistence, and the `dns_passive` discovery cap (ADR 0022).
- Added unit/integration/fixture tests; updated architecture, security, add-scanner skill,
  AGENTS, CHANGELOG and ADR 0022.
- Addressed the Cert Spotter pagination review comment: cursor-based `after` pagination until
  an empty page, with incomplete results never cached.
- Squash-merged PR #155 into `main` as `dfc8111`; the remote issue branch was deleted and the
  local checkout is on `main`.
- Local `worker-passive` was restarted to load the new scanner; the Compose stack is still up.

## Next step
Implement #16 (DNS resolution + asset graph); it should
read `Asset.details["wildcard"]` before treating wildcard answers as real hosts and can reuse
`ctx.runtime.cache` for RDAP-style source data.

## Open threads
- The live scan seeded the shared Redis cache with the public CT result for `example.com`
  (`attacksurf:scan-cache:v1:ct:v1:example.com`, TTL 6 h). It is safe to leave; delete the key if
  a fresh live source query is needed.
- The dev Compose stack and the `.venv` remain from this session; no production deploy was done.

## Notes for the next agent
- Production plugins are registered explicitly in `src/attacksurf/app.py` and
  `src/attacksurf/workers/app.py`; a new plugin needs both imports. `scanners/__init__.py`
  intentionally only holds the package docstring (importing a subpackage there breaks the
  import-linter entry-point contract).
- `ScanOutput.wildcard_zones` is validated by `services.scan_results`; persistence marks only
  the root and admitted discovered zones. A marker for a non-root input is rejected.
- Tests that need Redis behavior use `tests.fakes.FakeCache`; `workers.runtime.scan_cache` is
  `lru_cache`d and cleared on worker fork.
