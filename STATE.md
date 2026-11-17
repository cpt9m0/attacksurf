# STATE

> Handoff for the next session. Overwritten at the end of every task; not a history log.

**Updated:** 2026-11-18 · **Branch:** `84-sandbox-runner-client` · **Issue:** #84 (analysis sandbox)

## Status
PR 3d (worker-side sandbox client) is done locally and not pushed; no PR is open. It was rebased
onto `origin/main` (`022e53e`), which has PR 3c (#172, squash-merged); only the 3 PR 3d commits are
on top. Unit tests for sandbox, config and workers pass; the full suite has not been re-run.

## Last task
- `infra/sandbox.py`: `LauncherSandboxRunner` (3 MiB capped, strictly validated reply; only 503 or
  unreachable is retried; fixed error text).
- `SANDBOX_LAUNCHER_URL` setting (`SecretStr`, plain `http://host[:port]`), `compose.yaml` and
  `.env.example` entries, `workers.runtime.sandbox_runner()` wired into `scanner_gate()`.
- 3c fix: a proxy 403 (ownership denial) is unconfirmed cleanup, so `sandbox_cleanup_failed`
  fires instead of being suppressed.
- Docs, CHANGELOG and this file synced, including the tenant-safety note.

## Next step
1. Check the `.env.example` line: it says port 8080, the launcher's default is 8791.
2. Run `pre-pr-check`, push 3d, open its draft PR ("Merge order: 3d of #84"; 3c is merged).
3. Then PR 4/5: the analysis worker and the first analyzer image (`sandbox-images.lock`).

## Open threads
- Nothing enforces "the artifact belongs to the job's org" before `SandboxRunner.run`: the scope
  guard only checks the analyzer allowlist. The first analysis scanner must `get_scoped` the
  artifact first and add a tenant-isolation test (docs/security.md, Sandbox launcher).
- After a real proxy restart a stray container is alerted on but not removed. Propose a follow-up
  issue: sweep leftover `attacksurf-*` containers after a launcher or proxy crash (before #92).
- `http.client` timeouts in the launcher's proxy client apply per socket operation, not per run.
- The full test suite has not been run on this branch; `stash@{0}` and the
  `backup-3d-pre-rebase` branch are leftovers from the 3d rebase and can be deleted.
- The #84 plans are in `docs/plans/84-analysis-sandbox/` (PR #180); issue #84 is the source of
  truth for the PR split.

## Notes for the next agent
- The launcher copies proxy constants and `domain.scanners.MAX_OUTPUT_BYTES` on purpose (it may
  not import them); a parity test guards each copy. Don't "fix" that by importing.
- `sandbox-images.lock` does not exist yet (the first analyzer PR adds it); the catalog is empty,
  so every `POST /runs` is a 404 and local runs need a `{}` lock file.
- The 3 MiB reply cap assumes stdout is at most 2 MiB (base64 about 2.67 MiB).
- Compose has no launcher or proxy service yet (ADR 0016); `SANDBOX_LAUNCHER_URL` stays empty there.
- ADR numbers move fast: check `origin/main` and open branches for the next free number first.
- Production plugins are registered explicitly in `src/attacksurf/app.py` and
  `src/attacksurf/workers/app.py`; a new plugin needs both imports.
- Tests that need Redis behavior use `tests.fakes.FakeCache`.
- DB tests need `TEST_DATABASE_URL`; the dev Compose stack exposes PostgreSQL on
  `127.0.0.1:5432` with an `attacksurf_test` database (`make test` runs them in `web`).
- The ruff format hook strips imports that aren't used yet: add imports together with their
  first use.
