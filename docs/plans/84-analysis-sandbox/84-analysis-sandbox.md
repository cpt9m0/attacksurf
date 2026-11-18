# Plan: issue #84, analysis sandbox runner and analysis worker

## Context
#84 builds the foundation that lets scanners run analysis tools on untrusted repositories and
binaries (epics #67, #68). Its text predates ADR 0016 and conflicts with it: it lets the caller
pass tool, args, inputs and limits, and omits the launcher and proxy. Decision: keep the ADR 0016
fixed-menu architecture. The caller names only an analyzer and an artifact ID.

**Answer: 5 branches, 5 PRs**, all squash-merged in the order below. PRs 1-4 say `Refs #84`;
PR 5 says `Closes #84`.

## What you need to do
1. Approve the rewritten issue text (drafted in chat). Claude applies it with `gh issue edit`.
2. Decide on #133: it adds `compose.prod.yaml`, which PR 4 extends. Default: merge #133 before
   PR 4. Alternative: dev compose only, with a follow-up issue for prod.
3. Decide how to record that the `analysis` queue goes live before a real analyzer exists.
   Default: a short new ADR in PR 4 (AGENTS.md: changing a decision means a new ADR; number it
   after #133's ADR 0020). Alternative: move queue activation to #92.
4. Review and merge each PR, in order. Claude commits and pushes, and merges only when asked.
5. Before PR 4 is deployed to prod: register `runsc` in the VPS Docker `daemon.json`, because the
   launcher refuses to start in prod without it.

## Branches and PRs
Branches start from up-to-date `main`, except drafts stacked as described in "Recording the
merge order". PR 2 does not depend on PR 1, so those two proceed in parallel.

### PR 1: `84-sandbox-port`, `feat(scanners): add sandbox port and analyzer grants`
- `domain/`: `SandboxRunner.run(analyzer, artifact_id) -> SandboxResult`, plus a fail-closed
  unconfigured runner.
- `ScannerGrant` (`domain/scanners.py`): analyzer allowlist field, default empty, validated.
- `ScannerRuntime` (`domain/net.py`): `sandbox` slot. `ScopeGuard.check`
  (`infra/scope_guard.py`) wraps the runner so every call is checked against the grant; wire in
  `workers/runtime.py`.
- Fake runner and `FixtureGate` update in `tests/scanner_fixtures.py`.
- Delivers the acceptance criterion: a scanner without the grant can't call the sandbox.

### PR 2: `84-sandbox-proxy`, `feat(security): add sandbox proxy with create policy`
- Small deny-by-default service, the only Docker socket holder. Allows create, start, wait,
  attach (stdout), kill, remove. Stdout attach is a hijacked stream, so it needs raw pass-through
  (check the Docker Engine API docs first).
- Pure policy module validating create bodies: digest allowlist, runtime, flags, limits, one
  read-only bind under the artifact root, OSV volume for the osv-scanner image only.
- Table-driven rejection tests for every case in the rewritten issue. Standard library preferred.
- New import-linter contract: proxy and launcher never import db, services, Celery or web.

### PR 3: `84-sandbox-launcher`, `feat(infra): add sandbox launcher and runner client`
- Launcher service with a declarative allowlist (digest, fixed command and args, capped limit
  overrides). Resolves artifact ID to a directory, rejecting traversal.
- Enforces wall-time kill, 2 MiB stdout kill and fail, stderr discard, `runsc` check in prod.
- Own settings class in `config.py`: `Settings` requires `SECRET_KEY` in prod, and the launcher
  must hold no such secrets. Update `.env.example`.
- Infra `SandboxRunner` HTTP client (`httpx`), with a deadline above the wall-time limit.
- Server timeout must exceed the 600 s wall limit. The artifact root must be a host bind path,
  because Docker resolves bind sources on the host.

### PR 4: `84-analysis-worker`, `feat(workers): add analysis worker and sandbox services`
- Move `analysis` from `RESERVED_QUEUES` to `QUEUES` (`infra/queue.py`); update `test_queue.py`.
- Add a guard and test that no scan profile selects an analysis scanner until #92.
- `compose.yaml` and `compose.prod.yaml`: `worker-analysis`, `sandbox-launcher`, `sandbox-proxy`
  on an internal network; only the proxy mounts the socket. New Dockerfile targets.
- Queue decision record (see step 3).

### PR 5: `84-sandbox-ci`, `ci(security): build sandbox images and test under runsc`
- Harmless fixture analyzer image, `sandbox-images.lock` (fixture allowed in dev and CI only).
- Image build workflow with SHA-pinned actions and minimal permissions.
- CI job installing `runsc`, running integration tests: no network, read-only input and root,
  timeout kills, output cap kills and fails. Locally built images use their `sha256:` image ID.

## Recording the merge order
Required merge order: PR 1 → 2 → 3 → 4 → 5. PRs may be open at the same time, but still merge
in this order.

Working order:
| Stage | PRs | When |
|---|---|---|
| 1 | PRs 1 and 2 | Open together from `main` once the issue is rewritten |
| 2 | PR 3 | Draft once PR 2's rules pass review; rebase on `main` after PRs 1 and 2 merge |
| 3 | PRs 4 and 5 | Start once PR 3 merges; PR 5 may be a draft on top of PR 4 |

- **Issue #84 (source of truth):** add this "Merge order" checklist to the rewritten issue, and
  link each PR as it opens.
  ```markdown
  ## Merge order
  - [ ] 1. `84-sandbox-port`
  - [ ] 2. `84-sandbox-proxy`
  - [ ] 3. `84-sandbox-launcher`
  - [ ] 4. `84-analysis-worker` (after #133)
  - [ ] 5. `84-sandbox-ci` (closes this issue)
  ```
- **Each PR description:** `Merge order: N of 5. Merge after #<PR>, before #<PR>. See #84.`
- **`STATE.md`:** current position and next PR only.

## Conventions for every PR
- Follow `AGENTS.md`: tests first for security checks, `pre-pr-check`, `finish-task`, and update
  `CHANGELOG.md`, `STATE.md`, `docs/architecture.md`, `docs/security.md`, `docs/development.md`.
- PR 2 or 3 adds the new service packages to the `AGENTS.md` layout section.
- Keep each PR to about 400 changed lines, excluding tests and fixtures.
- Add a tenant-safety note: the worker must confirm the artifact belongs to the org before asking
  the launcher (real enforcement arrives with #85's artifact table).

## Verification
- Every PR: `uv run ruff check .`, `uv run ruff format --check .`, `uv run pyright`,
  `uv run lint-imports`, `uv run pytest` (coverage at least 80%).
- PR 4: `make up` reports all new services healthy; inspect containers to confirm the socket and
  credential separation.
- PR 5: the `runsc` CI job passes and exercises every issue acceptance criterion.
