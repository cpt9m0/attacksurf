# Plan: PR 3d of #84 (`84-sandbox-runner-client`), per-commit plans

## Context
- **Earlier PRs:**
  - PR 3a (#157, proxy `GET /info`) and PR 3b (#158, launcher building blocks) are on `main`.
  - PR 3c (`84-sandbox-launcher-service`) adds the launcher service, with `POST /runs` and
    `GET /healthz` on 8791.
- **The gap:** nothing on the worker side calls the launcher. `ScopeGuard` still defaults to
  `UnconfiguredSandboxRunner`, which refuses every run.
- **This PR:** adds the worker-side client and wires it into the scanner gate. It stays off until
  `SANDBOX_LAUNCHER_URL` is set.
- **Size:** about 80 non-test lines in three commits, following
  `../84-pr3-sandbox-launcher-split-4-prs.md`.

The outcome: `runtime.scanner_gate()` hands scanners a strict, bounded client for the internal
launcher when it is configured, and a fail-closed runner when it isn't. The docs state the
tenant-safety rule for callers.

## Branch and base
- `git switch -c 84-sandbox-runner-client 84-sandbox-launcher-service`. The PR is stacked on 3c,
  so its base is the 3c branch while 3c is open.
- After 3c merges:
  - Retarget the PR to `main`.
  - Run `git rebase --onto origin/main 84-sandbox-launcher-service 84-sandbox-runner-client`.
  - Push with `git push --force-with-lease`, wait for CI, then squash-merge.
- Every commit:
  - `Refs #84`. PR 5 closes #84.
  - Red → green → full gate: `ruff check`, `ruff format --check`, `pyright`, `lint-imports`, and
    the full `pytest` run with coverage of at least 80%.
  - Hooks on, never `--no-verify`.
  - Push and the draft PR happen only when the user asks.

## Commits

| File | Commit subject | Size |
|---|---|---|
| `01-add-launcher-runner-client.md` | `feat(infra): add the launcher sandbox runner client` | ~65 lines + tests |
| `02-wire-runner-into-scanner-gate.md` | `feat(workers): wire the sandbox runner into the scanner gate` | ~30 lines + tests |
| `03-document-sandbox-runner-client.md` | `docs(infra): document the sandbox runner client` | docs only |

### 1. Client (`infra/sandbox.py`)
- **Class:** `LauncherSandboxRunner(base_url, *, timeout_seconds=900.0, transport=None)`.
- **Client options:** a plain `httpx.Client(trust_env=False, follow_redirects=False)`,
  `Timeout(900, connect=5)`. It is not `SafeHttpClient`, because the launcher is internal by
  design.
- **Request:** `POST /runs {"analyzer", "artifact_id"}`.
- **Reply:** read as a stream, capped at 3 MiB. Exactly four keys with strict types. Base64 is
  decoded with `validate=True`, and the decoded stdout may be at most `MAX_OUTPUT_BYTES`.
- **Errors:**
  - 503 and transport failures raise `TransientJobError`.
  - Every other status, and every malformed reply, raises `SandboxError`.
  - Messages are fixed text and never echo the reply.
- **Tests:** `httpx.MockTransport` tables, plus contract tests against the real launcher
  `make_server` on loopback.

### 2. Wiring
- **Setting:** `Settings.sandbox_launcher_url: SecretStr | None = None`. Its validator requires
  `http://host[:port]` only.
- **`.env.example`:** gets a commented-out entry.
- **Runner:** `runtime.sandbox_runner()` is `lru_cache`'d and returns `UnconfiguredSandboxRunner`
  when the URL is unset.
- **Gate:** `scanner_gate(sandbox=...)`.
- **Fork reset:** `worker_process_init` clears the cached runner.

### 3. Docs
- `docs/architecture.md`: the worker client and the status table.
- `docs/security.md`: the tenant-safety rule (the caller confirms the artifact belongs to the org
  before `runtime.sandbox.run`; enforced with #85), and why the client is not SSRF-guarded.
- `docs/development.md`, `AGENTS.md`, `CHANGELOG.md`, `STATE.md`.

## Reused code
- `domain.sandbox`: `SandboxRunner`, `SandboxResult`, `SandboxError`,
  `UnconfiguredSandboxRunner`.
- `domain.jobs`: `TransientJobError`.
- `domain.scanners`: `MAX_OUTPUT_BYTES`.
- `infra.scope_guard`: `ScopeGuard(sandbox=...)`, `_GuardedSandbox`, which checks the analyzer
  allowlist before the client is reached.
- `workers.runtime` adapter caches, and `workers.app._fresh_db_pool`.
- `config.SandboxLauncherSettings._require_http_proxy_url` (pattern) and
  `sandbox_launcher.proxy.ProxyClient.from_url` (URL rule, copied).
- Tests only: `sandbox_launcher.server.make_server`, `sandbox_launcher.runner.RunOutcome` and
  `tests/docker_fakes.serving`.

## Verification
- Per commit: the gate above.
- Scratch-only checks (reverted):
  - Import `sandbox_launcher` from `infra/sandbox.py`. Confirm `lint-imports` fails.
  - Map 503 to `SandboxError`. Confirm the busy tests fail.
  - Drop the fork `cache_clear()`. Confirm the fork test fails.
- Optional local smoke after commit 2:
  - Start the proxy and launcher with the empty catalog, as in `docs/development.md`.
  - With `SANDBOX_LAUNCHER_URL=http://127.0.0.1:8791`, `runtime.sandbox_runner().run(...)`
    raises `SandboxError` (404).
- Real analyzer runs under `runsc` remain PR 5's job.

## After 3d merges
- Tick 3a to 3d in #84.
- Propose a follow-up issue: sweep leftover `attacksurf-*` containers after a launcher or proxy
  crash (before #92).
