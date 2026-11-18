# Plan: PR 3d, commit 2: `feat(workers): wire the sandbox runner into the scanner gate`

Branch `84-sandbox-runner-client` · `Refs #84` · follows `feat(infra): add the launcher sandbox
runner client` (commit 1 of PR 3d; see `../84-pr3-sandbox-launcher-split-4-prs.md`).

## Purpose

**In plain words.** The worker now has a client for the launcher, but nothing hands that client
to scanners. This commit adds one optional setting: the launcher's address. When it is set, the
scanner gate gives scanners the real client. When it is empty, which is the default, every
sandbox request is refused just as it is today. Turning the feature on is one line of
configuration and needs no code change, and a typo in the address stops the worker from
starting instead of failing later.

**Technical.**
- **Setting:** `Settings.sandbox_launcher_url: SecretStr | None = None` in `config.py`. A field
  validator requires `http://host[:port]` with no userinfo, path, query or fragment. Its fixed
  message never repeats the value.
- **`.env.example`:** gets a commented-out `SANDBOX_LAUNCHER_URL=` entry.
- **`workers/runtime.py`:** gets `sandbox_runner() -> SandboxRunner`, cached per process with
  `@lru_cache(maxsize=1)`. It returns `LauncherSandboxRunner(url.get_secret_value())` when the
  URL is set and `UnconfiguredSandboxRunner()` when it isn't.
- **Gate:** `scanner_gate()` passes `sandbox=sandbox_runner()` to `ScopeGuard`.
- **Fork reset:** `workers/app.py` clears the new cache in the `worker_process_init` handler, so
  a forked worker never shares its parent's connection pool.
- **Layers:** `workers` → `infra` and `domain`, which is already allowed.
- **Proof:** gate tests with and without the URL, plus settings tests.

## Context
- **From commit 1:** `infra.sandbox.LauncherSandboxRunner`.
- **Existing patterns this follows:**
  - `workers/runtime.py` builds each per-process adapter as an `lru_cache`'d function:
    `session_factory`, `dns_resolver`, `ip_intel`, `scan_cache`.
  - `scanner_gate()` composes them into a `ScopeGuard`.
  - `workers/app.py:_fresh_db_pool` clears the caches that hold sockets after a fork.
  - `ScopeGuard.__init__` already accepts `sandbox` and falls back to
    `UnconfiguredSandboxRunner`. `_GuardedSandbox` enforces the analyzer allowlist on top.
- **What is missing:** the setting and the wiring.
- **Why a separate commit:** wiring and configuration are reviewed apart from the client's
  failure mapping, and the default stays off, so the change is safe to merge alone.

## Decisions
1. **`SecretStr | None`, not `str | None`.** The split plan said `str | None`, but `AGENTS.md`
   treats URLs that may embed credentials as secrets, and the other service URLs (`database_url`,
   `redis_url`, `llm_base_url`, `sandbox_proxy_url`) are `SecretStr`. The value is unwrapped only
   inside `sandbox_runner()`.
2. **Same URL rule as the client, checked at startup.**
   - The validator `_require_plain_launcher_url` uses `urlsplit` and requires all of:
     - `scheme == "http"`
     - a hostname
     - no username or password
     - a path of `""` or `"/"`
     - no query or fragment
     - a valid port
   - Message: `"SANDBOX_LAUNCHER_URL must be http://host[:port] only"`.
   - So `LauncherSandboxRunner`'s own `ValueError` can never fire from config. A bad value
     surfaces when settings load, not on the first scan.
   - It is stricter than `SandboxLauncherSettings._require_http_proxy_url`, which allows a path.
     That validator is not reused, because its message names `SANDBOX_PROXY_URL`.
3. **Off by default.** `None` keeps `UnconfiguredSandboxRunner`, so dev, test and existing
   deployments behave exactly as before. `env_ignore_empty=True` already makes an empty value in
   `.env` mean "unset".
4. **The runner is cached; the gate is not.** `sandbox_runner()` holds one `httpx.Client` and
   its connection pool per process, like `scan_cache()` holds one Redis pool.
   `scanner_gate()` stays uncached and is rebuilt per call, as today.
5. **Fork safety.** `runtime.sandbox_runner.cache_clear()` is added to `_fresh_db_pool`, next to
   the session and Redis resets, so no process inherits the parent's sockets. The handler name
   stays the same, and its comment broadens to "pools".
6. **No `compose.yaml` change.** The launcher service is not in compose yet (PR 4), so setting
   the URL there now would point at nothing. `.env.example` documents the variable, commented
   out.
7. **No prod requirement.** Prod may run without the launcher until the analysis worker exists
   (PR 4 and PR 5). A missing URL fails closed at run time, not at start.
8. **No docs in this commit.** Commit 3 of PR 3d carries `docs/development.md`,
   `docs/architecture.md`, `CHANGELOG.md` and `STATE.md`.

## Requirements
- [ ] `Settings.sandbox_launcher_url: SecretStr | None = None`, read from `SANDBOX_LAUNCHER_URL`.
- [ ] Its validator refuses the URL shapes in decision 2 with a fixed message that never contains
      the value. `None` passes untouched.
- [ ] `.env.example` has a commented-out `SANDBOX_LAUNCHER_URL` entry with a one-line comment
      (internal `http://sandbox-launcher:8791`, empty = sandbox off).
- [ ] `runtime.sandbox_runner()` is `@lru_cache(maxsize=1)` and returns `LauncherSandboxRunner`
      when the URL is set, `UnconfiguredSandboxRunner` otherwise.
- [ ] `runtime.scanner_gate()` passes `sandbox=runtime.sandbox_runner()`. The other arguments
      are unchanged.
- [ ] `workers/app.py` `worker_process_init` handler calls `runtime.sandbox_runner.cache_clear()`.
- [ ] No change to `infra/sandbox.py`, `infra/scope_guard.py`, `domain/` or `compose.yaml`.

## Acceptance criteria
- [ ] **Contract (off):** with default settings, `scanner_gate()._sandbox` is an
      `UnconfiguredSandboxRunner`, and a run through it raises `SandboxError`.
- [ ] **Contract (on):** with `sandbox_launcher_url=SecretStr("http://sandbox-launcher:8791")`,
      `scanner_gate()._sandbox` is a `LauncherSandboxRunner`.
- [ ] **Contract (allowlist still first):** a gate built with the URL, checked for a scanner whose
      grant has no `sandbox_analyzers`, still raises `ScopePolicyError` from `runtime.sandbox.run`
      before any request leaves (the runner's transport is never called).
- [ ] **Fork:** `sandbox_runner()` is cached, and `worker_process_init.send(...)` returns a new
      instance.
- [ ] **Negative:** each bad URL raises `ValidationError` whose text contains
      `SANDBOX_LAUNCHER_URL` and not the value's secret marker.
- [ ] **Masking:** a URL set from the environment does not appear in `repr(settings)` or
      `model_dump_json()`.
- [ ] **Isolation:** `uv run lint-imports` passes.
- [ ] **Gate:** `ruff check`, `ruff format --check`, `pyright`, `lint-imports` and the full
      `pytest` run all pass with coverage of at least 80%. The commit passes the hooks without
      `--no-verify`.

## Changes

### 1. `src/attacksurf/config.py` (~+15 lines)
- A field under a `# Sandboxed analysis (ADR 0016, #84)` comment: `sandbox_launcher_url:
  SecretStr | None = None`.
- `@field_validator("sandbox_launcher_url")` `_require_plain_launcher_url` as in decision 2.

### 2. `.env.example` (+2 lines)
- A comment line and `# SANDBOX_LAUNCHER_URL=http://sandbox-launcher:8791`.
- This file is read-protected in the planning session. The edit may need the user's approval,
  or the user may make it.

### 3. `src/attacksurf/workers/runtime.py` (~+12 lines)
- `sandbox_runner()`, with a docstring: "Off unless SANDBOX_LAUNCHER_URL is set; one client and
  pool per process."
- `scanner_gate()` gains `sandbox=sandbox_runner()`.
- Imports: `LauncherSandboxRunner` from `infra.sandbox`, and `SandboxRunner` and
  `UnconfiguredSandboxRunner` from `domain.sandbox`.

### 4. `src/attacksurf/workers/app.py` (+1 line)
- `runtime.sandbox_runner.cache_clear()` in `_fresh_db_pool`, with the comment updated.

### 5. Tests (written first)
- **Config tests:** in `tests/unit/test_config.py`, style following the
  `test_sandbox_launcher_settings_*_proxy_urls` tests.
- **Gate tests:** in `tests/unit/workers/test_app.py`, style following
  `test_production_gate_checks_ownership_in_the_database`. A fixture monkeypatches
  `runtime.settings` to `make_settings(env="test", secret_key=..., sandbox_launcher_url=...)` and
  clears `runtime.sandbox_runner` before and after, so the session-wide hermetic settings from
  `tests/conftest.py` are restored.

#### A. Happy path
| Test | Given | Expect |
|---|---|---|
| `test_sandbox_launcher_url_defaults_to_none` | `make_settings()` | `None` |
| `test_sandbox_launcher_url_reads_from_environment` | `clean_env` + `SANDBOX_LAUNCHER_URL` | `SecretStr`, value kept |
| `test_gate_refuses_sandbox_runs_without_a_launcher_url` | default settings | `gate._sandbox` is `UnconfiguredSandboxRunner` |
| `test_gate_uses_the_launcher_client_when_configured` | URL set | `gate._sandbox` is `LauncherSandboxRunner` |
| `test_sandbox_runner_is_cached_per_process_and_rebuilt_after_fork` | URL set | same object twice; new one after `worker_process_init` |

#### B. Boundary cases
| Test | Given | Expect |
|---|---|---|
| `test_sandbox_launcher_url_accepts_plain_http` (param `http://sandbox-launcher:8791`, `http://10.0.0.5:8791/`, `http://launcher`) | each | accepted |
| `test_empty_sandbox_launcher_url_means_off` | `clean_env` + `SANDBOX_LAUNCHER_URL=""` | `None`; gate unconfigured |

#### C. Invalid inputs (must raise `ValidationError`, message never echoes the value)
| Test | Given | Expect |
|---|---|---|
| `test_sandbox_launcher_url_refuses_other_shapes` (param `https://l:1`, `ftp://l`, `l:8791`, `http://`, `http://u:hunter2@l:1`, `http://l:1/api`, `http://l:1?x=1`, `http://l:1#f`, `http://l:99999`) | each | `ValidationError` naming `SANDBOX_LAUNCHER_URL` |
| `test_sandbox_launcher_url_error_does_not_echo_credentials` | `ftp://u:hunter2@l` | `hunter2` absent |
| `test_sandbox_launcher_url_is_masked` | `http://l:8791` set | absent from `repr` and `model_dump_json` |

#### D. Neighbor rejection and drift guards
| Test | Given | Expect |
|---|---|---|
| `test_gate_still_enforces_the_analyzer_allowlist` | URL set, `MockTransport` runner swapped in via monkeypatch on `runtime.sandbox_runner`, scanner with empty `sandbox_analyzers` | `ScopePolicyError`; transport never called |
| `test_every_valid_setting_builds_a_runner` (param the B URLs) | settings value passed to `LauncherSandboxRunner` | no `ValueError` (the two URL rules agree) |

Section D shows that the setting and the client cannot drift apart, since any URL the settings
accept, the client accepts too. It also shows that wiring a real client does not weaken the
analyzer allowlist.

## Order of work (red → green)
1. Write the new tests in `tests/unit/test_config.py` and `tests/unit/workers/test_app.py`. Run
   them and confirm they fail because the field and `sandbox_runner` are missing.
2. Add the setting and validator, then `sandbox_runner()`, the gate argument and the fork reset.
   Finally edit `.env.example`, with approval if needed.
3. Full gate:
   ```bash
   uv run ruff check . && uv run ruff format --check . && uv run pyright \
     && uv run lint-imports && uv run pytest
   ```
4. `finish-task` is deferred to commit 3. Run the `pre-pr-check` self-review.
5. Commit:
   - Subject: `feat(workers): wire the sandbox runner into the scanner gate`.
   - Body: explains *why* (the sandbox is reachable only when configured, and stays fail-closed
     by default).
   - Footer: `Refs #84` and the Co-Authored-By trailer.
   - Never `--no-verify`.

## Reused code
- `src/attacksurf/infra/sandbox.py`: `LauncherSandboxRunner` (commit 1).
- `src/attacksurf/domain/sandbox.py`: `SandboxRunner`, `UnconfiguredSandboxRunner`.
- `src/attacksurf/workers/runtime.py`: the `lru_cache` adapter pattern (`scan_cache`, `ip_intel`).
- `src/attacksurf/workers/app.py`: `_fresh_db_pool`.
- `src/attacksurf/config.py`: `SandboxLauncherSettings._require_http_proxy_url` (pattern) and
  the `SecretStr` URL convention.
- `tests/helpers.py`: `make_settings`, `settings_from_env`. The `clean_env` fixture.
- `tests/unit/infra/test_scope_guard.py`: scanner and grant fixtures for the allowlist test.

## Verification
- Run `uv run pytest tests/unit/test_config.py tests/unit/workers -q` until green, then the full
  suite with coverage of at least 80%.
- Scratch-only checks (revert afterwards):
  - Remove the `cache_clear()` line. Confirm the fork test fails.
  - Pass the URL with `str` instead of `SecretStr`. Confirm the masking test fails.
  - Drop `sandbox=` from `scanner_gate()`. Confirm the "configured" gate test fails.
- Optional manual smoke (needs PR 3c's local setup in `docs/development.md`):
  - Start the proxy and the launcher.
  - Run `SANDBOX_LAUNCHER_URL=http://127.0.0.1:8791 uv run python -c "from attacksurf.workers
    import runtime; ..."`, which calls `runtime.sandbox_runner().run("x", uuid4())`.
  - Expect `SandboxError`: the launcher answers 404 because the catalog is empty.

## Notes for later commits
- **Commit 3 (docs):** document `SANDBOX_LAUNCHER_URL` in `docs/development.md` and the off-by-default
  behavior in `docs/architecture.md`.
- **PR 4 (compose):** set `SANDBOX_LAUNCHER_URL=http://sandbox-launcher:8791` only for the
  analysis worker service; keep it unset for `worker-passive` and `web`.
- **PR 5:** the first analyzer scanner declares `sandbox_analyzers`; its tests use a fake
  `SandboxRunner`, not this wiring.
