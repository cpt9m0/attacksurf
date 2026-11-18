# Plan: PR 3 of #84, `84-sandbox-launcher`

`feat(infra): add sandbox launcher and runner client` · Merge order 3 of 5 · `Refs #84`

## Context
PRs 1 (#134, the sandbox port and grants) and 2 (#135, the Docker socket proxy) are merged.
Workers can name an analyzer and an artifact ID, and the proxy can refuse unsafe Docker requests.
Nothing connects the two yet. PR 3 adds the **launcher**. It turns "run analyzer X on artifact Y"
into one proxy-approved sandbox container. It watches the run, kills it if it runs too long or
prints too much, and returns the result. PR 3 also adds the worker-side client that calls the
launcher. Compose wiring is PR 4. Real Docker and `runsc` tests are PR 5.

The work is split into 10 small commits. Each commit leaves the branch green.

## Step 0: rename this plan file
Rename `docs/plans/what-do-each-of-vivid-alpaca.md` to
`docs/plans/84-analysis-sandbox/84-pr3-sandbox-launcher.md` (issue 84, PR 3 of 5, the sandbox launcher). It sits
next to `84-analysis-sandbox.md`. `docs/plans/` is untracked, so the plan is never committed.

## Testing gate before every commit
Each commit follows the same loop. Nothing is committed until every step passes.
1. **Red:** write the commit's tests first and run them. Confirm they fail for the expected
   reason (security checks are always tests-first, per AGENTS.md).
2. **Green:** implement until `uv run pytest <the commit's test files>` passes.
3. **Full gate:**
   ```bash
   uv run ruff check . && uv run ruff format --check . && uv run pyright \
     && uv run lint-imports && uv run pytest     # full suite, Postgres, coverage >= 80%
   ```
4. Commit. The pre-commit hook also runs ruff and gitleaks. Never use `--no-verify`.

## Decisions taken (change them at review if needed)
- **`runsc` check:** the proxy gets one new read-only call, `GET /info`. It replies with
  runtime **names only** and strips everything else Docker reports. The launcher asks at
  startup and refuses to start in prod without `runsc` (commit 2 and commit 8).
- **Wall-time ceiling:** the launcher's wall time is capped at 840 s, below the proxy's
  `RUN_TIMEOUT_SECONDS = 900`, so the launcher's own kill always fires first. The worker
  client waits 900 s, which is above any allowed wall time. No shared setting is needed.
- **Analyzer catalog:** it is defined in code and starts **empty**. Digests come from
  `sandbox-images.lock`. The harmless fixture analyzer arrives in PR 5.
- **Size:** the estimate is about 600 non-test lines, which is over the ~400 guideline. If the
  diff is over budget after commit 8, commit 9 (client and wiring) moves to its own stacked PR,
  `84-sandbox-client`, and the merge-order note is updated.

## Commits

### 1. `test(security): share the fake Docker daemon`
- Move `FakeDocker` out of `tests/unit/sandbox_proxy/test_server.py` into
  `tests/docker_fakes.py`.
- Extend it to send scripted attach frames (stdout and stderr), to stay open until killed, and
  to let `wait?condition=removed` return after an exit or a kill.
- Tests only. Existing proxy tests must pass unchanged.

### 2. `feat(security): expose runtime names through the sandbox proxy`
- `sandbox_proxy/policy.py` `classify_request`: allow `GET /info`, with the optional
  `/v1.NN` prefix, no query string, and `Route("info", None, "/info")`. Every other `GET` is
  still denied.
- `sandbox_proxy/server.py`: forward the call, parse the reply, and answer only
  `{"Runtimes": [sorted names]}`. A bad Docker reply gets a 502.
- Tests first: add policy table rows (allowed, with a query, other GET paths) and a server
  test proving that extra `/info` fields are never relayed.

### 3. `feat(infra): add sandbox launcher settings`
- In `config.py`, add `SandboxLauncherSettings`, modeled on `SandboxProxySettings`: env only,
  no `.env`, and no DB, Redis or `SECRET_KEY`. Fields:
  - `env`
  - `sandbox_artifact_root`
  - `sandbox_images_lock`
  - `sandbox_proxy_url` (default `http://sandbox-proxy:8790`)
  - `sandbox_launcher_host`
  - `sandbox_launcher_port` (8791)
  - `sandbox_wall_time_seconds` (600, between 1 and 840)
  - `sandbox_max_concurrent_runs` (2, between 1 and 16)
  - `sandbox_allow_runc` (refused in prod)
- Move the artifact-root check into one shared helper that both settings classes use.
- Add the new variables to `.env.example`.
- Tests first in `tests/unit/test_config.py`: runc refused in prod, wall time above 840
  refused, a bad root refused, and no secret fields.

### 4. `feat(infra): add sandbox analyzer catalog and artifact resolver`
- Create the `src/attacksurf/sandbox_launcher/` package and add an import-linter contract in
  `pyproject.toml`. The launcher may not import web, workers, services, infra, scanners, ai,
  `sandbox_proxy`, celery, flask, httpx, psycopg, redis or sqlalchemy. Also add
  `attacksurf.sandbox_launcher` to the proxy contract.
- `catalog.py`:
  - frozen `AnalyzerSpec` holding a fixed command and args, plus optional CPU, memory, pids and
    scratch overrides, each capped below the proxy ceilings;
  - an empty `CATALOG`;
  - `load_catalog(lock_path)`, which joins specs to lock digests, so an analyzer missing from
    the lock is unavailable.
- `artifacts.py`: `resolve_artifact(root, artifact_id: UUID) -> Path`. It returns
  `{root}/{uuid}` and requires a real directory: not a symlink, and resolving inside the root.
- Tests first: missing directory, symlink, file instead of directory, symlink escaping the
  root, unknown analyzer, override above a ceiling, and a lock entry without a spec.

### 5. `feat(infra): build sandbox create bodies the proxy accepts`
- `sandbox_launcher/container.py`: `build_create_body(spec, digest, artifact_dir, runtime)`.
  It produces the ADR 0016 body, with the OSV bind only for `osv-scanner`.
- Contract test: every body it builds passes the **real** `sandbox_proxy.policy.validate_create`.
  Tests may import both packages. Also test that every catalog limit stays within the proxy
  ceilings.

### 6. `feat(infra): read capped stdout from docker attach streams`
- `sandbox_launcher/stream.py`: a pure function that splits Docker's 8-byte frame headers
  apart. It keeps stdout, throws stderr away, and stops as soon as stdout passes 2 MiB.
- Tests first, using byte fixtures: frames split across reads, a stderr frame dropped, exactly
  2 MiB accepted, 2 MiB + 1 byte rejected, a cut-off header, and an unknown stream type.

### 7. `feat(infra): supervise sandbox runs through the proxy` (riskiest)
- `sandbox_launcher/runner.py` uses stdlib `http.client` to talk to the proxy. Order:
  1. create;
  2. `wait?condition=removed` on a thread, armed before start so automatic removal can't race it;
  3. attach;
  4. start;
  5. read stdout through `stream.py`.
- Kill (`POST kill?signal=SIGKILL`) when the wall time passes or when the output cap trips. If
  removal isn't confirmed, fall back to `DELETE ?force=1`. Every failure path cleans up.
- Return `exit_code`, `stdout`, `timed_out` and `output_exceeded`. When the cap trips, stdout
  is dropped.
- Log one line per run: analyzer, exit status, byte count, duration and flags. Never log
  output or paths.
- Tests first, running against the real proxy (`make_server`) in front of `FakeDocker`:
  - a clean exit;
  - a non-zero exit;
  - a wall-time kill;
  - an output-cap kill;
  - stderr never returned;
  - the proxy refusing create;
  - attach failing after create, with cleanup still happening;
  - the proxy unreachable;
  - the log line containing no stdout bytes.

### 8. `feat(infra): serve the sandbox launcher api`
- `sandbox_launcher/server.py`, built on `ThreadingHTTPServer`, which the proxy uses too:
  - `GET /healthz`;
  - `POST /runs {analyzer, artifact_id}`, with a strict JSON body, a size cap, the analyzer
    name pattern and a UUID. It answers `{exit_code, stdout_b64, timed_out, output_exceeded}`.
- Status codes: 404 for an unknown analyzer or artifact, 503 when the concurrency limit is
  full or the proxy fails, and generic messages throughout.
- `__main__.py`: load the settings and catalog, then run the `runsc` check:
  - prod needs `runsc` listed in the proxy's `/info`;
  - outside prod, `runc` is used only when `runsc` is missing **and**
    `SANDBOX_ALLOW_RUNC=true`;
  - otherwise the launcher exits non-zero.
- Tests first: every bad-request case, the busy reply, a full round trip, and the startup
  check in prod with and without `runsc`.

### 9. `feat(infra): add the launcher sandbox runner client`
- `infra/sandbox.py`: `LauncherSandboxRunner`, built on `httpx.Client` with
  `trust_env=False`, no redirects and a 900 s timeout. It caps the reply at about 3 MiB and
  decodes it into `SandboxResult`. It is not the SSRF-guarded client, because the launcher is
  an internal service.
- Error mapping: 4xx raises `SandboxError`; 503 or connection failure raises
  `TransientJobError`. Messages are generic.
- `Settings.sandbox_launcher_url: str | None = None` (`.env.example`), wired in
  `workers/runtime.scanner_gate()`. When the URL is `None`, the existing
  `UnconfiguredSandboxRunner` is used.
- Tests first with `httpx.MockTransport`: the success decode, an oversized reply, each error
  mapping, and `scanner_gate` with and without the URL.

### 10. `docs(infra): document the sandbox launcher`
- Run the `finish-task` steps: `docs/architecture.md`, `docs/security.md` (the launcher's role
  and the `/info` exposure), `docs/development.md`, the `AGENTS.md` layout (add
  `sandbox_launcher/`), `CHANGELOG.md` `[Unreleased]` and `STATE.md`.
- Add the tenant-safety note: the worker must check that the artifact belongs to the org before
  calling the launcher.
- Run the gate again, then run `pre-pr-check`.

## Critical files
- New: `src/attacksurf/sandbox_launcher/{__init__,__main__,catalog,artifacts,container,stream,runner,server}.py`,
  `src/attacksurf/infra/sandbox.py` and `tests/docker_fakes.py`
- New tests: `tests/unit/sandbox_launcher/` and `tests/unit/infra/test_sandbox.py`
- Changed: `src/attacksurf/config.py`, `src/attacksurf/sandbox_proxy/{policy,server}.py`,
  `src/attacksurf/workers/runtime.py`, `pyproject.toml`, `.env.example` and the docs
- Reused: `sandbox_proxy.policy` constants, `validate_create` and `load_images` (tests and the
  lock format), `domain.sandbox.SandboxResult` / `SandboxError` / `UnconfiguredSandboxRunner`,
  and the `ScopeGuard(sandbox=...)` slot in `infra/scope_guard.py`

## Verification
- Every commit: the testing gate above.
- Before opening the PR: `pre-pr-check`, and confirm the diff size (see Decisions).
- Optional local smoke test, safe because it uses the empty catalog: start the proxy with
  `SANDBOX_ALLOW_RUNC=true` and the launcher, then check that `GET /healthz` returns 200 and
  that `POST /runs` with any analyzer returns 404.
- Real container behavior (no network, kills under `runsc`) is proven in PR 5's CI job.

## After merge
- Tick item 3 in #84's merge-order checklist.
- Propose a follow-up issue: sweep leftover `attacksurf-*` containers after a launcher or proxy
  crash (before #92).
