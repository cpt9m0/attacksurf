# Plan: #84 PR 3 (sandbox launcher), split into 4 PRs

## Context
PRs 1 (#134, the sandbox port and grants) and 2 (#135, the Docker socket proxy) are merged.
Workers can name an analyzer and an artifact ID, and the proxy can refuse unsafe Docker requests.
Nothing connects the two yet. The original PR 3 adds the **launcher**. It turns "run analyzer X
on artifact Y" into one proxy-approved sandbox container, kills the container if it runs too
long or prints too much, and returns the result. PR 3 also adds the worker-side client that
calls the launcher.

At about 600 lines, PR 3 is too big for one review, so it is split into **4 PRs (3a to 3d)**.
Issue #84 goes from 5 PRs to 8. Compose wiring (PR 4) and the real `runsc` tests (PR 5) don't
change.

## Step 0: housekeeping (before any code)
1. Move this file over `docs/plans/84-analysis-sandbox/84-pr3-sandbox-launcher.md`, the name you chose. That
   replaces the older single-PR version. `docs/plans/` is untracked.
2. Update the "PR 3" section of `docs/plans/84-analysis-sandbox/84-analysis-sandbox.md` to list 3a to 3d.
3. Update the "Merge order" checklist on issue #84. I'll show you the new text first and run
   `gh issue edit` only after you approve it:
   ```markdown
   - [x] 1. `84-sandbox-port` (#134)
   - [x] 2. `84-sandbox-proxy` (#135)
   - [ ] 3a. `84-sandbox-runtime-info`
   - [ ] 3b. `84-sandbox-launcher-core`
   - [ ] 3c. `84-sandbox-launcher-service`
   - [ ] 3d. `84-sandbox-runner-client`
   - [ ] 4. `84-analysis-worker` (after #133)
   - [ ] 5. `84-sandbox-ci` (closes this issue)
   ```

## Order and parallel work
| PR | Branch | Depends on | Can start |
|---|---|---|---|
| 3a | `84-sandbox-runtime-info` | none | now |
| 3b | `84-sandbox-launcher-core` | none | now, in parallel with 3a |
| 3c | `84-sandbox-launcher-service` | 3a and 3b | after both merge (or as a draft stacked on them) |
| 3d | `84-sandbox-runner-client` | 3c (the API shape) | draft stacked on 3c |

All four PRs say `Refs #84`. Each description includes:
`Merge order: 3x of #84. Merge after #<PR>, before #<PR>. See #84.`

## Testing gate before every commit (all PRs)
1. **Red:** write the commit's tests first and run them. Confirm they fail for the expected
   reason.
2. **Green:** implement until `uv run pytest <the commit's test files>` passes.
3. **Full gate:**
   ```bash
   uv run ruff check . && uv run ruff format --check . && uv run pyright \
     && uv run lint-imports && uv run pytest     # full suite, Postgres, coverage >= 80%
   ```
4. Commit. The pre-commit hook runs ruff and gitleaks. Never use `--no-verify`.

Before each PR opens: run `pre-pr-check` and check the diff size, then make the last commit
with `finish-task` (docs, `CHANGELOG.md`, `STATE.md`).

## Decisions taken (change them at review if needed)
- **`runsc` check:** the proxy gets one new read-only call, `GET /info`. It replies with
  runtime **names only** and strips everything else Docker reports. The launcher asks at
  startup and refuses to start in prod without `runsc`.
- **Wall-time ceiling:** the launcher's wall time is capped at 840 s, below the proxy's
  `RUN_TIMEOUT_SECONDS = 900`, so the launcher's own kill always fires first. The worker client
  waits 900 s.
- **Analyzer catalog:** it is defined in code and starts **empty**. Digests come from
  `sandbox-images.lock`. The fixture analyzer arrives in PR 5.

---

## PR 3a: `feat(security): let the sandbox proxy report runtime names` (~40 lines)
Gives the launcher a safe way to ask "is gVisor (`runsc`) installed?".
1. `feat(security): allow a runtime-names info call through the proxy`
   - `sandbox_proxy/policy.py` `classify_request`: allow `GET /info`, with the optional
     `/v1.NN` prefix, no query string, and `Route("info", None, "/info")`. Every other `GET`
     is still denied.
   - `sandbox_proxy/server.py`: forward the call and answer only
     `{"Runtimes": [sorted names]}`. A bad Docker reply gets a 502.
   - Tests first: policy table rows (allowed, with a query, other GET paths), and a server test
     using the existing `FakeDocker`, extended for `/info`, proving that extra fields are never
     relayed.
2. `docs(security): document the proxy info call`: `docs/security.md`, `CHANGELOG.md`,
   `STATE.md`.

## PR 3b: `feat(infra): add sandbox launcher building blocks` (~230 lines)
The pure parts of the launcher. They make no network calls and run no containers, so each one
is easy to test.
1. `feat(infra): add sandbox launcher settings`
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
   - Share the artifact-root check with `SandboxProxySettings`, and update `.env.example`.
   - Tests first in `tests/unit/test_config.py`.
2. `feat(infra): add sandbox analyzer catalog and artifact resolver`
   - Create the `src/attacksurf/sandbox_launcher/` package and add an import-linter contract.
     The launcher may not import web, workers, services, infra, scanners, ai, `sandbox_proxy`,
     celery, flask, httpx, psycopg, redis or sqlalchemy. Add `attacksurf.sandbox_launcher` to
     the proxy's contract too.
   - `catalog.py`:
     - frozen `AnalyzerSpec` holding a fixed command and args, plus capped limit overrides;
     - an empty `CATALOG`;
     - `load_catalog(lock_path)`, so an analyzer missing from the lock is unavailable.
   - `artifacts.py`: `resolve_artifact(root, artifact_id: UUID) -> Path`. It returns
     `{root}/{uuid}`, and only if that is a real directory: not a symlink, and resolving inside
     the root.
   - Tests first: missing, symlink, file, escaping symlink, unknown analyzer, override above a
     ceiling, and a lock entry without a spec.
3. `feat(infra): build sandbox create bodies the proxy accepts`
   - `container.py`: `build_create_body(spec, digest, artifact_dir, runtime)`, producing the
     ADR 0016 body, with the OSV bind only for `osv-scanner`.
   - Contract test: every body passes the **real** `sandbox_proxy.policy.validate_create`, and
     every catalog limit stays within the proxy ceilings.
4. `feat(infra): read capped stdout from docker attach streams`
   - `stream.py`: a pure function that splits Docker's 8-byte frame headers apart. It keeps
     stdout, discards stderr, and stops once stdout passes 2 MiB.
   - Tests first: split frames, stderr dropped, exactly 2 MiB accepted, 2 MiB + 1 byte
     rejected, a cut-off header, and an unknown stream type.
5. `docs(infra): document the launcher building blocks`: the `AGENTS.md` layout
   (`sandbox_launcher/`), `docs/architecture.md`, `CHANGELOG.md` and `STATE.md`.

## PR 3c: `feat(infra): add the sandbox launcher service` (~270 lines, riskiest)
Puts the building blocks together into a running service. This PR gets the closest review.
1. `test(security): share the fake Docker daemon`
   - Move `FakeDocker` into `tests/docker_fakes.py`.
   - Extend it to send scripted stdout and stderr frames, to stay open until killed, and to
     let `wait?condition=removed` return after an exit or a kill.
   - Tests only. Existing proxy tests pass unchanged.
2. `feat(infra): supervise sandbox runs through the proxy`
   - `runner.py` uses stdlib `http.client` to the proxy. Order: create, then
     `wait?condition=removed` on a thread (armed before start), then attach, then start, then
     read stdout through `stream.py`.
   - Use `SIGKILL` at the wall time or when the output cap trips. If removal isn't confirmed,
     fall back to `DELETE ?force=1`. Every failure path cleans up.
   - Return `exit_code`, `stdout`, `timed_out` and `output_exceeded`. When the cap trips,
     stdout is dropped.
   - Log one line per run with metadata only: no output and no paths.
   - Tests first, running against the real proxy (`make_server`) in front of `FakeDocker`:
     - a clean exit;
     - a non-zero exit;
     - a wall-time kill;
     - an output-cap kill;
     - stderr never returned;
     - the proxy refusing create;
     - attach failing after create, with cleanup still happening;
     - the proxy unreachable;
     - the log line containing no output.
3. `feat(infra): serve the sandbox launcher api`
   - `server.py`, built on `ThreadingHTTPServer`:
     - `GET /healthz`;
     - `POST /runs {analyzer, artifact_id}`, with a strict JSON body, a size cap, the analyzer
       name pattern and a UUID. It answers `{exit_code, stdout_b64, timed_out,
       output_exceeded}`.
   - Status codes: 404 for an unknown analyzer or artifact, and 503 when busy or when the proxy
     fails. Messages are generic.
   - Tests first: each bad request, the busy reply, and a full round trip.
4. `feat(security): refuse to start the launcher without runsc in prod`
   - `__main__.py`: load the settings and catalog, then ask the proxy's `/info`:
     - prod needs `runsc`;
     - outside prod, `runc` is used only when `runsc` is missing **and**
       `SANDBOX_ALLOW_RUNC=true`;
     - otherwise the launcher exits non-zero.
   - Tests first: prod with and without `runsc`, dev fallback allowed and refused, and the
     proxy unreachable.
5. `docs(infra): document the sandbox launcher service`: `docs/architecture.md`,
   `docs/security.md` (the launcher's role and limits), `docs/development.md`, `CHANGELOG.md`
   and `STATE.md`.

## PR 3d: `feat(infra): add the sandbox runner client` (~70 lines)
Lets workers call the launcher. It stays off until a URL is configured.
1. `feat(infra): add the launcher sandbox runner client`
   - `infra/sandbox.py`: `LauncherSandboxRunner`, built on `httpx.Client` with
     `trust_env=False`, no redirects, a 900 s timeout and a reply cap of about 3 MiB. It decodes
     into `SandboxResult`. It is not the SSRF-guarded client, because the launcher is internal.
   - Error mapping: 4xx raises `SandboxError`; 503 or a connection failure raises
     `TransientJobError`. Messages are generic.
   - Tests first with `httpx.MockTransport`.
2. `feat(workers): wire the sandbox runner into the scanner gate`
   - `Settings.sandbox_launcher_url: str | None = None` (`.env.example`), and
     `workers/runtime.scanner_gate()` passes the client to `ScopeGuard(sandbox=...)`. When the
     URL is `None`, `UnconfiguredSandboxRunner` is used.
   - Tests first: the gate with and without the URL.
3. `docs(infra): document the sandbox runner client`: `docs/architecture.md`, the
   tenant-safety note (the worker must confirm the artifact belongs to the org before calling
   the launcher), `CHANGELOG.md` and `STATE.md`.

---

## Reused code
- `sandbox_proxy.policy`: the constants, `validate_create` (tests only) and the lock format
  from `load_images`.
- `domain.sandbox`: `SandboxResult`, `SandboxError` and `UnconfiguredSandboxRunner`.
- The `ScopeGuard(sandbox=...)` slot in `infra/scope_guard.py`.
- The `SandboxProxySettings` pattern in `config.py`.

## Verification
- Every commit: the testing gate above.
- Every PR: `pre-pr-check`, CI green, and a diff of about 400 lines or fewer.
- After 3c, optional local smoke test with the empty catalog: proxy with
  `SANDBOX_ALLOW_RUNC=true`, plus the launcher. `GET /healthz` returns 200, and `POST /runs`
  returns 404.
- Real container behavior (no network, kills under `runsc`) is proven in PR 5's CI job.

## After 3d merges
- Tick 3a to 3d in #84.
- Propose a follow-up issue: sweep leftover `attacksurf-*` containers after a launcher or proxy
  crash (before #92).
