# Plan: PR 3c of #84 (`84-sandbox-launcher-service`), per-commit plans + implementation

## Context
PR 3a (#157, proxy `GET /info` with runtime names) and PR 3b (#158, launcher building blocks:
`SandboxLauncherSettings`, `catalog.py`, `artifacts.py`, `container.py`, `stream.py`) are merged
on `main` (`65aa36c`). Nothing yet *runs* a sandbox: there is no code that drives the proxy
through create → wait → attach → start → read → kill/remove, no HTTP API the worker can call, and
no startup `runsc` check (ADR 0016, ADR 0023). PR 3c adds that service. It is the riskiest of the
four PRs, so each commit gets its own plan file in the template format for close review.

Outcome: `python -m attacksurf.sandbox_launcher` starts (or refuses to start) after checking the
proxy's runtimes, serves `GET /healthz` and `POST /runs`, and supervises each run through the real
proxy with a wall-time kill, a 2 MiB stdout cap and guaranteed cleanup.

## Step 1: write the per-commit plans (first action after approval)
Folder `docs/plans/84-analysis-sandbox/84-pr3c-add-sandbox-launcher-service/`, naming `NN-<slug>.md` as in
`84-pr3b-launcher-building-blocks/`. Each file follows `docs/plans/plan-template.md` exactly
(Purpose in plain words + technical, Context, Decisions, Requirements, Acceptance criteria,
Changes with A–D test tables, Order of work, Reused code, Verification, Notes for later commits),
with all HTML comments and placeholders removed. The "follows `<sha>`" line uses `65aa36c` for
commit 1 and "the previous commit of PR 3c" for later ones (SHAs filled in as commits land).

| File | Commit subject |
|---|---|
| `01-share-fake-docker-daemon.md` | `test(security): share the fake Docker daemon` |
| `02-supervise-sandbox-runs.md` | `feat(infra): supervise sandbox runs through the proxy` |
| `03-serve-launcher-api.md` | `feat(infra): serve the sandbox launcher api` |
| `04-refuse-start-without-runsc.md` | `feat(security): refuse to start the launcher without runsc in prod` |
| `05-document-launcher-service.md` | `docs(infra): document the sandbox launcher service` |

The empty `test` file in that folder is left alone (it's yours); say if it should go.

## Step 2: branch
`git switch -c 84-sandbox-launcher-service main`. Every commit: `Refs #84`, red → green → full
gate (`ruff check`, `ruff format --check`, `pyright`, `lint-imports`, full `pytest` ≥ 80%), hooks
on, never `--no-verify`. Commits are made locally; push / draft PR only when you ask.

## Commit contents (what each plan file specifies)

### 1. Share the fake Docker daemon (tests only)
- Move `FakeDocker` + `_FakeDockerHandler` from `tests/unit/sandbox_proxy/test_server.py`
  into `tests/docker_fakes.py`, plus a `serving(server)` context manager (thread +
  shutdown) used by the `docker`/`proxy` fixtures. `DOCKER_INFO`, `CREATED` move with it.
- Add an opt-in scripted run, `FakeRun` dataclass (`chunks: list[bytes]` each sent as its own
  write, `exit_code`, `hold_open`, `attach_status`, events `started`/`killed`/`exited`), set as
  `docker.run`. When `docker.run is None`, behaviour is byte-for-byte the current one, so
  existing proxy tests pass unchanged.
  - attach: writes the real Docker head (`HTTP/1.1 101 UPGRADED`, `Content-Type:
    application/vnd.docker.raw-stream`, `Upgrade: tcp`), waits for `started`, sends each chunk,
    then closes, or with `hold_open` blocks until `killed`; sets `exited`.
  - start sets `started`; kill sets `killed` + `exited` (exit 137); DELETE sets `exited`.
  - `wait?condition=removed` blocks on `exited` (bounded) and replies `{"StatusCode": n}`.
- New proxy tests (they prove the run path the launcher relies on): scripted frames split
  across writes reach the client intact; `wait?condition=removed` returns after a kill and
  releases ownership; a held-open attach ends when killed.

### 2. Supervise sandbox runs through the proxy (riskiest)
Two new modules (stdlib `http.client`/`socket`/`threading` + structlog; the existing launcher
import contract already covers them, no `pyproject.toml` change):
- `sandbox_launcher/proxy.py`: `ProxyClient(host, port)`, `ProxyClient.from_url(url)` (http
  only; userinfo, path, query refused with a fixed `ValueError`, so nothing is silently
  dropped). One connection per call, `CONTROL_TIMEOUT_SECONDS = 30`. Methods: `create(body) ->
  str` (201 + 64-hex `Id`), `wait_removed(id, timeout) -> int | None`, `attach(id) ->
  (socket, leftover bytes)` (raw upgrade request like the proxy's own, head ≤ 4 KiB, must be
  `101`), `start(id)` (204), `kill(id)` (`signal=SIGKILL`; 204/404/409 ok), `remove(id) -> bool`
  (`force=1`; 204/404 = confirmed), `runtimes() -> list[str]` (strict `{"Runtimes": [str]}`).
  Every failure raises `ProxyError` (fixed message, carries a `stage` and optional `status`
  for logging, never reply bytes).
- `sandbox_launcher/runner.py`: `RunOutcome` (frozen; `exit_code`, `stdout` `repr=False`,
  `timed_out`, `output_exceeded`), `SandboxRunFailed`, and
  `run_sandbox(proxy, analyzer, artifact_dir, *, runtime, wall_time) -> RunOutcome`:
  1. `create(build_create_body(...))`;
  2. wait thread (daemon) calling `wait_removed` with timeout `wall_time + KILL_GRACE_SECONDS`;
  3. `attach`; 4. `start` (deadline starts here); 5. `read_stdout(chunks)` where the chunk
     generator sets `sock.settimeout(deadline - now)` per `recv` and raises an internal
     `_WallTimeExceeded`, so the read stops *before* the kill and never sees a kill-truncated
     frame (the STATE note's concern);
  6. after EOF, join the wait thread until the deadline.
  - Wall time passed → `timed_out`; `OutputLimitExceeded` → `output_exceeded`; in both,
    `exit_code=None` and `stdout=b""` (no partial results).
  - Stop path: `kill`, join wait thread for `KILL_GRACE_SECONDS = 30`; if removal is not
    confirmed, `remove`; if that fails too, log `sandbox_cleanup_failed` (container ID only).
    A `try/finally` guarantees the stop path on every exit after a successful create.
  - `ProxyError`, `MalformedStream`, `OSError`, or an unconfirmed wait after a normal end →
    stop path, then `SandboxRunFailed` (fixed message).
  - One structlog line per run, `sandbox_run`: analyzer, runtime, outcome, exit_code,
    stdout_bytes, duration_ms, timed_out, output_exceeded. Never stdout, stderr or paths.
- Decisions recorded in the plan: deadline-driven reads instead of a timer thread; residual race
  (the wait request may reach Docker after a very fast exit + AutoRemove → 404) fails the run
  as `SandboxRunFailed` (503, worker retries) rather than guessing an exit code; a guard test
  `SANDBOX_MAX_WALL_TIME_SECONDS + KILL_GRACE_SECONDS < sandbox_proxy.server.RUN_TIMEOUT_SECONDS`.
- Tests (written first) in `tests/unit/sandbox_launcher/test_runner.py` (+ `test_proxy.py` for
  URL parsing and reply validation), against the **real** proxy (`make_server`, policy with
  `artifact_root=tmp_path`) in front of `FakeDocker`: clean exit (exact stdout, call order
  create → wait → attach → start), non-zero exit, wall-time kill (`wall_time=0.3`,
  `hold_open`), output-cap kill (2 MiB + 1), exactly 2 MiB accepted, stderr never returned,
  create refused (403 from policy), attach failing after create (cleanup DELETE seen), start
  failing, proxy unreachable (closed port), malformed stream, unconfirmed wait → cleanup +
  failure, cleanup failure logged, log line contains no stdout marker and no path.

### 3. Serve the sandbox launcher API
- `sandbox_launcher/server.py`: `LauncherServer(ThreadingHTTPServer)` (`daemon_threads`),
  `make_server(host, port, *, catalog, artifact_root, run, max_concurrent_runs)` where `run:
  Callable[[Analyzer, Path], RunOutcome]` is bound in `__main__` (tests inject a fake).
  Handler `timeout = 30`, stdlib access log silenced (as in the proxy).
  - `GET /healthz` → 200 `{"status": "ok"}`.
  - `POST /runs`: no `Transfer-Encoding`, `Content-Length` 1…`MAX_REQUEST_BYTES = 1024`,
    `Content-Type: application/json`, JSON object with exactly `analyzer` and `artifact_id`,
    duplicate keys refused, `analyzer` matches `catalog.ANALYZER_NAME`, `artifact_id` a
    canonical lowercase UUID string → else 400.
  - Unknown analyzer or `ArtifactNotFound` → 404 (same generic message for both).
  - `BoundedSemaphore(max_concurrent_runs)`, non-blocking acquire → 503 busy.
  - `SandboxRunFailed` → 503; unexpected exception → 500, logged by type name only.
  - 200 `{"exit_code", "stdout_b64", "timed_out", "output_exceeded"}`.
  - Other paths 404, other methods 405. Messages are fixed text, never echo input.
- Tests first (`test_server.py`): each bad request (table), unknown analyzer/artifact, busy
  (fake run blocked on an event), run failure → 503, healthz, and one full round trip through
  the real proxy + `FakeDocker` with a test catalog entry (base64 decodes to the scripted stdout).

### 4. Refuse to start without `runsc` in prod
- `sandbox_launcher/__main__.py`: `select_runtime(names, *, prod, allow_runc) -> str`
  (`runsc` if listed; else `runc` only when not prod, `allow_runc` and `runc` listed; else
  `RuntimeUnavailable`), and `main()`: load `SandboxLauncherSettings`, `load_catalog`,
  `ProxyClient.from_url(...get_secret_value())`, `proxy.runtimes()`, `select_runtime`, log
  `sandbox_launcher_started` (runtime, analyzer count), then `make_server(...).serve_forever()`.
  Any failure → `SystemExit` with a fixed message (non-zero); no retry loop (Compose restarts it,
  PR 4).
- Tests first (`test_main.py`): prod with/without `runsc`, dev fallback allowed and refused,
  `runc` missing too, proxy unreachable, malformed `/info` → exit; happy path builds the server
  with the chosen runtime (serve_forever patched).

### 5. Document the sandbox launcher service
`docs/architecture.md` (launcher service section replaces "nothing runs them yet"; the
`analysis` row), `docs/security.md` (launcher role, limits, cleanup, residual wait race),
`docs/development.md` (running proxy + launcher locally with `SANDBOX_ALLOW_RUNC=true`),
`AGENTS.md` layout line for `sandbox_launcher/`, `CHANGELOG.md` `[Unreleased]`, `STATE.md`.
Then `pre-pr-check`, diff-size check (target ≤ ~400 non-test lines; estimate ~350).

## Reused code
- `sandbox_launcher.catalog`: `Analyzer`, `ANALYZER_NAME`, `load_catalog`.
- `sandbox_launcher.artifacts.resolve_artifact`, `ArtifactNotFound`.
- `sandbox_launcher.container.build_create_body`; `sandbox_launcher.stream.read_stdout`,
  `OutputLimitExceeded`, `MalformedStream`.
- `config.SandboxLauncherSettings`, `SANDBOX_MAX_WALL_TIME_SECONDS`.
- `sandbox_proxy.server`: request/upgrade pattern, `ThreadingHTTPServer` handler style,
  `_reject_duplicate_keys` pattern (copied, not imported); `make_server`, `RUN_TIMEOUT_SECONDS`
  in tests only.
- `tests/unit/sandbox_proxy/test_policy.py`: `IMAGE`, `create_body` for fixtures.

## Verification
- Per commit: the gate above; `uv run pytest tests/unit/sandbox_launcher tests/unit/sandbox_proxy -q`.
- Scratch-only checks (reverted): import `httpx` in `runner.py` → launcher contract fails;
  remove the `finally` cleanup → the attach-failure test fails; drop the deadline → the
  wall-time test fails.
- After commit 4, local smoke with the empty catalog: proxy (`SANDBOX_ALLOW_RUNC=true`) +
  launcher; `curl /healthz` → 200, `POST /runs` → 404.
- Real container behaviour under `runsc` stays PR 5's job.
