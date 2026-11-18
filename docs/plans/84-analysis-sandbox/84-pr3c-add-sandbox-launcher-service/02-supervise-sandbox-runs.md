# Plan: PR 3c, commit 2: `feat(infra): supervise sandbox runs through the proxy`

Branch `84-sandbox-launcher-service` · `Refs #84` · follows `test(security): share the fake
Docker daemon` (commit 1 of PR 3c; see `../84-pr3-sandbox-launcher-split-4-prs.md`).

## Purpose

**In plain words.** This is the part of the launcher that actually runs an analysis. Given an
analyzer and an artifact folder, it asks the proxy to create one sandbox, listens to its output,
starts it, and collects what it prints. It enforces the two hard limits: if the run takes longer
than the wall time, or prints more than 2 MiB, the sandbox is killed and the partial output is
thrown away. Whatever happens, including the proxy refusing or breaking off halfway, the sandbox
is killed and removed before the launcher answers. It never returns error output, and it never
logs what the tool printed or where the artifact lives.

**Technical.** Adds `sandbox_launcher/proxy.py` (`ProxyClient`, `ProxyError`) over stdlib
`http.client` and `socket`, and `sandbox_launcher/runner.py` with
`run_sandbox(proxy, analyzer, artifact_dir, *, runtime, wall_time) -> RunOutcome` and
`SandboxRunFailed`. The order is create → removed-wait on a daemon thread → attach → start →
`stream.read_stdout` over a deadline-bounded chunk generator, then the removed-wait's exit code.
The stop path is `kill?signal=SIGKILL`, a bounded join on the wait, then `DELETE ?force=1` if
removal is unconfirmed, guaranteed by `try/finally` after a successful create (ADR 0016: "launcher
kills and removes the container"). Imports only the stdlib, `structlog` and the launcher's own
modules; the existing "sandbox launcher stays isolated" contract covers both files. Proven by
tests against the real `sandbox_proxy.server.make_server` in front of `FakeDocker`.

## Context
PR 3b produced `build_create_body` (`container.py`), `read_stdout` with `OutputLimitExceeded` /
`MalformedStream` (`stream.py`), `Analyzer` (`catalog.py`) and `resolve_artifact`
(`artifacts.py`). The proxy (PR 2, PR 3a) allows create, start, `wait?condition=removed`, stdout
attach (a raw hijacked relay that includes Docker's 101 head), `kill?signal=SIGKILL`,
`DELETE ?force=1` and `GET /info`, and its `wait`/`attach` connections live
`RUN_TIMEOUT_SECONDS = 900`. Commit 1 gave tests a Docker that acts out a run. Nothing turns these
pieces into a run yet; commit 3 (`server.py`) calls `run_sandbox` per request and commit 4
(`__main__.py`) uses `ProxyClient.runtimes()` for the `runsc` check. This is its own commit
because supervision (threads, deadlines, cleanup) is the riskiest code in #84 and is tested
without any HTTP API in front of it.

## Decisions
1. **Two modules: wire calls and supervision.** `proxy.py` knows URLs, status codes and reply
   shapes; `runner.py` knows ordering, limits and cleanup. Each is tested on its own terms and
   `__main__` reuses `ProxyClient` for `/info`. The split plan named only `runner.py`; keeping
   the HTTP details out of it keeps the supervision logic short enough to review line by line.
2. **The deadline drives the reads; no timer thread kills mid-read.** The chunk generator sets
   `sock.settimeout(deadline - now)` before every `recv` and raises an internal
   `_WallTimeExceeded` when the budget is gone. So the runner decides "timed out" *before* it
   kills, and never sees the kill-truncated frame that would surface as `MalformedStream` (the
   STATE note's concern). The deadline starts after `start` succeeds. Rejected: a
   `threading.Timer` that kills while the reader blocks, which races the reader's outcome.
3. **Outcome rules.** Wall time passed → `RunOutcome(exit_code=None, stdout=b"",
   timed_out=True)`; `OutputLimitExceeded` → `RunOutcome(exit_code=None, stdout=b"",
   output_exceeded=True)`; a normal end → exit code from the removed-wait and the full stdout.
   Partial output is never returned (same rule as `stream.py`). The stream ending before the
   container exits (tool closed stdout) is not an error: the runner keeps waiting until the
   deadline, then kills.
4. **Fail closed on anything unexplained.** `ProxyError` at any stage, `MalformedStream`, an
   `OSError` while reading, or a removed-wait that returns no confirmed exit code →
   stop path, then `SandboxRunFailed("Sandbox run failed.")`. Commit 3 maps it to 503, so the
   worker retries (PR 3d) rather than storing a doubtful result.
5. **Known race, failing safe.** The removed-wait is sent before attach and start, but through
   the proxy the launcher cannot observe the moment Docker registers it. If a container exits
   and is auto-removed before that, Docker answers 404, the wait is unconfirmed, and decision 4
   applies (retry). Rejected: guessing exit code 0. Real timing is checked under `runsc` in PR 5.
6. **Time constants and the proxy's ceiling.** `CONTROL_TIMEOUT_SECONDS = 30` for create, start,
   kill, remove and `/info`; `KILL_GRACE_SECONDS = 30` for the post-kill join; the wait
   connection times out at `wall_time + KILL_GRACE_SECONDS`. A test pins
   `SANDBOX_MAX_WALL_TIME_SECONDS + KILL_GRACE_SECONDS < sandbox_proxy.server.RUN_TIMEOUT_SECONDS`
   (840 + 30 < 900), so the proxy never cuts the launcher's own connections first.
7. **Stop path.** `kill` (204, 404 and 409 all mean "not running any more"), join the wait thread
   for `KILL_GRACE_SECONDS`; if removal is not confirmed, `remove` (`force=1`; 204 or 404 =
   gone, which also frees the proxy's slot). If that fails too, log `sandbox_cleanup_failed`
   with the container ID and stage only; the crash-sweep follow-up issue owns leftovers.
8. **`ProxyClient.from_url` is strict.** It accepts `http://host[:port]` only and refuses
   userinfo, a path other than `/`, a query or a fragment with a fixed `ValueError`, so a
   configured value is never silently dropped (`SANDBOX_PROXY_URL` is a `SecretStr`; the proxy
   has no authentication to send credentials to). The URL is unwrapped by the caller only.
9. **Strict reply parsing.** `create` needs 201 and a 64-hex `Id`; `attach` needs a `101` status
   line and a head within 4 KiB (leftover bytes after the head are the first chunk);
   `wait_removed` needs 200 and an `int` `StatusCode` with no `Error`; `runtimes` needs
   `{"Runtimes": [str, ...]}`. Replies are read with a 64 KiB cap. `ProxyError` carries `stage`
   and optional `status` for logs, and a fixed message; never reply bytes.
10. **One log line per run, metadata only.** `sandbox_run` with analyzer, runtime, outcome
    (`exited`, `timed_out`, `output_exceeded`, `failed`), exit_code, stdout_bytes, duration_ms,
    and on failure the stage and status. Never stdout, stderr, paths or the create body.
11. **Left out.** The HTTP API, the concurrency limit and request validation (commit 3); the
    runtime choice (commit 4); sweeping containers left by a launcher crash (follow-up issue).
12. **No docs in this commit.** Commit 5 of PR 3c carries the docs, `CHANGELOG.md` and `STATE.md`.

## Requirements
- [ ] `src/attacksurf/sandbox_launcher/proxy.py` and `runner.py` exist; they import only the
      stdlib, `structlog` and `attacksurf.sandbox_launcher.*`.
- [ ] `ProxyClient(host: str, port: int)`, `ProxyClient.from_url(url: str) -> ProxyClient`;
      methods `create(body) -> str`, `wait_removed(container_id, timeout) -> int | None`,
      `attach(container_id) -> tuple[socket.socket, bytes]`, `start(container_id)`,
      `kill(container_id)`, `remove(container_id) -> bool`, `runtimes() -> list[str]`.
- [ ] Wire targets exactly: `POST /containers/create`, `POST /containers/{id}/wait?condition=removed`,
      `POST /containers/{id}/attach?stream=1&stdout=1` (raw `Connection: Upgrade`,
      `Upgrade: tcp`), `POST /containers/{id}/start`, `POST /containers/{id}/kill?signal=SIGKILL`,
      `DELETE /containers/{id}?force=1`, `GET /info`.
- [ ] `ProxyError(stage, status=None)` for connection failures, timeouts, unexpected statuses
      and malformed replies; message is fixed text.
- [ ] `RunOutcome` frozen dataclass: `exit_code: int | None`, `stdout: bytes` (`repr=False`),
      `timed_out: bool`, `output_exceeded: bool`.
- [ ] `run_sandbox(proxy, analyzer, artifact_dir, *, runtime: str, wall_time: float) ->
      RunOutcome` follows create → wait thread → attach → start → read → wait result.
- [ ] Outcome rules of decision 3; `SandboxRunFailed` for every case of decision 4.
- [ ] After a successful create, every exit path (return or raise) leaves the container killed
      and removal confirmed, or logs `sandbox_cleanup_failed`.
- [ ] `CONTROL_TIMEOUT_SECONDS == 30`, `KILL_GRACE_SECONDS == 30`.
- [ ] Exactly one `sandbox_run` log event per call, with the fields of decision 10 and none of
      stdout, stderr or paths.
- [ ] No change to `pyproject.toml`, `config.py`, `sandbox_proxy/` or the PR 3b modules.

## Acceptance criteria
- [ ] **Contract:** a clean run through the real proxy returns the scripted stdout and exit code
      0; Docker sees create, removed-wait, attach, start in that order, and the proxy's create
      validation passed (it is the real `validate_create`).
- [ ] **Limits:** a held-open run with `wall_time=0.3` ends `timed_out` within about a second,
      with a kill seen by Docker; 2 MiB + 1 byte of stdout ends `output_exceeded` with a kill;
      exactly 2 MiB returns in full.
- [ ] **Cleanup:** attach refused after create, start refused, malformed stream, and an
      unconfirmed wait each raise `SandboxRunFailed` and Docker sees kill and/or forced DELETE.
- [ ] **Negative:** proxy unreachable (closed port) and create refused (policy 403, image not on
      the allowlist) raise `SandboxRunFailed`; no container is left tracked by the proxy.
- [ ] **No leakage:** stderr bytes never appear in `stdout`; captured log events contain no
      stdout marker and no artifact path; `repr(outcome)` has no stdout.
- [ ] **Drift guard:** `SANDBOX_MAX_WALL_TIME_SECONDS + KILL_GRACE_SECONDS < RUN_TIMEOUT_SECONDS`.
- [ ] **Isolation:** `uv run lint-imports` passes; `sandbox_proxy` is imported in tests only.
- [ ] **Gate:** `ruff check`, `ruff format --check`, `pyright`, `lint-imports` and full `pytest`
      pass with coverage >= 80%; the commit passes the hooks without `--no-verify`.

## Changes

### 1. `src/attacksurf/sandbox_launcher/proxy.py` (~110 lines)
- Docstring: the launcher's only way to Docker; one connection per call; strict replies; why
  attach is a raw socket (the proxy relays a hijacked stream).
- Constants: `CONTROL_TIMEOUT_SECONDS`, `_MAX_REPLY_BYTES = 64 * 1024`, `_MAX_HEAD_BYTES = 4096`,
  `_CONTAINER_ID` pattern.
- `ProxyError`, `ProxyClient` with a private `_call(method, target, *, stage, body=None,
  timeout=CONTROL_TIMEOUT_SECONDS) -> tuple[int, bytes]` that every method uses, and
  `_read_head(sock) -> tuple[int, bytes]` for attach.

### 2. `src/attacksurf/sandbox_launcher/runner.py` (~120 lines)
- Docstring: the ADR 0016 run, its order and why (wait armed before start because of
  AutoRemove; attach before start so no output is missed), the deadline rule and the race.
- `RunOutcome`, `SandboxRunFailed`, `KILL_GRACE_SECONDS`, `run_sandbox`, helpers `_Waiter`
  (daemon thread + result), `_chunks(sock, first, deadline)`, `_stop(proxy, container_id,
  waiter)`, `_log(...)`.

### 3. Tests, `tests/unit/sandbox_launcher/test_proxy.py` and `test_runner.py` (written first)
Style follows `tests/unit/sandbox_proxy/test_server.py` (real servers on threads, plain
functions). Fixtures: `docker` (`FakeDocker` via `serving()`), `proxy_port` (`make_server` with a
policy allowing `IMAGE`, `runsc`, `artifact_root=tmp_path`), `client` (`ProxyClient`), an
`analyzer` built like `test_container.py`'s, and `artifact_dir` (a real directory under
`tmp_path`). A `frame(type, payload)` helper as in `test_stream.py`.

#### A. Happy path
| Test | Given | Expect |
|---|---|---|
| `test_run_returns_stdout_and_exit_code` | stdout frames, exit 0 | `RunOutcome(0, b"...", False, False)` |
| `test_run_calls_docker_in_order` | same | create, removed-wait, attach, start order in `docker.calls` |
| `test_run_reports_a_non_zero_exit` | exit 3 | `exit_code == 3`, stdout kept |
| `test_run_drops_stderr` | interleaved stdout/stderr | stdout only |
| `test_run_handles_frames_split_across_writes` | one frame in 5 chunks | full payload |
| `test_runtimes_returns_the_proxy_names` | default `DOCKER_INFO` | `["io.containerd.runc.v2", "runc", "runsc"]` |
| `test_from_url_uses_host_and_port` (param with/without port, trailing `/`) | `http://h:1`, `http://h`, `http://h:1/` | host and port (80 default) |

#### B. Boundary cases
| Test | Given | Expect |
|---|---|---|
| `test_run_accepts_exactly_the_stdout_cap` | 2 MiB stdout | returned in full |
| `test_run_kills_at_the_wall_time` | `hold_open`, `wall_time=0.3` | `timed_out`, `exit_code None`, `stdout b""`, kill seen |
| `test_run_kills_when_stdout_passes_the_cap` | 2 MiB + 1 | `output_exceeded`, `stdout b""`, kill seen |
| `test_run_waits_for_exit_after_stdout_closes` | stream ends, exit arrives later | exit code returned |
| `test_wall_time_and_grace_fit_under_the_proxy_timeout` | constants | `840 + 30 < 900` |

#### C. Invalid inputs and failures (raise, clean up, never echo)
| Test | Given | Expect |
|---|---|---|
| `test_proxy_unreachable_fails_the_run` | closed port | `SandboxRunFailed` |
| `test_refused_create_fails_without_cleanup_calls` | image not allowlisted | `SandboxRunFailed`; Docker never called |
| `test_attach_failure_after_create_cleans_up` | `attach_status=500` | `SandboxRunFailed`; forced DELETE seen |
| `test_start_failure_cleans_up` | start answers 500 | `SandboxRunFailed`; cleanup seen |
| `test_malformed_stream_fails_and_cleans_up` | bad frame type | `SandboxRunFailed`; kill seen |
| `test_unconfirmed_wait_fails_and_removes` | wait answers 404 | `SandboxRunFailed`; forced DELETE seen |
| `test_cleanup_failure_is_logged` | DELETE answers 500 after a failure | `sandbox_cleanup_failed` event |
| `test_from_url_refuses_extras` (param userinfo, path, query, fragment, `https`) | each | `ValueError` without the value |
| `test_malformed_replies_raise_proxy_error` (param create id, wait body, runtimes body, attach head) | each | `ProxyError`; message fixed |

#### D. Logging and leakage guards
| Test | Given | Expect |
|---|---|---|
| `test_run_logs_one_metadata_line` | clean run, `capture_logs` | one `sandbox_run` with the decision 10 fields |
| `test_logs_never_contain_output_or_paths` (param clean, timeout, cap, failure) | stdout with a marker | marker and `artifact_dir` absent from every event |
| `test_outcome_repr_hides_stdout` | outcome with a marker | marker not in `repr` |

Section D proves the runner never turns tool output into a log line, on every path. Tests may
import `sandbox_proxy` to stand up the real proxy; source modules stay isolated.

## Order of work (red → green)
1. Write `test_proxy.py` and `test_runner.py`; run them. Confirm they fail on the missing
   modules, not on fixture typos.
2. Implement `proxy.py` until `test_proxy.py` passes, then `runner.py` until `test_runner.py`
   passes.
3. Full gate:
   ```bash
   uv run ruff check . && uv run ruff format --check . && uv run pyright \
     && uv run lint-imports && uv run pytest
   ```
4. `finish-task` deferred to commit 5; `pre-pr-check` self-review (threads joined, sockets
   closed, no output in logs).
5. Commit with subject `feat(infra): supervise sandbox runs through the proxy`, a body explaining
   *why* (ADR 0016's kill-and-remove guarantees live here, decided from the launcher's own
   deadline), footer `Refs #84`, and the Co-Authored-By trailer. Never `--no-verify`.

## Reused code
- `sandbox_launcher/container.py`: `build_create_body`.
- `sandbox_launcher/stream.py`: `read_stdout`, `OutputLimitExceeded`, `MalformedStream`.
- `sandbox_launcher/catalog.py`: `Analyzer`, `AnalyzerSpec`.
- `sandbox_proxy/server.py`: the raw attach request and `_UnixConnection` patterns (copied in
  spirit, not imported); `make_server`, `RUN_TIMEOUT_SECONDS` in tests only.
- `config.py`: `SANDBOX_MAX_WALL_TIME_SECONDS` (tests).
- `tests/docker_fakes.py`: `FakeDocker`, `FakeRun`, `serving`.

## Verification
- `uv run pytest tests/unit/sandbox_launcher -q` green, then the full suite with coverage >= 80%.
- `uv run lint-imports`; scratch check: `import httpx` in `runner.py` makes the launcher contract
  fail.
- Mutation checks (scratch only): drop the `finally` stop path → attach-failure test fails;
  remove the per-`recv` timeout → the wall-time test fails (bounded by the fake's timeout);
  return partial stdout on timeout → the timeout test fails.
- Optional manual smoke: none; the API arrives in commit 3.

## Notes for later commits
- **Commit 3 (`server.py`):** binds `run_sandbox(proxy, analyzer, dir, runtime=..., wall_time=
  settings.sandbox_wall_time_seconds)`; maps `SandboxRunFailed` to 503.
- **Commit 4 (`__main__.py`):** uses `ProxyClient.from_url(settings.sandbox_proxy_url
  .get_secret_value())` and `runtimes()`; a `ValueError` or `ProxyError` there means exit.
- **PR 3d:** 503 → `TransientJobError`; the result has no stdout when either flag is set.
- **Follow-up issue:** sweep `attacksurf-*` containers left after a launcher or proxy crash;
  `sandbox_cleanup_failed` is the signal to alert on.
