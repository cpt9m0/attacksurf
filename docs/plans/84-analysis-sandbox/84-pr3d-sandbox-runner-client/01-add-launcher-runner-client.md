# Plan: PR 3d, commit 1: `feat(infra): add the launcher sandbox runner client`

Branch `84-sandbox-runner-client` · `Refs #84` · follows `4cc7c4b Merge remote-tracking branch
'origin/main' into 84-sandbox-launcher-service` (the tip of PR 3c; the branch is stacked on it, see
`../84-pr3-sandbox-launcher-split-4-prs.md`).

## Purpose

**In plain words.** The launcher can now run an analyzer when asked, but nothing in the worker
knows how to ask. This commit adds the worker's side of that conversation: a small client that
sends "run analyzer X on artifact Y" and turns the answer into a result. It trusts nothing in the
answer. It refuses replies that are too big or oddly shaped. It says "try again later" only when
the launcher is busy or unreachable, and it never copies the launcher's words into an error.
The client is not connected to anything yet, so no scan can use it after this commit.

**Technical.** Adds `src/attacksurf/infra/sandbox.py` with
`LauncherSandboxRunner(base_url: str, *, timeout_seconds: float = 900.0, transport:
httpx.BaseTransport | None = None)`. It implements `domain.sandbox.SandboxRunner.run(analyzer,
artifact_id) -> SandboxResult` with a dedicated `httpx.Client(trust_env=False,
follow_redirects=False)`.
- **Request:** `POST /runs` with `{"analyzer", "artifact_id": str(uuid)}`.
- **Reply:** read as a stream, capped at `MAX_REPLY_BYTES = 3 MiB`. The JSON must have exactly
  the four keys `exit_code`, `stdout_b64`, `timed_out` and `output_exceeded`, each with the right
  type. The base64 is decoded strictly, and the decoded stdout may be at most
  `domain.scanners.MAX_OUTPUT_BYTES`.
- **Errors:**
  - 503 and transport failures raise `TransientJobError`.
  - Every other non-200 reply, and every malformed reply, raises `SandboxError`.

Layers: `infra` imports `httpx` and `domain` only and never `sandbox_launcher`. The existing
import contracts already cover this, so `pyproject.toml` does not change. The table tests use
`httpx.MockTransport`. One contract test runs against the real `sandbox_launcher.server` on
loopback, which proves the two sides agree on the wire format.

## Context
- **Already in place:**
  - PR 3c's `server.py` serves `POST /runs` and `GET /healthz`. It returns fixed JSON error
    bodies `{"message": ...}`: 400 malformed, 404 unknown analyzer or artifact, 405 wrong
    method, 503 busy or run failed, 500 internal.
  - `domain/sandbox.py` already defines `SandboxRunner`, `SandboxResult`, `SandboxError` and
    `UnconfiguredSandboxRunner`.
  - `ScopeGuard(sandbox=...)` already wraps any runner in `_GuardedSandbox`, which enforces the
    per-scanner analyzer allowlist.
- **What is missing:** a real runner.
- **What comes next:** commit 2 builds this client from settings and passes it to the gate.
- **Why a separate commit:** it is pure client code with no settings or wiring, so its failure
  mapping is reviewed and tested on its own.

## Decisions
1. **A dedicated plain `httpx.Client`, not `SafeHttpClient`.** The SSRF-guarded client refuses
   private addresses, and the launcher only lives on the internal network (ADR 0016). That is
   correct by design, not a hole: the URL comes from operator config, never from a scanner or a
   user. `trust_env=False` keeps `HTTP(S)_PROXY` and `.netrc` from redirecting or decorating the
   request. `follow_redirects=False`, so a 3xx is an error, never a hop.
2. **Timeouts.** `httpx.Timeout(timeout_seconds, connect=CONNECT_TIMEOUT_SECONDS)` with
   `CONNECT_TIMEOUT_SECONDS = 5.0` and a default `timeout_seconds = 900.0`.
   - The launcher's wall-time ceiling is `SANDBOX_MAX_WALL_TIME_SECONDS = 840`, and its kill
     grace sits under the proxy's 900 s. So with a 900 s read timeout the launcher always answers
     first.
   - A short connect timeout means a launcher that is down shows up quickly as a transient
     error.
3. **Reply cap of 3 MiB, enforced while streaming.**
   - `MAX_REPLY_BYTES = 3 * 1024 * 1024`.
   - A `Content-Length` above the cap is refused before any of the body is read.
   - Otherwise the client counts bytes from `iter_bytes()` and stops at cap + 1.
   - The cap holds base64 of 2 MiB (about 2.67 MiB) plus the JSON wrapper. A parity test
     guards this.
   - Rejected alternative: `response.read()` with no limit, which a broken launcher could make
     buffer unbounded memory.
4. **Strict decoding, mirroring the launcher's strict parsing.**
   - The reply must be a JSON object with exactly the four keys. Duplicate keys are refused with
     an `object_pairs_hook`, the same pattern the launcher uses.
   - `exit_code` is an `int` or `None`. `bool` is refused, because `True` would pass an `int`
     check.
   - `timed_out` and `output_exceeded` must be `bool`.
   - `stdout_b64` is a `str`, decoded with `base64.b64decode(value, validate=True)`.
   - Decoded stdout larger than `MAX_OUTPUT_BYTES` is an error. The launcher already enforces
     this, so the check is defense in depth.
5. **Status mapping (fixed messages; the reply body is never read into an error).**
   - **200:** decoded into a `SandboxResult`.
   - **503:** `TransientJobError("The sandbox is busy; the run will be retried.")`. This covers
     both "busy" and "run failed"; the launcher already chose 503 for both because they are
     worth retrying.
   - **`httpx.TransportError`** (connect refused, read timeout, reset):
     `TransientJobError("The sandbox could not be reached; the run will be retried.")`.
   - **Any other status** (3xx, 400, 404, 405, 500, unexpected codes):
     `SandboxError("The sandbox run failed.")`. A 404 means the analyzer or artifact is missing,
     and retrying will not fix that. A 500 is a launcher bug, and retrying would only repeat it.
   - **Malformed or oversized 200 reply:** `SandboxError("The sandbox returned an invalid
     reply.")`.
   - Rejected alternative: echoing the launcher's `message`. The messages are fixed text, but
     copying them would make a worker error depend on a remote body, and `JobError` messages are
     shown to users.
6. **Constructor guard on the URL.**
   - The base URL must be `http://host[:port]`: no userinfo, a path of only `""` or `"/"`, no
     query and no fragment. Anything else raises
     `ValueError("the sandbox launcher URL must be http://host[:port] only")`.
   - This is the same rule as `ProxyClient.from_url`, copied rather than imported because of the
     layers. The launcher has no authentication, so credentials would have nowhere to go, and a
     path would be silently dropped.
7. **Logging.** One `sandbox_client_error` warning per failure, carrying `status` or the
   `error_type` name and the analyzer. The analyzer is safe to log because the allowlist already
   checked it. Logs never include the artifact ID, the reply body or stdout. A successful run
   logs nothing here; the scanner pipeline logs the job.
8. **Killed runs are returned, not raised.** `timed_out` and `output_exceeded` replies become a
   `SandboxResult` with `exit_code=None` and empty stdout. The scanner that asked decides what
   that means (PR 5). This matches the domain contract, where `exit_code` is `None` when the run
   was killed.
9. **Testing seam.** The constructor takes `transport`, which is passed to `httpx.Client`, so
   tests inject `httpx.MockTransport` without patching. The client is created once per runner,
   and commit 2 caches one runner per worker process.
10. **Left out.**
    - Settings and wiring: commit 2.
    - Artifact ownership checks: the worker's job, documented in commit 3 and enforced with #85.
    - Health checks from the worker: compose health checks are PR 4.
11. **No docs in this commit.** Commit 3 of PR 3d carries `docs/architecture.md`,
    `docs/security.md`, `AGENTS.md`, `CHANGELOG.md` and `STATE.md`.

## Requirements
- [ ] `src/attacksurf/infra/sandbox.py` exists. It imports only stdlib, `httpx`, `structlog` and
      `attacksurf.domain.*`.
- [ ] Constants: `MAX_REPLY_BYTES == 3 * 1024 * 1024`, `CONNECT_TIMEOUT_SECONDS == 5.0`.
- [ ] `LauncherSandboxRunner(base_url, *, timeout_seconds=900.0, transport=None)` structurally
      satisfies `domain.sandbox.SandboxRunner` (pyright).
- [ ] The client is built with `trust_env=False` and `follow_redirects=False`, and its timeout is
      `timeout_seconds` with connect `CONNECT_TIMEOUT_SECONDS`.
- [ ] Each `run` sends exactly one `POST {base}/runs` with `Content-Type: application/json` and the
      body `{"analyzer": analyzer, "artifact_id": str(artifact_id)}`.
- [ ] A 200 reply decodes into `SandboxResult(exit_code, stdout, timed_out, output_exceeded)` as
      in decision 4.
- [ ] The status mapping follows decision 5, and every message is fixed text.
- [ ] Replies above `MAX_REPLY_BYTES` are refused without buffering more than cap + 1 bytes.
- [ ] Invalid base URLs raise `ValueError`, and the message does not contain the URL.
- [ ] No change to `pyproject.toml`, `config.py`, `workers/`, `infra/scope_guard.py` or
      `sandbox_launcher/`.

## Acceptance criteria
- [ ] **Contract (round trip):** the client calls a real `sandbox_launcher.server.make_server` on
      `127.0.0.1:0`, built with a one-entry test catalog, an artifact directory under `tmp_path`
      and a fake `run` that returns a scripted `RunOutcome`. The client returns a
      `SandboxResult` whose fields equal the outcome's. Stdout includes non-UTF-8 bytes.
- [ ] **Contract (error side):** against the same real server, an unknown analyzer raises
      `SandboxError`, and a busy server (`max_concurrent_runs=1`, one run blocked) raises
      `TransientJobError`.
- [ ] **Tight fit:** a golden test pins the exact request: method, path, content type and body
      bytes, parsed as JSON.
- [ ] **Cap parity:** `len(json.dumps({...4 keys with base64 of MAX_OUTPUT_BYTES bytes...})) <
      MAX_REPLY_BYTES`.
- [ ] **Negative:** every table case in C raises the listed error, and `str(exc)` contains no
      reply or URL marker.
- [ ] **Isolation:** `uv run lint-imports` passes. `infra/sandbox.py` does not import
      `sandbox_launcher`; only the tests do.
- [ ] **Gate:** `ruff check`, `ruff format --check`, `pyright`, `lint-imports` and the full
      `pytest` run all pass with coverage of at least 80%. The commit passes the hooks without
      `--no-verify`.

## Changes

### 1. `src/attacksurf/infra/sandbox.py` (~65 lines)
- **Docstring:** the worker's client for `sandbox-launcher` (ADR 0016). It says why the client
  is a plain internal `httpx.Client` rather than the SSRF-guarded one, and that ownership is
  checked by the caller.
- **Constants:** `MAX_REPLY_BYTES`, `CONNECT_TIMEOUT_SECONDS`, and the private fixed messages.
- **`LauncherSandboxRunner`:**
  - `__init__`: validates the URL and builds the client.
  - `run`: posts the request, maps the status and decodes the reply.
- **Helpers:**
  - `_require_plain_http_url(url) -> str`
  - `_read_capped(response) -> bytes`
  - `_decode_result(raw: bytes) -> SandboxResult`
  - `_reject_duplicate_keys` (copied pattern)
- **Reuses:** `SandboxResult` and `SandboxError` from `domain.sandbox`, `TransientJobError` from
  `domain.jobs`, and `MAX_OUTPUT_BYTES` from `domain.scanners`.

### 2. Tests, `tests/unit/infra/test_sandbox.py` (written first)
- Style follows `tests/unit/infra/test_http.py`, which already exercises httpx in this layer.
- The file is split into four sections, each under a comment banner.
- A `launcher_reply(...)` helper builds a well-formed 200 JSON body.
- A `runner_with(handler)` helper builds `LauncherSandboxRunner("http://launcher:8791",
  transport=httpx.MockTransport(handler))`.
- The D tests use a `serving` thread helper (the pattern from `tests/docker_fakes.py`) around
  `make_server`.

#### A. Happy path (valid reply → the exact result)
| Test | Given | Expect |
|---|---|---|
| `test_run_sends_exactly_the_analyzer_and_artifact_id` | handler captures the request | `POST /runs`, `application/json`, body `{"analyzer": "echo", "artifact_id": "<uuid>"}` |
| `test_run_decodes_the_reply_into_a_result` | 200, exit 0, stdout `b"\x00\xff{}"` | `SandboxResult(0, b"\x00\xff{}", False, False)` |
| `test_nonzero_exit_code_is_returned` | exit 3 | `exit_code == 3`, no exception |
| `test_timed_out_run_is_returned_not_raised` | `exit_code: null`, `timed_out: true`, `""` | result with `timed_out`, empty stdout |
| `test_output_exceeded_run_is_returned_not_raised` | `output_exceeded: true` | result with `output_exceeded` |
| `test_base_url_with_trailing_slash_posts_to_runs` | `"http://launcher:8791/"` | path is `/runs`, not `//runs` |
| `test_result_repr_hides_stdout` | stdout with a marker | marker absent from `repr(result)` |

#### B. Boundary cases
| Test | Given | Expect |
|---|---|---|
| `test_stdout_at_the_output_cap_is_accepted` | base64 of exactly `MAX_OUTPUT_BYTES` | accepted, length equal |
| `test_reply_at_the_reply_cap_is_accepted` | JSON padded with whitespace to exactly `MAX_REPLY_BYTES` | accepted |
| `test_empty_stdout_is_accepted` | `stdout_b64: ""` | `stdout == b""` |
| `test_exit_codes_at_the_edges_are_kept` (param 0, 1, 137, 255) | each | kept unchanged |
| `test_reply_without_content_length_is_still_capped` | streamed chunks, no header, cap + 1 bytes | `SandboxError` |

A request that is too large is impossible here: the client sends a fixed two-field body, and
the launcher's 1 KiB limit is covered by its own tests.

#### C. Invalid inputs and replies (fixed messages, nothing echoed)
| Test | Given | Expect |
|---|---|---|
| `test_retryable_statuses_raise_transient` (param 503 busy, 503 run failed) | each | `TransientJobError` |
| `test_other_statuses_raise_sandbox_error` (param 301, 302, 400, 404, 405, 418, 500, 502) | each, with a JSON `message` | `SandboxError` |
| `test_transport_failures_raise_transient` (param `ConnectError`, `ReadTimeout`, `RemoteProtocolError`) | handler raises | `TransientJobError` |
| `test_malformed_replies_raise_sandbox_error` (param: not JSON, array, missing key, extra key, duplicate key, `exit_code` `"0"`, `exit_code` `true`, `exit_code` `1.0`, `timed_out` `"false"`, `timed_out` `0`, `stdout_b64` `null`, bad base64 `"@@"`, base64 without padding) | 200 with each body | `SandboxError` |
| `test_decoded_stdout_over_the_cap_is_refused` | base64 of `MAX_OUTPUT_BYTES + 1` (fits the reply cap) | `SandboxError` |
| `test_oversized_content_length_is_refused_unread` | `Content-Length: MAX_REPLY_BYTES + 1`, body stream that records reads | `SandboxError`; body never read |
| `test_invalid_base_urls_are_refused` (param `https://l:1`, `http://`, `http://u:p@l:1`, `http://l:1/api`, `http://l:1?x=1`, `http://l:1#f`, `l:1`, `http://l:99999`) | each | `ValueError` |
| `test_errors_never_echo_the_reply_or_url` | bodies and URLs carrying `hunter2` | marker absent from every `str(exc)` and log line |

#### D. Neighbor contract and drift guards
| Test | Given | Expect |
|---|---|---|
| `test_round_trip_against_the_real_launcher_server` | real `make_server`, fake `run` returning a scripted `RunOutcome` | result fields equal the outcome; fake saw the catalog analyzer |
| `test_real_launcher_unknown_analyzer_is_sandbox_error` | same server, unknown name | `SandboxError` |
| `test_real_launcher_busy_is_transient` | `max_concurrent_runs=1`, first run blocked on an event | second call `TransientJobError` |
| `test_closed_port_is_transient` | URL to a port that was bound and closed | `TransientJobError` |
| `test_reply_cap_fits_the_largest_launcher_reply` | `MAX_OUTPUT_BYTES` of stdout encoded as the launcher does | encoded reply `< MAX_REPLY_BYTES` |
| `test_redirects_are_not_followed` | 302 to another path | one request seen; `SandboxError` |
| `test_proxy_environment_is_ignored` | `HTTP_PROXY`/`ALL_PROXY` set via `monkeypatch.setenv` | the `MockTransport` handler receives the request with host `launcher` (no proxy hop); `trust_env` is off |

Section D shows that the client and the launcher agree on the wire format, on both the success
path and the error path. If either side changes a key, a status or the encoding, a test fails.
Only tests import `sandbox_launcher.server` and `sandbox_launcher.runner.RunOutcome`. The source
module stays isolated.

## Order of work (red → green)
1. Write `tests/unit/infra/test_sandbox.py` and run `uv run pytest tests/unit/infra/test_sandbox.py`.
   Confirm it fails because `attacksurf.infra.sandbox` is missing, not because of a typo.
2. Implement `infra/sandbox.py` until the file passes.
3. Full gate:
   ```bash
   uv run ruff check . && uv run ruff format --check . && uv run pyright \
     && uv run lint-imports && uv run pytest
   ```
4. `finish-task` is deferred to commit 3. Run the `pre-pr-check` self-review.
5. Commit on `84-sandbox-runner-client`:
   - Subject: `feat(infra): add the launcher sandbox runner client`.
   - Body: explains *why* (workers need a strict, bounded client for the internal launcher, and
     only busy or unreachable is worth a retry).
   - Footer: `Refs #84` and the Co-Authored-By trailer.
   - Never `--no-verify`.

## Reused code
- `src/attacksurf/domain/sandbox.py`: `SandboxRunner`, `SandboxResult`, `SandboxError`.
- `src/attacksurf/domain/jobs.py`: `TransientJobError`.
- `src/attacksurf/domain/scanners.py`: `MAX_OUTPUT_BYTES`.
- `src/attacksurf/sandbox_launcher/proxy.py`: the URL rule in `ProxyClient.from_url` (copied,
  not imported).
- `src/attacksurf/sandbox_launcher/server.py`: `_reject_duplicate_keys` pattern (copied), and
  `make_server` and `MAX_REQUEST_BYTES` (tests only).
- `src/attacksurf/sandbox_launcher/runner.py`: `RunOutcome` (tests only).
- `src/attacksurf/sandbox_launcher/catalog.py`: `Analyzer` (tests only, for the one-entry
  catalog).
- `tests/docker_fakes.py`: `serving` (thread helper for the real server).

## Verification
- Run `uv run pytest tests/unit/infra/test_sandbox.py -q` until it is green, then the full suite
  with coverage of at least 80%.
- Scratch-only checks (revert afterwards):
  - Import `attacksurf.sandbox_launcher` from `infra/sandbox.py`. Confirm `lint-imports` fails
    (the launcher's independence contract).
  - Map 503 to `SandboxError`. Confirm the retryable-status and real-busy tests fail.
  - Drop `validate=True`. Confirm the bad-base64 case fails.
  - Replace the streaming read with `response.read()`. Confirm the no-content-length cap test
    fails.
- No manual smoke test in this commit. After commit 2, see that plan.

## Notes for later commits
- **Commit 2 (wiring):** builds `LauncherSandboxRunner(url)` from
  `Settings.sandbox_launcher_url`, once per worker process. The `ValueError` from a bad URL
  cannot happen at runtime, because the setting's validator applies the same rule, and commit 2
  tests that.
- **Commit 3 (docs):** documents the status mapping table, the timeout ordering and the reply
  cap, and states that the client is deliberately not SSRF-guarded.
- **PR 4 (compose):** the worker reaches `sandbox-launcher:8791` on the internal network, and
  `SANDBOX_LAUNCHER_URL` is set only for the analysis worker.
- **PR 5 (first analyzer):** the scanner treats `timed_out` and `output_exceeded` as a failed
  analysis, and validates stdout as `ScanOutput`.
