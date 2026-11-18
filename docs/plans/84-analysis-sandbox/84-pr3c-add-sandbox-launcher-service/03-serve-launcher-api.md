# Plan: PR 3c, commit 3: `feat(infra): serve the sandbox launcher api`

Branch `84-sandbox-launcher-service` · `Refs #84` · follows `feat(infra): supervise sandbox runs
through the proxy` (commit 2 of PR 3c; see `../84-pr3-sandbox-launcher-split-4-prs.md`).

## Purpose

**In plain words.** The worker needs a door to knock on: "run analyzer X on artifact Y". This
commit adds that door as a tiny web service with two addresses: one that says "I'm alive", and
one that takes exactly two things, an analyzer name and an artifact ID, and nothing else. It
refuses anything shaped differently, says "not found" for an analyzer or artifact it doesn't
know, and says "busy, try again" when too many runs are already going. It cannot be told which
image, command, folder or limits to use; those stay fixed on the launcher's side.

**Technical.** Adds `sandbox_launcher/server.py`: `LauncherServer(ThreadingHTTPServer)` and
`make_server(host, port, *, catalog, artifact_root, run, max_concurrent_runs)`. `GET /healthz`
→ 200; `POST /runs` takes a strict JSON body `{"analyzer", "artifact_id"}` (≤ 1 KiB, no chunked
transfer, no duplicate keys, `catalog.ANALYZER_NAME`, canonical UUID), looks the analyzer up in
the loaded catalog, resolves the artifact with `resolve_artifact`, takes a slot from a
`BoundedSemaphore`, calls `run(analyzer, artifact_dir)` and answers `{exit_code, stdout_b64,
timed_out, output_exceeded}`. Status mapping: 400 malformed, 404 unknown analyzer or artifact,
405 wrong method, 503 busy or `SandboxRunFailed`, 500 unexpected. Stdlib + structlog only; the
existing launcher contract covers it.

## Context
Commit 2 produced `run_sandbox(...) -> RunOutcome` and `SandboxRunFailed`. PR 3b produced
`load_catalog` (a `Mapping[str, Analyzer]`), `ANALYZER_NAME` and `resolve_artifact` /
`ArtifactNotFound`. The proxy's `server.py` is the in-repo pattern for a hardened stdlib HTTP
server (fixed messages, duplicate-key rejection, silenced access log). Commit 4 builds this
server in `__main__.py`; PR 3d's worker client calls `POST /runs`. It is a separate commit so the
request surface (what a compromised worker can send) is reviewed on its own, with a fake `run`
for every validation case.

## Decisions
1. **`run` is injected as a callable.** `make_server(..., run: Callable[[Analyzer, Path],
   RunOutcome])`. `__main__` binds the proxy client, runtime and wall time; tests pass a fake for
   validation, busy and error cases, and the real `run_sandbox` for one round trip. Rejected:
   the server owning a `ProxyClient`, which would force a proxy into every validation test.
2. **Strict body, fixed shape.** `Content-Type` must be `application/json`; `Transfer-Encoding`
   refused; `Content-Length` 1 to `MAX_REQUEST_BYTES = 1024`; a JSON object with exactly the keys
   `analyzer` and `artifact_id` (duplicates refused via an `object_pairs_hook`, as in the proxy);
   both strings; `analyzer` matches `ANALYZER_NAME`; `artifact_id` equals `str(UUID(value))`
   (lowercase, hyphenated). All violations → 400 `"Request is malformed."`.
3. **404 hides which part is unknown.** Unknown analyzer and `ArtifactNotFound` answer the same
   `"Analyzer or artifact not found."`, so the endpoint can't be used to probe which artifact IDs
   exist on disk. The analyzer is looked up first, so an unknown analyzer never touches the
   filesystem.
4. **Busy is checked last, never queued.** Validation and lookups run before the slot is taken,
   so bad requests can't hold a slot. `acquire(blocking=False)`; on failure 503
   `"Sandbox is busy."`. The worker retries (PR 3d). Queuing here would hide back-pressure and
   hold worker connections open.
5. **Failure mapping.** `SandboxRunFailed` → 503 `"Sandbox run failed."`; any other exception →
   500 `"Internal error."` and a `sandbox_launcher_error` log with the exception *type name* only
   (a message could carry values). The slot is released in `finally`.
6. **Reply shape.** `{"exit_code": int | null, "stdout_b64": str, "timed_out": bool,
   "output_exceeded": bool}`, base64 standard alphabet; at most about 2.67 MiB for the 2 MiB cap,
   which PR 3d's ~3 MiB reply cap relies on.
7. **Routing.** Exact paths only (no query strings): `/healthz` GET, `/runs` POST; a known path
   with another method → 405; anything else → 404. `HEAD`, `PUT`, `PATCH`, `OPTIONS` handled the
   same way so stdlib's default 501 pages never appear.
8. **Socket hygiene.** Handler `timeout = 30` (slow-loris on the request read); `daemon_threads =
   True`; stdlib access log silenced. Each rejection logs `sandbox_launcher_rejected` with the
   status and a fixed reason, never request values.
9. **Left out.** Authentication between worker and launcher: the launcher is reachable only on
   the internal network (PR 4 compose), and the caller can only pick from the fixed menu. The
   tenant check (artifact belongs to the org) is the worker's job (PR 3d docs, #85).
10. **No docs in this commit.** Commit 5 of PR 3c carries the docs, `CHANGELOG.md` and `STATE.md`.

## Requirements
- [ ] `src/attacksurf/sandbox_launcher/server.py` exists, stdlib + structlog + launcher modules.
- [ ] `MAX_REQUEST_BYTES == 1024`, `CLIENT_TIMEOUT_SECONDS == 30`.
- [ ] `make_server(host, port, *, catalog, artifact_root, run, max_concurrent_runs) ->
      LauncherServer`.
- [ ] `GET /healthz` → 200 `{"status": "ok"}`, never runs anything.
- [ ] `POST /runs` validation as in decision 2 → 400 on any violation, body unread when the
      length is out of range.
- [ ] Unknown analyzer / `ArtifactNotFound` → 404 with one shared message.
- [ ] No free slot → 503; slot released on every path.
- [ ] `SandboxRunFailed` → 503; other exceptions → 500, logged by type name.
- [ ] 200 reply of decision 6; `exit_code` `null` when the run was killed.
- [ ] 404 for unknown paths, 405 for wrong methods, including `HEAD`/`PUT`/`PATCH`/`OPTIONS`.
- [ ] All replies `Content-Type: application/json` with `Content-Length`; messages are fixed.
- [ ] No change to `pyproject.toml`, `config.py`, `sandbox_proxy/` or other launcher modules.

## Acceptance criteria
- [ ] **Contract (round trip):** `POST /runs` for a test catalog entry, through `run_sandbox`,
      the real proxy and `FakeDocker`, returns 200 and `stdout_b64` decodes to the scripted
      stdout.
- [ ] **Contract (fixed menu):** the `run` callable receives the catalog's `Analyzer` and the
      `resolve_artifact` path; nothing from the request body beyond the two fields reaches it.
- [ ] **Negative:** every malformed request in the table returns 400 and `run` is never called.
- [ ] **Not found:** unknown analyzer and missing/symlinked artifact both return the same 404
      body.
- [ ] **Busy:** with `max_concurrent_runs=1` and one run blocked on an event, a second valid
      request returns 503; after release, a third succeeds.
- [ ] **No leakage:** reply bodies and captured logs never contain the request's analyzer value,
      artifact ID or a stdout marker.
- [ ] **Isolation:** `uv run lint-imports` passes.
- [ ] **Gate:** `ruff check`, `ruff format --check`, `pyright`, `lint-imports` and full `pytest`
      pass with coverage >= 80%; the commit passes the hooks without `--no-verify`.

## Changes

### 1. `src/attacksurf/sandbox_launcher/server.py` (~120 lines)
- Docstring: the launcher's only entry point; what the caller can and cannot choose (ADR 0016).
- Constants: `MAX_REQUEST_BYTES`, `CLIENT_TIMEOUT_SECONDS`.
- `_BadRequest` internal exception; `_parse_run_request(headers, rfile) -> tuple[str, UUID]`;
  `_reject_duplicate_keys`.
- `LauncherServer`, `_LauncherHandler` (`do_GET`, `do_POST`, `_deny` for the rest, `_reply`),
  `make_server`.

### 2. Tests, `tests/unit/sandbox_launcher/test_server.py` (written first)
Style follows `tests/unit/sandbox_proxy/test_server.py` (`call` helper with `http.client`). A
`launcher` fixture builds the server with a `FakeRunner` (records calls, returns a scripted
`RunOutcome`, optionally blocks on an event or raises) and `artifact_root=tmp_path` with one real
artifact directory.

#### A. Happy path
| Test | Given | Expect |
|---|---|---|
| `test_healthz_is_ok` | `GET /healthz` | 200 `{"status": "ok"}`; no run |
| `test_run_returns_the_outcome` | valid request | 200, exact JSON with base64 stdout |
| `test_run_passes_the_catalog_analyzer_and_resolved_dir` | valid request | fake saw `catalog["echo"]` and `tmp_path/<uuid>` |
| `test_killed_run_reports_null_exit_code` | outcome `timed_out` | `exit_code: null`, `stdout_b64: ""` |
| `test_full_round_trip_through_the_proxy` | real `run_sandbox`, proxy, `FakeDocker` | 200; decoded stdout equals scripted |

#### B. Boundary cases
| Test | Given | Expect |
|---|---|---|
| `test_request_at_the_size_limit_is_accepted` | padded-whitespace body of 1024 bytes | 200 |
| `test_slot_is_released_after_a_failure` | first run raises, `max=1` | second request 200 |
| `test_busy_reply_when_all_slots_are_taken` | `max=1`, run blocked | second 503; after release 200 |

#### C. Invalid inputs (400 / 404 / 405; `run` never called; messages fixed)
| Test | Given | Expect |
|---|---|---|
| `test_malformed_run_requests_are_rejected` (param: not JSON, array, missing key, extra key, duplicate key, non-string values, bad analyzer pattern, uppercase UUID, UUID without hyphens, braces UUID, wrong content type, no length, length 0, length 1025, chunked) | each | 400 |
| `test_unknown_analyzer_and_artifact_share_one_404` (param unknown analyzer, missing dir, symlink dir) | each | 404, identical body |
| `test_unknown_paths_are_404` (param `/`, `/runs/`, `/runs?x=1`, `/healthz/x`) | each | 404 |
| `test_wrong_methods_are_405` (param GET `/runs`, POST `/healthz`, PUT, PATCH, DELETE, OPTIONS) | each | 405 |
| `test_run_failure_is_503` | fake raises `SandboxRunFailed` | 503 |
| `test_unexpected_error_is_500_and_logged_by_type` | fake raises `KeyError("secret")` | 500; log has `KeyError`, not `secret` |

#### D. Leakage guards
| Test | Given | Expect |
|---|---|---|
| `test_rejections_never_echo_the_request` | bad requests carrying a marker | marker absent from replies and logs |
| `test_success_logs_never_contain_stdout` | stdout with a marker | marker absent from logs |

## Order of work (red → green)
1. Write `tests/unit/sandbox_launcher/test_server.py`; run it; confirm it fails on the missing
   module.
2. Implement `server.py` until the file passes.
3. Full gate:
   ```bash
   uv run ruff check . && uv run ruff format --check . && uv run pyright \
     && uv run lint-imports && uv run pytest
   ```
4. `finish-task` deferred to commit 5; `pre-pr-check` self-review.
5. Commit with subject `feat(infra): serve the sandbox launcher api`, a body explaining *why*
   (the worker's only door to the sandbox, limited to the fixed menu), footer `Refs #84`, and the
   Co-Authored-By trailer. Never `--no-verify`.

## Reused code
- `sandbox_launcher/catalog.py`: `ANALYZER_NAME`, `Analyzer`.
- `sandbox_launcher/artifacts.py`: `resolve_artifact`, `ArtifactNotFound`.
- `sandbox_launcher/runner.py`: `RunOutcome`, `SandboxRunFailed`, `run_sandbox` (round trip).
- `sandbox_proxy/server.py`: handler patterns (`log_message`, `_reply`, duplicate keys), copied.
- `tests/docker_fakes.py`: `FakeDocker`, `FakeRun`, `serving`.

## Verification
- `uv run pytest tests/unit/sandbox_launcher -q` green, then the full suite with coverage >= 80%.
- Mutation checks (scratch only): take the slot before validation → the "bad requests can't hold
  a slot" path shows in the busy test; accept uppercase UUIDs → the table fails.
- Optional manual smoke after commit 4: see that plan.

## Notes for later commits
- **Commit 4 (`__main__.py`):** builds `make_server` with `load_catalog(...)`,
  `Path(settings.sandbox_artifact_root)`, the bound `run_sandbox` and
  `settings.sandbox_max_concurrent_runs`.
- **PR 3d (worker client):** 400/404 → `SandboxError`; 503 and connection errors →
  `TransientJobError`; 500 → `SandboxError`; reply cap ~3 MiB.
- **PR 4 (compose):** health check on `GET /healthz`; launcher port only on the internal network.
