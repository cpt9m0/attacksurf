# Plan: PR 3c, commit 1: `test(security): share the fake Docker daemon`

Branch `84-sandbox-launcher-service` · `Refs #84` · follows `917e2b4 docs(ai): record no sampling
and no sdk retries in adr 0024` on `main` (PR 3b merged as `65aa36c`; see
`../84-pr3-sandbox-launcher-split-4-prs.md`).

## Purpose

**In plain words.** The launcher will drive real sandbox runs through the proxy, and we want to
test that without a real Docker. The proxy's tests already have a small pretend Docker, but it is
hidden inside one test file and it can only answer "here is some output" in one go. This commit
moves the pretend Docker into a shared place and teaches it to act out a whole run: wait until
the container is started, print output in several separate pieces (normal and error output),
keep running until it is killed if asked to, and report when the container is gone. It changes
no application code, and the proxy tests that exist today keep passing unchanged.

**Technical.** Moves `FakeDocker` and its handler from `tests/unit/sandbox_proxy/test_server.py`
to `tests/docker_fakes.py`, with a `serving(server)` context manager for the thread lifecycle.
Adds an opt-in `FakeRun` script (`docker.run`): attach sends Docker's real hijack head, waits for
`start`, sends each scripted chunk as its own write, then closes or, with `hold_open`, blocks
until `kill`; `wait?condition=removed` blocks until the run has exited and answers
`{"StatusCode": n}`. With `docker.run is None` every reply is the current one. New proxy tests
prove the run path the launcher relies on (frames split across writes are relayed intact, a
removed-wait returns after a kill and releases ownership). Tests only; no `src/` change.

## Context
PR 2 (#135) wrote `FakeDocker` inline in the proxy tests: a Unix-socket `ThreadingMixIn` HTTP
server whose attach writes `HTTP/1.1 101 UPGRADED ... tool-output` at once and whose wait replies
immediately. PR 3b's `stream.py` (`read_stdout`) parses Docker's 8-byte frames. Commit 2
(`runner.py`) must be tested against the real proxy in front of a Docker that behaves like a run:
output only after start, frames split at any byte, a container that never exits on its own, and
a removed-wait that only answers after exit or kill. This is a separate commit so the move is
reviewed as a pure move, and the new fake behaviour is proven against the proxy before any
launcher code depends on it.

## Decisions
1. **Opt-in script, legacy default.** `FakeDocker.run: FakeRun | None = None`. When `None`, the
   handler keeps today's exact replies (`tool-output`, immediate wait with `wait_status` and
   `wait_body`), so the 60-odd proxy tests stay unchanged. Rejected: changing the default
   behaviour and adjusting old tests, which would hide regressions in the move.
2. **`FakeRun` is a dataclass of plain fields plus three events.**
   `FakeRun(chunks: list[bytes] = [], exit_code: int = 0, hold_open: bool = False,
   attach_status: int = 101)`, with `started`, `killed`, `exited` as `threading.Event` fields.
   Tests read the events to assert ordering (for example "stdout was not sent before start").
3. **Real Docker head.** Attach answers `HTTP/1.1 101 UPGRADED\r\nContent-Type:
   application/vnd.docker.raw-stream\r\nConnection: Upgrade\r\nUpgrade: tcp\r\n\r\n` (what the
   daemon sends), so the launcher's head parser is tested against the real shape.
   `attach_status != 101` answers a normal JSON error reply instead, for "attach failed".
4. **Each chunk is its own `sendall` + `flush`.** That is how "frames split across writes" is
   scripted: the test passes pre-split bytes. Recv boundaries on the reader side still vary;
   `stream.py` already tolerates any split.
5. **Bounded waits everywhere.** Every `Event.wait` in the fake uses `FAKE_TIMEOUT_SECONDS = 10`,
   so a launcher bug fails a test instead of hanging the suite.
6. **Kill and remove end the run.** `kill` sets `killed` and `exited` with exit code 137 (what
   Docker reports for SIGKILL); `DELETE` sets `exited` too (forced removal of a running
   container). Removed-wait then replies with that code.
7. **Shared fixtures stay per package.** `tests/docker_fakes.py` holds the fake, the
   `serving()` helper and the constants (`CREATED`, `DOCKER_INFO`). The `docker`/`proxy`
   fixtures stay in each test module because the proxy policy differs (the launcher's
   artifact root is `tmp_path`).
8. **No docs in this commit.** Commit 5 of PR 3c carries the docs, `CHANGELOG.md` and `STATE.md`.

## Requirements
- [ ] `tests/docker_fakes.py` exists with `FakeDocker`, its handler, `FakeRun`, `serving()`,
      `CREATED`, `DOCKER_INFO`, `HOST_DETAILS`, `FAKE_TIMEOUT_SECONDS`, and a module docstring.
- [ ] `tests/unit/sandbox_proxy/test_server.py` imports them; no test in it changes behaviour or
      assertions (only imports and the fixture body use `serving()`).
- [ ] With `run is None`, every reply is byte-identical to the old fake's.
- [ ] With a `run`: attach writes the 101 head, waits for `started`, sends each chunk separately,
      closes (or blocks until `killed` when `hold_open`), then sets `exited`.
- [ ] `start` sets `started`; `kill` sets `killed` and `exited` (exit 137); `DELETE` sets
      `exited`.
- [ ] `wait?condition=removed` waits for `exited` and replies `200 {"StatusCode": <code>}`;
      `wait` with other conditions keeps the legacy reply.
- [ ] `attach_status != 101` answers that status with a JSON body and no stream.
- [ ] All waits in the fake are bounded by `FAKE_TIMEOUT_SECONDS`.
- [ ] Unix-socket skip guard stays (module-level skip where `UnixStreamServer` is missing).
- [ ] No change under `src/`, `pyproject.toml` or docs.

## Acceptance criteria
- [ ] **Move is pure:** the full existing proxy test file passes with only import/fixture edits
      (reviewable as a diff of moved lines).
- [ ] **Run path through the real proxy:** scripted stdout and stderr frames split across
      writes arrive at a client attached through `make_server` unchanged and in order.
- [ ] **Ordering:** no stream byte after the head is sent before `start`.
- [ ] **Kill ends a held-open attach**, and the removed-wait then returns `{"StatusCode": 137}`
      and releases the proxy's ownership (a later `start` on that ID is 403).
- [ ] **Gate:** `ruff check`, `ruff format --check`, `pyright`, `lint-imports` and full `pytest`
      pass with coverage >= 80%; the commit passes the hooks without `--no-verify`.

## Changes

### 1. `tests/docker_fakes.py` (~150 lines, moved + ~50 new)
- Docstring: a stand-in Docker daemon on a Unix socket for proxy and launcher tests; legacy
  replies by default, a scripted run when `run` is set.
- `FakeRun` dataclass; `FakeDocker` (fields as today plus `run`); handler branches for
  attach/start/kill/wait/DELETE consult `run`.
- `serving(server) -> Iterator[server]` context manager: starts `serve_forever(0.01)` on a
  daemon thread, then `shutdown()` and `server_close()`.

### 2. `tests/unit/sandbox_proxy/test_server.py` (imports, fixtures, +3 tests)
- Replace the class definitions with imports; fixtures use `serving()`.

#### A. Happy path (scripted run relayed by the proxy)
| Test | Given | Expect |
|---|---|---|
| `test_attach_relays_scripted_frames_split_across_writes` | `FakeRun` with a stdout frame split into 3 chunks plus a stderr frame; attach, then start | bytes after the head equal the concatenated chunks |
| `test_attach_sends_nothing_before_start` | attach without start, short read timeout | only the head arrives; after start, the frames |

#### B. Boundary cases
| Test | Given | Expect |
|---|---|---|
| `test_kill_ends_a_held_open_attach_and_removed_wait_reports_it` | `hold_open=True`; attach, start, kill | attach closes, removed-wait `{"StatusCode": 137}`, later `start` 403 |

#### C. Invalid inputs
None new: the proxy's refusal tables are unchanged and still pass.

#### D. Drift guards
None: the legacy-default rule is guarded by the unchanged proxy suite itself.

## Order of work (red → green)
1. Add the three new proxy tests importing `FakeRun` from `tests.docker_fakes`; run
   `uv run pytest tests/unit/sandbox_proxy/test_server.py`. Confirm the failure is the missing
   module, not a typo.
2. Create `tests/docker_fakes.py` by moving the fake, then add `FakeRun` until the file passes.
3. Full gate:
   ```bash
   uv run ruff check . && uv run ruff format --check . && uv run pyright \
     && uv run lint-imports && uv run pytest
   ```
4. `finish-task` deferred to commit 5 (see Decisions); `pre-pr-check` self-review of the diff.
5. Commit on `84-sandbox-launcher-service` with subject
   `test(security): share the fake Docker daemon`, a body explaining *why* (the launcher's
   runner needs a Docker that acts out a run, behind the real proxy), footer `Refs #84`, and the
   Co-Authored-By trailer. Never `--no-verify`.

## Reused code
- `tests/unit/sandbox_proxy/test_server.py`: `FakeDocker`, `_FakeDockerHandler`, `DOCKER_INFO`,
  `HOST_DETAILS`, `CREATED`, the `docker`/`proxy` fixtures and `call`/`create` helpers.
- `tests/unit/sandbox_proxy/test_policy.py`: `IMAGE`, `create_body`.
- `src/attacksurf/sandbox_proxy/server.py`: `make_server` (unchanged, under test).

## Verification
- `uv run pytest tests/unit/sandbox_proxy -q` green, then the full suite with coverage >= 80%.
- Scratch check (revert afterwards): make attach send chunks before `started` and confirm
  `test_attach_sends_nothing_before_start` fails.
- Optional manual smoke: none; no runtime code changes.

## Notes for later commits
- **Commit 2 (`runner.py`):** uses `FakeRun` for every run scenario (clean, non-zero,
  hold-open wall-time kill, oversized stdout, stderr, attach failure) behind the real proxy with
  `artifact_root=tmp_path`.
- **Commit 3 (`server.py`):** one full round trip uses the same fixtures.
- **PR 5 (`runsc` CI):** real Docker replaces the fake; any difference from the scripted head or
  wait semantics shows up there.
