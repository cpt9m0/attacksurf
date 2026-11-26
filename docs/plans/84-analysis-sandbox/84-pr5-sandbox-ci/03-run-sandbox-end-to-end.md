# Plan: PR 5, commit 3: run the sandbox end to end under a real runtime

Branch `84-sandbox-ci` · `Refs #84` · follows `94c2add feat(infra): add fixture analyzers to the
launcher for dev and CI`.

Commit 3 is now **two commits**, in this order:

| | Subject | Non-test files |
|---|---|---|
| **3a** | `fix(security): keep /tmp read-only in the sandbox` | `sandbox_launcher/container.py`, `sandbox_proxy/policy.py`, `docs/adr/0034-sandbox-tmp-read-only.md` |
| **3b** | `test(infra): run the sandbox end to end under a real runtime` | `sandbox/images/fixture/probe.py`, `pyproject.toml`, `Makefile` |

## Context

**In plain words.** So far the sandbox has only been tested against a fake Docker. Commit 3 runs it
for real: tests start the real launcher and proxy, which start real containers from the fixture
image, and check that the walls hold. Researching it turned up one gap to close first: gVisor can
give a sandbox its own writable `/tmp`. So 3a locks `/tmp`, and 3b adds the tests.

**What the research found**

1. **`/tmp` under gVisor.** In `runsc/boot/vfs.go` (current master), `mountTmp` mounts an internal
   tmpfs at `/tmp` when `/tmp` is empty or missing and no explicit mount exists there. It doesn't
   look at the read-only root flag, and its only option is `mode=01777`, so it is writable and
   allows exec. ADR 0016 says `/scratch` (`noexec`) is the only writable path. This comes from
   reading the source; it has not been run here, and the release commit 4 pins may differ. You
   chose to lock `/tmp` at the gate.
2. **The probe's root check proves nothing yet.** It writes to `/etc`, which user 65532 can't write
   even on a writable root. It needs a world-writable directory.
3. **The input check would prove nothing either** if the staged files were not writable by 65532:
   file permissions would block the write, with or without `:ro`.
4. **Docker mounts `/dev/shm`** (and `/dev/mqueue` under `runc`, to be confirmed) writable even
   with a read-only root. Checking two named paths can't show what else is writable.
5. gVisor's `/proc/self/status` does write `CapEff` and `NoNewPrivs` (`task_files.go`), so those
   probe keys work under `runsc`. gVisor ignores the `nodev` tmpfs option with a warning, and
   passes `size` through; `ro` and `noexec` are parsed.
6. This host has `runc` only. **Everything specific to `runsc` stays unproven until commit 4's CI
   job runs it.**

---

## Commit 3a: `fix(security): keep /tmp read-only in the sandbox`

### Decisions
1. **An explicit tmpfs at `/tmp`:** `ro,noexec,nosuid,nodev,size=4096`. An explicit mount makes
   `runsc` skip its own, and under `runc` it is read-only too.
2. **Enforced by the proxy, not trusted from the launcher.** The proxy requires exactly the two
   tmpfs mounts, `/scratch` (rules unchanged) and `/tmp` with that exact option string. A missing,
   writable or reworded `/tmp` entry is refused.
3. **A constant on each side** (`TMP_MOUNT_OPTIONS`), because the launcher never imports the proxy;
   a test keeps them equal, like the other copied constants.
4. **New ADR 0034**, since this changes the create shape ADR 0016 describes ("no other mount
   except…"). It records the gVisor behavior, the lock, and the remaining exceptions (kernel
   mounts under `/dev`, to be confirmed by 3b and CI). ADR 0016 gets a one-line pointer.
5. Tools that need temporary space use `/scratch` (`TMPDIR=/scratch` is set by real analyzer
   images, #92). The fixture needs nothing.

### Changes and tests (tests first)
- `sandbox_launcher/container.py`: add the constant and the `/tmp` entry in `Tmpfs`.
- `sandbox_proxy/policy.py`: `_check_scratch` becomes `_check_tmpfs` and checks both mounts.
- Update the expected bodies in `tests/unit/sandbox_launcher/test_container.py`,
  `.../test_artifacts.py` and `tests/unit/sandbox_proxy/test_policy.py`.
- New rejection cases in `test_policy.py`: no `/tmp`; `/tmp` writable (`rw,…`); `/tmp` without
  `noexec`; `/tmp` with another size; a third tmpfs.
- New drift test: the launcher and proxy constants are equal.
- `docs/security.md`: the parser-exploit row (line 65) mentions the locked `/tmp`.
  (That is a fourth non-test file; still within the limit.)

### Acceptance
- Gate green. Under local `runc`, a body from `build_create_body` runs, and `touch /tmp/x` fails
  with "Read-only file system" (hand check with the same `--tmpfs` options).
- Reverting the proxy check makes the new rejection cases fail.

---

## Commit 3b: `test(infra): run the sandbox end to end under a real runtime`

### Decisions
1. **Real services in-process** (overview Decision 1): `sandbox_proxy.server.make_server` on
   `/var/run/docker.sock`, `sandbox_launcher.server.make_server` in front of it with the real
   `run_sandbox`, called through `LauncherSandboxRunner`. Only analyzers run as containers.
2. **Real code for the wiring too:** a tmp lock (four fixture names, one image ID) read by both
   `load_images` and `load_catalog(lock, select_specs(prod=False, fixtures=True))`; the runtime
   from `select_runtime(ProxyClient.runtimes(), …)`; allowed runtimes from
   `SandboxProxySettings().allowed_runtimes`.
3. **Skip only when not asked.** Tests skip unless `RUN_SANDBOX_TESTS=1`. Once set, a missing
   Docker, a failed build or the wrong runtime **fails**. This replaces the overview's "`CI=true`
   means fail" rule, which would break the ordinary CI `test` job. Commit 4 adds a workflow test
   that the sandbox job sets the variable.
4. **`SANDBOX_EXPECT_RUNTIME`** (`runsc` in CI): the selected runtime must equal it.
5. **Two wall times:** 60 s normally, 3 s only for `fixture-sleep`. A 3 s limit for everything
   (the overview) could kill `flood` or `probe` by time on a slow runner.
6. **Make the checks able to fail:**
   - the staged directory is `0777` and its file `0666`, so only `:ro` can block a write;
   - `ROOT_PROBE_PATH` moves to `/var/tmp/.attacksurf-probe` (world-writable in the Debian base),
     so only the read-only root can block it;
   - the probe reports `network_error` (errno name), so "no route" is told apart from "no
     internet here";
   - the probe walks the filesystem and reports `writable_dirs`: `{path: can_exec}`.
7. **Writable-directory allow-list:** `/scratch` must be there; nothing outside
   `{/scratch, /dev/shm, /dev/mqueue}` may be; **none may allow exec**; `/tmp` must be absent.
   If a real run shows another entry or an exec-able one, **stop and report it**. The list is
   never widened just to get green; any change is recorded in ADR 0034.
8. **Environment check against the image,** not a name pattern: names must be within the image's
   `Config.Env` plus `HOSTNAME`, `HOME`, `LC_CTYPE`. (The Python base has `GPG_KEY`, which a
   "looks secret" rule would flag.) A sentinel variable set in the test process must be absent.
9. **No container may survive a test.** An autouse fixture checks
   `docker ps -aq --filter ancestor=<image id>`, force-removes leftovers and fails. (In commit 1,
   a timed-out `docker run` left a container running.) Not a name filter: dev stack containers
   are also named `attacksurf-*`.
10. **The probe runs once per session;** the wall tests assert on that one result.

### Probe changes (`probe.py`, standard library only)
- `ROOT_PROBE_PATH` → `/var/tmp/.attacksurf-probe`.
- `network_error`: `None` if the connect worked, else the errno name, or the exception type name.
- `writable_dirs`: walk `WALK_ROOT` (`/`), skip `/proc` and `/sys`, don't follow links; for each
  directory where a file can be created, record whether a script there runs.
  `_can_execute_in_scratch` becomes `_can_execute_in(directory)`. Stop after 20 000 directories
  and report `walk_truncated`; the test requires `false`. Every created file is removed.

### New files
- `tests/integration/sandbox/__init__.py`, `conftest.py`, `test_runtime.py`.
- `conftest.py` fixtures: `image_id` (session; `SANDBOX_FIXTURE_IMAGE`, else
  `scripts/build-sandbox-images.sh fixture`; checks the `sha256:` shape), `artifact_root` (one
  `<uuid>/hello.txt`, explicit modes), `launch(wall_time)` (starts both servers with
  `tests.docker_fakes.serving`, returns the client), `probe_facts`, the leftover guard.
- `pyproject.toml`: marker `sandbox_runtime`.
- `Makefile`: `sandbox-test` runs `RUN_SANDBOX_TESTS=1 uv run pytest tests/integration/sandbox
  -m sandbox_runtime --no-cov`. It does **not** default `SANDBOX_ALLOW_RUNC`; without gVisor run
  `SANDBOX_ALLOW_RUNC=true make sandbox-test`.

### Runtime tests (`test_runtime.py`)

**A. Happy path**
- `test_ok_analyzer_returns_its_json_and_exit_zero`
- `test_selected_runtime_is_the_expected_one` (when `SANDBOX_EXPECT_RUNTIME` is set)
- `test_probe_exits_zero_and_sees_the_input_file` (`input_files == 1`, `walk_truncated` false)

**B. The walls**
- `test_probe_has_no_network` (connect and DNS fail; `network_error` is `ENETUNREACH` or
  `EHOSTUNREACH`; what `runsc` returns is to be confirmed)
- `test_probe_cannot_change_the_input` (also: the host file is unchanged, nothing new beside it)
- `test_probe_cannot_write_the_root_filesystem`
- `test_only_expected_directories_are_writable_and_none_allows_exec`
- `test_probe_runs_non_root_without_capabilities` (65532, `CapEff` zero, `NoNewPrivs` 1)
- `test_probe_sees_no_docker_socket_and_only_the_image_environment`
- `test_probe_runs_under_gvisor_when_expected` (`kernel_release == "4.4.0"`; under `runc` it
  equals the host's)

**C. The kills**
- `test_sleeping_analyzer_is_killed_at_the_wall_time` (`timed_out`, no exit code, empty stdout,
  took at least 3 s and less than 3 s plus `KILL_GRACE_SECONDS`, no container left)
- `test_flooding_analyzer_is_killed_at_the_output_cap` (`output_exceeded`, not `timed_out`,
  empty stdout, no container left)

**D. Refusals** (`SandboxError`, a logged 404, no container)
- `test_unknown_artifact_is_refused`
- `test_symlink_out_of_the_artifact_root_is_refused`

**E. Prod start-up**
- `test_launcher_refuses_to_start_in_prod_without_runsc`: run `main()` with `ENV=prod` against
  the real proxy; expect `SystemExit`, and `serve_forever` is never reached. Where `runsc` is
  registered it skips, **except** with `SANDBOX_EXPECT_RUNTIME=runc`, where it fails. Commit 4
  runs it with that setting **before** installing `runsc`, so CI really exercises it.

### Unit test updates
- `tests/unit/test_sandbox_images.py`: new keys in `PROBE_KEYS`; point `WALK_ROOT` at `tmp_path`;
  tests for `writable_dirs` (finds a writable dir, omits a read-only one, skips links), truncation,
  `network_error` and cleanup. Guard: `ROOT_PROBE_PATH` is not under `/etc` or `/tmp`.
- `tests/unit/test_makefile.py`: `make -n sandbox-test`.

---

## Order of work (when asked to implement)
1. 3a: failing policy and body tests, then `container.py`, `policy.py`, ADR 0034, security doc.
   Gate. Commit when asked.
2. 3b: probe unit tests, then `probe.py`.
3. Harness and runtime tests; rebuild the image; run under `runc`. Compare `writable_dirs` with
   the allow-list and report any difference before changing it.
4. Marker and `make sandbox-test`. Gate. Commit when asked.

## Reused code
- `tests.docker_fakes.serving` and the shape of `tests/unit/sandbox_launcher/conftest.py`.
- `infra/sandbox.py: LauncherSandboxRunner`; `sandbox_launcher`: `__main__.select_runtime` and
  `select_specs`, `catalog.load_catalog`, `runner.run_sandbox` and `KILL_GRACE_SECONDS`;
  `sandbox_proxy.policy.load_images`.
- `tests/unit/sandbox_launcher/test_main.py`: the `main()` environment setup and patched
  `serve_forever`.
- `tests/e2e/web/test_shell_layout.py`: the marker plus `skipif` opt-in pattern.

## Verification
- Gate after each commit: `uv run ruff check . && uv run ruff format --check . && uv run pyright
  && uv run lint-imports && uv run pytest` (the runtime tests show as skipped).
- `SANDBOX_ALLOW_RUNC=true SANDBOX_EXPECT_RUNTIME=runc make sandbox-test`: all pass except the
  gVisor marker's `runsc` branch. The prod refusal runs for real here.
- With `RUN_SANDBOX_TESTS=1` and no `SANDBOX_ALLOW_RUNC` on this host, the run **fails**.
- **Proof the tests can fail** (scratch edits, reverted): drop `:ro` from both the body builder and
  the proxy check, and the input test fails; set `ReadonlyRootfs` false in both, and the root test
  fails; put a long sleep under the 60 s wall time into the `flood` path, and its test fails.
- The `/tmp` lock can't be shown to matter under `runc` (the read-only root covers `/tmp` there).
  Its real proof is commit 4's `runsc` run.
- `docker ps -a` shows no fixture containers afterwards.

## Risks to settle on the first `runsc` run (commit 4)
The errno for no network; the `writable_dirs` set and exec on `/dev/shm`; that the read-only
`/tmp` mount is honoured; `kernel_release`; startup time within 60 s. A failure here is a finding
to look at, not an assertion to loosen.

## Notes for later commits
- **Commit 4:** run the prod-refusal test with `SANDBOX_EXPECT_RUNTIME=runc` before
  `install-runsc.sh`; then the full suite with `RUN_SANDBOX_TESTS=1 SANDBOX_ALLOW_RUNC=false
  SANDBOX_EXPECT_RUNTIME=runsc`. The workflow test checks those variables.
- **Commit 6:** document `make sandbox-test`; in the PR description, call out 3a and ADR 0034.
