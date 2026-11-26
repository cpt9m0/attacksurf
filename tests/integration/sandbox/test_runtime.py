"""The ADR 0016 walls, tried by a real container (#84). Run with `make sandbox-test`.

The fixture probe reports what the sandbox let it do; these tests say what is acceptable. A
failure here is a finding about the sandbox: don't loosen an assertion to get a pass.
"""

import json
import os
import time
from collections.abc import Callable
from pathlib import Path
from uuid import uuid4

import pytest
from structlog.testing import capture_logs

from attacksurf.domain.sandbox import SandboxError
from attacksurf.infra.sandbox import LauncherSandboxRunner
from attacksurf.sandbox_launcher.__main__ import main
from attacksurf.sandbox_launcher.proxy import ProxyClient
from attacksurf.sandbox_launcher.runner import KILL_GRACE_SECONDS
from attacksurf.sandbox_launcher.server import LauncherServer
from tests.integration.sandbox.conftest import (
    INPUT_TEXT,
    SENTINEL_NAME,
    SHORT_WALL_TIME_SECONDS,
    ProbeRun,
    Staged,
)

pytestmark = [
    pytest.mark.sandbox_runtime,
    pytest.mark.skipif(
        os.environ.get("RUN_SANDBOX_TESTS") != "1",
        reason="needs Docker: RUN_SANDBOX_TESTS=1 (make sandbox-test)",
    ),
]

# `/scratch` plus the kernel mounts Docker adds under /dev (ADR 0034). Don't add to this to get a
# pass: a new entry is a hole to look at.
ALLOWED_WRITABLE = {"/scratch", "/dev/shm", "/dev/mqueue"}  # noqa: S108 (paths in the sandbox)
GVISOR_KERNEL_RELEASE = "4.4.0"


def expected_runtime() -> str | None:
    return os.environ.get("SANDBOX_EXPECT_RUNTIME")


# --- A. Happy path ------------------------------------------------------------------------------


def test_ok_analyzer_returns_its_json_and_exit_zero(
    runner: LauncherSandboxRunner, staged: Staged
) -> None:
    result = runner.run("fixture-ok", staged.artifact_id)

    assert (result.exit_code, result.timed_out, result.output_exceeded) == (0, False, False)
    assert json.loads(result.stdout) == {"status": "ok"}


def test_selected_runtime_is_the_expected_one(runtime: str) -> None:
    if expected_runtime() is None:
        pytest.skip("SANDBOX_EXPECT_RUNTIME is not set")

    assert runtime == expected_runtime()


def test_probe_exits_zero_and_sees_the_input_file(probe_run: ProbeRun) -> None:
    assert probe_run.facts["input_files"] == 1
    assert probe_run.facts["walk_truncated"] is False


# --- B. The walls -------------------------------------------------------------------------------


def test_probe_has_no_network(probe_run: ProbeRun) -> None:
    assert probe_run.facts["network_connect_allowed"] is False
    assert probe_run.facts["dns_resolve_allowed"] is False
    # "No route", not merely "nothing answered": a host with no internet can't pass this.
    assert probe_run.facts["network_error"] in {"ENETUNREACH", "EHOSTUNREACH"}


def test_probe_cannot_change_the_input(probe_run: ProbeRun, staged: Staged) -> None:
    assert probe_run.facts["input_write_allowed"] is False
    assert probe_run.facts["input_create_allowed"] is False
    assert [path.name for path in staged.directory.iterdir()] == ["hello.txt"]
    assert (staged.directory / "hello.txt").read_text() == INPUT_TEXT


def test_probe_cannot_write_the_root_filesystem(probe_run: ProbeRun) -> None:
    assert probe_run.facts["root_write_allowed"] is False


def test_only_expected_directories_are_writable_and_none_allows_exec(probe_run: ProbeRun) -> None:
    writable = probe_run.facts["writable_dirs"]

    assert "/scratch" in writable
    assert set(writable) <= ALLOWED_WRITABLE, writable
    assert not [path for path, runs in writable.items() if runs], writable
    assert probe_run.facts["scratch_write_allowed"] is True
    assert probe_run.facts["scratch_exec_allowed"] is False


def test_probe_runs_non_root_without_capabilities(probe_run: ProbeRun) -> None:
    assert (probe_run.facts["uid"], probe_run.facts["gid"]) == (65532, 65532)
    assert int(probe_run.facts["cap_eff"], 16) == 0
    assert probe_run.facts["no_new_privs"] == 1


def test_probe_sees_no_docker_socket_and_only_the_image_environment(
    probe_run: ProbeRun, image_env_names: frozenset[str]
) -> None:
    names = set(probe_run.facts["env_names"])

    assert probe_run.facts["docker_socket_present"] is False
    # Docker sets HOSTNAME and HOME; Python's locale coercion may set LC_CTYPE.
    assert names <= image_env_names | {"HOSTNAME", "HOME", "LC_CTYPE"}, names
    assert SENTINEL_NAME not in names


def test_probe_runs_under_gvisor_when_expected(probe_run: ProbeRun, runtime: str) -> None:
    release = probe_run.facts["kernel_release"]
    if "runsc" in (runtime, expected_runtime()):
        assert release == GVISOR_KERNEL_RELEASE
    else:
        assert release == os.uname().release


# --- C. The kills -------------------------------------------------------------------------------


def test_sleeping_analyzer_is_killed_at_the_wall_time(
    short_runner: LauncherSandboxRunner,
    staged: Staged,
    fixture_containers: Callable[[], list[str]],
) -> None:
    began = time.monotonic()

    result = short_runner.run("fixture-sleep", staged.artifact_id)

    elapsed = time.monotonic() - began
    assert (result.exit_code, result.stdout, result.timed_out) == (None, b"", True)
    assert result.output_exceeded is False
    assert SHORT_WALL_TIME_SECONDS <= elapsed < SHORT_WALL_TIME_SECONDS + KILL_GRACE_SECONDS
    assert fixture_containers() == []


def test_flooding_analyzer_is_killed_at_the_output_cap(
    runner: LauncherSandboxRunner,
    staged: Staged,
    fixture_containers: Callable[[], list[str]],
) -> None:
    result = runner.run("fixture-flood", staged.artifact_id)

    assert (result.exit_code, result.stdout, result.output_exceeded) == (None, b"", True)
    assert result.timed_out is False
    assert fixture_containers() == []


# --- D. Refusals --------------------------------------------------------------------------------


def assert_refused_before_any_run(runner: LauncherSandboxRunner, artifact_id: object) -> None:
    with capture_logs() as logs, pytest.raises(SandboxError):
        runner.run("fixture-ok", artifact_id)  # type: ignore[arg-type]

    rejected = [entry for entry in logs if entry["event"] == "sandbox_launcher_rejected"]
    assert [entry["status"] for entry in rejected] == [404]
    assert not [entry for entry in logs if entry["event"] == "sandbox_run"]


def test_unknown_artifact_is_refused(runner: LauncherSandboxRunner) -> None:
    assert_refused_before_any_run(runner, uuid4())


def test_symlink_out_of_the_artifact_root_is_refused(
    runner: LauncherSandboxRunner, staged: Staged, tmp_path: Path
) -> None:
    link_id = uuid4()
    link = staged.root / str(link_id)
    link.symlink_to(tmp_path, target_is_directory=True)
    try:
        assert_refused_before_any_run(runner, link_id)
    finally:
        link.unlink()


# --- E. Production start-up ---------------------------------------------------------------------


def test_launcher_refuses_to_start_in_prod_without_runsc(
    proxy: ProxyClient,
    proxy_port: int,
    images_lock: Path,
    staged: Staged,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    if "runsc" in proxy.runtimes():
        if expected_runtime() == "runc":
            pytest.fail("expected a host without runsc, but it is registered")
        pytest.skip("runsc is registered here; CI runs this before installing it")

    def serve_forever(_self: LauncherServer, poll_interval: float = 0.5) -> None:
        raise AssertionError("the launcher started without runsc")

    monkeypatch.setattr(LauncherServer, "serve_forever", serve_forever)
    for name, value in {
        "ENV": "prod",
        "SANDBOX_ALLOW_RUNC": "false",
        "SANDBOX_FIXTURE_ANALYZERS": "false",
        "SANDBOX_PROXY_URL": f"http://127.0.0.1:{proxy_port}",
        "SANDBOX_IMAGES_LOCK": str(images_lock),
        "SANDBOX_ARTIFACT_ROOT": str(staged.root),
        "SANDBOX_LAUNCHER_HOST": "127.0.0.1",
    }.items():
        monkeypatch.setenv(name, value)

    # The message pins the reason: an unreachable proxy would also exit.
    with pytest.raises(SystemExit, match="no permitted container runtime"):
        main()
