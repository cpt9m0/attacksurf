"""The supervised run: order, limits, cleanup, and nothing from the tool in logs."""

import socket
import struct
import threading
import time
from contextlib import suppress
from pathlib import Path
from typing import Any

import pytest
from structlog.testing import capture_logs

from attacksurf.config import SANDBOX_MAX_WALL_TIME_SECONDS
from attacksurf.sandbox_launcher.catalog import Analyzer
from attacksurf.sandbox_launcher.proxy import ProxyClient, ProxyError
from attacksurf.sandbox_launcher.runner import (
    KILL_GRACE_SECONDS,
    RunOutcome,
    SandboxRunFailed,
    run_sandbox,
)
from attacksurf.sandbox_launcher.stream import MAX_STDOUT_BYTES
from attacksurf.sandbox_proxy.server import RUN_TIMEOUT_SECONDS
from tests.docker_fakes import CREATED, FakeDocker, FakeRun
from tests.unit.sandbox_launcher.test_container import analyzer

MARKER = b"TOOL-OUTPUT-MARKER-5d2e"
WALL_TIME = 5.0


def frame(stream_type: int, payload: bytes) -> bytes:
    return struct.pack(">BxxxI", stream_type, len(payload)) + payload


def run(
    client: ProxyClient,
    artifact_dir: Path,
    *,
    tool: Analyzer | None = None,
    wall_time: float = WALL_TIME,
) -> RunOutcome:
    return run_sandbox(
        client, tool or analyzer(), artifact_dir, runtime="runsc", wall_time=wall_time
    )


def paths(docker: FakeDocker) -> list[str]:
    return [f"{method} {path.split('?')[0]}" for method, path, _, _ in docker.calls]


def saw(docker: FakeDocker, method: str, suffix: str) -> bool:
    return any(entry.startswith(method) and entry.endswith(suffix) for entry in paths(docker))


# --- A. Happy path ------------------------------------------------------------------------------


def test_run_returns_stdout_and_exit_code(
    client: ProxyClient, docker: FakeDocker, artifact_dir: Path
) -> None:
    docker.run = FakeRun(chunks=[frame(1, b"hello "), frame(1, b"world")])

    outcome = run(client, artifact_dir)

    assert outcome == RunOutcome(0, b"hello world", False, False)


def test_run_calls_docker_in_order(
    client: ProxyClient, docker: FakeDocker, artifact_dir: Path
) -> None:
    docker.run = FakeRun(chunks=[frame(1, b"x")])

    run(client, artifact_dir)

    calls = paths(docker)
    attach, start = f"POST /containers/{CREATED}/attach", f"POST /containers/{CREATED}/start"
    assert calls[0] == "POST /containers/create"
    assert calls.index(attach) < calls.index(start)  # attach first, or output is missed
    # The runner only knows the wait is in flight, not that Docker has it, so its position
    # among the calls isn't pinned; that it was armed is.
    assert f"POST /containers/{CREATED}/wait" in calls
    assert len(calls) == 4  # a clean exit needs no kill or remove


def test_run_reports_a_non_zero_exit(
    client: ProxyClient, docker: FakeDocker, artifact_dir: Path
) -> None:
    docker.run = FakeRun(chunks=[frame(1, b"partial but whole")], exit_code=3)

    outcome = run(client, artifact_dir)

    assert (outcome.exit_code, outcome.stdout) == (3, b"partial but whole")


def test_run_drops_stderr(client: ProxyClient, docker: FakeDocker, artifact_dir: Path) -> None:
    docker.run = FakeRun(chunks=[frame(1, b"out"), frame(2, MARKER), frame(1, b"put")])

    outcome = run(client, artifact_dir)

    assert outcome.stdout == b"output"
    assert MARKER not in outcome.stdout


def test_run_handles_frames_split_across_writes(
    client: ProxyClient, docker: FakeDocker, artifact_dir: Path
) -> None:
    data = frame(1, b"split across many writes")
    docker.run = FakeRun(chunks=[data[i : i + 5] for i in range(0, len(data), 5)])

    assert run(client, artifact_dir).stdout == b"split across many writes"


# --- B. Boundary cases --------------------------------------------------------------------------


def test_run_accepts_exactly_the_stdout_cap(
    client: ProxyClient, docker: FakeDocker, artifact_dir: Path
) -> None:
    payload = b"a" * MAX_STDOUT_BYTES
    docker.run = FakeRun(chunks=[frame(1, payload)])

    outcome = run(client, artifact_dir)

    assert outcome.output_exceeded is False
    assert outcome.stdout == payload


def test_run_kills_at_the_wall_time(
    client: ProxyClient, docker: FakeDocker, artifact_dir: Path
) -> None:
    docker.run = FakeRun(chunks=[frame(1, MARKER)], hold_open=True)
    began = time.monotonic()

    outcome = run(client, artifact_dir, wall_time=0.3)

    assert time.monotonic() - began < 3
    assert outcome == RunOutcome(None, b"", True, False)
    assert docker.run.killed.is_set()


def test_run_kills_when_stdout_passes_the_cap(
    client: ProxyClient, docker: FakeDocker, artifact_dir: Path
) -> None:
    docker.run = FakeRun(chunks=[frame(1, b"a" * (MAX_STDOUT_BYTES + 1))], hold_open=True)

    outcome = run(client, artifact_dir)

    assert outcome == RunOutcome(None, b"", False, True)
    assert docker.run.killed.is_set()


def test_run_waits_for_exit_after_stdout_closes(
    client: ProxyClient, docker: FakeDocker, artifact_dir: Path
) -> None:
    fake = FakeRun(chunks=[frame(1, b"done")], hold_exit=True)
    docker.run = fake
    timer = threading.Timer(0.3, fake.end, args=(7,))
    timer.start()

    outcome = run(client, artifact_dir)

    assert outcome == RunOutcome(7, b"done", False, False)
    assert not fake.killed.is_set()


def test_run_kills_a_tool_that_closes_stdout_and_keeps_running(
    client: ProxyClient, docker: FakeDocker, artifact_dir: Path
) -> None:
    docker.run = FakeRun(chunks=[frame(1, b"x")], hold_exit=True)

    outcome = run(client, artifact_dir, wall_time=0.3)

    assert outcome.timed_out is True
    assert docker.run.killed.is_set()


def test_run_counts_a_delayed_start_reply_against_the_wall_time(
    client: ProxyClient, docker: FakeDocker, artifact_dir: Path
) -> None:
    # Docker has started the analyzer but sits on its reply: the clock must already be running.
    docker.run = FakeRun(chunks=[frame(1, b"x")], hold_open=True, start_delay=5)
    began = time.monotonic()

    outcome = run(client, artifact_dir, wall_time=0.2)

    assert time.monotonic() - began < 2
    assert outcome == RunOutcome(None, b"", True, False)
    assert docker.run.killed.is_set()


def test_wall_time_and_grace_fit_under_the_proxy_timeout() -> None:
    assert SANDBOX_MAX_WALL_TIME_SECONDS + KILL_GRACE_SECONDS < RUN_TIMEOUT_SECONDS


# --- C. Invalid inputs and failures -------------------------------------------------------------


def test_proxy_unreachable_fails_the_run(artifact_dir: Path) -> None:
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        port = sock.getsockname()[1]

    with pytest.raises(SandboxRunFailed, match=r"Sandbox run failed\."):
        run(ProxyClient("127.0.0.1", port), artifact_dir)


def test_refused_create_fails_without_touching_docker(
    client: ProxyClient, docker: FakeDocker, artifact_dir: Path
) -> None:
    other = analyzer(image="ghcr.io/acme/other@sha256:" + "c" * 64)

    with pytest.raises(SandboxRunFailed):
        run(client, artifact_dir, tool=other)

    assert docker.calls == []


def test_attach_failure_after_create_kills_the_container(
    client: ProxyClient, docker: FakeDocker, artifact_dir: Path
) -> None:
    docker.run = FakeRun(attach_status=500)

    with pytest.raises(SandboxRunFailed):
        run(client, artifact_dir)

    assert docker.run.killed.is_set()
    assert not saw(docker, "POST", "/start")


def test_start_failure_kills_the_container(
    client: ProxyClient, docker: FakeDocker, artifact_dir: Path
) -> None:
    docker.run = FakeRun(start_status=500)

    with pytest.raises(SandboxRunFailed):
        run(client, artifact_dir)

    assert docker.run.killed.is_set()


def test_malformed_stream_fails_and_kills(
    client: ProxyClient, docker: FakeDocker, artifact_dir: Path
) -> None:
    docker.run = FakeRun(chunks=[b"\x09\x00\x00\x00\x00\x00\x00\x01x"], hold_open=True)

    with pytest.raises(SandboxRunFailed):
        run(client, artifact_dir)

    assert docker.run.killed.is_set()


def test_unconfirmed_wait_fails_and_force_removes(
    client: ProxyClient, docker: FakeDocker, artifact_dir: Path
) -> None:
    docker.run = FakeRun(chunks=[frame(1, b"x")])
    docker.wait_status = 404

    with pytest.raises(SandboxRunFailed):
        run(client, artifact_dir)

    assert saw(docker, "DELETE", f"/containers/{CREATED}")


def test_failed_kill_falls_back_to_a_forced_remove(
    client: ProxyClient, docker: FakeDocker, artifact_dir: Path
) -> None:
    class KillFails(ProxyClient):
        def kill(self, container_id: str) -> None:
            raise ProxyError("kill")

    docker.run = FakeRun(attach_status=500)

    with pytest.raises(SandboxRunFailed):
        run(KillFails("127.0.0.1", client._port), artifact_dir)  # pyright: ignore[reportPrivateUsage]

    assert saw(docker, "DELETE", f"/containers/{CREATED}")


def test_cleanup_failure_is_logged(
    client: ProxyClient, docker: FakeDocker, artifact_dir: Path
) -> None:
    docker.run = FakeRun(chunks=[frame(1, b"x")])
    docker.wait_status = 404
    docker.remove_status = 500

    with capture_logs() as events, pytest.raises(SandboxRunFailed):
        run(client, artifact_dir)

    failed = [event for event in events if event["event"] == "sandbox_cleanup_failed"]
    assert len(failed) == 1
    assert failed[0]["container_id"] == CREATED


# --- D. Logging and leakage guards --------------------------------------------------------------


def scripted(case: str, docker: FakeDocker) -> dict[str, Any]:
    leak = frame(1, MARKER) + frame(2, MARKER)
    if case == "clean":
        docker.run = FakeRun(chunks=[leak])
        return {}
    if case == "timeout":
        docker.run = FakeRun(chunks=[leak], hold_open=True)
        return {"wall_time": 0.3}
    if case == "cap":
        docker.run = FakeRun(chunks=[leak, frame(1, b"a" * MAX_STDOUT_BYTES)], hold_open=True)
        return {}
    docker.run = FakeRun(chunks=[leak, b"\x09\x00\x00\x00\x00\x00\x00\x01x"], hold_open=True)
    return {}


def test_run_logs_one_metadata_line(
    client: ProxyClient, docker: FakeDocker, artifact_dir: Path
) -> None:
    docker.run = FakeRun(chunks=[frame(1, b"four")], exit_code=2)

    with capture_logs() as events:
        run(client, artifact_dir)

    [event] = [event for event in events if event["event"] == "sandbox_run"]
    assert event["analyzer"] == "echo"
    assert event["runtime"] == "runsc"
    assert event["outcome"] == "exited"
    assert event["exit_code"] == 2
    assert event["stdout_bytes"] == 4
    assert isinstance(event["duration_ms"], int)


@pytest.mark.parametrize("case", ["clean", "timeout", "cap", "failure"])
def test_logs_never_contain_output_or_paths(
    case: str, client: ProxyClient, docker: FakeDocker, artifact_dir: Path
) -> None:
    options = scripted(case, docker)

    with capture_logs() as events, suppress(SandboxRunFailed):
        run(client, artifact_dir, **options)

    text = repr(events)
    assert MARKER.decode() not in text
    assert str(artifact_dir) not in text
    assert [event["event"] for event in events].count("sandbox_run") == 1


def test_failure_log_names_the_stage_and_status(
    client: ProxyClient, docker: FakeDocker, artifact_dir: Path
) -> None:
    docker.run = FakeRun(start_status=500)

    with capture_logs() as events, pytest.raises(SandboxRunFailed):
        run(client, artifact_dir)

    [event] = [event for event in events if event["event"] == "sandbox_run"]
    assert (event["outcome"], event["stage"], event["status"]) == ("failed", "start", 500)


def test_outcome_repr_hides_stdout() -> None:
    outcome = RunOutcome(0, MARKER, False, False)

    assert MARKER.decode() not in repr(outcome)
