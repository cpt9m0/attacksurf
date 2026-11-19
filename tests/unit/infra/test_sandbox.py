"""The worker's launcher client: a fixed request out, a strict bounded reply in, nothing echoed."""

import base64
import gzip
import json
import socket
import threading
from collections.abc import Callable, Iterator
from pathlib import Path
from typing import Any
from uuid import UUID

import httpx
import pytest
from structlog.testing import capture_logs

from attacksurf.domain.jobs import JobError, TransientJobError
from attacksurf.domain.sandbox import SandboxError, SandboxResult, SandboxRunner
from attacksurf.domain.scanners import MAX_OUTPUT_BYTES
from attacksurf.infra.sandbox import (
    CONNECT_TIMEOUT_SECONDS,
    MAX_REPLY_BYTES,
    LauncherSandboxRunner,
)
from attacksurf.sandbox_launcher.catalog import Analyzer
from attacksurf.sandbox_launcher.runner import RunOutcome
from attacksurf.sandbox_launcher.server import make_server
from tests.docker_fakes import serving
from tests.unit.sandbox_launcher.test_container import analyzer as launcher_analyzer

ARTIFACT_ID = UUID("11111111-1111-4111-8111-111111111111")
BASE_URL = "http://launcher:8791"
MARKER = "hunter2"

Handler = Callable[[httpx.Request], httpx.Response]


def launcher_reply(
    exit_code: Any = 0,
    stdout: bytes = b"",
    timed_out: Any = False,
    output_exceeded: Any = False,
) -> bytes:
    """A well-formed 200 body, encoded the way the launcher encodes it."""
    return json.dumps(
        {
            "exit_code": exit_code,
            "stdout_b64": base64.b64encode(stdout).decode("ascii"),
            "timed_out": timed_out,
            "output_exceeded": output_exceeded,
        }
    ).encode()


def streamed(status: int, body: bytes, headers: dict[str, str] | None = None) -> httpx.Response:
    """A reply whose body is still on the wire, as a real one is. `content=` would read it
    eagerly, which hides what the client does with the stream."""
    return httpx.Response(status, headers=headers, stream=httpx.ByteStream(body))


def reply_with(body: bytes, status: int = 200) -> Handler:
    def handler(request: httpx.Request) -> httpx.Response:
        return streamed(status, body)

    return handler


def runner_with(handler: Handler, base_url: str = BASE_URL) -> LauncherSandboxRunner:
    return LauncherSandboxRunner(base_url, transport=httpx.MockTransport(handler))


def run_with(handler: Handler) -> SandboxResult:
    return runner_with(handler).run("echo", ARTIFACT_ID)


# --- A. Happy path ---------------------------------------------------------------------------


def test_runner_satisfies_the_sandbox_port() -> None:
    runner: SandboxRunner = runner_with(reply_with(launcher_reply()))

    assert isinstance(runner, LauncherSandboxRunner)


def test_run_sends_exactly_the_analyzer_and_artifact_id() -> None:
    seen: list[httpx.Request] = []

    def handler(request: httpx.Request) -> httpx.Response:
        seen.append(request)
        return streamed(200, launcher_reply())

    run_with(handler)

    [request] = seen
    assert request.method == "POST"
    assert str(request.url) == "http://launcher:8791/runs"
    assert request.headers["Content-Type"] == "application/json"
    assert request.headers["Accept-Encoding"] == "identity"
    assert json.loads(request.content) == {"analyzer": "echo", "artifact_id": str(ARTIFACT_ID)}


def test_run_decodes_the_reply_into_a_result() -> None:
    result = run_with(reply_with(launcher_reply(stdout=b"\x00\xff{}")))

    assert result == SandboxResult(0, b"\x00\xff{}", False, False)


def test_nonzero_exit_code_is_returned() -> None:
    result = run_with(reply_with(launcher_reply(exit_code=3, stdout=b"oops")))

    assert result.exit_code == 3
    assert result.stdout == b"oops"


def test_timed_out_run_is_returned_not_raised() -> None:
    result = run_with(reply_with(launcher_reply(exit_code=None, timed_out=True)))

    assert result == SandboxResult(None, b"", timed_out=True, output_exceeded=False)


def test_output_exceeded_run_is_returned_not_raised() -> None:
    result = run_with(reply_with(launcher_reply(exit_code=None, output_exceeded=True)))

    assert result == SandboxResult(None, b"", timed_out=False, output_exceeded=True)


def test_base_url_with_trailing_slash_posts_to_runs() -> None:
    paths: list[str] = []

    def handler(request: httpx.Request) -> httpx.Response:
        paths.append(request.url.path)
        return streamed(200, launcher_reply())

    runner_with(handler, base_url="http://launcher:8791/").run("echo", ARTIFACT_ID)

    assert paths == ["/runs"]


def test_result_repr_hides_stdout() -> None:
    result = run_with(reply_with(launcher_reply(stdout=MARKER.encode())))

    assert MARKER not in repr(result)


def test_client_ignores_the_environment_and_redirects() -> None:
    client = runner_with(reply_with(launcher_reply()))._client

    assert client.trust_env is False
    assert client.follow_redirects is False
    assert client.timeout == httpx.Timeout(900.0, connect=CONNECT_TIMEOUT_SECONDS)


def test_custom_timeout_keeps_the_short_connect_timeout() -> None:
    runner = LauncherSandboxRunner(BASE_URL, timeout_seconds=60.0)

    assert runner._client.timeout == httpx.Timeout(60.0, connect=CONNECT_TIMEOUT_SECONDS)


# --- B. Boundary cases -----------------------------------------------------------------------


def test_stdout_at_the_output_cap_is_accepted() -> None:
    stdout = b"\xff" * MAX_OUTPUT_BYTES

    result = run_with(reply_with(launcher_reply(stdout=stdout)))

    assert len(result.stdout) == MAX_OUTPUT_BYTES


def test_reply_at_the_reply_cap_is_accepted() -> None:
    body = launcher_reply(stdout=b"ok")
    padded = body + b" " * (MAX_REPLY_BYTES - len(body))

    result = run_with(reply_with(padded))

    assert len(padded) == MAX_REPLY_BYTES
    assert result.stdout == b"ok"


def test_empty_stdout_is_accepted() -> None:
    result = run_with(reply_with(launcher_reply(stdout=b"")))

    assert result.stdout == b""


@pytest.mark.parametrize("exit_code", [0, 1, 137, 255])
def test_exit_codes_at_the_edges_are_kept(exit_code: int) -> None:
    result = run_with(reply_with(launcher_reply(exit_code=exit_code)))

    assert result.exit_code == exit_code


def test_reply_without_content_length_is_still_capped() -> None:
    chunk = b" " * 65536
    sent = 0

    def endless() -> Iterator[bytes]:
        nonlocal sent
        while True:
            sent += len(chunk)
            yield chunk

    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, content=endless())

    with pytest.raises(SandboxError):
        run_with(handler)

    assert sent <= MAX_REPLY_BYTES + 1 + len(chunk)


def test_reply_that_lies_about_its_length_is_still_capped() -> None:
    body = launcher_reply() + b" " * MAX_REPLY_BYTES

    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, headers={"Content-Length": "10"}, stream=_Chunks([body]))

    with pytest.raises(SandboxError):
        run_with(handler)


# --- C. Invalid inputs and replies -----------------------------------------------------------


class _Chunks(httpx.SyncByteStream):
    """A response body that records whether anyone read it."""

    def __init__(self, chunks: list[bytes]) -> None:
        self.chunks = chunks
        self.read = False

    def __iter__(self) -> Iterator[bytes]:
        self.read = True
        yield from self.chunks


@pytest.mark.parametrize("message", ["Sandbox is busy.", "Sandbox run failed."])
def test_retryable_statuses_raise_transient(message: str) -> None:
    body = json.dumps({"message": message}).encode()

    with pytest.raises(TransientJobError) as caught:
        run_with(reply_with(body, status=503))

    assert str(caught.value) == "The sandbox is busy; the run will be retried."


@pytest.mark.parametrize("status", [301, 302, 400, 404, 405, 418, 500, 502])
def test_other_statuses_raise_sandbox_error(status: int) -> None:
    body = json.dumps({"message": "Analyzer or artifact not found."}).encode()

    with pytest.raises(SandboxError) as caught:
        run_with(reply_with(body, status=status))

    assert not isinstance(caught.value, TransientJobError)
    assert str(caught.value) == "The sandbox run failed."


@pytest.mark.parametrize(
    "error",
    [
        httpx.ConnectError("refused"),
        httpx.ReadTimeout("slow"),
        httpx.RemoteProtocolError("reset"),
    ],
)
def test_transport_failures_raise_transient(error: httpx.TransportError) -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        raise error

    with pytest.raises(TransientJobError) as caught:
        run_with(handler)

    assert str(caught.value) == "The sandbox could not be reached; the run will be retried."


def test_transport_failure_while_reading_the_reply_is_transient() -> None:
    def broken() -> Iterator[bytes]:
        yield b'{"exit_code": 0'
        raise httpx.ReadError("connection reset")

    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, content=broken())

    with pytest.raises(TransientJobError):
        run_with(handler)


def _reply_dict(**overrides: Any) -> bytes:
    body: dict[str, Any] = json.loads(launcher_reply(stdout=b"ok"))
    body.update(overrides)
    return json.dumps(body).encode()


def _without(key: str) -> bytes:
    body: dict[str, Any] = json.loads(launcher_reply())
    del body[key]
    return json.dumps(body).encode()


MALFORMED_REPLIES = {
    "not json": b"not json",
    "not utf-8": b"\xff\xfe\x00",
    "array": b"[]",
    "missing key": _without("timed_out"),
    "extra key": _reply_dict(message="hi"),
    "duplicate key": launcher_reply()[:-1] + b', "timed_out": true}',
    "exit_code string": _reply_dict(exit_code="0"),
    "exit_code bool": _reply_dict(exit_code=True),
    "exit_code float": _reply_dict(exit_code=1.0),
    "timed_out string": _reply_dict(timed_out="false"),
    "timed_out int": _reply_dict(timed_out=0),
    "output_exceeded null": _reply_dict(output_exceeded=None),
    "stdout_b64 null": _reply_dict(stdout_b64=None),
    "bad base64": _reply_dict(stdout_b64="@@"),
    "base64 without padding": _reply_dict(stdout_b64="aGk"),
    "non-ascii base64": _reply_dict(stdout_b64="aGké"),
    "deeply nested": b'{"exit_code": ' + b"[" * 100000 + b"]" * 100000 + b"}",
    "compressed": gzip.compress(launcher_reply()),
}


@pytest.mark.parametrize("body", MALFORMED_REPLIES.values(), ids=MALFORMED_REPLIES.keys())
def test_malformed_replies_raise_sandbox_error(body: bytes) -> None:
    with pytest.raises(SandboxError) as caught:
        run_with(reply_with(body))

    assert str(caught.value) == "The sandbox returned an invalid reply."


def test_compressed_reply_is_never_inflated() -> None:
    body = gzip.compress(launcher_reply())

    def handler(request: httpx.Request) -> httpx.Response:
        return streamed(200, body, {"Content-Encoding": "gzip"})

    with pytest.raises(SandboxError):
        run_with(handler)


def test_decoded_stdout_over_the_cap_is_refused() -> None:
    body = launcher_reply(stdout=b"\xff" * (MAX_OUTPUT_BYTES + 1))
    assert len(body) <= MAX_REPLY_BYTES

    with pytest.raises(SandboxError):
        run_with(reply_with(body))


def test_oversized_content_length_is_refused_unread() -> None:
    stream = _Chunks([launcher_reply()])

    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(
            200, headers={"Content-Length": str(MAX_REPLY_BYTES + 1)}, stream=stream
        )

    with pytest.raises(SandboxError):
        run_with(handler)

    assert stream.read is False


@pytest.mark.parametrize("length", ["lots", "-1", ""])
def test_unparseable_content_length_is_refused(length: str) -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, headers={"Content-Length": length}, stream=_Chunks([b"{}"]))

    with pytest.raises(SandboxError):
        run_with(handler)


@pytest.mark.parametrize(
    "url",
    [
        "https://l:1",
        "http://",
        "http://u:p@l:1",
        "http://u@l:1",
        "http://l:1/api",
        "http://l:1?x=1",
        "http://l:1#f",
        "l:1",
        "http://l:99999",
        "http://[::1",
    ],
)
def test_invalid_base_urls_are_refused(url: str) -> None:
    with pytest.raises(
        ValueError, match=r"^the sandbox launcher URL must be http://host\[:port\] only$"
    ):
        LauncherSandboxRunner(url)


@pytest.mark.parametrize("url", ["http://launcher", "http://launcher:8791/", "http://[::1]:8791"])
def test_plain_base_urls_are_accepted(url: str) -> None:
    LauncherSandboxRunner(url)


ECHO_CASES = {
    "busy": (503, json.dumps({"message": MARKER}).encode()),
    "not found": (404, json.dumps({"message": MARKER}).encode()),
    "internal": (500, MARKER.encode()),
    "malformed": (200, json.dumps({"message": MARKER}).encode()),
    "bad stdout": (200, _reply_dict(stdout_b64=MARKER)),
}


@pytest.mark.parametrize(("status", "body"), ECHO_CASES.values(), ids=ECHO_CASES.keys())
def test_errors_never_echo_the_reply(status: int, body: bytes) -> None:
    with capture_logs() as logs, pytest.raises(JobError) as caught:
        run_with(reply_with(body, status=status))

    assert MARKER not in str(caught.value)
    assert MARKER not in repr(logs)
    assert logs == [
        {
            "event": "sandbox_client_error",
            "log_level": "warning",
            "analyzer": "echo",
            "status": status,
        }
    ]


def test_transport_errors_never_echo_the_cause() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        raise httpx.ConnectError(MARKER)

    with capture_logs() as logs, pytest.raises(TransientJobError) as caught:
        run_with(handler)

    assert MARKER not in str(caught.value)
    assert caught.value.__cause__ is None
    assert logs == [
        {
            "event": "sandbox_client_error",
            "log_level": "warning",
            "analyzer": "echo",
            "error_type": "ConnectError",
        }
    ]


def test_logs_never_carry_the_artifact_id() -> None:
    with capture_logs() as logs, pytest.raises(SandboxError):
        run_with(reply_with(b"{}", status=404))

    assert str(ARTIFACT_ID) not in repr(logs)


def test_invalid_url_errors_never_echo_the_url() -> None:
    with pytest.raises(ValueError, match="must be http") as caught:
        LauncherSandboxRunner(f"http://user:{MARKER}@launcher:8791")

    assert MARKER not in str(caught.value)


def test_successful_run_logs_nothing() -> None:
    with capture_logs() as logs:
        run_with(reply_with(launcher_reply()))

    assert logs == []


# --- D. Neighbor contract and drift guards ---------------------------------------------------


class ScriptedRun:
    """Stands in for `run_sandbox` behind the real launcher server."""

    def __init__(self, outcome: RunOutcome) -> None:
        self.outcome = outcome
        self.calls: list[tuple[Analyzer, Path]] = []
        self.entered = threading.Event()
        self.release: threading.Event | None = None

    def __call__(self, tool: Analyzer, artifact_dir: Path) -> RunOutcome:
        self.calls.append((tool, artifact_dir))
        self.entered.set()
        if self.release is not None:
            assert self.release.wait(5)
        return self.outcome


@pytest.fixture
def scripted() -> ScriptedRun:
    return ScriptedRun(RunOutcome(3, b"\x00\xff not utf-8 \x80", False, False))


@pytest.fixture
def launcher_url(scripted: ScriptedRun, tmp_path: Path) -> Iterator[str]:
    root = tmp_path / "artifacts"
    (root / str(ARTIFACT_ID)).mkdir(parents=True)
    server = make_server(
        "127.0.0.1",
        0,
        catalog={"echo": launcher_analyzer()},
        artifact_root=root,
        run=scripted,
        max_concurrent_runs=1,
    )
    with serving(server):
        yield f"http://127.0.0.1:{server.server_address[1]}"


def test_round_trip_against_the_real_launcher_server(
    launcher_url: str, scripted: ScriptedRun
) -> None:
    result = LauncherSandboxRunner(launcher_url).run("echo", ARTIFACT_ID)

    assert result == SandboxResult(
        scripted.outcome.exit_code,
        scripted.outcome.stdout,
        scripted.outcome.timed_out,
        scripted.outcome.output_exceeded,
    )
    [(tool, artifact_dir)] = scripted.calls
    assert tool.spec.name == "echo"
    assert artifact_dir.name == str(ARTIFACT_ID)


def test_round_trip_of_a_killed_run(launcher_url: str, scripted: ScriptedRun) -> None:
    scripted.outcome = RunOutcome(None, b"", timed_out=True)

    result = LauncherSandboxRunner(launcher_url).run("echo", ARTIFACT_ID)

    assert result == SandboxResult(None, b"", timed_out=True, output_exceeded=False)


def test_real_launcher_unknown_analyzer_is_sandbox_error(launcher_url: str) -> None:
    with pytest.raises(SandboxError) as caught:
        LauncherSandboxRunner(launcher_url).run("missing", ARTIFACT_ID)

    assert not isinstance(caught.value, TransientJobError)


def test_real_launcher_unknown_artifact_is_sandbox_error(launcher_url: str) -> None:
    other = UUID("22222222-2222-4222-8222-222222222222")

    with pytest.raises(SandboxError) as caught:
        LauncherSandboxRunner(launcher_url).run("echo", other)

    assert not isinstance(caught.value, TransientJobError)


def test_real_launcher_busy_is_transient(launcher_url: str, scripted: ScriptedRun) -> None:
    scripted.release = threading.Event()
    first = threading.Thread(
        target=LauncherSandboxRunner(launcher_url).run, args=("echo", ARTIFACT_ID), daemon=True
    )
    first.start()
    assert scripted.entered.wait(5)

    try:
        with pytest.raises(TransientJobError):
            LauncherSandboxRunner(launcher_url).run("echo", ARTIFACT_ID)
    finally:
        scripted.release.set()
        first.join(5)

    assert not first.is_alive()


def test_proxy_environment_is_ignored(launcher_url: str, monkeypatch: pytest.MonkeyPatch) -> None:
    dead = _closed_port()
    for name in ("HTTP_PROXY", "http_proxy", "ALL_PROXY", "all_proxy"):
        monkeypatch.setenv(name, f"http://127.0.0.1:{dead}")
    monkeypatch.delenv("NO_PROXY", raising=False)
    monkeypatch.delenv("no_proxy", raising=False)

    result = LauncherSandboxRunner(launcher_url).run("echo", ARTIFACT_ID)

    assert result.exit_code == 3


def _closed_port() -> int:
    with socket.socket() as probe:
        probe.bind(("127.0.0.1", 0))
        return probe.getsockname()[1]


def test_closed_port_is_transient() -> None:
    url = f"http://127.0.0.1:{_closed_port()}"

    with pytest.raises(TransientJobError):
        LauncherSandboxRunner(url).run("echo", ARTIFACT_ID)


def test_reply_cap_fits_the_largest_launcher_reply() -> None:
    largest = launcher_reply(exit_code=255, stdout=b"\xff" * MAX_OUTPUT_BYTES)

    assert len(largest) < MAX_REPLY_BYTES


def test_redirects_are_not_followed() -> None:
    seen: list[str] = []

    def handler(request: httpx.Request) -> httpx.Response:
        seen.append(request.url.path)
        if request.url.path == "/runs":
            return httpx.Response(302, headers={"Location": "/elsewhere"})
        return streamed(200, launcher_reply())

    with pytest.raises(SandboxError):
        run_with(handler)

    assert seen == ["/runs"]
