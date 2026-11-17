"""The launcher API: a fixed two-field request in, a bounded reply out, nothing echoed."""

import base64
import http.client
import json
import socket
import threading
from collections.abc import Iterator
from pathlib import Path

import pytest
from structlog.testing import capture_logs

from attacksurf.sandbox_launcher.catalog import Analyzer
from attacksurf.sandbox_launcher.proxy import ProxyClient
from attacksurf.sandbox_launcher.runner import RunOutcome, SandboxRunFailed, run_sandbox
from attacksurf.sandbox_launcher.server import (
    CLIENT_TIMEOUT_SECONDS,
    MAX_REQUEST_BYTES,
    make_server,
)
from tests.docker_fakes import FakeDocker, FakeRun, serving
from tests.unit.sandbox_launcher.test_container import analyzer

ARTIFACT_ID = "11111111-1111-4111-8111-111111111111"
LETTERED_ID = "abcdefab-abcd-4abc-8abc-abcdefabcdef"
OTHER_ID = "22222222-2222-4222-8222-222222222222"
MARKER = "REQUEST-MARKER-84be"
STDOUT_MARKER = b"TOOL-OUTPUT-MARKER-7c1d"


class FakeRunner:
    """Stands in for `run_sandbox`: records calls, and can block, fail or script an outcome."""

    def __init__(self) -> None:
        self.calls: list[tuple[Analyzer, Path]] = []
        self.outcome = RunOutcome(0, b"hello", False, False)
        self.error: Exception | None = None
        self.entered = threading.Event()
        self.release: threading.Event | None = None

    def __call__(self, tool: Analyzer, artifact_dir: Path) -> RunOutcome:
        self.calls.append((tool, artifact_dir))
        self.entered.set()
        if self.release is not None:
            assert self.release.wait(5)
        if self.error is not None:
            raise self.error
        return self.outcome


@pytest.fixture
def runner() -> FakeRunner:
    return FakeRunner()


@pytest.fixture
def root(tmp_path: Path) -> Path:
    path = tmp_path / "artifacts"
    (path / ARTIFACT_ID).mkdir(parents=True)
    return path


@pytest.fixture
def port(runner: FakeRunner, root: Path) -> Iterator[int]:
    server = make_server(
        "127.0.0.1",
        0,
        catalog={"echo": analyzer()},
        artifact_root=root,
        run=runner,
        max_concurrent_runs=1,
    )
    with serving(server):
        yield server.server_address[1]


def call(
    port: int,
    method: str,
    target: str,
    body: bytes | None = None,
    headers: dict[str, str] | None = None,
) -> tuple[int, bytes]:
    connection = http.client.HTTPConnection("127.0.0.1", port, timeout=10)
    try:
        connection.request(method, target, body=body, headers=headers or {})
        response = connection.getresponse()
        return response.status, response.read()
    finally:
        connection.close()


def request_body(analyzer_name: str = "echo", artifact_id: str = ARTIFACT_ID) -> bytes:
    return json.dumps({"analyzer": analyzer_name, "artifact_id": artifact_id}).encode()


def post_run(port: int, body: bytes | None = None, content_type: str = "application/json"):
    return call(
        port,
        "POST",
        "/runs",
        request_body() if body is None else body,
        {"Content-Type": content_type},
    )


def raw(port: int, request: bytes) -> int:
    with socket.create_connection(("127.0.0.1", port), timeout=10) as sock:
        sock.sendall(request)
        return int(sock.recv(4096).split(b" ", 2)[1])


# --- A. Happy path ------------------------------------------------------------------------------


def test_healthz_is_ok(port: int, runner: FakeRunner) -> None:
    status, body = call(port, "GET", "/healthz")

    assert (status, json.loads(body)) == (200, {"status": "ok"})
    assert runner.calls == []


def test_run_returns_the_outcome(port: int) -> None:
    status, body = post_run(port)

    assert status == 200
    assert json.loads(body) == {
        "exit_code": 0,
        "stdout_b64": base64.b64encode(b"hello").decode(),
        "timed_out": False,
        "output_exceeded": False,
    }


def test_run_passes_the_catalog_analyzer_and_resolved_dir(
    port: int, runner: FakeRunner, root: Path
) -> None:
    post_run(port)

    assert runner.calls == [(analyzer(), root / ARTIFACT_ID)]


def test_killed_run_reports_null_exit_code(port: int, runner: FakeRunner) -> None:
    runner.outcome = RunOutcome(None, b"", timed_out=True)

    status, body = post_run(port)

    assert status == 200
    assert json.loads(body) == {
        "exit_code": None,
        "stdout_b64": "",
        "timed_out": True,
        "output_exceeded": False,
    }


def test_full_round_trip_through_the_proxy(
    proxy_port: int, docker: FakeDocker, artifact_dir: Path
) -> None:
    docker.run = FakeRun(chunks=[b"\x01\x00\x00\x00\x00\x00\x00\x05world"])
    client = ProxyClient("127.0.0.1", proxy_port)

    def run(tool: Analyzer, directory: Path) -> RunOutcome:
        return run_sandbox(client, tool, directory, runtime="runsc", wall_time=5)

    server = make_server(
        "127.0.0.1",
        0,
        catalog={"echo": analyzer()},
        artifact_root=artifact_dir.parent,
        run=run,
        max_concurrent_runs=1,
    )
    with serving(server):
        status, body = post_run(server.server_address[1])

    assert status == 200
    assert base64.b64decode(json.loads(body)["stdout_b64"]) == b"world"


# --- B. Boundary cases --------------------------------------------------------------------------


def test_request_at_the_size_limit_is_accepted(port: int) -> None:
    body = request_body()
    padded = body + b" " * (MAX_REQUEST_BYTES - len(body))

    assert len(padded) == MAX_REQUEST_BYTES
    assert post_run(port, padded)[0] == 200


def test_slot_is_released_after_a_failure(port: int, runner: FakeRunner) -> None:
    runner.error = SandboxRunFailed()
    assert post_run(port)[0] == 503
    runner.error = KeyError("boom")
    assert post_run(port)[0] == 500
    runner.error = None

    assert post_run(port)[0] == 200


def test_busy_reply_when_all_slots_are_taken(port: int, runner: FakeRunner) -> None:
    runner.release = threading.Event()
    first: list[tuple[int, bytes]] = []
    thread = threading.Thread(target=lambda: first.append(post_run(port)))
    thread.start()
    assert runner.entered.wait(5)

    status, body = post_run(port)
    runner.release.set()
    thread.join(5)

    assert (status, json.loads(body)) == (503, {"message": "Sandbox is busy."})
    assert first[0][0] == 200
    assert post_run(port)[0] == 200


def test_bad_requests_do_not_take_a_slot(port: int, runner: FakeRunner) -> None:
    runner.release = threading.Event()
    thread = threading.Thread(target=lambda: post_run(port))
    thread.start()
    assert runner.entered.wait(5)
    try:
        # A malformed request is refused as malformed, not as busy.
        assert post_run(port, b"nope")[0] == 400
        assert post_run(port, request_body("nope-tool"))[0] == 404
    finally:
        runner.release.set()
        thread.join(5)


# --- C. Invalid inputs --------------------------------------------------------------------------

DUPLICATE = f'{{"analyzer": "echo", "analyzer": "echo", "artifact_id": "{ARTIFACT_ID}"}}'.encode()


@pytest.mark.parametrize(
    ("body", "content_type"),
    [
        (b"nope", "application/json"),
        (b"[]", "application/json"),
        (b'{"analyzer": "echo"}', "application/json"),
        (
            json.dumps({"analyzer": "echo", "artifact_id": ARTIFACT_ID, "image": "x"}).encode(),
            "application/json",
        ),
        (DUPLICATE, "application/json"),
        (b'{"analyzer": 1, "artifact_id": 2}', "application/json"),
        (request_body("Echo!"), "application/json"),
        (request_body("../etc"), "application/json"),
        (request_body(artifact_id=LETTERED_ID.upper()), "application/json"),
        (request_body(artifact_id=ARTIFACT_ID.replace("-", "")), "application/json"),
        (request_body(artifact_id="{" + ARTIFACT_ID + "}"), "application/json"),
        (request_body(artifact_id="urn:uuid:" + ARTIFACT_ID), "application/json"),
        (request_body(), "text/plain"),
        (request_body(), "application/x-www-form-urlencoded"),
        (b"", "application/json"),
        (request_body() + b" " * (MAX_REQUEST_BYTES + 1), "application/json"),
    ],
)
def test_malformed_run_requests_are_rejected(
    port: int, runner: FakeRunner, body: bytes, content_type: str
) -> None:
    status, reply = post_run(port, body, content_type)

    assert (status, json.loads(reply)) == (400, {"message": "Request is malformed."})
    assert runner.calls == []


def test_missing_content_length_is_rejected(port: int, runner: FakeRunner) -> None:
    request = b"POST /runs HTTP/1.0\r\nContent-Type: application/json\r\n\r\n"

    assert raw(port, request) == 400
    assert runner.calls == []


def test_chunked_requests_are_rejected(port: int, runner: FakeRunner) -> None:
    body = request_body()
    request = (
        b"POST /runs HTTP/1.1\r\nContent-Type: application/json\r\n"
        b"Transfer-Encoding: chunked\r\n\r\n"
        + f"{len(body):x}\r\n".encode()
        + body
        + b"\r\n0\r\n\r\n"
    )

    assert raw(port, request) == 400
    assert runner.calls == []


def test_oversized_body_is_not_read(port: int, runner: FakeRunner) -> None:
    request = (
        b"POST /runs HTTP/1.0\r\nContent-Type: application/json\r\n"
        + f"Content-Length: {MAX_REQUEST_BYTES + 1}\r\n\r\n".encode()
    )

    assert raw(port, request) == 400  # answered before any body byte was sent


@pytest.mark.parametrize(
    "body",
    [
        request_body("nope-tool"),
        request_body(artifact_id=OTHER_ID),
    ],
)
def test_unknown_analyzer_and_artifact_share_one_404(
    port: int, runner: FakeRunner, body: bytes
) -> None:
    status, reply = post_run(port, body)

    assert (status, json.loads(reply)) == (404, {"message": "Analyzer or artifact not found."})
    assert runner.calls == []


def test_symlinked_artifact_gets_the_same_404(port: int, runner: FakeRunner, root: Path) -> None:
    (root / OTHER_ID).symlink_to(root / ARTIFACT_ID)

    status, reply = post_run(port, request_body(artifact_id=OTHER_ID))

    assert (status, json.loads(reply)) == (404, {"message": "Analyzer or artifact not found."})
    assert runner.calls == []


@pytest.mark.parametrize("target", ["/", "/runs/", "/runs?x=1", "/healthz/x", "/healthz?x=1"])
def test_unknown_paths_are_404(port: int, target: str) -> None:
    assert call(port, "GET", target)[0] == 404
    assert call(port, "POST", target, b"{}", {"Content-Type": "application/json"})[0] == 404


@pytest.mark.parametrize(
    ("method", "target"),
    [
        ("GET", "/runs"),
        ("POST", "/healthz"),
        ("PUT", "/runs"),
        ("PATCH", "/runs"),
        ("DELETE", "/runs"),
        ("OPTIONS", "/runs"),
        ("HEAD", "/healthz"),
        ("PUT", "/healthz"),
    ],
)
def test_wrong_methods_are_405(port: int, runner: FakeRunner, method: str, target: str) -> None:
    status, reply = call(port, method, target)

    assert status == 405
    assert method == "HEAD" or json.loads(reply) == {"message": "Method not allowed."}
    assert runner.calls == []


def test_run_failure_is_503(port: int, runner: FakeRunner) -> None:
    runner.error = SandboxRunFailed()

    status, reply = post_run(port)

    assert (status, json.loads(reply)) == (503, {"message": "Sandbox run failed."})


def test_unexpected_error_is_500_and_logged_by_type(port: int, runner: FakeRunner) -> None:
    runner.error = KeyError("secret-value")

    with capture_logs() as events:
        status, reply = post_run(port)

    assert (status, json.loads(reply)) == (500, {"message": "Internal error."})
    [event] = [event for event in events if event["event"] == "sandbox_launcher_error"]
    assert event["error_type"] == "KeyError"
    assert "secret-value" not in repr(events) + reply.decode()


def test_client_timeout_is_set() -> None:
    assert CLIENT_TIMEOUT_SECONDS == 30


# --- D. Leakage guards --------------------------------------------------------------------------


@pytest.mark.parametrize(
    "body",
    [
        json.dumps({"analyzer": "echo", "artifact_id": ARTIFACT_ID, MARKER: MARKER}).encode(),
        json.dumps({"analyzer": MARKER, "artifact_id": ARTIFACT_ID}).encode(),
        json.dumps({"analyzer": "echo", "artifact_id": MARKER}).encode(),
        request_body("marker-tool"),
        request_body(artifact_id="33333333-3333-4333-8333-333333333333"),
    ],
)
def test_rejections_never_echo_the_request(port: int, body: bytes) -> None:
    with capture_logs() as events:
        status, reply = post_run(port, body)

    assert status in (400, 404)
    for value in (MARKER, "marker-tool", "33333333"):
        assert value not in reply.decode() + repr(events)
    assert any(event["event"] == "sandbox_launcher_rejected" for event in events)


def test_success_logs_never_contain_stdout(port: int, runner: FakeRunner) -> None:
    runner.outcome = RunOutcome(0, STDOUT_MARKER)

    with capture_logs() as events:
        post_run(port)

    assert STDOUT_MARKER.decode() not in repr(events)
