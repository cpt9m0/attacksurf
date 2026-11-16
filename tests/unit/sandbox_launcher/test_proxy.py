"""The proxy client: exact wire calls, strict replies, fixed error text."""

import re
import socket
import socketserver
import threading
from collections.abc import Iterator
from pathlib import Path

import pytest

from attacksurf.sandbox_launcher.container import build_create_body
from attacksurf.sandbox_launcher.proxy import ProxyClient, ProxyError
from tests.docker_fakes import CREATED, FakeDocker, FakeRun, serving
from tests.unit.sandbox_launcher.test_container import analyzer

MARKER = "REPLY-MARKER-31c7"


class _Stub(socketserver.ThreadingTCPServer):
    """A TCP server that answers every request with fixed raw bytes."""

    daemon_threads = True
    allow_reuse_address = True

    def __init__(self, reply: bytes) -> None:
        super().__init__(("127.0.0.1", 0), _StubHandler)
        self.reply = reply


class _StubHandler(socketserver.BaseRequestHandler):
    server: _Stub  # type: ignore[assignment]

    def handle(self) -> None:
        data = b""
        while b"\r\n\r\n" not in data:
            chunk = self.request.recv(4096)
            if not chunk:
                return
            data += chunk
        self.request.sendall(self.server.reply)


def http_reply(status: int, body: bytes) -> bytes:
    head = f"HTTP/1.1 {status} X\r\nContent-Length: {len(body)}\r\nConnection: close\r\n\r\n"
    return head.encode() + body


@pytest.fixture
def stub_client(request: pytest.FixtureRequest) -> Iterator[ProxyClient]:
    with serving(_Stub(request.param)) as server:
        yield ProxyClient("127.0.0.1", server.server_address[1])


def methods_and_paths(docker: FakeDocker) -> list[tuple[str, str]]:
    return [(method, path) for method, path, _, _ in docker.calls]


# --- A. Happy path ------------------------------------------------------------------------------


def test_runtimes_returns_the_proxy_names(client: ProxyClient) -> None:
    assert client.runtimes() == ["io.containerd.runc.v2", "runc", "runsc"]


@pytest.mark.parametrize(
    ("url", "host", "port"),
    [("http://h:1", "h", 1), ("http://h", "h", 80), ("http://h:1/", "h", 1)],
)
def test_from_url_uses_host_and_port(url: str, host: str, port: int) -> None:
    client = ProxyClient.from_url(url)

    assert (client._host, client._port) == (host, port)  # pyright: ignore[reportPrivateUsage]


def test_calls_use_the_exact_wire_targets(
    client: ProxyClient, docker: FakeDocker, artifact_dir: Path
) -> None:
    docker.run = FakeRun(chunks=[b"x"])
    body = build_create_body(analyzer(), artifact_dir, "runsc")

    container_id = client.create(body)
    sock, _ = client.attach(container_id)
    sock.close()
    client.start(container_id)
    assert client.wait_removed(container_id, 5) == 0

    assert container_id == CREATED
    assert methods_and_paths(docker)[0] == ("POST", "/containers/create?name=" + _name(docker))
    assert [call for call in methods_and_paths(docker)[1:] if "wait" not in call[1]] == [
        ("POST", f"/containers/{CREATED}/attach?stdout=1&stream=1"),
        ("POST", f"/containers/{CREATED}/start"),
    ]
    assert ("POST", f"/containers/{CREATED}/wait?condition=removed") in methods_and_paths(docker)


def _name(docker: FakeDocker) -> str:
    return docker.calls[0][1].split("name=", 1)[1]


def test_remove_sends_a_forced_delete(
    client: ProxyClient, docker: FakeDocker, artifact_dir: Path
) -> None:
    docker.run = FakeRun()
    container_id = client.create(build_create_body(analyzer(), artifact_dir, "runsc"))

    assert client.remove(container_id) is True

    assert ("DELETE", f"/containers/{CREATED}?force=1") in methods_and_paths(docker)


def test_kill_sends_sigkill(client: ProxyClient, docker: FakeDocker, artifact_dir: Path) -> None:
    docker.run = FakeRun()
    container_id = client.create(build_create_body(analyzer(), artifact_dir, "runsc"))

    client.kill(container_id)

    assert ("POST", f"/containers/{CREATED}/kill?signal=SIGKILL") in methods_and_paths(docker)


def test_attach_returns_bytes_that_followed_the_head(
    client: ProxyClient, docker: FakeDocker, artifact_dir: Path
) -> None:
    docker.run = FakeRun(chunks=[b"frame-bytes"])
    container_id = client.create(build_create_body(analyzer(), artifact_dir, "runsc"))
    sock, first = client.attach(container_id)
    with sock:
        client.start(container_id)
        sock.settimeout(5)
        data = first
        while len(data) < len(b"frame-bytes"):
            data += sock.recv(64)

    assert data == b"frame-bytes"


# --- B. Boundary cases --------------------------------------------------------------------------


def test_attach_accepts_a_head_split_across_reads() -> None:
    reply = b"HTTP/1.1 101 UPGRADED\r\nUpgrade: tcp\r\n\r\nrest"
    with serving(_Stub(reply)) as server:
        client = ProxyClient("127.0.0.1", server.server_address[1])
        sock, first = client.attach(CREATED)
        sock.close()

    assert first == b"rest"


# --- C. Invalid inputs and failures -------------------------------------------------------------


@pytest.mark.parametrize(
    "url",
    [
        "http://user:pw@h:1",
        "http://h:1/path",
        "http://h:1/?q=1",
        "http://h:1/#frag",
        "https://h:1",
        "http://",
        "http://h:notaport",
        "h:1",
    ],
)
def test_from_url_refuses_extras_without_echoing_them(url: str) -> None:
    with pytest.raises(ValueError, match=re.escape("must be http://host[:port] only")) as error:
        ProxyClient.from_url(url)

    assert str(error.value) == "the sandbox proxy URL must be http://host[:port] only"


@pytest.mark.parametrize(
    ("stub_client", "call"),
    [
        (http_reply(201, b'{"Id": "short"}'), lambda c: c.create({})),
        (http_reply(201, b"not json"), lambda c: c.create({})),
        (http_reply(201, b'{"Id": 7}'), lambda c: c.create({})),
        (http_reply(403, b'{"message": "no"}'), lambda c: c.create({})),
        (http_reply(200, b'{"StatusCode": "0"}'), lambda c: c.wait_removed(CREATED, 1)),
        (http_reply(200, b'{"StatusCode": true}'), lambda c: c.wait_removed(CREATED, 1)),
        (
            http_reply(200, b'{"StatusCode": 0, "Error": {"Message": "x"}}'),
            lambda c: c.wait_removed(CREATED, 1),
        ),
        (http_reply(404, b"{}"), lambda c: c.wait_removed(CREATED, 1)),
        (http_reply(200, b'{"Runtimes": "runsc"}'), lambda c: c.runtimes()),
        (http_reply(200, b'{"Runtimes": [1]}'), lambda c: c.runtimes()),
        (http_reply(500, b"{}"), lambda c: c.runtimes()),
        (http_reply(500, b"{}"), lambda c: c.start(CREATED)),
        (http_reply(500, b"{}"), lambda c: c.kill(CREATED)),
        (b"HTTP/1.1 403 X\r\nContent-Length: 0\r\n\r\n", lambda c: c.attach(CREATED)),
        (b"garbage\r\n\r\n", lambda c: c.attach(CREATED)),
        (b"HTTP/1.1 101 X\r\n" + b"a: b\r\n" * 2000, lambda c: c.attach(CREATED)),
        (b"HTTP/1.1 101 UPGRADED\r\n", lambda c: c.attach(CREATED)),
    ],
    indirect=["stub_client"],
)
def test_malformed_replies_raise_proxy_error(stub_client: ProxyClient, call: object) -> None:
    with pytest.raises(ProxyError) as error:
        call(stub_client)  # type: ignore[operator]

    assert str(error.value) == "The sandbox proxy call failed."


@pytest.mark.parametrize("stub_client", [http_reply(500, MARKER.encode())], indirect=True)
def test_proxy_error_carries_stage_and_status_not_reply_bytes(stub_client: ProxyClient) -> None:
    with pytest.raises(ProxyError) as error:
        stub_client.start(CREATED)

    assert (error.value.stage, error.value.status) == ("start", 500)
    assert MARKER not in repr(error.value) + str(error.value.args)


@pytest.mark.parametrize(("status", "gone"), [(204, True), (404, True), (403, True), (500, False)])
def test_remove_reports_whether_the_container_is_gone(status: int, gone: bool) -> None:
    with serving(_Stub(http_reply(status, b""))) as server:
        client = ProxyClient("127.0.0.1", server.server_address[1])

        assert client.remove(CREATED) is gone


@pytest.mark.parametrize("status", [204, 403, 404, 409])
def test_kill_accepts_a_container_that_is_not_running(status: int) -> None:
    with serving(_Stub(http_reply(status, b""))) as server:
        ProxyClient("127.0.0.1", server.server_address[1]).kill(CREATED)


def test_unreachable_proxy_raises_proxy_error() -> None:
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        port = sock.getsockname()[1]

    with pytest.raises(ProxyError) as error:
        ProxyClient("127.0.0.1", port).runtimes()

    assert error.value.stage == "info"


def test_a_silent_proxy_times_out_as_proxy_error() -> None:
    release = threading.Event()

    class Silent(socketserver.BaseRequestHandler):
        def handle(self) -> None:
            release.wait(5)

    class Server(socketserver.ThreadingTCPServer):
        daemon_threads = True

    with serving(Server(("127.0.0.1", 0), Silent)) as server:
        client = ProxyClient("127.0.0.1", server.server_address[1])
        try:
            with pytest.raises(ProxyError) as error:
                client.wait_removed(CREATED, 0.2)
        finally:
            release.set()

    assert error.value.stage == "wait"
