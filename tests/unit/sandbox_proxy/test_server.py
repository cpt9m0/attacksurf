"""The proxy process: deny by default, forward only canonical requests, own containers only."""

import http.client
import json
import socketserver
import threading
from collections.abc import Iterator
from http.server import BaseHTTPRequestHandler
from pathlib import Path, PurePosixPath
from typing import Any

import pytest

from attacksurf.sandbox_proxy.policy import SandboxPolicy
from attacksurf.sandbox_proxy.server import MAX_TRACKED_CONTAINERS, make_server
from tests.unit.sandbox_proxy.test_policy import IMAGE, create_body

CREATED = "e" * 64
FOREIGN = "f" * 64


class FakeDocker(socketserver.ThreadingMixIn, socketserver.UnixStreamServer):
    daemon_threads = True

    def __init__(self, path: str) -> None:
        super().__init__(path, _FakeDockerHandler)
        self.calls: list[tuple[str, str, dict[str, str], bytes]] = []
        self.next_id = CREATED


class _FakeDockerHandler(BaseHTTPRequestHandler):
    server: FakeDocker  # type: ignore[assignment]

    def log_message(self, format: str, *args: Any) -> None:
        pass

    def _handle(self) -> None:
        length = int(self.headers.get("Content-Length", 0))
        body = self.rfile.read(length)
        self.server.calls.append((self.command, self.path, dict(self.headers), body))
        if self.path.endswith("/containers/create"):
            self._reply(201, json.dumps({"Id": self.server.next_id}).encode())
        elif "/attach" in self.path:
            self.wfile.write(b"HTTP/1.1 101 UPGRADED\r\nUpgrade: tcp\r\n\r\ntool-output")
        elif "/wait" in self.path:
            self._reply(200, b'{"StatusCode": 0}')
        else:
            self._reply(204, b"")

    do_POST = do_DELETE = _handle

    def _reply(self, status: int, body: bytes) -> None:
        self.send_response(status)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)


@pytest.fixture
def docker(tmp_path: Path) -> Iterator[FakeDocker]:
    server = FakeDocker(str(tmp_path / "d.sock"))
    thread = threading.Thread(target=server.serve_forever, args=(0.01,), daemon=True)
    thread.start()
    yield server
    server.shutdown()
    server.server_close()


@pytest.fixture
def proxy(docker: FakeDocker) -> Iterator[int]:
    policy = SandboxPolicy(
        images=frozenset({IMAGE}),
        runtimes=frozenset({"runsc"}),
        artifact_root=PurePosixPath("/srv/artifacts"),
        osv_image=None,
    )
    server = make_server("127.0.0.1", 0, policy, str(docker.server_address))
    thread = threading.Thread(target=server.serve_forever, args=(0.01,), daemon=True)
    thread.start()
    yield server.server_address[1]
    server.shutdown()
    server.server_close()


def call(
    port: int,
    method: str,
    target: str,
    body: bytes | None = None,
    headers: dict[str, str] | None = None,
) -> tuple[int, bytes]:
    connection = http.client.HTTPConnection("127.0.0.1", port, timeout=5)
    try:
        connection.request(method, target, body=body, headers=headers or {})
        response = connection.getresponse()
        return response.status, response.read()
    finally:
        connection.close()


def create(port: int) -> tuple[int, bytes]:
    return call(port, "POST", "/containers/create", json.dumps(create_body()).encode())


def test_valid_create_is_forwarded_and_returns_the_container_id(
    proxy: int, docker: FakeDocker
) -> None:
    status, body = create(proxy)

    assert status == 201
    assert json.loads(body)["Id"] == CREATED
    assert docker.calls[0][0:2] == ("POST", "/containers/create")


def test_unsafe_create_never_reaches_docker(proxy: int, docker: FakeDocker) -> None:
    unsafe = create_body()
    unsafe["HostConfig"]["Privileged"] = True

    status, _ = call(proxy, "POST", "/containers/create", json.dumps(unsafe).encode())

    assert status == 403
    assert docker.calls == []


def test_forwarded_requests_drop_client_headers(proxy: int, docker: FakeDocker) -> None:
    call(
        proxy,
        "POST",
        "/containers/create",
        json.dumps(create_body()).encode(),
        {"X-Registry-Auth": "stolen"},
    )

    assert "X-Registry-Auth" not in docker.calls[0][2]


def test_forwarded_create_body_is_the_validated_one(proxy: int, docker: FakeDocker) -> None:
    create(proxy)

    assert json.loads(docker.calls[0][3]) == create_body()


def test_duplicate_json_keys_are_rejected(proxy: int, docker: FakeDocker) -> None:
    body = json.dumps(create_body())[:-1] + ', "Image": "evil"}'

    status, _ = call(proxy, "POST", "/containers/create", body.encode())

    assert status == 403
    assert docker.calls == []


@pytest.mark.parametrize("body", [b"not json", b"[" * 60_000])
def test_invalid_json_is_rejected(proxy: int, docker: FakeDocker, body: bytes) -> None:
    status, _ = call(proxy, "POST", "/containers/create", body)

    assert status == 403
    assert docker.calls == []


def test_oversized_create_body_is_rejected_unread(proxy: int, docker: FakeDocker) -> None:
    status, _ = call(
        proxy, "POST", "/containers/create", b"x", {"Content-Length": str(10 * 1024 * 1024)}
    )

    assert status == 403
    assert docker.calls == []


def test_chunked_requests_are_rejected(proxy: int, docker: FakeDocker) -> None:
    status, _ = call(proxy, "POST", "/containers/create", b"", {"Transfer-Encoding": "chunked"})

    assert status == 403
    assert docker.calls == []


def test_body_on_a_bodiless_call_is_rejected(proxy: int, docker: FakeDocker) -> None:
    create(proxy)

    status, _ = call(proxy, "POST", f"/containers/{CREATED}/start", b"{}")

    assert status == 403
    assert len(docker.calls) == 1


@pytest.mark.parametrize("method", ["GET", "PUT", "HEAD", "PATCH", "OPTIONS"])
def test_other_http_methods_are_denied(proxy: int, docker: FakeDocker, method: str) -> None:
    status, _ = call(proxy, method, "/containers/json")

    assert status == 403
    assert docker.calls == []


def test_exec_is_denied(proxy: int, docker: FakeDocker) -> None:
    status, _ = call(proxy, "POST", f"/containers/{FOREIGN}/exec")

    assert status == 403
    assert docker.calls == []


@pytest.mark.parametrize(
    ("method", "suffix"),
    [
        ("POST", "/start"),
        ("POST", "/wait"),
        ("POST", "/attach?stream=1&stdout=1"),
        ("POST", "/kill?signal=SIGKILL"),
        ("DELETE", "?force=1"),
    ],
)
def test_containers_the_proxy_did_not_create_are_denied(
    proxy: int, docker: FakeDocker, method: str, suffix: str
) -> None:
    status, _ = call(proxy, method, f"/containers/{FOREIGN}{suffix}")

    assert status == 403
    assert docker.calls == []


def test_own_container_can_be_started_waited_killed_and_removed(
    proxy: int, docker: FakeDocker
) -> None:
    create(proxy)

    assert call(proxy, "POST", f"/containers/{CREATED}/start")[0] == 204
    assert call(proxy, "POST", f"/containers/{CREATED}/wait?condition=removed")[0] == 200
    assert call(proxy, "POST", f"/containers/{CREATED}/kill?signal=SIGKILL")[0] == 204
    assert call(proxy, "DELETE", f"/containers/{CREATED}?force=1")[0] == 204


def test_removed_container_is_forgotten(proxy: int, docker: FakeDocker) -> None:
    create(proxy)
    call(proxy, "DELETE", f"/containers/{CREATED}")

    status, _ = call(proxy, "POST", f"/containers/{CREATED}/start")

    assert status == 403


def test_attach_passes_the_raw_output_stream_through(proxy: int, docker: FakeDocker) -> None:
    create(proxy)

    connection = http.client.HTTPConnection("127.0.0.1", proxy, timeout=5)
    connection.connect()
    assert connection.sock is not None
    request = (
        f"POST /containers/{CREATED}/attach?stream=1&stdout=1 HTTP/1.1\r\n"
        "Host: proxy\r\nConnection: close\r\n\r\n"
    )
    connection.sock.sendall(request.encode())
    received = b""
    while chunk := connection.sock.recv(4096):
        received += chunk
    connection.close()

    assert received.startswith(b"HTTP/1.1 101")
    assert received.endswith(b"tool-output")
    upstream = docker.calls[-1][2]
    assert upstream["Upgrade"] == "tcp"


def test_creates_stop_when_too_many_containers_are_tracked(
    proxy: int, docker: FakeDocker, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr("attacksurf.sandbox_proxy.server.MAX_TRACKED_CONTAINERS", 1)
    assert MAX_TRACKED_CONTAINERS > 1
    create(proxy)

    status, _ = create(proxy)

    assert status == 429
    assert len(docker.calls) == 1


def test_create_reply_without_a_valid_id_is_not_trusted(proxy: int, docker: FakeDocker) -> None:
    docker.next_id = "not-a-container-id"

    status, _ = create(proxy)

    assert status == 502
    assert call(proxy, "POST", "/containers/not-a-container-id/start")[0] == 403


def test_unreachable_docker_is_a_gateway_error(proxy: int, docker: FakeDocker) -> None:
    Path(docker.server_address).unlink()  # type: ignore[arg-type]

    status, _ = create(proxy)

    assert status == 502
