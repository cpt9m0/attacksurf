"""The proxy process: deny by default, forward only canonical requests, own containers only."""

import http.client
import json
import socketserver
import threading
from collections.abc import Iterator
from concurrent.futures import ThreadPoolExecutor, wait
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
        self.create_status = 201
        self.remove_status = 204
        self.wait_status = 200
        self.wait_body = b'{"StatusCode": 0}'
        self.create_entered: threading.Event | None = None
        self.create_release: threading.Event | None = None


class _FakeDockerHandler(BaseHTTPRequestHandler):
    server: FakeDocker  # type: ignore[assignment]

    def log_message(self, format: str, *args: Any) -> None:
        pass

    def _handle(self) -> None:
        length = int(self.headers.get("Content-Length", 0))
        body = self.rfile.read(length)
        self.server.calls.append((self.command, self.path, dict(self.headers), body))
        if self.path.endswith("/containers/create"):
            if self.server.create_entered is not None:
                self.server.create_entered.set()
            if self.server.create_release is not None:
                assert self.server.create_release.wait(5)
            self._reply(self.server.create_status, json.dumps({"Id": self.server.next_id}).encode())
        elif "/attach" in self.path:
            self.wfile.write(b"HTTP/1.1 101 UPGRADED\r\nUpgrade: tcp\r\n\r\ntool-output")
        elif "/wait" in self.path:
            self._reply(self.server.wait_status, self.server.wait_body)
        elif self.command == "DELETE":
            self._reply(self.server.remove_status, b"")
        else:
            self._reply(204, b"")

    do_POST = do_DELETE = _handle

    def _reply(self, status: int, body: bytes) -> None:
        self.send_response(status)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        if body:
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
    assert call(proxy, "POST", f"/containers/{CREATED}/wait?condition=not-running")[0] == 200
    assert call(proxy, "POST", f"/containers/{CREATED}/kill?signal=SIGKILL")[0] == 204
    assert call(proxy, "DELETE", f"/containers/{CREATED}?force=1")[0] == 204


def test_removed_container_is_forgotten(proxy: int, docker: FakeDocker) -> None:
    create(proxy)
    call(proxy, "DELETE", f"/containers/{CREATED}")

    status, _ = call(proxy, "POST", f"/containers/{CREATED}/start")

    assert status == 403


@pytest.mark.parametrize("remove_status", [304, 400, 403, 409, 500])
def test_failed_removal_retains_ownership_and_capacity(
    proxy: int, docker: FakeDocker, monkeypatch: pytest.MonkeyPatch, remove_status: int
) -> None:
    monkeypatch.setattr("attacksurf.sandbox_proxy.server.MAX_TRACKED_CONTAINERS", 1)
    create(proxy)
    docker.remove_status = remove_status

    assert call(proxy, "DELETE", f"/containers/{CREATED}")[0] == remove_status

    assert create(proxy)[0] == 429
    assert call(proxy, "POST", f"/containers/{CREATED}/kill")[0] == 204
    assert call(proxy, "POST", f"/containers/{CREATED}/wait")[0] == 200
    docker.remove_status = 204
    assert call(proxy, "DELETE", f"/containers/{CREATED}?force=1")[0] == 204
    assert create(proxy)[0] == 201


def test_missing_container_removal_releases_capacity(
    proxy: int, docker: FakeDocker, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr("attacksurf.sandbox_proxy.server.MAX_TRACKED_CONTAINERS", 1)
    create(proxy)
    docker.remove_status = 404

    assert call(proxy, "DELETE", f"/containers/{CREATED}")[0] == 404

    assert call(proxy, "POST", f"/containers/{CREATED}/start")[0] == 403
    assert create(proxy)[0] == 201


def test_removed_wait_releases_ownership_and_capacity(
    proxy: int, docker: FakeDocker, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr("attacksurf.sandbox_proxy.server.MAX_TRACKED_CONTAINERS", 1)
    create(proxy)

    assert call(proxy, "POST", f"/containers/{CREATED}/wait?condition=removed")[0] == 200

    assert call(proxy, "POST", f"/containers/{CREATED}/start")[0] == 403
    assert create(proxy)[0] == 201


@pytest.mark.parametrize(
    ("query", "status", "body"),
    [
        ("", 200, b'{"StatusCode": 0}'),
        ("?condition=not-running", 200, b'{"StatusCode": 0}'),
        ("?condition=next-exit", 200, b'{"StatusCode": 0}'),
        ("?condition=removed", 500, b"{}"),
        ("?condition=removed", 200, b'{"Error": {"Message": "wait failed"}}'),
        ("?condition=removed", 200, b"not json"),
    ],
)
def test_wait_without_confirmed_removal_retains_ownership(
    *,
    proxy: int,
    docker: FakeDocker,
    monkeypatch: pytest.MonkeyPatch,
    query: str,
    status: int,
    body: bytes,
) -> None:
    monkeypatch.setattr("attacksurf.sandbox_proxy.server.MAX_TRACKED_CONTAINERS", 1)
    create(proxy)
    docker.wait_status, docker.wait_body = status, body

    assert call(proxy, "POST", f"/containers/{CREATED}/wait{query}")[0] == status

    assert create(proxy)[0] == 429
    assert call(proxy, "POST", f"/containers/{CREATED}/kill")[0] == 204


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


def test_inflight_create_reserves_capacity_before_docker_replies(
    proxy: int, docker: FakeDocker, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr("attacksurf.sandbox_proxy.server.MAX_TRACKED_CONTAINERS", 1)
    docker.create_entered = threading.Event()
    docker.create_release = threading.Event()
    with ThreadPoolExecutor(max_workers=9) as pool:
        first = pool.submit(create, proxy)
        try:
            assert docker.create_entered.wait(2)
            competitors = [pool.submit(create, proxy) for _ in range(8)]
            _, pending = wait(competitors, timeout=2)
            assert not pending, "Excess creates reached Docker instead of being rejected"
            assert [future.result()[0] for future in competitors] == [429] * 8
            assert len(docker.calls) == 1
        finally:
            docker.create_release.set()
        assert first.result()[0] == 201
    assert create(proxy)[0] == 429
    assert call(proxy, "DELETE", f"/containers/{CREATED}")[0] == 204
    assert create(proxy)[0] == 201


@pytest.mark.parametrize("failure", ["rejected", "invalid-id", "unavailable"])
def test_failed_create_releases_reserved_capacity(
    proxy: int, docker: FakeDocker, monkeypatch: pytest.MonkeyPatch, failure: str
) -> None:
    monkeypatch.setattr("attacksurf.sandbox_proxy.server.MAX_TRACKED_CONTAINERS", 1)
    socket_path = Path(docker.server_address)  # type: ignore[arg-type]
    backup = socket_path.with_suffix(".backup")
    if failure == "rejected":
        docker.create_status = 500
    elif failure == "invalid-id":
        docker.next_id = "not-a-container-id"
    else:
        socket_path.rename(backup)
    try:
        assert create(proxy)[0] == (500 if failure == "rejected" else 502)
    finally:
        if failure == "unavailable":
            backup.rename(socket_path)
        docker.create_status = 201
        docker.next_id = CREATED

    assert create(proxy)[0] == 201
    assert create(proxy)[0] == 429


def test_create_reply_without_a_valid_id_is_not_trusted(proxy: int, docker: FakeDocker) -> None:
    docker.next_id = "not-a-container-id"

    status, _ = create(proxy)

    assert status == 502
    assert call(proxy, "POST", "/containers/not-a-container-id/start")[0] == 403


def test_unreachable_docker_is_a_gateway_error(proxy: int, docker: FakeDocker) -> None:
    Path(docker.server_address).unlink()  # type: ignore[arg-type]

    status, _ = create(proxy)

    assert status == 502
