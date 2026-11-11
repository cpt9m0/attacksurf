"""The proxy process: deny by default, forward only canonical requests, own containers only."""

import http.client
import json
import socketserver
import threading
from collections.abc import Iterator, Mapping, Sequence
from concurrent.futures import ThreadPoolExecutor, wait
from http.server import BaseHTTPRequestHandler
from pathlib import Path, PurePosixPath
from typing import Any

import pytest
from structlog.testing import capture_logs

from attacksurf.sandbox_proxy.policy import SandboxPolicy
from attacksurf.sandbox_proxy.server import (
    MAX_DOCKER_REPLY_BYTES,
    MAX_TRACKED_CONTAINERS,
    make_server,
)
from tests.unit.sandbox_proxy.test_policy import IMAGE, create_body

if not hasattr(socketserver, "UnixStreamServer"):
    # The proxy only runs on Linux; CI runs these tests, Windows dev machines can't.
    pytest.skip("needs Unix domain sockets", allow_module_level=True)

CREATED = "e" * 64
FOREIGN = "f" * 64

# Trimmed from a real `docker info` reply on a gVisor host: everything except the runtime names
# is host detail the proxy must keep to itself (ADR 0023).
DOCKER_INFO: dict[str, Any] = {
    "ID": "7f3c2a9e-5b1d-4e8a-9c6f-2d4b8e1a3f70",
    "Name": "vps-fra-01",
    "ServerVersion": "27.3.1",
    "OperatingSystem": "Ubuntu 24.04.1 LTS",
    "DockerRootDir": "/var/lib/docker",
    "Labels": ["com.attacksurf.region=eu-central"],
    "RegistryConfig": {"Mirrors": ["https://mirror.gcr.io/"]},
    "DefaultRuntime": "runc",
    "Runtimes": {
        "runc": {"path": "runc"},
        "io.containerd.runc.v2": {
            "path": "runc",
            "status": {"org.opencontainers.runtime-spec.features": "{}"},
        },
        "runsc": {"path": "/usr/local/bin/runsc", "runtimeArgs": ["--platform=systrap"]},
    },
}
HOST_DETAILS = ("vps-fra-01", "/var/lib/docker", "/usr/local/bin/runsc", "systrap", "eu-central")
UNAVAILABLE = {"message": "Docker runtimes are unavailable."}


class FakeDocker(socketserver.ThreadingMixIn, socketserver.UnixStreamServer):
    daemon_threads = True

    def __init__(self, path: str) -> None:
        super().__init__(path, _FakeDockerHandler)
        self.calls: list[tuple[str, str, dict[str, str], bytes]] = []
        self.next_id = CREATED
        self.create_status = 201
        self.drop_create_reply = False
        self.remove_status = 204
        self.drop_remove_reply = False
        self.wait_status = 200
        self.wait_body = b'{"StatusCode": 0}'
        self.create_entered: threading.Event | None = None
        self.create_release: threading.Event | None = None
        self.info_status = 200
        self.info_body = json.dumps(DOCKER_INFO).encode()
        self.drop_info_reply = False
        self.info_entered: threading.Event | None = None
        self.info_release: threading.Event | None = None


class _FakeDockerHandler(BaseHTTPRequestHandler):
    server: FakeDocker  # type: ignore[assignment]

    def log_message(self, format: str, *args: Any) -> None:
        pass

    def _handle(self) -> None:
        length = int(self.headers.get("Content-Length", 0))
        body = self.rfile.read(length)
        self.server.calls.append((self.command, self.path, dict(self.headers), body))
        if self.path.split("?", 1)[0].endswith("/containers/create"):
            if self.server.drop_create_reply:
                return
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
            if self.server.drop_remove_reply:
                return
            self._reply(self.server.remove_status, b"")
        else:
            self._reply(204, b"")

    do_POST = do_DELETE = _handle

    def do_GET(self) -> None:
        self.server.calls.append((self.command, self.path, dict(self.headers), b""))
        if self.server.info_entered is not None:
            self.server.info_entered.set()
        if self.server.info_release is not None:
            assert self.server.info_release.wait(5)
        if self.server.drop_info_reply:
            return
        self._reply(self.server.info_status, self.server.info_body)

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
    assert docker.calls[0][0] == "POST"
    assert docker.calls[0][1].startswith("/containers/create?name=attacksurf-")


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


@pytest.mark.parametrize("method", ["PUT", "HEAD", "PATCH", "OPTIONS"])
def test_methods_other_than_get_post_delete_are_denied(
    proxy: int, docker: FakeDocker, method: str
) -> None:
    status, _ = call(proxy, method, "/info")

    assert status == 403
    assert docker.calls == []


# GET is allowed for the runtime-info call only (ADR 0023); every other read stays denied,
# including reads on a container the proxy created itself.
@pytest.mark.parametrize(
    "target",
    [
        "/containers/json",
        "/_ping",
        "/version",
        "/images/json",
        f"/containers/{CREATED}/json",
        "/info/",
    ],
)
def test_get_is_denied_on_every_path_except_info(
    proxy: int, docker: FakeDocker, target: str
) -> None:
    create(proxy)

    status, _ = call(proxy, "GET", target)

    assert status == 403
    assert [method for method, *_ in docker.calls] == ["POST"]


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


@pytest.mark.parametrize("remove_status", [404, 409, 500])
def test_uncertain_create_retains_capacity_until_named_cleanup_succeeds(
    proxy: int, docker: FakeDocker, monkeypatch: pytest.MonkeyPatch, remove_status: int
) -> None:
    monkeypatch.setattr("attacksurf.sandbox_proxy.server.MAX_TRACKED_CONTAINERS", 1)
    docker.drop_create_reply = True
    docker.remove_status = remove_status

    assert create(proxy)[0] == 502
    assert create(proxy)[0] == 429
    assert sum(method == "POST" for method, _, _, _ in docker.calls) == 1

    docker.remove_status = 204
    docker.drop_create_reply = False
    assert create(proxy)[0] == 201
    create_target = docker.calls[0][1]
    name = create_target.split("?name=", 1)[1]
    assert name.startswith("attacksurf-")
    assert ("DELETE", f"/containers/{name}?force=1") == docker.calls[1][:2]


def test_uncertain_create_keeps_capacity_when_cleanup_cannot_reach_docker(
    proxy: int, docker: FakeDocker, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr("attacksurf.sandbox_proxy.server.MAX_TRACKED_CONTAINERS", 1)
    docker.drop_create_reply = True
    docker.drop_remove_reply = True

    assert create(proxy)[0] == 502
    assert create(proxy)[0] == 429

    docker.drop_create_reply = False
    docker.drop_remove_reply = False
    assert create(proxy)[0] == 201


def test_create_reply_without_a_valid_id_is_not_trusted(proxy: int, docker: FakeDocker) -> None:
    docker.next_id = "not-a-container-id"

    status, _ = create(proxy)

    assert status == 502
    assert call(proxy, "POST", "/containers/not-a-container-id/start")[0] == 403


def test_unreachable_docker_on_a_container_call_keeps_ownership(
    proxy: int, docker: FakeDocker
) -> None:
    create(proxy)
    socket_path = Path(docker.server_address)  # type: ignore[arg-type]
    backup = socket_path.with_suffix(".backup")
    socket_path.rename(backup)
    try:
        status, body = call(proxy, "POST", f"/containers/{CREATED}/start")
    finally:
        backup.rename(socket_path)

    assert status == 502
    assert json.loads(body) == {"message": "Docker is unavailable."}
    assert call(proxy, "POST", f"/containers/{CREATED}/start")[0] == 204


def test_unreachable_docker_is_a_gateway_error(proxy: int, docker: FakeDocker) -> None:
    Path(docker.server_address).unlink()  # type: ignore[arg-type]

    status, _ = create(proxy)

    assert status == 502


def info_reply(**changes: Any) -> bytes:
    return json.dumps({**DOCKER_INFO, **changes}).encode()


def info_of_size(size: int) -> bytes:
    """A valid info reply padded through its labels to exactly `size` bytes."""
    note = "com.attacksurf.maintenance=sun-02:00-04:00-utc;"
    base = len(info_reply(Labels=[""]))
    padding = (note * (size // len(note) + 1))[: size - base]
    body = info_reply(Labels=[padding])
    assert len(body) == size
    return body


def info_failures(logs: Sequence[Mapping[str, Any]]) -> list[Mapping[str, Any]]:
    return [entry for entry in logs if entry["event"] == "sandbox_proxy_info_failed"]


# Happy path: the launcher learns which runtimes exist, and nothing else about the host.
def test_info_returns_only_the_sorted_runtime_names(proxy: int, docker: FakeDocker) -> None:
    status, body = call(proxy, "GET", "/info")

    assert status == 200
    assert json.loads(body) == {"Runtimes": ["io.containerd.runc.v2", "runc", "runsc"]}


def test_info_never_relays_host_details_from_docker(proxy: int, docker: FakeDocker) -> None:
    _, body = call(proxy, "GET", "/info")

    assert not [detail for detail in HOST_DETAILS if detail in body.decode()]


def test_versioned_info_is_forwarded_to_the_same_versioned_path(
    proxy: int, docker: FakeDocker
) -> None:
    status, _ = call(proxy, "GET", "/v1.47/info")

    assert status == 200
    assert docker.calls[0][:2] == ("GET", "/v1.47/info")


def test_info_forwards_no_client_headers(proxy: int, docker: FakeDocker) -> None:
    call(
        proxy,
        "GET",
        "/info",
        headers={
            "X-Registry-Auth": "stolen-registry-login",
            "Cookie": "attacksurf_session=stolen-session",
        },
    )

    forwarded = {name.lower() for name in docker.calls[0][2]}
    assert not forwarded & {"x-registry-auth", "cookie"}


# Boundaries: no runtimes, a single runtime, and the info reply size limit.
def test_info_with_no_registered_runtimes_returns_an_empty_list(
    proxy: int, docker: FakeDocker
) -> None:
    docker.info_body = info_reply(Runtimes={})

    status, body = call(proxy, "GET", "/info")

    assert status == 200
    assert json.loads(body) == {"Runtimes": []}


def test_info_with_only_runsc_registered_returns_just_runsc(proxy: int, docker: FakeDocker) -> None:
    docker.info_body = info_reply(Runtimes={"runsc": {"path": "/usr/local/bin/runsc"}})

    _, body = call(proxy, "GET", "/info")

    assert json.loads(body) == {"Runtimes": ["runsc"]}


def test_info_reply_exactly_at_the_size_limit_is_accepted(
    proxy: int, docker: FakeDocker, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr("attacksurf.sandbox_proxy.server.MAX_DOCKER_INFO_BYTES", 4096)
    docker.info_body = info_of_size(4096)

    status, _ = call(proxy, "GET", "/info")

    assert status == 200


def test_info_reply_one_byte_over_the_size_limit_is_refused(
    proxy: int, docker: FakeDocker, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr("attacksurf.sandbox_proxy.server.MAX_DOCKER_INFO_BYTES", 4096)
    docker.info_body = info_of_size(4097)

    status, body = call(proxy, "GET", "/info")

    assert status == 502
    assert json.loads(body) == UNAVAILABLE


def test_info_reply_larger_than_the_general_reply_cap_is_accepted(
    proxy: int, docker: FakeDocker
) -> None:
    docker.info_body = info_of_size(MAX_DOCKER_REPLY_BYTES + 100 * 1024)

    status, body = call(proxy, "GET", "/info")

    assert status == 200
    assert "runsc" in json.loads(body)["Runtimes"]


# Invalid client requests on the info path are refused before anything reaches Docker.
def test_info_with_query_options_is_denied_before_docker(proxy: int, docker: FakeDocker) -> None:
    status, _ = call(proxy, "GET", "/info?format=json")

    assert status == 403
    assert docker.calls == []


def test_info_with_a_request_body_is_rejected(proxy: int, docker: FakeDocker) -> None:
    status, _ = call(proxy, "GET", "/info", b'{"verbose": true}')

    assert status == 403
    assert docker.calls == []


def test_chunked_info_request_is_rejected(proxy: int, docker: FakeDocker) -> None:
    status, _ = call(proxy, "GET", "/info", b"", {"Transfer-Encoding": "chunked"})

    assert status == 403
    assert docker.calls == []


# Docker fails to answer: the launcher gets a generic 502, and the operator gets a logged
# reason (status code only) that never repeats the daemon's reply.
@pytest.mark.parametrize("docker_status", [404, 500, 503])
def test_docker_error_status_on_info_is_a_gateway_error(
    proxy: int, docker: FakeDocker, docker_status: int
) -> None:
    docker.info_status = docker_status
    docker.info_body = b'{"message": "page not found"}'

    with capture_logs() as logs:
        status, body = call(proxy, "GET", "/info")

    assert status == 502
    assert json.loads(body) == UNAVAILABLE
    assert info_failures(logs) == [
        {
            "event": "sandbox_proxy_info_failed",
            "log_level": "warning",
            "reason": "docker_status",
            "status": docker_status,
        }
    ]


@pytest.mark.parametrize(
    "reply",
    [
        b"<html><body><h1>502 Bad Gateway</h1></body></html>",
        b"",
        b"[]",
        b'{"Runtimes": null}',
        b'{"Runtimes": ["runsc"]}',
        json.dumps(DOCKER_INFO).encode()[:200],
    ],
    ids=["html-page", "empty", "json-array", "null-runtimes", "runtimes-list", "cut-off"],
)
def test_malformed_info_reply_is_a_gateway_error(
    proxy: int, docker: FakeDocker, reply: bytes
) -> None:
    docker.info_body = reply

    with capture_logs() as logs:
        status, body = call(proxy, "GET", "/info")

    assert status == 502
    assert json.loads(body) == UNAVAILABLE
    assert [entry["reason"] for entry in info_failures(logs)] == ["invalid_reply"]


def test_unreachable_docker_on_info_is_a_gateway_error(proxy: int, docker: FakeDocker) -> None:
    Path(docker.server_address).unlink()  # type: ignore[arg-type]

    with capture_logs() as logs:
        status, body = call(proxy, "GET", "/info")

    assert status == 502
    assert json.loads(body) == UNAVAILABLE
    assert [entry["reason"] for entry in info_failures(logs)] == ["docker_unavailable"]


def test_docker_hanging_up_on_info_is_a_gateway_error(proxy: int, docker: FakeDocker) -> None:
    docker.drop_info_reply = True

    with capture_logs() as logs:
        status, _ = call(proxy, "GET", "/info")

    assert status == 502
    assert [entry["reason"] for entry in info_failures(logs)] == ["docker_unavailable"]


def test_info_failure_logs_never_include_the_daemon_reply(proxy: int, docker: FakeDocker) -> None:
    docker.info_status = 500
    docker.info_body = (
        b'{"message": "error opening /var/lib/docker/runtimes/runsc on vps-fra-01: '
        b'permission denied"}'
    )

    with capture_logs() as logs:
        call(proxy, "GET", "/info")

    assert not [detail for detail in HOST_DETAILS if detail in repr(logs)]


# Caching and concurrency: one daemon call serves many requests, failures are never kept,
# and a slow info call never holds up container work.
def test_repeated_info_calls_within_the_cache_window_reach_docker_once(
    proxy: int, docker: FakeDocker
) -> None:
    replies = [call(proxy, "GET", "/info") for _ in range(3)]

    assert [status for status, _ in replies] == [200, 200, 200]
    assert len(docker.calls) == 1


def test_info_is_fetched_again_after_the_cache_window_expires(
    proxy: int, docker: FakeDocker, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr("attacksurf.sandbox_proxy.server.RUNTIMES_CACHE_SECONDS", 0)
    docker.info_body = info_reply(Runtimes={"runc": {"path": "runc"}})
    assert json.loads(call(proxy, "GET", "/info")[1]) == {"Runtimes": ["runc"]}
    docker.info_body = info_reply()  # the operator registers gVisor and restarts Docker

    _, body = call(proxy, "GET", "/info")

    assert "runsc" in json.loads(body)["Runtimes"]
    assert len(docker.calls) == 2


def test_failed_info_is_not_cached_so_a_repaired_daemon_is_seen_next_time(
    proxy: int, docker: FakeDocker
) -> None:
    docker.info_status = 500
    assert call(proxy, "GET", "/info")[0] == 502
    docker.info_status = 200

    status, _ = call(proxy, "GET", "/info")

    assert status == 200
    assert len(docker.calls) == 2


def test_cached_runtimes_are_served_while_docker_briefly_fails(
    proxy: int, docker: FakeDocker
) -> None:
    assert call(proxy, "GET", "/info")[0] == 200
    docker.info_status = 503

    status, body = call(proxy, "GET", "/info")

    assert status == 200
    assert "runsc" in json.loads(body)["Runtimes"]
    assert len(docker.calls) == 1


def test_concurrent_info_requests_share_a_single_docker_call(
    proxy: int, docker: FakeDocker
) -> None:
    docker.info_entered = threading.Event()
    docker.info_release = threading.Event()
    with ThreadPoolExecutor(max_workers=9) as pool:
        first = pool.submit(call, proxy, "GET", "/info")
        try:
            assert docker.info_entered.wait(2)
            waiting = [pool.submit(call, proxy, "GET", "/info") for _ in range(8)]
            _, pending = wait(waiting, timeout=0.3)
            assert len(pending) == 8, "Requests were answered before Docker replied"
        finally:
            docker.info_release.set()
        replies = [first.result(), *(future.result() for future in waiting)]

    assert [status for status, _ in replies] == [200] * 9
    assert len({body for _, body in replies}) == 1
    assert len(docker.calls) == 1


def test_slow_info_call_does_not_block_container_creation(proxy: int, docker: FakeDocker) -> None:
    docker.info_entered = threading.Event()
    docker.info_release = threading.Event()
    with ThreadPoolExecutor(max_workers=1) as pool:
        info = pool.submit(call, proxy, "GET", "/info")
        try:
            assert docker.info_entered.wait(2)

            status, _ = create(proxy)

            assert status == 201
            assert not info.done()
        finally:
            docker.info_release.set()
        assert info.result()[0] == 200
