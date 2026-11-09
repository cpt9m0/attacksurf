"""HTTP front for the Docker socket: validates each request and forwards a canonical copy."""

import http.client
import json
import re
import socket
import threading
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any, NoReturn

import structlog

from attacksurf.sandbox_proxy.policy import (
    PolicyViolation,
    Route,
    SandboxPolicy,
    classify_request,
    validate_create,
)

MAX_CREATE_BODY_BYTES = 64 * 1024
MAX_DOCKER_REPLY_BYTES = 1024 * 1024
MAX_TRACKED_CONTAINERS = 256
CLIENT_TIMEOUT_SECONDS = 30
DOCKER_TIMEOUT_SECONDS = 30
# Above any sandbox wall-time limit: wait and attach stay open for a whole run.
RUN_TIMEOUT_SECONDS = 900

_CONTAINER_ID = re.compile(r"[0-9a-f]{64}")

log = structlog.get_logger(__name__)


class _TrackedContainers:
    """IDs this proxy created. ADR 0016 forbids acting on any other container."""

    def __init__(self) -> None:
        self._ids: set[str] = set()
        self._pending = 0
        self._lock = threading.Lock()

    def reserve(self) -> bool:
        with self._lock:
            if len(self._ids) + self._pending >= MAX_TRACKED_CONTAINERS:
                return False
            self._pending += 1
            return True

    def release(self) -> None:
        with self._lock:
            self._pending -= 1

    def add(self, container_id: str) -> None:
        with self._lock:
            self._ids.add(container_id)

    def discard(self, container_id: str) -> None:
        with self._lock:
            self._ids.discard(container_id)

    def __contains__(self, container_id: str) -> bool:
        with self._lock:
            return container_id in self._ids


class ProxyServer(ThreadingHTTPServer):
    daemon_threads = True

    def __init__(self, address: tuple[str, int], policy: SandboxPolicy, docker_socket: str) -> None:
        super().__init__(address, _ProxyHandler)
        self.policy = policy
        self.docker_socket = docker_socket
        self.containers = _TrackedContainers()


def make_server(host: str, port: int, policy: SandboxPolicy, docker_socket: str) -> ProxyServer:
    return ProxyServer((host, port), policy, docker_socket)


class _UnixConnection(http.client.HTTPConnection):
    def __init__(self, path: str, timeout: float) -> None:
        super().__init__("docker", timeout=timeout)
        self._path = path

    def connect(self) -> None:
        sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        sock.settimeout(self.timeout)
        sock.connect(self._path)
        self.sock = sock


def _created_id(reply: bytes) -> str | None:
    try:
        parsed = json.loads(reply)
    except ValueError:
        return None
    container_id = parsed.get("Id") if isinstance(parsed, dict) else None
    if isinstance(container_id, str) and _CONTAINER_ID.fullmatch(container_id):
        return container_id
    return None


def _wait_succeeded(reply: bytes) -> bool:
    try:
        parsed = json.loads(reply)
    except ValueError:
        return False
    return (
        isinstance(parsed, dict)
        and type(parsed.get("StatusCode")) is int
        and not parsed.get("Error")
    )


def _reject_duplicate_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result = dict(pairs)
    if len(result) != len(pairs):
        raise PolicyViolation("Request is malformed.")
    return result


class _ProxyHandler(BaseHTTPRequestHandler):
    server: ProxyServer  # type: ignore[assignment]
    timeout = CLIENT_TIMEOUT_SECONDS

    def log_message(self, format: str, *args: Any) -> None:
        """Silence stdlib access logs; denials are logged with a safe reason instead."""

    def _handle(self) -> None:
        try:
            route = classify_request(self.command, self.path)
            body = self._read_body(route)
            self._check_ownership(route)
            if route.action == "attach":
                self._stream(route)
            else:
                self._forward(route, body)
        except PolicyViolation as violation:
            log.warning("sandbox_proxy_denied", reason=str(violation))
            self._reply(403, json.dumps({"message": str(violation)}).encode())

    do_POST = do_DELETE = _handle

    def _deny(self) -> None:
        log.warning("sandbox_proxy_denied", reason="Docker call not allowed.")
        self._reply(403, b'{"message": "Docker call not allowed."}')

    do_GET = do_HEAD = do_PUT = do_PATCH = do_OPTIONS = _deny

    def _read_body(self, route: Route) -> bytes:
        if self.headers.get("Transfer-Encoding"):
            self._violation("Chunked requests are not allowed.")
        try:
            length = int(self.headers.get("Content-Length", "0"))
        except ValueError:
            self._violation("Request is malformed.")
        limit = MAX_CREATE_BODY_BYTES if route.action == "create" else 0
        if not 0 <= length <= limit:
            self._violation("Request body is not allowed.")
        if route.action != "create":
            return b""
        try:
            parsed = json.loads(self.rfile.read(length), object_pairs_hook=_reject_duplicate_keys)
        except (ValueError, RecursionError):
            self._violation("Request is malformed.")
        validate_create(parsed, self.server.policy)
        # Forward what was validated, not the client's bytes, so parsers can't disagree.
        return json.dumps(parsed).encode()

    def _check_ownership(self, route: Route) -> None:
        if route.container_id is not None and route.container_id not in self.server.containers:
            self._violation("Container is not managed by the sandbox.")

    def _forward(self, route: Route, body: bytes) -> None:
        creating = route.action == "create"
        if creating and not self.server.containers.reserve():
            self._reply(429, b'{"message": "Too many sandboxes."}')
            return
        try:
            self._forward_reserved(route, body)
        finally:
            if creating:
                self.server.containers.release()

    def _forward_reserved(self, route: Route, body: bytes) -> None:
        timeout = RUN_TIMEOUT_SECONDS if route.action == "wait" else DOCKER_TIMEOUT_SECONDS
        connection = _UnixConnection(self.server.docker_socket, timeout)
        method = "DELETE" if route.action == "remove" else "POST"
        headers = {"Content-Type": "application/json"} if route.action == "create" else {}
        try:
            connection.request(method, route.target, body=body, headers=headers)
            response = connection.getresponse()
            reply = response.read(MAX_DOCKER_REPLY_BYTES)
        except (OSError, http.client.HTTPException):
            self._reply(502, b'{"message": "Docker is unavailable."}')
            return
        finally:
            connection.close()
        if not self._record(route, response.status, reply):
            self._reply(502, b'{"message": "Docker sent an invalid reply."}')
            return
        self._reply(response.status, reply)

    def _record(self, route: Route, status: int, reply: bytes) -> bool:
        """Update ownership from Docker's answer; False when a create reply can't be trusted."""
        containers = self.server.containers
        if route.action == "create" and status == HTTPStatus.CREATED:
            container_id = _created_id(reply)
            if container_id is None:
                return False
            containers.add(container_id)
        elif (
            route.action == "wait"
            and route.target.endswith("?condition=removed")
            and status == HTTPStatus.OK
            and _wait_succeeded(reply)
            and route.container_id
        ) or (
            route.action == "remove"
            and (
                HTTPStatus.OK <= status < HTTPStatus.MULTIPLE_CHOICES
                or status == HTTPStatus.NOT_FOUND
            )
            and route.container_id
        ):
            containers.discard(route.container_id)
        return True

    def _stream(self, route: Route) -> None:
        """Relay the hijacked attach stream. One way only: nothing reaches the container."""
        request = (
            f"POST {route.target} HTTP/1.1\r\nHost: docker\r\n"
            "Connection: Upgrade\r\nUpgrade: tcp\r\nContent-Length: 0\r\n\r\n"
        )
        started = False
        try:
            with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as upstream:
                upstream.settimeout(RUN_TIMEOUT_SECONDS)
                upstream.connect(self.server.docker_socket)
                upstream.sendall(request.encode())
                while chunk := upstream.recv(64 * 1024):
                    started = True
                    self.wfile.write(chunk)
        except OSError:
            if not started:
                self._reply(502, b'{"message": "Docker is unavailable."}')

    def _reply(self, status: int, body: bytes) -> None:
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        if self.command != "HEAD":
            self.wfile.write(body)

    @staticmethod
    def _violation(message: str) -> NoReturn:
        raise PolicyViolation(message)
