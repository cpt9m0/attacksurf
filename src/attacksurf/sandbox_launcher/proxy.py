"""The launcher's only way to Docker: calls to `sandbox-proxy`, one connection per call.

The proxy relays canonical requests and answers a fixed set of shapes, so each reply is parsed
strictly and anything else is a `ProxyError`. Attach is a raw socket instead of `http.client`
because the proxy relays a hijacked stream: Docker's `101` head is followed at once by the
multiplexed frames, and `HTTPResponse` would try to frame them as a body.

Errors carry the stage and status only, with fixed text: replies come from a daemon that handles
scanned content, so their bytes never reach an exception or a log.
"""

import http.client
import json
import re
import socket
from collections.abc import Callable
from http import HTTPStatus
from typing import Any, Self
from urllib.parse import urlsplit

CONTROL_TIMEOUT_SECONDS = 30

_MAX_REPLY_BYTES = 64 * 1024
_MAX_HEAD_BYTES = 4096
_CONTAINER_ID = re.compile(r"[0-9a-f]{64}")
_HEAD_END = b"\r\n\r\n"
_GONE = (HTTPStatus.NOT_FOUND, HTTPStatus.FORBIDDEN)
_KILL_DONE = (HTTPStatus.NO_CONTENT, HTTPStatus.CONFLICT, *_GONE)
_REMOVE_DONE = (HTTPStatus.NO_CONTENT, *_GONE)


class ProxyError(Exception):
    """A proxy call failed or answered with something the launcher doesn't accept."""

    def __init__(self, stage: str, status: int | None = None) -> None:
        super().__init__("The sandbox proxy call failed.")
        self.stage = stage
        self.status = status


class ProxyClient:
    def __init__(self, host: str, port: int) -> None:
        self._host = host
        self._port = port

    @classmethod
    def from_url(cls, url: str) -> Self:
        """Accept `http://host[:port]` only, so a configured value is never silently dropped.

        The proxy has no authentication, so userinfo has nowhere to go; a path, query or
        fragment would be ignored. Errors don't echo the value, which is a secret setting.
        """
        try:
            parts = urlsplit(url)
            port = parts.port or 80
        except ValueError:
            raise ValueError("the sandbox proxy URL must be http://host[:port] only") from None
        plain = (
            parts.scheme == "http"
            and parts.hostname
            and parts.username is None
            and parts.password is None
            and parts.path in ("", "/")
            and not parts.query
            and not parts.fragment
        )
        if not plain or not parts.hostname:
            raise ValueError("the sandbox proxy URL must be http://host[:port] only")
        return cls(parts.hostname, port)

    def create(self, body: dict[str, Any]) -> str:
        status, reply = self._call(
            "POST", "/containers/create", stage="create", body=json.dumps(body).encode()
        )
        container_id = _field(reply, "Id") if status == HTTPStatus.CREATED else None
        if not isinstance(container_id, str) or not _CONTAINER_ID.fullmatch(container_id):
            raise ProxyError("create", status)
        return container_id

    def wait_removed(
        self, container_id: str, timeout: float, on_sent: Callable[[], None] | None = None
    ) -> int:
        """Block until the container is gone and return its exit code; unconfirmed raises.

        `on_sent` runs once the request is on the wire, so a caller can hold back until the
        wait is at least in flight; the proxy gives no sign of when Docker registers it.
        """
        status, reply = self._call(
            "POST",
            f"/containers/{container_id}/wait?condition=removed",
            stage="wait",
            timeout=timeout,
            on_sent=on_sent,
        )
        code = _field(reply, "StatusCode") if status == HTTPStatus.OK else None
        if type(code) is not int or _field(reply, "Error"):
            raise ProxyError("wait", status)
        return code

    def attach(self, container_id: str) -> tuple[socket.socket, bytes]:
        """Open the stdout stream. Returns the socket and any frame bytes read past the head.

        The caller owns the socket and must close it.
        """
        request = (
            f"POST /containers/{container_id}/attach?stream=1&stdout=1 HTTP/1.1\r\n"
            f"Host: {self._host}\r\nConnection: Upgrade\r\nUpgrade: tcp\r\n"
            "Content-Length: 0\r\n\r\n"
        )
        try:
            sock = socket.create_connection((self._host, self._port), CONTROL_TIMEOUT_SECONDS)
        except OSError:
            raise ProxyError("attach") from None
        try:
            sock.sendall(request.encode())
            status, rest = _read_head(sock)
            if status != HTTPStatus.SWITCHING_PROTOCOLS:
                raise ProxyError("attach", status)
        except OSError:
            sock.close()
            raise ProxyError("attach") from None
        except ProxyError:
            sock.close()
            raise
        return sock, rest

    def start(self, container_id: str, timeout: float = CONTROL_TIMEOUT_SECONDS) -> None:
        """Start the container. The analyzer may already be running while Docker is slow to
        answer, so a caller with a wall-time budget passes what is left of it as `timeout`."""
        status, _ = self._call(
            "POST", f"/containers/{container_id}/start", stage="start", timeout=timeout
        )
        if status != HTTPStatus.NO_CONTENT:
            raise ProxyError("start", status)

    def kill(self, container_id: str) -> None:
        """SIGKILL. 404, 409 and 403 all mean it is not running any more: the proxy answers 403
        for a container it has forgotten, which it does once removal is confirmed."""
        status, _ = self._call(
            "POST", f"/containers/{container_id}/kill?signal=SIGKILL", stage="kill"
        )
        if status not in _KILL_DONE:
            raise ProxyError("kill", status)

    def remove(self, container_id: str) -> bool:
        """Force-remove; True when the container is gone (204, 404, or 403 from a proxy that
        has already forgotten it)."""
        status, _ = self._call("DELETE", f"/containers/{container_id}?force=1", stage="remove")
        return status in _REMOVE_DONE

    def runtimes(self) -> list[str]:
        """Names of the runtimes Docker has registered (ADR 0023)."""
        status, reply = self._call("GET", "/info", stage="info")
        names = _field(reply, "Runtimes") if status == HTTPStatus.OK else None
        if not isinstance(names, list) or not all(isinstance(name, str) for name in names):
            raise ProxyError("info", status)
        return list(names)

    def _call(
        self,
        method: str,
        target: str,
        *,
        stage: str,
        body: bytes | None = None,
        timeout: float = CONTROL_TIMEOUT_SECONDS,
        on_sent: Callable[[], None] | None = None,
    ) -> tuple[int, bytes]:
        connection = http.client.HTTPConnection(self._host, self._port, timeout=timeout)
        headers = {"Content-Type": "application/json"} if body is not None else {}
        try:
            connection.request(method, target, body=body, headers=headers)
            if on_sent is not None:
                on_sent()
            response = connection.getresponse()
            return response.status, response.read(_MAX_REPLY_BYTES)
        except (OSError, http.client.HTTPException):
            raise ProxyError(stage) from None
        finally:
            connection.close()


def _field(reply: bytes, name: str) -> Any:
    """One top-level field of a JSON object reply, or None when it isn't one."""
    try:
        parsed = json.loads(reply)
    except ValueError:
        return None
    return parsed.get(name) if isinstance(parsed, dict) else None


def _read_head(sock: socket.socket) -> tuple[int, bytes]:
    """Read an HTTP response head: its status code and the bytes that followed it."""
    buffer = b""
    while _HEAD_END not in buffer:
        if len(buffer) >= _MAX_HEAD_BYTES:
            raise ProxyError("attach")
        chunk = sock.recv(_MAX_HEAD_BYTES - len(buffer))
        if not chunk:
            raise ProxyError("attach")
        buffer += chunk
    head, _, rest = buffer.partition(_HEAD_END)
    parts = head.split(b"\r\n", 1)[0].split(b" ", 2)
    if not parts[0].startswith(b"HTTP/") or len(parts) == 1 or not parts[1].isdigit():
        raise ProxyError("attach")
    return int(parts[1]), rest
