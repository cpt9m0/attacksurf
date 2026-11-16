"""A stand-in Docker daemon on a Unix socket, for sandbox proxy and launcher tests.

By default it answers each call at once with fixed replies. With `run` set to a `FakeRun` it
acts out one container run: attach output only after start, each scripted chunk as its own
write, a container that can stay up until killed, and a removed-wait that answers only once
the run has ended.
"""

import json
import socketserver
import threading
from collections.abc import Iterator
from contextlib import contextmanager
from dataclasses import dataclass, field
from http.server import BaseHTTPRequestHandler
from typing import Any

CREATED = "e" * 64

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

# Every wait in the fake is bounded, so a bug fails a test instead of hanging the suite.
FAKE_TIMEOUT_SECONDS = 10
KILLED_EXIT_CODE = 137  # what Docker reports for SIGKILL

ATTACH_HEAD = (
    b"HTTP/1.1 101 UPGRADED\r\n"
    b"Content-Type: application/vnd.docker.raw-stream\r\n"
    b"Connection: Upgrade\r\n"
    b"Upgrade: tcp\r\n\r\n"
)


@dataclass
class FakeRun:
    """One scripted container run. Tests read the events to check ordering."""

    chunks: list[bytes] = field(default_factory=list)
    exit_code: int = 0
    hold_open: bool = False  # keep running (and attached) until killed
    hold_exit: bool = False  # close the stream but keep running until the test calls `end`
    attach_status: int = 101  # anything else: a plain error reply, no stream
    start_status: int = 204
    started: threading.Event = field(default_factory=threading.Event)
    killed: threading.Event = field(default_factory=threading.Event)
    exited: threading.Event = field(default_factory=threading.Event)

    def end(self, exit_code: int) -> None:
        if not self.exited.is_set():
            self.exit_code = exit_code
            self.exited.set()


class FakeDocker(socketserver.ThreadingMixIn, socketserver.UnixStreamServer):
    daemon_threads = True

    def __init__(self, path: str) -> None:
        super().__init__(path, _FakeDockerHandler)
        self.calls: list[tuple[str, str, dict[str, str], bytes]] = []
        self.run: FakeRun | None = None
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
        path = self.path.split("?", 1)[0]
        run = self.server.run
        if path.endswith("/containers/create"):
            self._create()
        elif path.endswith("/attach"):
            self._attach_route(run)
        elif path.endswith("/wait"):
            self._wait(run)
        elif self.command == "DELETE":
            self._remove(run)
        elif run is not None and path.endswith("/start"):
            if run.start_status == 204:
                run.started.set()
            self._reply(run.start_status, b"")
        elif run is not None and path.endswith("/kill"):
            run.killed.set()
            run.end(KILLED_EXIT_CODE)
            self._reply(204, b"")
        else:
            self._reply(204, b"")

    def _create(self) -> None:
        if self.server.drop_create_reply:
            return
        if self.server.create_entered is not None:
            self.server.create_entered.set()
        if self.server.create_release is not None:
            assert self.server.create_release.wait(5)
        self._reply(self.server.create_status, json.dumps({"Id": self.server.next_id}).encode())

    def _attach_route(self, run: FakeRun | None) -> None:
        if run is None:
            self.wfile.write(b"HTTP/1.1 101 UPGRADED\r\nUpgrade: tcp\r\n\r\ntool-output")
        else:
            self._attach(run)

    def _wait(self, run: FakeRun | None) -> None:
        if (
            run is not None
            and self.server.wait_status == 200
            and self.path.endswith("?condition=removed")
        ):
            self._wait_removed(run)
        else:
            self._reply(self.server.wait_status, self.server.wait_body)

    def _remove(self, run: FakeRun | None) -> None:
        if self.server.drop_remove_reply:
            return
        if run is not None:
            run.end(KILLED_EXIT_CODE)
        self._reply(self.server.remove_status, b"")

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

    def _attach(self, run: FakeRun) -> None:
        if run.attach_status != 101:
            self._reply(run.attach_status, b'{"message": "attach failed"}')
            return
        self.wfile.write(ATTACH_HEAD)
        self.wfile.flush()
        if not run.started.wait(FAKE_TIMEOUT_SECONDS):
            return
        try:
            for chunk in run.chunks:
                self.wfile.write(chunk)
                self.wfile.flush()
        except OSError:
            pass  # the reader went away (output cap or wall time): the run carries on
        if run.hold_open:
            run.killed.wait(FAKE_TIMEOUT_SECONDS)
        if not run.hold_exit:
            run.end(run.exit_code)

    def _wait_removed(self, run: FakeRun) -> None:
        if not run.exited.wait(FAKE_TIMEOUT_SECONDS):
            self._reply(500, b'{"message": "fake run never ended"}')
            return
        self._reply(200, json.dumps({"StatusCode": run.exit_code}).encode())

    def _reply(self, status: int, body: bytes) -> None:
        self.send_response(status)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        if body:
            self.wfile.write(body)


@contextmanager
def serving[Server: socketserver.BaseServer](server: Server) -> Iterator[Server]:
    """Serve `server` on a daemon thread for the duration of the block."""
    thread = threading.Thread(target=server.serve_forever, args=(0.01,), daemon=True)
    thread.start()
    try:
        yield server
    finally:
        server.shutdown()
        server.server_close()
