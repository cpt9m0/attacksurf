"""The launcher's only entry point: "run analyzer X on artifact Y", and nothing else (ADR 0016).

The caller names an analyzer and an artifact ID and can choose nothing more: the image, command,
mount and limits come from the loaded catalog and the artifact root. So a compromised worker can
only pick from the fixed menu, on artifacts the fetcher put under the root. Anything shaped
differently is refused before any sandbox exists, and a bad request never holds a run slot.

Every message is fixed text and every log line carries a status and a reason, never a request
value: request fields are caller-controlled and the reply bytes are scanned content. There is no
authentication; the launcher is reachable only on the internal network, and the artifact's owner
is checked by the worker before it asks.
"""

import base64
import json
import threading
from collections.abc import Callable, Mapping
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any, NoReturn
from uuid import UUID

import structlog

from attacksurf.sandbox_launcher.artifacts import ArtifactNotFound, resolve_artifact
from attacksurf.sandbox_launcher.catalog import ANALYZER_NAME, Analyzer
from attacksurf.sandbox_launcher.runner import RunOutcome, SandboxRunFailed

MAX_REQUEST_BYTES = 1024
CLIENT_TIMEOUT_SECONDS = 30

_MALFORMED = "Request is malformed."
_NOT_FOUND = "Analyzer or artifact not found."

log = structlog.get_logger(__name__)


class _Reject(Exception):
    """A request refused with a fixed status and message."""

    def __init__(self, status: int, message: str) -> None:
        super().__init__(message)
        self.status = status
        self.message = message


class LauncherServer(ThreadingHTTPServer):
    daemon_threads = True

    def __init__(
        self,
        address: tuple[str, int],
        *,
        catalog: Mapping[str, Analyzer],
        artifact_root: Path,
        run: Callable[[Analyzer, Path], RunOutcome],
        max_concurrent_runs: int,
    ) -> None:
        super().__init__(address, _LauncherHandler)
        self.catalog = catalog
        self.artifact_root = artifact_root
        self.run = run
        self.slots = threading.BoundedSemaphore(max_concurrent_runs)


def make_server(
    host: str,
    port: int,
    *,
    catalog: Mapping[str, Analyzer],
    artifact_root: Path,
    run: Callable[[Analyzer, Path], RunOutcome],
    max_concurrent_runs: int,
) -> LauncherServer:
    """`run` is injected so tests (and `__main__`) decide how a run happens."""
    return LauncherServer(
        (host, port),
        catalog=catalog,
        artifact_root=artifact_root,
        run=run,
        max_concurrent_runs=max_concurrent_runs,
    )


def _reject_duplicate_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result = dict(pairs)
    if len(result) != len(pairs):
        raise _Reject(400, _MALFORMED)
    return result


def _malformed() -> NoReturn:
    raise _Reject(400, _MALFORMED)


def _parse_run_request(raw: bytes) -> tuple[str, UUID]:
    """Exactly `{"analyzer": str, "artifact_id": str}`; the ID in canonical form only."""
    try:
        parsed = json.loads(raw, object_pairs_hook=_reject_duplicate_keys)
    except (ValueError, RecursionError):
        _malformed()
    if not isinstance(parsed, dict) or set(parsed) != {"analyzer", "artifact_id"}:
        _malformed()
    name, artifact_id = parsed["analyzer"], parsed["artifact_id"]
    if not isinstance(name, str) or not ANALYZER_NAME.fullmatch(name):
        _malformed()
    if not isinstance(artifact_id, str):
        _malformed()
    try:
        artifact = UUID(artifact_id)
    except ValueError:
        _malformed()
    if str(artifact) != artifact_id:  # lowercase and hyphenated, so one ID has one spelling
        _malformed()
    return name, artifact


class _LauncherHandler(BaseHTTPRequestHandler):
    server: LauncherServer  # type: ignore[assignment]
    timeout = CLIENT_TIMEOUT_SECONDS

    def log_message(self, format: str, *args: Any) -> None:
        """Silence stdlib access logs; rejections are logged with a safe reason instead."""

    def do_GET(self) -> None:
        self._dispatch(allowed={"/healthz": self._healthz})

    def do_POST(self) -> None:
        self._dispatch(allowed={"/runs": self._run})

    def _method_not_allowed(self) -> None:
        self._dispatch(allowed={})

    do_HEAD = do_PUT = do_PATCH = do_DELETE = do_OPTIONS = _method_not_allowed

    def _dispatch(self, allowed: Mapping[str, Callable[[], None]]) -> None:
        try:
            handler = allowed.get(self.path)
            if handler is not None:
                handler()
            elif self.path in ("/healthz", "/runs"):
                raise _Reject(405, "Method not allowed.")
            else:
                raise _Reject(404, "Not found.")
        except _Reject as rejection:
            log.warning(
                "sandbox_launcher_rejected", status=rejection.status, reason=rejection.message
            )
            self._reply(rejection.status, {"message": rejection.message})

    def _healthz(self) -> None:
        self._reply(200, {"status": "ok"})

    def _run(self) -> None:
        name, artifact_id = _parse_run_request(self._read_body())
        tool = self.server.catalog.get(name)
        if tool is None:
            raise _Reject(404, _NOT_FOUND)  # before the filesystem, so unknown names cost nothing
        try:
            artifact_dir = resolve_artifact(self.server.artifact_root, artifact_id)
        except ArtifactNotFound:
            raise _Reject(404, _NOT_FOUND) from None
        if not self.server.slots.acquire(blocking=False):
            raise _Reject(503, "Sandbox is busy.")
        try:
            outcome = self.server.run(tool, artifact_dir)
        except SandboxRunFailed:
            raise _Reject(503, "Sandbox run failed.") from None
        except Exception as error:
            # The type name only: a message could carry paths or scanned values.
            log.error("sandbox_launcher_error", error_type=type(error).__name__)
            raise _Reject(500, "Internal error.") from None
        finally:
            self.server.slots.release()
        self._reply(
            200,
            {
                "exit_code": outcome.exit_code,
                "stdout_b64": base64.b64encode(outcome.stdout).decode("ascii"),
                "timed_out": outcome.timed_out,
                "output_exceeded": outcome.output_exceeded,
            },
        )

    def _read_body(self) -> bytes:
        content_type = self.headers.get("Content-Type", "").split(";")[0].strip().lower()
        if content_type != "application/json" or self.headers.get("Transfer-Encoding"):
            _malformed()
        try:
            length = int(self.headers.get("Content-Length", ""))
        except ValueError:
            _malformed()
        if not 1 <= length <= MAX_REQUEST_BYTES:
            _malformed()  # refused before reading, so an oversized body is never buffered
        return self.rfile.read(length)

    def _reply(self, status: int, payload: dict[str, Any]) -> None:
        body = json.dumps(payload).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        if self.command != "HEAD":
            self.wfile.write(body)
