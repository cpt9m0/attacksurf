"""Run one analyzer in one sandbox and bring back its stdout (ADR 0016).

The order matters. Create the container; arm the removed-wait first, because `AutoRemove` deletes
the container the moment it exits and Docker then has nothing left to report an exit code from;
attach before start so no output is missed; start the wall-time clock and send start (the request
gets only the budget that is left, since the analyzer may run before Docker answers); read stdout
against the deadline; then take the exit code from the wait.

The deadline drives the reads: before every `recv` the socket timeout is set to the time left, so
the runner decides "timed out" itself and only then kills. No timer kills mid-read, so a
kill-truncated frame never reaches `read_stdout` to be mistaken for a malformed stream.

Whatever happens after a successful create, the container is killed and removed before the call
returns. Anything unexplained (a proxy error, a broken stream, an exit code nobody confirmed)
fails the run rather than guess; the one known case is a container that exits and is removed
before Docker registers the wait, which Docker answers with 404. Partial output is never returned
and neither stdout nor paths reach a log.
"""

import socket
import threading
import time
from collections.abc import Iterator
from contextlib import closing
from dataclasses import dataclass, field
from pathlib import Path

import structlog

from attacksurf.sandbox_launcher.catalog import Analyzer
from attacksurf.sandbox_launcher.container import build_create_body
from attacksurf.sandbox_launcher.proxy import CONTROL_TIMEOUT_SECONDS, ProxyClient, ProxyError
from attacksurf.sandbox_launcher.stream import MalformedStream, OutputLimitExceeded, read_stdout

# Longer than a kill needs, shorter than the proxy's own connection ceiling (a test pins the sum).
KILL_GRACE_SECONDS = 30

_RECV_BYTES = 64 * 1024

log = structlog.get_logger(__name__)


@dataclass(frozen=True)
class RunOutcome:
    """What a run produced. `stdout` is empty whenever a limit stopped the run."""

    exit_code: int | None
    stdout: bytes = field(repr=False)
    timed_out: bool = False
    output_exceeded: bool = False


class SandboxRunFailed(Exception):
    """The run could not be completed or trusted. The worker may retry it."""

    def __init__(self) -> None:
        super().__init__("Sandbox run failed.")


class _WallTimeExceeded(Exception):
    pass


class _Waiter:
    """The removed-wait on its own thread: it outlives the attach read and ends at the exit."""

    def __init__(self, proxy: ProxyClient, container_id: str, timeout: float) -> None:
        self.exit_code: int | None = None
        self._sent = threading.Event()
        self._thread = threading.Thread(
            target=self._run, args=(proxy, container_id, timeout), daemon=True
        )
        self._thread.start()

    def _run(self, proxy: ProxyClient, container_id: str, timeout: float) -> None:
        try:
            self.exit_code = proxy.wait_removed(container_id, timeout, self._sent.set)
        except ProxyError:
            pass
        finally:
            self._sent.set()  # a failed wait must not hold the run back

    def armed(self) -> None:
        """Hold until the wait request is on the wire (bounded), so start can't overtake it."""
        self._sent.wait(CONTROL_TIMEOUT_SECONDS)

    def ended(self, timeout: float) -> bool:
        """Wait up to `timeout` for the wait call to end, whether or not it confirmed an exit."""
        self._thread.join(max(timeout, 0))
        return not self._thread.is_alive()

    def confirmed(self, timeout: float) -> bool:
        """Wait up to `timeout`; True only when the wait ended with an exit code."""
        return self.ended(timeout) and self.exit_code is not None


def run_sandbox(
    proxy: ProxyClient,
    analyzer: Analyzer,
    artifact_dir: Path,
    *,
    runtime: str,
    wall_time: float,
) -> RunOutcome:
    """Run `analyzer` on `artifact_dir` (from `resolve_artifact`) and return what it printed.

    Raises `SandboxRunFailed` for anything but a clean exit, a wall-time kill or an output-cap
    kill; `ValueError` from the create-body builder passes through (a caller bug).
    """
    began = time.monotonic()
    body = build_create_body(analyzer, artifact_dir, runtime)
    waiter: _Waiter | None = None
    container_id: str | None = None
    outcome: RunOutcome | None = None
    failure: Exception | None = None
    try:
        container_id = proxy.create(body)
        waiter = _Waiter(proxy, container_id, wall_time + KILL_GRACE_SECONDS)
        outcome = _supervise(proxy, container_id, waiter, wall_time)
    except (ProxyError, MalformedStream, OSError) as error:
        failure = error
    finally:
        if container_id is not None and waiter is not None:
            _stop(proxy, container_id, waiter)
        _log(analyzer.spec.name, runtime, began, outcome, failure)
    if outcome is None:
        raise SandboxRunFailed
    return outcome


def _supervise(
    proxy: ProxyClient, container_id: str, waiter: _Waiter, wall_time: float
) -> RunOutcome:
    waiter.armed()
    sock, first = proxy.attach(container_id)
    with closing(sock):
        # The clock starts before `start` is sent: Docker may run the analyzer and then be slow to
        # answer, and that time counts. The request gets only what is left of the budget.
        deadline = time.monotonic() + wall_time
        try:
            proxy.start(container_id, min(CONTROL_TIMEOUT_SECONDS, deadline - time.monotonic()))
        except ProxyError as error:
            # No status means no reply (a timeout or a dropped connection). Past the deadline the
            # container may be running unsupervised, so report the wall-time kill, not a failure.
            if error.status is None and time.monotonic() >= deadline:
                return RunOutcome(None, b"", timed_out=True)
            raise
        try:
            stdout = read_stdout(_chunks(sock, first, deadline))
        except _WallTimeExceeded:
            return RunOutcome(None, b"", timed_out=True)
        except OutputLimitExceeded:
            return RunOutcome(None, b"", output_exceeded=True)
    # Stdout closed. A tool that closes it and keeps running still has to meet the deadline.
    if not waiter.ended(deadline - time.monotonic()):
        return RunOutcome(None, b"", timed_out=True)
    if waiter.exit_code is None:
        raise ProxyError("wait")
    return RunOutcome(waiter.exit_code, stdout)


def _chunks(sock_: socket.socket, first: bytes, deadline: float) -> Iterator[bytes]:
    if first:
        yield first
    while True:
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise _WallTimeExceeded
        sock_.settimeout(remaining)
        try:
            chunk = sock_.recv(_RECV_BYTES)
        except TimeoutError:
            raise _WallTimeExceeded from None
        if not chunk:
            return
        yield chunk


def _stop(proxy: ProxyClient, container_id: str, waiter: _Waiter) -> None:
    """Leave the container killed and removed; log what could not be confirmed."""
    if waiter.confirmed(0):
        return  # it exited and was removed: nothing left to stop
    killed = True
    try:
        proxy.kill(container_id)
    except ProxyError:
        killed = False
    if killed and waiter.confirmed(KILL_GRACE_SECONDS):
        return
    try:
        gone = proxy.remove(container_id)
    except ProxyError:
        gone = False
    if not gone:
        log.error("sandbox_cleanup_failed", container_id=container_id, stage="remove")


def _log(
    analyzer: str,
    runtime: str,
    began: float,
    outcome: RunOutcome | None,
    failure: Exception | None,
) -> None:
    """One metadata-only line per run: never stdout, stderr, paths or the create body."""
    fields: dict[str, object] = {
        "analyzer": analyzer,
        "runtime": runtime,
        "duration_ms": int((time.monotonic() - began) * 1000),
    }
    if outcome is None:
        fields["outcome"] = "failed"
        if isinstance(failure, ProxyError):
            fields.update(stage=failure.stage, status=failure.status)
        else:
            fields["stage"] = "stream"
    else:
        fields["outcome"] = (
            "timed_out"
            if outcome.timed_out
            else "output_exceeded"
            if outcome.output_exceeded
            else "exited"
        )
        fields.update(exit_code=outcome.exit_code, stdout_bytes=len(outcome.stdout))
    log.info("sandbox_run", **fields)
