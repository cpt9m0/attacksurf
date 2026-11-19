"""Ends an LLM request at its call deadline, wherever it is on the wire (ADR 0019).

The SDKs' timeouts bound each wait for data, not a whole request: a server that sends a byte
every few seconds keeps a request alive forever. So both adapters build their SDK client on
`deadline_transport()` and send each request inside `until(deadline)`. Its network layer gives
every connect, TLS handshake, read and write at most the time left before that deadline, and
fails once it has passed. The request ends in the caller's own thread and its connection is
closed: nothing keeps running after `complete()` returns.
"""

import socket
from collections.abc import Iterable, Iterator
from contextlib import contextmanager
from contextvars import ContextVar
from ssl import SSLContext
from time import monotonic
from typing import Any, cast

import httpcore2
import httpx2

from attacksurf.domain.scope import AddressError, check_addresses

# The `monotonic()` time the call in progress must end by; None outside an `until` block.
_deadline: ContextVar[float | None] = ContextVar("llm_call_deadline", default=None)


@contextmanager
def until(deadline: float) -> Iterator[None]:
    """Requests sent inside this block fail once `deadline` (a `monotonic()` time) passes."""
    token = _deadline.set(deadline)
    try:
        yield
    finally:
        _deadline.reset(token)


def deadline_transport(*, block_private_ips: bool = False) -> httpx2.HTTPTransport:
    """An HTTP transport whose every network operation respects the current `until` block.

    When `block_private_ips` is True, every resolved IP is verified with ScopeGuard right before
    TCP dialing to close DNS-rebinding TOCTOU windows for org-supplied base URLs.
    """
    return _DeadlineTransport(block_private_ips=block_private_ips)


class _DeadlineTransport(httpx2.HTTPTransport):
    def __init__(self, *, block_private_ips: bool = False) -> None:
        ssl_context = httpx2.create_ssl_context()
        super().__init__(verify=ssl_context)
        # HTTPTransport takes no network backend, so its pool is rebuilt on one, with
        # HTTPTransport's default limits. The trickling-server tests fail if this stops working.
        self._pool = httpcore2.ConnectionPool(
            ssl_context=ssl_context,
            max_connections=100,
            max_keepalive_connections=20,
            keepalive_expiry=5.0,
            network_backend=_DeadlineBackend(block_private_ips=block_private_ips),
        )


class _DeadlineBackend(httpcore2.SyncBackend):
    def __init__(self, *, block_private_ips: bool = False) -> None:
        super().__init__()
        self._block_private_ips = block_private_ips

    def connect_tcp(
        self,
        host: str,
        port: int,
        timeout: float | None = None,
        local_address: str | None = None,
        socket_options: Iterable[httpcore2.SOCKET_OPTION] | None = None,
    ) -> httpcore2.NetworkStream:
        # Resolve once, then try each address with a freshly capped timeout.
        # `socket.create_connection` gives every address the same timeout, so
        # black-holed early addresses could push the whole connect past the deadline.
        if host.startswith("["):
            host = host[1:-1]
        try:
            targets = socket.getaddrinfo(host, port, type=socket.SOCK_STREAM)
        except TimeoutError as exc:
            raise httpcore2.ConnectTimeout(exc) from exc
        except OSError as exc:
            raise httpcore2.ConnectError(exc) from exc
        if self._block_private_ips and targets:
            resolved = tuple(cast(str, sockaddr[0]) for _, _, _, _, sockaddr in targets)
            try:
                check_addresses(resolved)
            except AddressError as exc:
                raise httpcore2.ConnectError("Target address is blocked by ScopeGuard.") from exc
        error: httpcore2.ConnectError | httpcore2.ConnectTimeout | None = None
        for _, _, _, _, sockaddr in targets:
            # Recomputed per attempt: an earlier slow address must not extend the
            # whole connect past the deadline. Raises once the deadline has passed.
            attempt_timeout = _capped(timeout, httpcore2.ConnectTimeout)
            address = cast(str, sockaddr[0])  # the host part of an IPv4/IPv6 sockaddr
            try:
                stream = super().connect_tcp(
                    address, port, attempt_timeout, local_address, socket_options
                )
            except (httpcore2.ConnectError, httpcore2.ConnectTimeout) as exc:
                error = exc
                continue
            return _DeadlineStream(stream)
        raise (
            error
            if error is not None
            else httpcore2.ConnectError("getaddrinfo returns an empty list")
        )


class _DeadlineStream(httpcore2.NetworkStream):
    def __init__(self, stream: httpcore2.NetworkStream) -> None:
        self._stream = stream

    def read(self, max_bytes: int, timeout: float | None = None) -> bytes:
        return self._stream.read(max_bytes, _capped(timeout, httpcore2.ReadTimeout))

    def write(self, buffer: bytes, timeout: float | None = None) -> None:
        self._stream.write(buffer, _capped(timeout, httpcore2.WriteTimeout))

    def close(self) -> None:
        self._stream.close()

    def start_tls(
        self,
        ssl_context: SSLContext,
        server_hostname: str | None = None,
        timeout: float | None = None,
    ) -> httpcore2.NetworkStream:
        tls = self._stream.start_tls(
            ssl_context, server_hostname, _capped(timeout, httpcore2.ConnectTimeout)
        )
        return _DeadlineStream(tls)

    def get_extra_info(self, info: str) -> Any:
        return self._stream.get_extra_info(info)


def _capped(timeout: float | None, timed_out: type[httpcore2.TimeoutException]) -> float | None:
    """`timeout`, cut to the time left before the current deadline; `timed_out` once it passed."""
    deadline = _deadline.get()
    if deadline is None:
        return timeout
    remaining = deadline - monotonic()
    if remaining <= 0:
        raise timed_out("the LLM call deadline has passed")
    return remaining if timeout is None else min(timeout, remaining)
