"""The deadline network layer on real local sockets: requests end at the call deadline."""

import socket
from collections.abc import Iterable
from time import monotonic, sleep

import httpcore2
import httpx2
import pytest

from attacksurf.ai.providers.deadline import deadline_transport, until
from tests.unit.ai.providers.slow_server import TRICKLING_HEAD, SlowServer

COMPLETE = b"HTTP/1.1 200 OK\r\ncontent-type: application/json\r\ncontent-length: 2\r\n\r\n{}"
DEADLINE = 0.3


def _client() -> httpx2.Client:
    # A generous client timeout, so only the call deadline can end these requests early.
    return httpx2.Client(transport=deadline_transport(), timeout=30)


def test_request_outside_a_call_is_unchanged() -> None:
    with SlowServer(COMPLETE) as server, _client() as client:
        assert client.get(server.url).json() == {}


def test_request_that_finishes_in_time_is_unchanged() -> None:
    with SlowServer(COMPLETE) as server, _client() as client, until(monotonic() + 5):
        assert client.get(server.url).json() == {}


def test_trickling_body_is_cut_off_at_the_deadline() -> None:
    # Each byte arrives well inside the read timeout, so only the deadline can end this.
    with SlowServer(TRICKLING_HEAD, b" ") as server, _client() as client:
        started = monotonic()

        with until(started + DEADLINE), pytest.raises(httpx2.ReadTimeout):
            client.get(server.url)

        assert monotonic() - started < 2


def test_trickling_headers_are_cut_off_at_the_deadline() -> None:
    with SlowServer(b"HTTP/1.1 200 OK\r\nx-slow: ", b"a") as server, _client() as client:
        started = monotonic()

        with until(started + DEADLINE), pytest.raises(httpx2.ReadTimeout):
            client.get(server.url)

        assert monotonic() - started < 2


def test_cut_off_request_closes_its_connection() -> None:
    # The request itself ends, not just the wait for it: the server sees the client hang up.
    with SlowServer(TRICKLING_HEAD, b" ") as server, _client() as client:
        with until(monotonic() + DEADLINE), pytest.raises(httpx2.ReadTimeout):
            client.get(server.url)

        assert server.hung_up.wait(timeout=2)


def test_stalled_tls_handshake_is_cut_off_at_the_deadline() -> None:
    # The server accepts the connection but never answers the TLS hello.
    with SlowServer(b"") as server, _client() as client:
        started = monotonic()
        url = server.url.replace("http://", "https://")

        with until(started + DEADLINE), pytest.raises(httpx2.ConnectTimeout):
            client.get(url)

        assert monotonic() - started < 2


def test_no_connection_is_made_once_the_deadline_has_passed() -> None:
    with SlowServer(COMPLETE) as server, _client() as client:
        with until(monotonic() - 1), pytest.raises(httpx2.ConnectTimeout):
            client.get(server.url)

        assert not server.connected.wait(timeout=0.2)


def test_each_resolved_address_gets_a_freshly_capped_timeout(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # The first resolved address is black-holed; the retry must get only the time
    # left, not the whole remaining time again. The stall is faked: in this
    # sandbox even TEST-NET addresses complete a TCP handshake after seconds.
    stalled_for = 0.3
    with SlowServer(COMPLETE) as server:
        port = int(server.url.rsplit(":", 1)[1])
        calls: list[float | None] = []
        real_connect = httpcore2.SyncBackend.connect_tcp
        real_getaddrinfo = socket.getaddrinfo

        def fake_getaddrinfo(*args: object, **kwargs: object) -> list[object]:
            return [
                (socket.AF_INET, socket.SOCK_STREAM, 6, "", ("198.51.100.1", port)),
                (socket.AF_INET, socket.SOCK_STREAM, 6, "", ("127.0.0.1", port)),
            ]

        def flaky_connect(  # noqa: PLR0917 (mirrors httpcore2.SyncBackend.connect_tcp)
            self: httpcore2.SyncBackend,
            host: str,
            port: int,
            timeout: float | None = None,
            local_address: str | None = None,
            socket_options: Iterable[httpcore2.SOCKET_OPTION] | None = None,
        ) -> httpcore2.NetworkStream:
            calls.append(timeout)
            if len(calls) == 1:
                sleep(stalled_for)  # a black hole consumes the attempt's budget
                raise httpcore2.ConnectError("the first address is black-holed")
            # The real fallback resolves for real: the fake above would send it
            # back to the black hole through the inner `create_connection`.
            socket.getaddrinfo = real_getaddrinfo  # type: ignore[method-assign]
            try:
                return real_connect(self, host, port, timeout, local_address, socket_options)
            finally:
                socket.getaddrinfo = fake_getaddrinfo  # type: ignore[method-assign]

        monkeypatch.setattr(httpcore2.SyncBackend, "connect_tcp", flaky_connect)
        monkeypatch.setattr(socket, "getaddrinfo", fake_getaddrinfo)
        with _client() as client, until(monotonic() + 5):
            assert client.get(server.url).json() == {}

    assert len(calls) == 2
    first, second = calls
    assert first is not None
    assert second is not None
    assert second < first - stalled_for / 2


def test_connect_fails_when_every_resolved_address_fails(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    with SlowServer(COMPLETE) as server:
        port = int(server.url.rsplit(":", 1)[1])
        attempts = 0

        def failing_connect(  # noqa: PLR0917 (mirrors httpcore2.SyncBackend.connect_tcp)
            self: httpcore2.SyncBackend,
            host: str,
            port: int,
            timeout: float | None = None,
            local_address: str | None = None,
            socket_options: Iterable[httpcore2.SOCKET_OPTION] | None = None,
        ) -> httpcore2.NetworkStream:
            nonlocal attempts
            attempts += 1
            raise httpcore2.ConnectError("no route to the address")

        monkeypatch.setattr(httpcore2.SyncBackend, "connect_tcp", failing_connect)
        monkeypatch.setattr(
            socket,
            "getaddrinfo",
            lambda *args, **kwargs: [
                (socket.AF_INET, socket.SOCK_STREAM, 6, "", ("198.51.100.1", port)),
                (socket.AF_INET, socket.SOCK_STREAM, 6, "", ("198.51.100.2", port)),
            ],
        )
        with _client() as client, until(monotonic() + 5), pytest.raises(httpx2.ConnectError):
            client.get(server.url)

    assert attempts == 2


def test_connect_fails_when_nothing_resolves(monkeypatch: pytest.MonkeyPatch) -> None:
    with SlowServer(COMPLETE) as server:
        monkeypatch.setattr(socket, "getaddrinfo", lambda *args, **kwargs: [])
        with _client() as client, until(monotonic() + 5), pytest.raises(httpx2.ConnectError):
            client.get(server.url)

        assert not server.connected.wait(timeout=0.2)


def test_connect_fails_when_resolution_fails(monkeypatch: pytest.MonkeyPatch) -> None:
    with SlowServer(COMPLETE) as server:

        def failing_resolution(*args: object, **kwargs: object) -> list[object]:
            raise socket.gaierror("no such host")

        monkeypatch.setattr(socket, "getaddrinfo", failing_resolution)
        with _client() as client, until(monotonic() + 5), pytest.raises(httpx2.ConnectError):
            client.get(server.url)

        assert not server.connected.wait(timeout=0.2)


def test_block_private_ips_rejects_loopback_and_rebinding_before_dialing(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    with (
        SlowServer(COMPLETE) as server,
        httpx2.Client(transport=deadline_transport(block_private_ips=True), timeout=30) as blocked,
    ):
        with pytest.raises(httpx2.ConnectError, match="ScopeGuard"):
            blocked.get(server.url)
        assert not server.connected.wait(timeout=0.15)

        port = int(server.url.rsplit(":", 1)[1])
        dialed: list[str] = []

        def fake_connect(  # noqa: PLR0917 (mirrors httpcore2.SyncBackend.connect_tcp)
            self: httpcore2.SyncBackend,
            host: str,
            port: int,
            timeout: float | None = None,
            local_address: str | None = None,
            socket_options: Iterable[httpcore2.SOCKET_OPTION] | None = None,
        ) -> httpcore2.NetworkStream:
            dialed.append(host)
            raise AssertionError("must not dial when any resolved IP is private/metadata")

        with monkeypatch.context() as mp:
            mp.setattr(httpcore2.SyncBackend, "connect_tcp", fake_connect)
            mp.setattr(
                socket,
                "getaddrinfo",
                lambda *args, **kwargs: [
                    (socket.AF_INET, socket.SOCK_STREAM, 6, "", ("93.184.216.34", port)),
                    (socket.AF_INET, socket.SOCK_STREAM, 6, "", ("169.254.169.254", port)),
                ],
            )
            with pytest.raises(httpx2.ConnectError, match="ScopeGuard"):
                blocked.get("http://rebind.example/v1")
            assert dialed == []

    # block_private_ips=False keeps loopback usable for operator-configured / test endpoints.
    with (
        SlowServer(COMPLETE) as server,
        httpx2.Client(transport=deadline_transport(block_private_ips=False), timeout=30) as allowed,
    ):
        assert allowed.get(server.url).json() == {}
