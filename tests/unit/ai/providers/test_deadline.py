"""The deadline network layer on real local sockets: requests end at the call deadline."""

from time import monotonic

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
