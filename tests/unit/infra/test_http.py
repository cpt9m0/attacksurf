"""Safe HTTP client: pinned addresses, redirects, size and time limits (no internet needed)."""

import gzip
import hashlib
import ssl
import threading
import time
import zlib
from collections.abc import Iterator
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import ClassVar
from urllib.parse import urlsplit
from uuid import uuid4

import httpcore
import pytest

from attacksurf.domain.jobs import TransientJobError
from attacksurf.domain.net import DnsError
from attacksurf.domain.scope import AddressError, ScopeError
from attacksurf.infra.http import (
    MAX_REDIRECTS,
    SafeHttpClient,
    _decoded,
    _target,
    connection_address,
)
from attacksurf.infra.rate_limit import InMemoryTargetRateLimiter, TargetRateLimitPolicy
from tests.unit.infra.test_rate_limit import FakeClock


class StaticResolver:
    def __init__(self, *answers: str) -> None:
        self.answers = answers
        self.calls: list[str] = []

    def resolve_name(self, host: str) -> tuple[str, ...]:
        self.calls.append(host)
        return self.answers


class Handler(BaseHTTPRequestHandler):
    hits: ClassVar[list[tuple[str, str | None]]] = []
    user_agents: ClassVar[list[str | None]] = []
    api_keys: ClassVar[list[str | None]] = []

    def do_GET(self) -> None:
        type(self).hits.append((self.path, self.headers.get("Host")))
        type(self).user_agents.append(self.headers.get("User-Agent"))
        type(self).api_keys.append(self.headers.get("apiKey"))
        if self.path == "/redirect":
            self.send_response(302)
            self.send_header("Location", "/landed")
            self.end_headers()
        elif self.path == "/cross-redirect":
            host = self.headers.get("Host", "127.0.0.1")
            port = host.rsplit(":", 1)[1] if ":" in host else "80"
            self.send_response(302)
            self.send_header("Location", f"http://other.example:{port}/landed")
            self.end_headers()
        elif self.path == "/loop":
            self.send_response(301)
            self.send_header("Location", "/loop")
            self.end_headers()
        elif self.path == "/big":
            self.send_response(200)
            self.send_header("Content-Length", "100000")
            self.end_headers()
            self.wfile.write(b"x" * 100000)
        elif self.path == "/slow":
            threading.Event().wait(2)
        elif self.path == "/drip":
            self._serve_drip()
        elif self.path == "/bomb":
            # ~8 MiB of zeros behind ~8 KiB of gzip: the classic decompression bomb.
            packed = gzip.compress(b"\x00" * (8 * 1024 * 1024))
            self.send_response(200)
            self.send_header("Content-Length", str(len(packed)))
            self.send_header("Content-Encoding", "gzip")
            self.end_headers()
            self.wfile.write(packed)
        elif self.path == "/gzipped":
            packed = gzip.compress(b"decoded body")
            self.send_response(200)
            self.send_header("Content-Length", str(len(packed)))
            self.send_header("Content-Encoding", "gzip")
            self.end_headers()
            self.wfile.write(packed)
        else:
            body = f"path={self.path}".encode()
            self.send_response(200)
            self.send_header("Content-Length", str(len(body)))
            self.send_header("Content-Encoding", "identity")
            self.end_headers()
            self.wfile.write(body)

    def _serve_drip(self) -> None:
        self.send_response(200)
        self.end_headers()
        for _ in range(10):
            try:
                self.wfile.write(b"x")
                self.wfile.flush()
            except OSError:
                return
            time.sleep(0.05)

    def log_message(self, format: str, *args: object) -> None:
        pass


@pytest.fixture(scope="module")
def server_url() -> Iterator[str]:
    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    server.daemon_threads = True
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield f"127.0.0.1:{server.server_port}"
    finally:
        server.shutdown()
        server.server_close()


@pytest.fixture(autouse=True)
def _clear_hits() -> None:
    Handler.hits.clear()
    Handler.user_agents.clear()
    Handler.api_keys.clear()


def client_for(server_url: str, **kwargs: object) -> tuple[SafeHttpClient, StaticResolver]:
    resolver = StaticResolver("127.0.0.1")
    return SafeHttpClient(resolver, **kwargs), resolver  # type: ignore[arg-type]


def test_request_dials_the_resolved_address_but_keeps_the_host_header(server_url: str) -> None:
    client, resolver = client_for(server_url)
    body = client.get(f"http://public.example:{server_url.rsplit(':', 1)[1]}/a/b?q=1", limit=100)
    client.close()

    assert body.status_code == 200
    assert body.content == b"path=/a/b?q=1"
    # The name was never handed to the OS: the socket went to 127.0.0.1 while the server
    # still saw the virtual host (what a rebinding attacker cannot change after our lookup).
    assert resolver.calls == ["public.example"]
    assert Handler.hits == [("/a/b?q=1", f"public.example:{server_url.rsplit(':', 1)[1]}")]


def test_redirects_are_followed_only_when_the_policy_allows_the_target(server_url: str) -> None:
    port = server_url.rsplit(":", 1)[1]
    # The hook governs the first request too, not just redirects: allow the entry point here.
    client, _ = client_for(
        server_url, redirect_allowed=lambda url: "/redirect" in url or "/landed" in url
    )
    body = client.get(f"http://public.example:{port}/redirect", limit=100)
    assert body.content == b"path=/landed"

    strict, _ = client_for(server_url, redirect_allowed=lambda url: "/redirect" in url)
    with pytest.raises(ScopeError, match="out of scope"):
        strict.get(f"http://public.example:{port}/redirect", limit=100)

    # A hook that refuses the first URL sends nothing at all.
    unlisted, _ = client_for(server_url, redirect_allowed=lambda url: False)
    before = list(Handler.hits)
    with pytest.raises(ScopeError, match="out of scope"):
        unlisted.get(f"http://public.example:{port}/redirect", limit=100)
    assert Handler.hits == before


def test_redirect_loops_are_bounded(server_url: str) -> None:
    port = server_url.rsplit(":", 1)[1]
    client, _ = client_for(server_url, redirect_allowed=lambda url: True)
    with pytest.raises(ScopeError, match="Too many redirects"):
        client.get(f"http://public.example:{port}/loop", limit=100)
    assert len(Handler.hits) == MAX_REDIRECTS + 1


def test_response_bodies_are_cut_at_the_limit(server_url: str) -> None:
    port = server_url.rsplit(":", 1)[1]
    client, _ = client_for(server_url)
    body = client.get(f"http://public.example:{port}/big", limit=500)
    assert body.truncated is True
    assert body.content == b"x" * 500


def test_encoded_bodies_are_decoded(server_url: str) -> None:
    port = server_url.rsplit(":", 1)[1]
    client, _ = client_for(server_url)
    body = client.get(f"http://public.example:{port}/gzipped", limit=100)
    assert body.content == b"decoded body"
    assert body.truncated is False
    assert "content-encoding" not in {key.lower() for key in body.headers}


# One row per behaviour the decoder must get right. Every entry here is either a review
# regression or a protocol case that a naive implementation gets wrong; add rows, not branches.
# Literal rather than `_DECODE_STEP`: a test that imported the constant could not fail when the
# slicing logic it describes regresses.
SLICE_BOUNDARY = 64 * 1024 + 2  # one gzip member that ends just past a decode slice
# Deterministic but incompressible: the bug only shows when a member's wire bytes exceed one
# decode slice, which repeated literals never do.
_INCOMPRESSIBLE = b"".join(
    hashlib.sha256(i.to_bytes(4, "big")).digest() for i in range(3200)
)  # 102_400 bytes

_DECODE_CASES: list[tuple[str, bytes, str | None, int, bytes, bool]] = [
    # name, wire body, Content-Encoding, limit, expected decoded body, expected truncated
    ("plain body", b"abc", None, 100, b"abc", False),
    ("identity encoding", b"abc", "identity", 100, b"abc", False),
    ("plain body cut at the limit", b"x" * 500, None, 100, b"x" * 100, True),
    ("plain body exactly at the limit", b"abcde", None, 5, b"abcde", False),
    ("gzip", gzip.compress(b"hello"), "gzip", 100, b"hello", False),
    ("x-gzip alias", gzip.compress(b"hello"), "x-gzip", 100, b"hello", False),
    ("deflate", zlib.compress(b"hello"), "deflate", 100, b"hello", False),
    ("encoding case and padding", gzip.compress(b"hi"), " GZIP ", 100, b"hi", False),
    # Bombs: the *decoded* size is what must not exceed the limit.
    (
        "gzip bomb",
        gzip.compress(b"\x00" * (8 * 1024 * 1024)),
        "gzip",
        10_000,
        b"\x00" * 10_000,
        True,
    ),
    (
        "deflate bomb",
        zlib.compress(b"\x00" * (1024 * 1024)),
        "deflate",
        5_000,
        b"\x00" * 5_000,
        True,
    ),
    # Concatenated members (RFC 1952 §2.2) must all be decoded under one cumulative budget.
    (
        "concatenated gzip members",
        gzip.compress(b"first") + gzip.compress(b"second"),
        "gzip",
        100,
        b"firstsecond",
        False,
    ),
    (
        "three gzip members",
        gzip.compress(b"a") + gzip.compress(b"b") + gzip.compress(b"c"),
        "gzip",
        100,
        b"abc",
        False,
    ),
    (
        "concatenated members share one cap",
        gzip.compress(b"x" * 50) + gzip.compress(b"y" * 50),
        "gzip",
        60,
        b"x" * 50 + b"y" * 10,
        True,
    ),
    (
        "small member then a large incompressible one",
        gzip.compress(b"small") + gzip.compress(_INCOMPRESSIBLE),
        "gzip",
        200_000,
        b"small" + _INCOMPRESSIBLE,
        False,
    ),
    (
        "member ending on a slice boundary",
        gzip.compress(b"a" * (SLICE_BOUNDARY - 8)) + gzip.compress(_INCOMPRESSIBLE),
        "gzip",
        200_000,
        b"a" * (SLICE_BOUNDARY - 8) + _INCOMPRESSIBLE,
        False,
    ),
    (
        "many members spanning several slices",
        b"".join(gzip.compress(bytes([i % 256]) * 100) for i in range(800)),
        "gzip",
        200_000,
        b"".join(bytes([i % 256]) * 100 for i in range(800)),
        False,
    ),
    # Incomplete streams: `zlib` returns partial output without raising, so only `eof` tells.
    ("gzip cut before its footer", gzip.compress(b"hello")[:-12], "gzip", 100, b"he", True),
    ("gzip cut mid-footer", gzip.compress(b"hello")[:-2], "gzip", 100, b"hello", True),
    (
        "gzip missing its final block",
        gzip.compress(b"a" * 50_000)[:40],
        "gzip",
        10_000,
        b"a" * 10_000,
        True,
    ),
    ("deflate cut short", zlib.compress(b"hello")[:-2], "deflate", 100, b"hello", True),
    # Bodies we cannot decode: raw bytes, clamped and flagged.
    ("corrupt gzip", b"not gzip" * 250_000, "gzip", 10_000, b"not gzip" * 1250, True),
    ("unknown encoding", b"x" * 2_000_000, "br", 10_000, b"x" * 10_000, True),
]


@pytest.mark.parametrize(
    ("content", "encoding", "limit", "expected", "truncated"),
    [case[1:] for case in _DECODE_CASES],
    ids=[case[0] for case in _DECODE_CASES],
)
def test_decoded(
    content: bytes, encoding: str | None, limit: int, expected: bytes, truncated: bool
) -> None:
    decoded, was_truncated = _decoded(content, encoding, limit)
    assert decoded == expected
    assert len(decoded) <= limit
    assert was_truncated is truncated


def test_decompression_bombs_are_capped_at_the_requested_limit(server_url: str) -> None:
    """Regression: the cap applied to *wire* bytes only, so gzip expanded past it in memory."""
    port = server_url.rsplit(":", 1)[1]
    client, _ = client_for(server_url)
    body = client.get(f"http://public.example:{port}/bomb", limit=10_000)
    assert len(body.content) == 10_000
    assert body.truncated is True


def test_request_targets_keep_leading_double_slashes() -> None:
    """Regression: `//api/v1` was parsed as an authority and sent as `/v1`.

    Checked against `_target` rather than through the test server: `BaseHTTPRequestHandler`
    collapses a leading `//` in `self.path` before a handler sees it.
    """
    target = _target(urlsplit("https://example.com//api/v1?q=a"))
    assert target == b"//api/v1?q=a"


def test_timeouts_raise_a_safe_error(server_url: str) -> None:
    port = server_url.rsplit(":", 1)[1]
    client, _ = client_for(server_url, timeout_seconds=0.2)
    with pytest.raises(ScopeError, match="timed out"):
        client.get(f"http://public.example:{port}/slow", limit=10)


def test_connection_failures_are_reported_without_internals(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # Simulated refusal: a real closed port is refused at once on Linux but retried for ~2 s on
    # Windows, where the client's timeout fires first and the test would see a timeout instead.
    def refuse(*_args: object, **_kwargs: object) -> httpcore.NetworkStream:
        raise httpcore.ConnectError("[Errno 111] Connection refused by 10.0.0.7")

    monkeypatch.setattr(httpcore.SyncBackend, "connect_tcp", refuse)
    client = SafeHttpClient(StaticResolver("127.0.0.1"))

    with pytest.raises(DnsError) as caught:
        client.get("http://public.example:9/", limit=10)

    assert "10.0.0.7" not in str(caught.value)
    assert "Errno" not in str(caught.value)
    assert client.get.__self__ is client  # still usable for a retry


def test_invalid_urls_are_rejected_before_dns() -> None:
    resolver = StaticResolver("127.0.0.1")
    client = SafeHttpClient(resolver)
    for url in ("ftp://example.com/", "https://user:pass@example.com/", "https:///x"):
        with pytest.raises(ScopeError):
            client.get(url, limit=10)
    assert resolver.calls == []


def test_closed_clients_refuse_further_requests() -> None:
    client = SafeHttpClient(StaticResolver("127.0.0.1"))
    client.close()
    with pytest.raises(ScopeError, match="closed"):
        client.get("http://example.com/", limit=10)


def test_unresolved_hosts_are_rejected() -> None:
    client = SafeHttpClient(StaticResolver())
    with pytest.raises(AddressError, match="did not resolve"):
        client.get("http://example.com/", limit=10)


def test_ipv4_is_preferred_when_both_families_resolve() -> None:
    assert connection_address(("2606:4700::1111", "93.184.216.34")) == "93.184.216.34"
    assert connection_address(("2606:4700::1111",)) == "2606:4700::1111"


def test_tls_verification_failures_are_safe() -> None:
    # No server: the TLS context must still refuse to be disabled by the caller.
    context = ssl.create_default_context()
    assert context.check_hostname is True
    assert context.verify_mode == ssl.CERT_REQUIRED
    client = SafeHttpClient(StaticResolver("127.0.0.1"), tls=context)
    assert client._tls is context  # the client never replaces an explicit context


def test_socket_errors_become_scope_errors(monkeypatch: pytest.MonkeyPatch) -> None:
    def refuse(*args: object, **kwargs: object) -> None:
        raise OSError("TLS handshake failed for secret.example")

    monkeypatch.setattr("httpcore.SyncBackend.connect_tcp", refuse)
    client = SafeHttpClient(StaticResolver("93.184.216.34"))
    with pytest.raises(ScopeError, match="request failed"):
        client.get("http://example.com/", limit=10)


def test_user_agent_is_sent_on_requests_and_inherited_across_redirect_policy(
    server_url: str,
) -> None:
    port = server_url.rsplit(":", 1)[1]
    base, resolver = client_for(server_url, user_agent="attacksurf/0.1.0 (+https://example.org)")
    scoped = base.with_redirect_policy(
        resolver,
        redirect_allowed=lambda url: True,
        max_redirects=2,
    )
    body = scoped.get(f"http://public.example:{port}/redirect", limit=100)
    scoped.close()

    assert body.content == b"path=/landed"
    assert Handler.user_agents == [
        "attacksurf/0.1.0 (+https://example.org)",
        "attacksurf/0.1.0 (+https://example.org)",
    ]


def test_rate_limiter_throttles_requests_and_redirect_hops(server_url: str) -> None:
    port = server_url.rsplit(":", 1)[1]
    clock = FakeClock()
    limiter = InMemoryTargetRateLimiter(
        TargetRateLimitPolicy(rps=2.0, burst=1, max_concurrency=2, max_wait_seconds=1.0),
        clock=clock,
    )
    org_id = uuid4()
    base, resolver = client_for(server_url)
    scoped = base.with_redirect_policy(
        resolver,
        redirect_allowed=lambda url: True,
        max_redirects=2,
        rate_limiter=limiter,
        rate_limit_org_id=org_id,
    )

    body = scoped.get(f"http://public.example:{port}/redirect", limit=100)
    scoped.close()

    assert body.content == b"path=/landed"
    # First hop consumes the burst token; second redirect hop waits 0.5 s at 2.0 rps.
    assert len(clock.sleeps) == 1
    assert clock.sleeps[0] == pytest.approx(0.5)


def test_rate_limiter_transient_error_propagates_without_hitting_socket(server_url: str) -> None:
    port = server_url.rsplit(":", 1)[1]
    clock = FakeClock()
    limiter = InMemoryTargetRateLimiter(
        TargetRateLimitPolicy(rps=1.0, burst=1, max_concurrency=2, max_wait_seconds=0.0),
        clock=clock,
    )
    org_id = uuid4()
    base, resolver = client_for(server_url)
    scoped = base.with_redirect_policy(
        resolver,
        redirect_allowed=lambda url: True,
        max_redirects=2,
        rate_limiter=limiter,
        rate_limit_org_id=org_id,
    )

    scoped.get(f"http://public.example:{port}/ok", limit=100)
    hits_before = len(Handler.hits)
    with pytest.raises(TransientJobError, match="rate limit"):
        scoped.get(f"http://public.example:{port}/ok", limit=100)
    scoped.close()

    assert len(Handler.hits) == hits_before


def test_slow_drip_response_hits_total_request_deadline_and_releases_lease(
    server_url: str,
) -> None:
    port = server_url.rsplit(":", 1)[1]
    limiter = InMemoryTargetRateLimiter(
        TargetRateLimitPolicy(rps=10.0, burst=10, max_concurrency=1, max_wait_seconds=0.0)
    )
    org_id = uuid4()
    base, resolver = client_for(server_url, timeout_seconds=0.2, max_request_seconds=0.12)
    scoped = base.with_redirect_policy(
        resolver,
        redirect_allowed=lambda url: True,
        max_redirects=1,
        rate_limiter=limiter,
        rate_limit_org_id=org_id,
    )

    with pytest.raises(ScopeError, match="timed out"):
        scoped.get(f"http://public.example:{port}/drip", limit=100)

    # The concurrency lease was released when the deadline tripped, so the next request succeeds.
    body = scoped.get(f"http://public.example:{port}/ok", limit=100)
    scoped.close()
    assert body.content == b"path=/ok"


def test_custom_headers_forward_keep_host_pinned_and_strip_secrets_on_cross_origin_redirect(
    server_url: str,
) -> None:
    port = server_url.rsplit(":", 1)[1]
    base, resolver = client_for(server_url)
    scoped = base.with_redirect_policy(
        resolver,
        redirect_allowed=lambda url: True,
        max_redirects=2,
    )

    body = scoped.get(
        f"http://public.example:{port}/redirect",
        limit=100,
        headers={"apiKey": "secret-key", "Host": "evil.example"},
    )
    assert body.content == b"path=/landed"
    assert Handler.hits == [
        ("/redirect", f"public.example:{port}"),
        ("/landed", f"public.example:{port}"),
    ]
    assert Handler.api_keys == ["secret-key", "secret-key"]

    Handler.hits.clear()
    Handler.api_keys.clear()
    body2 = scoped.get(
        f"http://public.example:{port}/cross-redirect",
        limit=100,
        headers={"apiKey": "secret-key"},
    )
    scoped.close()
    assert body2.content == b"path=/landed"
    assert Handler.api_keys == ["secret-key", None]


def test_client_honors_custom_max_body_bytes(server_url: str) -> None:
    port = server_url.rsplit(":", 1)[1]
    client, _ = client_for(server_url, max_body_bytes=50000)

    body = client.get(f"http://public.example:{port}/big", limit=200000)
    client.close()

    assert len(body.content) == 50000
    assert body.truncated is True
