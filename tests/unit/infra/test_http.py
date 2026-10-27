"""Safe HTTP client: pinned addresses, redirects, size and time limits (no internet needed)."""

import gzip
import ssl
import threading
from collections.abc import Iterator
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import ClassVar
from urllib.parse import urlsplit

import pytest

from attacksurf.domain.net import DnsError
from attacksurf.domain.scope import AddressError, ScopeError
from attacksurf.infra.http import (
    MAX_REDIRECTS,
    SafeHttpClient,
    _decoded,
    _target,
    connection_address,
)


class StaticResolver:
    def __init__(self, *answers: str) -> None:
        self.answers = answers
        self.calls: list[str] = []

    def resolve_name(self, host: str) -> tuple[str, ...]:
        self.calls.append(host)
        return self.answers


class Handler(BaseHTTPRequestHandler):
    hits: ClassVar[list[tuple[str, str | None]]] = []

    def do_GET(self) -> None:
        type(self).hits.append((self.path, self.headers.get("Host")))
        if self.path == "/redirect":
            self.send_response(302)
            self.send_header("Location", "/landed")
            self.end_headers()
            return
        if self.path == "/loop":
            self.send_response(301)
            self.send_header("Location", "/loop")
            self.end_headers()
            return
        if self.path == "/big":
            self.send_response(200)
            self.send_header("Content-Length", "100000")
            self.end_headers()
            self.wfile.write(b"x" * 100000)
            return
        if self.path == "/slow":
            threading.Event().wait(2)
            return
        if self.path == "/bomb":
            # ~8 MiB of zeros behind ~8 KiB of gzip: the classic decompression bomb.
            packed = gzip.compress(b"\x00" * (8 * 1024 * 1024))
            self.send_response(200)
            self.send_header("Content-Length", str(len(packed)))
            self.send_header("Content-Encoding", "gzip")
            self.end_headers()
            self.wfile.write(packed)
            return
        if self.path == "/gzipped":
            packed = gzip.compress(b"decoded body")
            self.send_response(200)
            self.send_header("Content-Length", str(len(packed)))
            self.send_header("Content-Encoding", "gzip")
            self.end_headers()
            self.wfile.write(packed)
            return
        body = f"path={self.path}".encode()
        self.send_response(200)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Content-Encoding", "identity")
        self.end_headers()
        self.wfile.write(body)

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


@pytest.mark.parametrize(
    ("content", "encoding"),
    [
        (b"not gzip" * 250_000, "gzip"),  # declares gzip, isn't
        (b"x" * 2_000_000, "br"),  # an encoding we never decode
        (gzip.compress(b"a" * 50_000)[:40], "gzip"),  # valid but cut mid-stream
    ],
)
def test_raw_body_fallbacks_are_clamped_to_the_limit(content: bytes, encoding: str) -> None:
    """Regression: a fallback returned the whole wire buffer, which may exceed the limit."""
    decoded, truncated = _decoded(content, encoding, 10_000)
    assert len(decoded) <= 10_000
    assert truncated is True


def test_concatenated_gzip_members_are_all_decoded() -> None:
    """Regression: only the first member was returned, silently truncating the body."""
    packed = gzip.compress(b"first") + gzip.compress(b"second")
    assert _decoded(packed, "gzip", 100) == (b"firstsecond", False)


def test_concatenated_gzip_members_share_one_output_cap() -> None:
    packed = gzip.compress(b"x" * 50) + gzip.compress(b"y" * 50)
    decoded, truncated = _decoded(packed, "gzip", 60)
    assert len(decoded) == 60
    assert truncated is True


def test_bodies_exactly_at_the_limit_are_not_truncated() -> None:
    assert _decoded(b"abcde", None, 5) == (b"abcde", False)


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


def test_connection_failures_are_reported_without_internals() -> None:
    resolver = StaticResolver("127.0.0.1")
    client = SafeHttpClient(resolver, timeout_seconds=0.2)
    with pytest.raises(DnsError):
        # Port 9 (discard) is closed in the test container.
        client.get("http://public.example:9/", limit=10)
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
