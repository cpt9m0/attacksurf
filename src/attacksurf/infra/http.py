"""Outbound HTTP for scanners: pinned IPs, re-validated redirects, hard size and time caps.

`httpx` handles URL parsing, header encoding and gzip decoding; connections go through `httpcore`
with a backend that dials an address the caller validated *after* resolving it (ADR 0013). TLS
still verifies the original hostname (SNI) and the `Host` header is untouched, so a server that
rebinds between our lookup and the connect can't redirect the socket somewhere else.
"""

import ipaddress
import ssl
import zlib
from collections.abc import Callable
from typing import Any, Protocol
from urllib.parse import SplitResult, urlsplit

import httpcore
import httpx

from attacksurf.domain.net import DnsError, HttpBody
from attacksurf.domain.scope import AddressError, ScopeError

REDIRECT_CODES = frozenset({301, 302, 303, 307, 308})
MAX_REDIRECTS = 4
# Hard ceiling on a response body, independent of what a scanner asks for: plugins must not be
# able to make a worker buffer an unbounded body by passing a huge `limit`.
MAX_BODY_BYTES = 1024 * 1024
REDIRECT_ERRORS = (httpx.InvalidURL, ValueError, ScopeError)


def bounded_limit(limit: int) -> int:
    """Clamp a scanner-supplied body limit; every request goes through this."""
    return max(1, min(limit, MAX_BODY_BYTES))


class AddressResolver(Protocol):
    """Validated answers for connection hosts (implemented by `infra.scope_guard`)."""

    def resolve_name(self, host: str) -> tuple[str, ...]:
        """Every A/AAAA answer for `host`, already checked against the address policy."""
        ...


class _PinnedBackend(httpcore.SyncBackend):
    """Dials an approved address while httpcore believes it is dialing the hostname."""

    def __init__(self, address: str, tls: ssl.SSLContext) -> None:
        # SyncBackend has no __init__ of its own and relies on the TLS context httpcore passes
        # to connect_tcp; ours is exactly the client's context, so no extra setup is needed.
        self._address = address
        self._tls = tls

    def connect_tcp(
        self,
        host: str,
        port: int,
        timeout: float | None = None,
        local_address: str | None = None,
        socket_options: Any = None,
    ) -> "httpcore.NetworkStream":
        return super().connect_tcp(
            self._address,
            port,
            timeout=timeout,
            local_address=local_address,
            socket_options=socket_options,
        )


def connection_address(values: tuple[str, ...]) -> str:
    """Pick the dialed address; IPv4 first because workers may lack IPv6 egress."""
    if not values:
        raise AddressError("The host did not resolve.")

    def is_v4(value: str) -> bool:
        return isinstance(ipaddress.ip_address(value), ipaddress.IPv4Address)

    return sorted(values, key=lambda value: not is_v4(value))[0]


class SafeHttpClient:
    """Scan-scoped client: every request resolves, validates and pins its own connection."""

    def __init__(
        self,
        resolver: AddressResolver,
        *,
        redirect_allowed: Callable[[str], bool] | None = None,
        max_redirects: int = MAX_REDIRECTS,
        timeout_seconds: float = 5.0,
        tls: ssl.SSLContext | None = None,
    ) -> None:
        self._resolver = resolver
        # `None` means no allowlist was installed (a bare transport client); an installed hook
        # is consulted before the first request as well as at every redirect.
        self._redirect_allowed = redirect_allowed
        self._max_redirects = min(max_redirects, MAX_REDIRECTS)
        self._timeout = timeout_seconds
        self._tls = tls or ssl.create_default_context()
        self._pool: httpcore.ConnectionPool | None = None
        self._pinned_to: tuple[str, str] | None = None
        self._closed = False

    def with_redirect_policy(
        self,
        resolver: AddressResolver,
        *,
        redirect_allowed: Callable[[str], bool],
        max_redirects: int,
    ) -> "SafeHttpClient":
        """Same settings, per-run resolver and allowlist: one client per scanner run."""
        return SafeHttpClient(
            resolver,
            redirect_allowed=redirect_allowed,
            max_redirects=max_redirects,
            timeout_seconds=self._timeout,
            tls=self._tls,
        )

    def get(self, url: str, *, limit: int) -> HttpBody:
        """GET `url`; an installed policy hook is consulted before this request, not just hops."""
        cap = bounded_limit(limit)
        for _hop in range(self._max_redirects + 1):
            # The hook is the gate's allowlist: checking it before every hop, including the
            # first, means a run-scoped client can never reach a host the guard refuses.
            if self._redirect_allowed is not None and not self._redirect_allowed(url):
                raise ScopeError("The target is out of scope.")
            body = self._request(url, limit=cap)
            if body.status_code not in REDIRECT_CODES:
                return body
            try:
                url = str(httpx.URL(url).join(body.headers.get("location", "")))
            except REDIRECT_ERRORS:
                raise ScopeError("Redirect target is invalid.") from None
        raise ScopeError("Too many redirects.")

    def close(self) -> None:
        self._closed = True
        self._drop_pool()

    def _drop_pool(self) -> None:
        """Drop the current connections; failures must never reuse a half-broken socket."""
        pool, self._pool = self._pool, None
        self._pinned_to = None
        if pool is not None:
            pool.close()

    def _request(self, url: str, *, limit: int) -> HttpBody:
        if self._closed:
            raise ScopeError("The client was closed.")
        try:
            parts = urlsplit(url)
            port = parts.port
        except ValueError:
            raise ScopeError("The URL is malformed.") from None
        if parts.scheme not in {"http", "https"}:
            raise ScopeError("Only http and https URLs can be requested.")
        if parts.username is not None or parts.password is not None:
            raise ScopeError("URLs with credentials can't be requested.")
        host = parts.hostname
        if not host:
            raise ScopeError("The URL has no host.")
        address = connection_address(self._resolver.resolve_name(host))
        pool = self._pool_for(host, address)
        request = httpx.Request("GET", url)
        core_request = httpcore.Request(
            method="GET",
            url=httpcore.URL(
                scheme=b"https" if parts.scheme == "https" else b"http",
                host=_encoded_host(host),
                port=None if port is None else int(port),
                target=_target(parts),
            ),
            headers=request.headers.raw,
            content=b"",
            extensions={"timeout": {"connect": self._timeout, "read": self._timeout}},
        )
        try:
            core_response = pool.handle_request(core_request)
            try:
                encoding = _header(core_response.headers, b"content-encoding")
                # A plain body is read up to `limit`; an encoded one may need more wire bytes
                # than its decoded size, but never unlimited (decompression expands, not shrinks).
                wire_cap = (
                    min(limit * MAX_EXPANSION, MAX_ENCODED_BYTES)
                    if _is_encoded(encoding)
                    else limit
                )
                raw, truncated = _read_capped(core_response, wire_cap)
                content, decoded_truncated = _decoded(raw, encoding, limit)
            finally:
                core_response.close()
            headers = _headers_without_encoding(core_response.headers)
            response = httpx.Response(
                core_response.status,
                headers=headers,
                content=content,
                request=request,
            )
        except httpcore.ConnectError:
            self._drop_pool()
            raise DnsError() from None
        except httpcore.TimeoutException:
            self._drop_pool()
            raise ScopeError("The request timed out.") from None
        except OSError:  # TLS verification and socket errors: their messages stay internal
            self._drop_pool()
            raise ScopeError("The request failed.") from None
        return HttpBody(
            response.status_code,
            response.content,
            truncated or decoded_truncated,
            response.headers,
        )

    def _pool_for(self, host: str, address: str) -> httpcore.ConnectionPool:
        if self._pool is not None and self._pinned_to == (host, address):
            return self._pool
        self._drop_pool()
        self._pool = httpcore.ConnectionPool(
            ssl_context=self._tls,
            max_connections=1,
            max_keepalive_connections=0,
            http1=True,
            http2=False,
            network_backend=_PinnedBackend(address, self._tls),
        )
        self._pinned_to = (host, address)
        return self._pool


def _encoded_host(host: str) -> bytes:
    try:
        return host.encode("ascii")
    except UnicodeEncodeError:  # a Unicode (not IDNA) name: httpx percent-encodes it the same way
        return httpx.URL(f"http://{host}/").raw_host or b""


ENCODINGS = frozenset({"gzip", "x-gzip", "deflate"})


def _is_encoded(encoding: str | None) -> bool:
    """Whether `encoding` is one we decode (anything else is passed through untouched)."""
    return (encoding or "").strip().lower() in ENCODINGS


def _header(headers: list[tuple[bytes, bytes]], name: bytes) -> str | None:
    """First value of `name` (case-insensitive) in httpcore's raw header list."""
    for key, value in headers:
        if key.lower() == name:
            return value.decode("latin-1")
    return None


def _headers_without_encoding(headers: list[tuple[bytes, bytes]]) -> list[tuple[bytes, bytes]]:
    """Drop `Content-Encoding`/`Content-Length`: the body was decoded and capped as `content`."""
    return [
        (name, value)
        for name, value in headers
        if name.lower() not in {b"content-encoding", b"content-length"}
    ]


def _target(parts: SplitResult) -> bytes:
    """Origin-form request target; httpx percent-encodes what the wire can't carry.

    Built from the *whole* URL, not from `parts.path`: a path starting with `//` makes
    `httpx.URL` read the first segment as an authority and drop it (`//api` -> `/api`),
    silently querying a different endpoint.
    """
    return httpx.URL(parts.geturl()).raw_path


def _read_capped(response: httpcore.Response, limit: int) -> tuple[bytes, bool]:
    """Read at most `limit` bytes and report truncation instead of buffering the whole body."""
    chunks: list[bytes] = []
    total = 0
    if limit <= 0:
        return b"", True
    for chunk in response.iter_stream():
        remaining = limit - total
        chunks.append(chunk[:remaining])
        total += min(len(chunk), remaining)
        if len(chunk) > remaining:
            return b"".join(chunks), True
    return b"".join(chunks), False


MAX_ENCODED_BYTES = MAX_BODY_BYTES * 2  # compressed wire bytes we are willing to retain
MAX_EXPANSION = 20  # most compressed bytes we are willing to read for a given decoded limit
_DECODE_STEP = 64 * 1024


def _decoded(content: bytes, encoding: str | None, limit: int) -> tuple[bytes, bool]:
    """Decode `content`, capping the *decoded* output: a compression bomb must not reach memory.

    Only the (already capped) wire bytes are decompressed, in bounded steps, and decoding stops
    as soon as `limit` bytes are produced, so the ceiling holds for the expanded body too. An
    unknown or corrupt encoding is reported as truncation rather than raised: scanners see the
    raw bytes and no internal error detail.
    """
    name = (encoding or "").strip().lower()
    if name in {"", "identity"}:
        return content, False
    if name not in ENCODINGS:
        return content, True
    # 16 + MAX_WBITS auto-detects gzip/zlib headers; deflate is zlib-wrapped per RFC 9110.
    wbits = 16 + zlib.MAX_WBITS if "gzip" in name else zlib.MAX_WBITS
    decoder = zlib.decompressobj(wbits)
    out = bytearray()
    try:
        for start in range(0, len(content), _DECODE_STEP):
            produced = decoder.decompress(content[start : start + _DECODE_STEP], limit - len(out))
            out += produced
            if len(out) >= limit:
                return bytes(out[:limit]), True
        out += decoder.flush(limit - len(out))
    except zlib.error:
        return content, True
    return (bytes(out[:limit]), True) if len(out) > limit else (bytes(out), False)
