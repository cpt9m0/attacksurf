"""Network lookups scanners may use: DNS answers and size-capped HTTP (implemented in `infra`).

Scanners receive these through `ScannerRuntime`; each call still goes through ScopeGuard, so a
plugin can only reach what its declared permissions allow.
"""

from collections.abc import Mapping
from typing import Protocol


class DnsError(Exception):
    """A lookup failed (timeout, resolver error). Never carries resolver internals."""


class DnsResolver(Protocol):
    def resolve_ipv4(self, host: str) -> tuple[str, ...]:
        """A records for `host`; every address is validated against the scope policy."""
        ...

    def resolve_name(self, host: str) -> tuple[str, ...]:
        """A and AAAA records for `host`, all validated: what an HTTP connection could use."""
        ...


class HttpBody:
    """A response as a scanner sees it: the body was capped by the client while reading."""

    __slots__ = ("content", "headers", "status_code", "truncated")

    def __init__(
        self,
        status_code: int,
        content: bytes,
        truncated: bool = False,
        headers: Mapping[str, str] | None = None,
    ) -> None:
        self.status_code = status_code
        self.content = content
        self.truncated = truncated
        self.headers = headers or {}

    def __repr__(self) -> str:
        return f"HttpBody(status_code={self.status_code}, bytes={len(self.content)})"


class SafeHttpClient(Protocol):
    def get(self, url: str, *, limit: int) -> HttpBody:
        """GET `url` if the scanner's contract allows the host; redirects are re-validated."""
        ...

    def close(self) -> None:
        """Release pooled connections; the worker calls this when the run ends."""
        ...


class ScannerRuntime:
    """Run-scoped adapters handed to a plugin after the gate approved it."""

    __slots__ = ("dns", "http")

    def __init__(self, dns: DnsResolver, http: SafeHttpClient) -> None:
        self.dns = dns
        self.http = http

    def close(self) -> None:
        self.http.close()
