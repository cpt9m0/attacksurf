"""Lookups scanners may use: DNS answers, size-capped HTTP and the run cache.

Scanners receive these through `ScannerRuntime`; DNS/HTTP calls still go through ScopeGuard, so a
plugin can only reach what its declared permissions allow. The cache is process-internal (never a
target) and uses its own namespace and bounds.
"""

from collections.abc import Mapping
from typing import Protocol

from attacksurf.domain.cache import NullCache, ScanCache
from attacksurf.domain.sandbox import SandboxRunner, UnconfiguredSandboxRunner


class DnsError(Exception):
    """A lookup failed (timeout, resolver error). Never carries resolver internals."""


class DnsResolver(Protocol):
    def resolve_ipv4(self, host: str) -> tuple[str, ...]:
        """A records for `host`; every address is validated against the scope policy."""
        ...

    def resolve_name(self, host: str) -> tuple[str, ...]:
        """A and AAAA records for `host`, all validated: what an HTTP connection could use."""
        ...


class TxtError(DnsError):
    """An authoritative TXT lookup failed (no reachable nameserver, timeout, bad answer)."""


class TxtLookup(Protocol):
    def lookup_txt(self, host: str, name: str) -> tuple[str, ...]:
        """TXT values of `name` in the zone `host`, read from `host`'s own nameservers.

        Caching resolvers may serve a stale record long after an owner removed it, so the
        ownership proof must come from the authoritative servers (ADR 0014).
        """
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

    __slots__ = ("cache", "dns", "http", "sandbox")

    def __init__(
        self,
        dns: DnsResolver,
        http: SafeHttpClient,
        sandbox: SandboxRunner | None = None,
        cache: ScanCache | None = None,
    ) -> None:
        self.dns = dns
        self.http = http
        self.sandbox = sandbox or UnconfiguredSandboxRunner()
        self.cache = cache if cache is not None else NullCache()

    def close(self) -> None:
        self.http.close()
