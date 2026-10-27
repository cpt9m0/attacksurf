"""ScopeGuard: the single gate every scanner run passes through.

It validates the target (public domain, public address ranges), requires verified ownership
for active checks, and hands the plugin run-scoped adapters that re-check every DNS name and
HTTP host against the plugin's declared `ScannerGrant` (ADR 0013).
"""

from collections.abc import Callable
from typing import Protocol
from urllib.parse import urlsplit
from uuid import UUID

from attacksurf.domain.assets import AssetType
from attacksurf.domain.net import DnsResolver, HttpBody, SafeHttpClient, ScannerRuntime
from attacksurf.domain.scanners import AssetRef, ScanContext, Scanner, ScannerGate, ScannerGrant
from attacksurf.domain.scope import (
    HttpPermission,
    PublicSuffix,
    ScopeError,
    ScopePolicyError,
    check_address,
    check_addresses,
    check_public_hostname,
    hostname_allowed,
)
from attacksurf.infra import public_suffix
from attacksurf.infra.http import bounded_limit

MAX_REDIRECTS = 4
MAX_DNS_LOOKUPS = 20


class OwnershipChecker(Protocol):
    def is_verified(self, org_id: UUID, asset: AssetRef) -> bool:
        """True only when the org proved control of `asset` (DNS TXT, #14)."""
        ...


class UnverifiedOwnership:
    """Until #14 ships verification, nothing is verified, so no active check can run."""

    def is_verified(self, org_id: UUID, asset: AssetRef) -> bool:
        return False


class ScopeHttp(SafeHttpClient, Protocol):
    """A safe client that can hand out a run-scoped copy with this run's redirect policy."""

    def with_redirect_policy(
        self, resolver: DnsResolver, *, redirect_allowed: Callable[[str], bool], max_redirects: int
    ) -> SafeHttpClient: ...


class ScopeGuard(ScannerGate):
    def __init__(
        self,
        *,
        dns: DnsResolver,
        http: ScopeHttp,
        ownership: OwnershipChecker,
        classify: Callable[[str], PublicSuffix] = public_suffix.classify,
    ) -> None:
        self._dns = dns
        self._http = http
        self._ownership = ownership
        self._classify = classify

    def check(self, ctx: ScanContext, asset: AssetRef, scanner: Scanner) -> ScannerRuntime:
        """Validate and authorize one run. Raises `ScopeError`, and the job is then skipped."""
        self._check_target(asset, scanner)
        if scanner.requires_verification and not self._ownership.is_verified(ctx.org_id, asset):
            raise ScopeError("Active checks need a verified asset.")
        grant = scanner.grant
        self._check_services(grant)
        guarded_dns = _GuardedDns(self._dns, max_lookups=grant.dns_lookups)
        http = _GuardedHttp(
            self._http,
            target=asset.value if grant.http is HttpPermission.TARGET else None,
            services=grant.http_hosts,
            check_host=self._check_host,
        )
        return ScannerRuntime(guarded_dns, http.client_for(guarded_dns))

    def _check_target(self, asset: AssetRef, scanner: Scanner) -> None:
        if asset.type not in scanner.asset_types:
            raise ScopePolicyError("The scanner does not support this asset type.")
        if asset.type in {AssetType.DOMAIN, AssetType.SUBDOMAIN}:
            self._check_host(asset.value)
        elif asset.type is AssetType.IP:
            check_address(asset.value)
        else:
            raise ScopeError("This asset type can't be scanned over the network.")

    def _check_host(self, host: str) -> str:
        return check_public_hostname(host, self._classify(host))

    def _check_services(self, grant: ScannerGrant) -> None:
        """Declared data services must be public hosts; their answers are checked per request."""
        for host in grant.http_hosts:
            try:
                self._check_host(host)
            except ScopeError:
                raise ScopePolicyError("A scanner's data service is out of scope.") from None
        # The run must be able to resolve each service before any request can be pinned.
        needed = len(grant.http_hosts) if grant.http is HttpPermission.SERVICES else 0
        if grant.dns_lookups < needed:
            raise ScopePolicyError("A scanner needs a DNS lookup for each data service.")


class _GuardedDns:
    """Per-run DNS budget; every answer is validated, so CNAME tricks are caught too."""

    def __init__(self, inner: DnsResolver, *, max_lookups: int) -> None:
        self._inner = inner
        self._remaining = min(max_lookups, MAX_DNS_LOOKUPS)

    def _take(self) -> None:
        if self._remaining <= 0:
            raise ScopeError("The scanner used up its DNS lookup budget.")
        self._remaining -= 1

    def resolve_ipv4(self, host: str) -> tuple[str, ...]:
        self._take()
        return tuple(str(address) for address in check_addresses(self._inner.resolve_ipv4(host)))

    def resolve_name(self, host: str) -> tuple[str, ...]:
        self._take()
        return tuple(str(address) for address in check_addresses(self._inner.resolve_name(host)))


class _GuardedHttp:
    """Per-run HTTP allowlist. Redirects never widen it: the client asks again at each hop."""

    def __init__(
        self,
        inner: ScopeHttp,
        *,
        target: str | None,
        services: frozenset[str],
        check_host: Callable[[str], str],
    ) -> None:
        self._inner = inner
        self._target = target
        self._services = services
        self._check_host = check_host

    def __repr__(self) -> str:
        return f"_GuardedHttp({self._target or ','.join(sorted(self._services))})"

    def host_allowed(self, url: str) -> bool:
        """Shared by the first request and, as the client's redirect hook, every hop."""
        if self._target is None and not self._services:
            return False  # a DNS-only grant never reaches the network over HTTP
        host = self._check_host(request_host(url))
        return hostname_allowed(host, self._services) or host == self._target

    def get(self, url: str, *, limit: int) -> HttpBody:
        self.require_allowed(url)
        return self._inner.get(url, limit=bounded_limit(limit))

    def require_allowed(self, url: str) -> None:
        if not self.host_allowed(url):
            raise ScopePolicyError("The scanner may not contact this host.")

    def client_for(self, resolver: DnsResolver) -> SafeHttpClient:
        """A pinned client whose redirects come back to this allowlist at every hop.

        The allowlist is the client's policy hook, which `SafeHttpClient.get()` now consults
        before the first request too, so handing the inner client to a run is not a bypass.
        """
        return self._inner.with_redirect_policy(
            resolver, redirect_allowed=self.host_allowed, max_redirects=MAX_REDIRECTS
        )


def request_host(url: str) -> str:
    """Host of a scanner-supplied URL; rejects other schemes, credentials and empty hosts."""
    try:
        parts = urlsplit(url)
        host = parts.hostname
    except ValueError:
        raise ScopeError("The URL is malformed.") from None
    if parts.scheme not in {"http", "https"}:
        raise ScopeError("Only http and https URLs can be requested.")
    if parts.username is not None or parts.password is not None:
        raise ScopeError("URLs with credentials can't be requested.")
    if not host:
        raise ScopeError("The URL has no host.")
    try:
        parts.port  # noqa: B018 - raises ValueError for an invalid or missing port
    except ValueError:
        raise ScopeError("The URL is malformed.") from None
    return host
