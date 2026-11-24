"""ScopeGuard: the single gate every scanner run passes through.

It validates the target (public domain, public address ranges), requires verified ownership
for active checks, and hands the plugin run-scoped adapters that re-check every DNS name and
HTTP host against the plugin's declared `ScannerGrant` (ADR 0013).
"""

import ipaddress
import re
from collections.abc import Callable, Sequence
from typing import Protocol
from urllib.parse import SplitResult, urlsplit
from uuid import UUID

import idna

from attacksurf.domain.assets import MAX_URL_LENGTH, AssetType
from attacksurf.domain.cache import NullCache, ScanCache
from attacksurf.domain.net import (
    AuthoritativeDns,
    DnsError,
    DnsLookup,
    DnsQuery,
    DnsRecordType,
    DnsResolver,
    DomainRegistration,
    HttpBody,
    IpIntel,
    RdapLookup,
    RecordResolver,
    SafeHttpClient,
    ScannerRuntime,
    ScopeHttp,
    TargetRateLimiter,
    TlsInspection,
    TlsInspector,
    VulnIntelLookup,
    ZoneAnswers,
    ZoneTransfer,
    ZoneTransferAttempt,
)
from attacksurf.domain.sandbox import SandboxResult, SandboxRunner, UnconfiguredSandboxRunner
from attacksurf.domain.scanners import (
    ALLOWED_WEB_PORTS,
    DEFAULT_HTTP_PORTS,
    AssetRef,
    ScanContext,
    Scanner,
    ScannerGate,
    ScannerGrant,
)
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
from attacksurf.infra.authoritative_dns import AuthoritativeLookup
from attacksurf.infra.http import bounded_limit
from attacksurf.infra.rdap import RdapClient
from attacksurf.infra.tls import SafeTlsClient, TlsConnector

MAX_REDIRECTS = 4
MAX_DNS_LOOKUPS = 40
# Authoritative probes need the NS RRset plus A/AAAA for at least one server; RDAP resolves the
# bootstrap host and the TLD's RDAP host.
MIN_AUTHORITATIVE_LOOKUPS = 3
MIN_RDAP_LOOKUPS = 2
MIN_TLS_LOOKUPS = 1


class OwnershipChecker(Protocol):
    def is_verified(self, org_id: UUID, asset: AssetRef) -> bool:
        """True only when the org proved control of `asset` (DNS TXT, #14)."""
        ...


class UnverifiedOwnership:
    """Until #14 ships verification, nothing is verified, so no active check can run."""

    def is_verified(self, org_id: UUID, asset: AssetRef) -> bool:
        return False


class ScopeGuard(ScannerGate):
    def __init__(
        self,
        *,
        dns: RecordResolver,
        http: ScopeHttp,
        ownership: OwnershipChecker,
        classify: Callable[[str], PublicSuffix] = public_suffix.classify,
        sandbox: SandboxRunner | None = None,
        cache: ScanCache | None = None,
        ip_intel: IpIntel | None = None,
        active_scans_enabled: bool = False,
        rate_limiter: TargetRateLimiter | None = None,
        user_agent: str | None = None,
        tls: TlsConnector | None = None,
        vuln_intel: VulnIntelLookup | None = None,
    ) -> None:
        self._dns = dns
        self._http = http
        self._ownership = ownership
        self._classify = classify
        self._sandbox = sandbox or UnconfiguredSandboxRunner()
        self._cache = cache if cache is not None else NullCache()
        self._ip_intel = ip_intel
        self._active_scans_enabled = active_scans_enabled
        self._rate_limiter = rate_limiter
        self._user_agent = user_agent
        self._tls = tls
        self._vuln_intel = vuln_intel

    def check(self, ctx: ScanContext, asset: AssetRef, scanner: Scanner) -> ScannerRuntime:
        """Validate and authorize one run. Raises `ScopeError`, and the job is then skipped."""
        self._check_target(asset, scanner)
        grant = scanner.grant
        # Target HTTP, TLS, zone transfer, and the active queue *are* active checks: the
        # grant/queue decides, not just `requires_verification`, so a plugin can't bypass it.
        is_active = (
            scanner.requires_verification
            or scanner.queue == "active"
            or grant.http is HttpPermission.TARGET
            or grant.zone_transfer
            or grant.tls
        )
        if is_active and not self._active_scans_enabled:
            raise ScopeError("Active scans are disabled on this instance.")
        if is_active and not self._ownership.is_verified(ctx.org_id, asset):
            raise ScopeError("Active checks need a verified asset.")
        self._check_services(grant)
        target_host = self._target_host(asset)
        guarded_dns = _GuardedDns(self._dns, max_lookups=grant.dns_lookups)
        is_target_http = grant.http is HttpPermission.TARGET
        verified_root = (
            ctx.root_asset.value
            if is_target_http and ctx.root_asset.type is AssetType.DOMAIN
            else None
        )
        http = _GuardedHttp(
            self._http,
            target=target_host if is_target_http else None,
            verified_root=verified_root,
            services=grant.http_hosts,
            allowed_ports=grant.http_ports,
            follow_redirects=grant.follow_redirects,
            stop_on_out_of_scope_redirect=is_target_http and grant.follow_redirects,
            check_host=self._check_host,
            rate_limiter=self._rate_limiter if is_target_http else None,
            rate_limit_org_id=ctx.org_id if is_target_http else None,
            user_agent=self._user_agent if is_target_http else None,
        )
        sandbox = _GuardedSandbox(self._sandbox, allowed=grant.sandbox_analyzers)
        # One read-only authoritative client serves both capabilities; each guard exposes only
        # the method its grant declared.
        authoritative_dns = (
            AuthoritativeLookup(guarded_dns)
            if grant.authoritative_dns or grant.zone_transfer
            else None
        )
        tls_inspector: TlsInspector | None = (
            _GuardedTls(
                SafeTlsClient(
                    guarded_dns,
                    connector=self._tls,
                    rate_limiter=self._rate_limiter,
                    rate_limit_org_id=ctx.org_id,
                ),
                target_host=target_host,
                allowed_ports=grant.tls_ports,
                check_host=self._check_host,
            )
            if grant.tls
            else None
        )
        return ScannerRuntime(
            guarded_dns,
            http.client_for(guarded_dns),
            sandbox,
            cache=self._cache,
            ip_intel=self._ip_intel,
            org_domain=public_suffix.registrable,
            authoritative=(
                _GuardedAuthoritative(authoritative_dns, target=asset.value)
                if grant.authoritative_dns and authoritative_dns is not None
                else None
            ),
            zone_transfer=(
                _GuardedZoneTransfer(authoritative_dns, target=asset.value)
                if grant.zone_transfer and authoritative_dns is not None
                else None
            ),
            rdap=(
                _GuardedRdap(
                    RdapClient(self._http, guarded_dns, self._cache),
                    target=asset.value,
                    registrable=public_suffix.registrable(asset.value),
                )
                if grant.rdap
                else None
            ),
            tls=tls_inspector,
            vuln_intel=self._vuln_intel,
        )

    def _check_target(self, asset: AssetRef, scanner: Scanner) -> None:
        if asset.type not in scanner.asset_types:
            raise ScopePolicyError("The scanner does not support this asset type.")
        if asset.type in {AssetType.DOMAIN, AssetType.SUBDOMAIN}:
            self._check_host(asset.value)
        elif asset.type is AssetType.IP:
            check_address(asset.value)
        elif asset.type is AssetType.URL:
            host = self._check_host(request_host(asset.value))
            parts = urlsplit(asset.value)
            port = (
                parts.port if parts.port is not None else (443 if parts.scheme == "https" else 80)
            )
            allowed = (
                scanner.grant.http_ports
                if scanner.grant.http is HttpPermission.TARGET
                else ALLOWED_WEB_PORTS
            )
            if port not in allowed:
                raise ScopeError("The URL port is outside the scanner's allowed web ports.")
            del host
        else:
            raise ScopeError("This asset type can't be scanned over the network.")

    def _target_host(self, asset: AssetRef) -> str:
        if asset.type is AssetType.URL:
            return self._check_host(request_host(asset.value))
        return asset.value

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
        if grant.authoritative_dns or grant.zone_transfer:
            needed = max(needed, MIN_AUTHORITATIVE_LOOKUPS)
        if grant.rdap:
            needed = max(needed, MIN_RDAP_LOOKUPS)
        if grant.tls:
            needed = max(needed, MIN_TLS_LOOKUPS)
        if grant.dns_lookups < needed:
            raise ScopePolicyError("A scanner needs a DNS lookup for each data service.")


class _GuardedDns:
    """Per-run DNS budget. Connection answers are validated; raw records are data only."""

    def __init__(self, inner: RecordResolver, *, max_lookups: int) -> None:
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

    def lookup_many(self, queries: Sequence[DnsQuery]) -> tuple[DnsLookup, ...]:
        """Raw records are data, not connection targets: only the budget is enforced."""
        for _query in queries:
            self._take()
        return self._inner.lookup_many(queries)

    def lookup_records(self, name: str, rdtype: str) -> tuple[str, tuple[str, ...]]:
        """Owner-aware raw records (zone discovery); one budget unit per lookup."""
        self._take()
        return self._inner.lookup_records(name, rdtype)

    def lookup_records_checking_disabled(
        self, name: str, rdtype: str
    ) -> tuple[str, tuple[str, ...]]:
        """Diagnostic variant of `lookup_records` (CD flag); budgeted the same way."""
        self._take()
        return self._inner.lookup_records_checking_disabled(name, rdtype)


class _GuardedSandbox:
    """Per-run analyzer allowlist, checked before anything reaches the launcher."""

    def __init__(self, inner: SandboxRunner, *, allowed: frozenset[str]) -> None:
        self._inner = inner
        self._allowed = allowed

    def run(self, analyzer: str, artifact_id: UUID) -> SandboxResult:
        if analyzer not in self._allowed:
            raise ScopePolicyError("The scanner may not run this analyzer.")
        return self._inner.run(analyzer, artifact_id)


class _GuardedHttp:
    """Per-run HTTP allowlist. Redirects never widen it: the client asks again at each hop."""

    def __init__(
        self,
        inner: ScopeHttp,
        *,
        target: str | None,
        verified_root: str | None = None,
        services: frozenset[str],
        allowed_ports: frozenset[int] = DEFAULT_HTTP_PORTS,
        follow_redirects: bool = True,
        stop_on_out_of_scope_redirect: bool = False,
        check_host: Callable[[str], str],
        rate_limiter: TargetRateLimiter | None = None,
        rate_limit_org_id: UUID | None = None,
        user_agent: str | None = None,
    ) -> None:
        self._inner = inner
        self._target = target
        self._verified_root = verified_root
        self._services = services
        self._allowed_ports = allowed_ports
        self._follow_redirects = follow_redirects
        self._stop_on_out_of_scope_redirect = stop_on_out_of_scope_redirect
        self._check_host = check_host
        self._rate_limiter = rate_limiter
        self._rate_limit_org_id = rate_limit_org_id
        self._user_agent = user_agent

    def __repr__(self) -> str:
        return f"_GuardedHttp({self._target or ','.join(sorted(self._services))})"

    def host_allowed(self, url: str) -> bool:
        """Shared by the first request and, as the client's redirect hook, every hop."""
        if self._target is None and not self._services:
            return False  # a DNS-only grant never reaches the network over HTTP
        host = self._check_host(request_host(url))
        if self._services and hostname_allowed(host, self._services):
            return True
        if self._target is None:
            return False
        parts = urlsplit(url)
        port = parts.port if parts.port is not None else (443 if parts.scheme == "https" else 80)
        host_ok = host == self._target or (
            self._verified_root is not None
            and (host == self._verified_root or host.endswith(f".{self._verified_root}"))
        )
        return port in self._allowed_ports and host_ok

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
            resolver,
            redirect_allowed=self.host_allowed,
            max_redirects=MAX_REDIRECTS if self._follow_redirects else 0,
            stop_on_out_of_scope_redirect=self._stop_on_out_of_scope_redirect,
            rate_limiter=self._rate_limiter,
            rate_limit_org_id=self._rate_limit_org_id,
            user_agent=self._user_agent,
        )


class _GuardedAuthoritative:
    """Read-only authoritative probes, restricted to the scanned asset's own zone."""

    def __init__(self, inner: AuthoritativeDns, *, target: str) -> None:
        self._inner = inner
        self._target = target

    def query(self, name: str, record_type: DnsRecordType) -> ZoneAnswers:
        if name != self._target:
            raise ScopePolicyError("The scanner may only query the target's zone.")
        return self._inner.query(name, record_type)


class _GuardedZoneTransfer:
    """AXFR attempts, restricted to the scanned asset itself (never a parent zone)."""

    def __init__(self, inner: ZoneTransfer, *, target: str) -> None:
        self._inner = inner
        self._target = target

    def attempt(self, zone: str) -> tuple[ZoneTransferAttempt, ...]:
        if zone != self._target:
            raise ScopePolicyError("The scanner may only transfer the target's zone.")
        return self._inner.attempt(zone)


class _GuardedRdap:
    """RDAP lookups, restricted to the target or its registrable domain."""

    def __init__(self, inner: RdapLookup, *, target: str, registrable: str | None) -> None:
        self._inner = inner
        self._target = target
        self._registrable = registrable

    def lookup(self, domain: str) -> DomainRegistration | None:
        if domain not in (self._target, self._registrable):
            raise ScopePolicyError("The scanner may only look up the target's registration.")
        return self._inner.lookup(domain)


class _GuardedTls:
    """TLS handshakes restricted to the scanned target host and granted web ports."""

    def __init__(
        self,
        inner: TlsInspector,
        *,
        target_host: str,
        allowed_ports: frozenset[int],
        check_host: Callable[[str], str],
    ) -> None:
        self._inner = inner
        self._target_host = target_host
        self._allowed_ports = allowed_ports
        self._check_host = check_host

    def inspect(self, host: str, port: int = 443, *, probe_legacy: bool = False) -> TlsInspection:
        norm_host = self._check_host(host.strip().lower().rstrip("."))
        if norm_host != self._target_host:
            raise ScopePolicyError("The scanner may only inspect the target host.")
        if port not in self._allowed_ports:
            raise ScopePolicyError("Port is outside the scanner's TLS grant.")
        return self._inner.inspect(norm_host, port, probe_legacy=probe_legacy)


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


_LLM_DEFAULT_PORTS = {"http": 80, "https": 443}
_UNSAFE_BASE_URL_CHARS = re.compile(r"[\x00-\x20\x7f]")


def validate_llm_base_url(
    raw: str,
    *,
    allowed_hosts: frozenset[str] = frozenset(),
    resolver: DnsResolver,
) -> str:
    """Validate and normalize an org-supplied LLM `base_url` against SSRF (#24).

    Unless the host is explicitly allowlisted via `LLM_ALLOWED_BASE_HOSTS`, requires `https://`,
    rejects IP literals and internal/non-public hostnames, resolves the host via `resolver`,
    and rejects any private, loopback, link-local/metadata or reserved address. Always rejects
    embedded credentials, query strings, fragments and control characters.
    """
    parts, scheme, port = _parse_llm_base_url(raw)
    normalized_host, is_ip = _normalize_llm_host(parts.netloc, parts.hostname or "")
    if normalized_host in allowed_hosts:
        host_part = f"[{normalized_host}]" if ":" in normalized_host else normalized_host
    else:
        host_part = _validate_public_llm_host(
            normalized_host, scheme=scheme, is_ip=is_ip, resolver=resolver
        )
    netloc = (
        f"{host_part}:{port}"
        if port is not None and port != _LLM_DEFAULT_PORTS[scheme]
        else host_part
    )
    clean = f"{scheme}://{netloc}{parts.path}"
    if len(clean) > MAX_URL_LENGTH:
        raise ScopeError(f"Base URL can be at most {MAX_URL_LENGTH} characters.")
    return clean


def is_allowlisted_llm_base_url(url: str, allowed_hosts: frozenset[str]) -> bool:
    """True when `url`'s normalized host is explicitly allowlisted in `allowed_hosts`."""
    if not allowed_hosts:
        return False
    parts = urlsplit(url)
    normalized_host, _ = _normalize_llm_host(parts.netloc, parts.hostname or "")
    return normalized_host in allowed_hosts


def _parse_llm_base_url(raw: str) -> tuple[SplitResult, str, int | None]:
    value = raw.strip()
    if not value:
        raise ScopeError("Base URL cannot be empty.")
    if _UNSAFE_BASE_URL_CHARS.search(value):
        raise ScopeError("Base URL cannot contain spaces or control characters.")
    if len(value) > MAX_URL_LENGTH:
        raise ScopeError(f"Base URL can be at most {MAX_URL_LENGTH} characters.")
    try:
        parts = urlsplit(value)
    except ValueError:
        raise ScopeError("The base URL is malformed.") from None
    scheme = parts.scheme.lower()
    if scheme not in _LLM_DEFAULT_PORTS:
        raise ScopeError("Base URL must use http or https.")
    if parts.username is not None or parts.password is not None or "@" in parts.netloc:
        raise ScopeError("Base URL must not contain credentials.")
    if "\\" in parts.netloc:
        raise ScopeError("The base URL host is malformed.")
    if parts.query or parts.fragment or "?" in value or "#" in value:
        raise ScopeError("Base URL must not contain a query string or fragment.")
    if not parts.hostname:
        raise ScopeError("The base URL has no host.")
    try:
        port = parts.port
    except ValueError:
        raise ScopeError("The base URL has an invalid port.") from None
    if port is not None and port == 0:
        raise ScopeError("The base URL has an invalid port.")
    return parts, scheme, port


def _validate_public_llm_host(
    normalized_host: str, *, scheme: str, is_ip: bool, resolver: DnsResolver
) -> str:
    if scheme != "https":
        raise ScopeError("Base URL must use https:// unless the host is allowlisted.")
    if is_ip:
        raise ScopeError("IP addresses are not allowed in custom base URLs.")
    public_host = check_public_hostname(normalized_host, public_suffix.classify(normalized_host))
    try:
        addresses = resolver.resolve_name(public_host)
    except DnsError:
        raise ScopeError("The base URL host could not be resolved.") from None
    if not addresses:
        raise ScopeError("The base URL host did not resolve to any IP address.")
    check_addresses(addresses)
    return public_host


def _normalize_llm_host(netloc: str, split_hostname: str) -> tuple[str, bool]:
    if "[" in netloc:
        if "%" in split_hostname:
            raise ScopeError("IPv6 zone IDs are not allowed.")
        try:
            address = ipaddress.IPv6Address(split_hostname)
        except ValueError:
            raise ScopeError("The base URL host is malformed.") from None
        return str(address), True
    raw_host = netloc.partition(":")[0]
    try:
        address = ipaddress.ip_address(raw_host)
    except ValueError:
        pass
    else:
        return str(address), True
    stripped = raw_host.removesuffix(".")
    if not stripped:
        raise ScopeError("The base URL has no host.")
    try:
        ascii_host = idna.encode(stripped, uts46=True).decode("ascii").removesuffix(".")
    except idna.IDNAError:
        raise ScopeError("The base URL host is malformed.") from None
    return ascii_host, False
