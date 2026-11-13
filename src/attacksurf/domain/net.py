"""Lookups scanners may use: DNS answers, size-capped HTTP and the run cache.

Scanners receive these through `ScannerRuntime`; DNS/HTTP calls still go through ScopeGuard, so a
plugin can only reach what its declared permissions allow. The cache is process-internal (never a
target) and uses its own namespace and bounds.
"""

from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass
from datetime import datetime
from enum import StrEnum
from typing import Protocol

from attacksurf.domain.cache import NullCache, ScanCache
from attacksurf.domain.sandbox import SandboxRunner, UnconfiguredSandboxRunner
from attacksurf.domain.scope import ScopePolicyError


class DnsError(Exception):
    """A lookup failed (timeout, resolver error). Never carries resolver internals."""


class DnsRecordType(StrEnum):
    """Record types scanners may ask for; `PTR` names come from `ipaddress.reverse_pointer`."""

    A = "A"
    AAAA = "AAAA"
    CNAME = "CNAME"
    MX = "MX"
    NS = "NS"
    TXT = "TXT"
    CAA = "CAA"
    SOA = "SOA"
    DS = "DS"
    DNSKEY = "DNSKEY"
    PTR = "PTR"


class DnsStatus(StrEnum):
    """Per-query outcome: an absent record is data, not a failed run."""

    OK = "ok"
    NXDOMAIN = "nxdomain"
    NO_ANSWER = "no_answer"
    ERROR = "error"


@dataclass(frozen=True)
class DnsQuery:
    name: str
    record_type: DnsRecordType


@dataclass(frozen=True)
class DnsLookup:
    """One query's answer; `values` are raw, unvalidated record strings (scan data)."""

    query: DnsQuery
    values: tuple[str, ...] = ()
    status: DnsStatus = DnsStatus.OK

    @property
    def found(self) -> bool:
        return self.status is DnsStatus.OK and bool(self.values)


class DnsResolver(Protocol):
    def resolve_ipv4(self, host: str) -> tuple[str, ...]:
        """A records for `host`; every address is validated against the scope policy."""
        ...

    def resolve_name(self, host: str) -> tuple[str, ...]:
        """A and AAAA records for `host`, all validated: what an HTTP connection could use."""
        ...

    def lookup_many(self, queries: Sequence[DnsQuery]) -> tuple[DnsLookup, ...]:
        """Raw records for scanners; answers are data and are not address-validated.

        Connection paths still use `resolve_ipv4`/`resolve_name`, so a private answer can be
        reported (e.g. as exposure) but never dialed. Each query costs one DNS-budget unit.
        """
        ...


class StubRecords(Protocol):
    """Owner-aware raw records: the owner exposes a CNAME the stub followed (ADR 0014)."""

    def lookup_records(self, name: str, rdtype: str) -> tuple[str, tuple[str, ...]]:
        """(owner name the stub answered for, values); raises `DnsError` on failure."""
        ...

    def lookup_records_checking_disabled(
        self, name: str, rdtype: str
    ) -> tuple[str, tuple[str, ...]]:
        """Same answer with DNSSEC checking disabled (the CD flag, RFC 4035 section 3.2.2).

        A validating resolver answers SERVFAIL for a zone whose DS and DNSKEY disagree, hiding
        the nameservers of the very zone a broken-chain check must probe. Only diagnostics use
        this path; it still raises `DnsError` on failure.
        """
        ...


class RecordResolver(DnsResolver, StubRecords, Protocol):
    """A resolver that can also report who owns a raw answer (zone discovery needs it)."""


@dataclass(frozen=True)
class IpInfo:
    """Offline ASN/organisation data for an address; every field is optional."""

    asn: int | None = None
    org: str | None = None
    country: str | None = None


class IpIntel(Protocol):
    def lookup(self, address: str) -> IpInfo | None:
        """Enrichment for `address`, or None when the offline database has no answer."""
        ...


class UnconfiguredIpIntel:
    """No database configured: scans run without ASN/organisation enrichment."""

    def lookup(self, address: str) -> IpInfo | None:
        return None


class TxtError(DnsError):
    """An authoritative TXT lookup failed (no reachable nameserver, timeout, bad answer)."""


class TxtLookup(Protocol):
    def lookup_txt(self, host: str, name: str) -> tuple[str, ...]:
        """TXT values of `name` in the zone `host`, read from `host`'s own nameservers.

        Caching resolvers may serve a stale record long after an owner removed it, so the
        ownership proof must come from the authoritative servers (ADR 0014).
        """
        ...


@dataclass(frozen=True)
class AuthoritativeAnswer:
    """One authoritative server's reply; `rcode` is empty when the server was unreachable."""

    server: str
    address: str
    status: DnsStatus
    authoritative: bool = False
    rcode: str = ""
    values: tuple[str, ...] = ()


@dataclass(frozen=True)
class ZoneAnswers:
    """A zone's nameserver set plus at most one answer per probed server."""

    zone: str
    servers: tuple[str, ...] = ()
    answers: tuple[AuthoritativeAnswer, ...] = ()


class AuthoritativeDns(Protocol):
    def query(self, name: str, record_type: DnsRecordType) -> ZoneAnswers:
        """Ask each authoritative server of `name`'s zone for one record type (read-only)."""
        ...


@dataclass(frozen=True)
class ZoneTransferAttempt:
    """One AXFR attempt; `records` is the first message's count, never its content."""

    server: str
    address: str
    allowed: bool
    records: int = 0


class ZoneTransfer(Protocol):
    def attempt(self, zone: str) -> tuple[ZoneTransferAttempt, ...]:
        """One AXFR per authoritative server of `zone`; empty when it is not a zone apex."""
        ...


@dataclass(frozen=True)
class DomainRegistration:
    """Trimmed RDAP registration data (public); every field is optional."""

    domain: str
    registrar: str | None = None
    expires_at: datetime | None = None
    statuses: tuple[str, ...] = ()


class RdapLookup(Protocol):
    def lookup(self, domain: str) -> DomainRegistration | None:
        """Registration data for `domain`, or None when RDAP has no usable answer."""
        ...


class UnconfiguredAuthoritative:
    """No authoritative grant: a plugin that tries anyway is a policy bug, not a skip."""

    def query(self, name: str, record_type: DnsRecordType) -> ZoneAnswers:
        raise ScopePolicyError("This scanner may not query authoritative nameservers.")


class UnconfiguredZoneTransfer:
    def attempt(self, zone: str) -> tuple[ZoneTransferAttempt, ...]:
        raise ScopePolicyError("This scanner may not attempt a zone transfer.")


class UnconfiguredRdap:
    def lookup(self, domain: str) -> DomainRegistration | None:
        raise ScopePolicyError("This scanner may not query RDAP.")


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


class ScopeHttp(SafeHttpClient, Protocol):
    """A safe client that can hand out a run-scoped copy with this run's redirect policy."""

    def with_redirect_policy(
        self, resolver: DnsResolver, *, redirect_allowed: Callable[[str], bool], max_redirects: int
    ) -> SafeHttpClient: ...


class ScannerRuntime:
    """Run-scoped adapters handed to a plugin after the gate approved it."""

    __slots__ = (
        "authoritative",
        "cache",
        "dns",
        "http",
        "ip_intel",
        "org_domain",
        "rdap",
        "sandbox",
        "zone_transfer",
    )

    def __init__(
        self,
        dns: DnsResolver,
        http: SafeHttpClient,
        sandbox: SandboxRunner | None = None,
        cache: ScanCache | None = None,
        ip_intel: IpIntel | None = None,
        *,
        org_domain: Callable[[str], str | None] | None = None,
        authoritative: AuthoritativeDns | None = None,
        zone_transfer: ZoneTransfer | None = None,
        rdap: RdapLookup | None = None,
    ) -> None:
        self.dns = dns
        self.http = http
        self.sandbox = sandbox or UnconfiguredSandboxRunner()
        self.cache = cache if cache is not None else NullCache()
        self.ip_intel = ip_intel or UnconfiguredIpIntel()
        # Capability adapters are only wired when the plugin's grant declared them; the null
        # versions fail the job as a policy bug rather than silently skipping the check.
        self.authoritative = authoritative or UnconfiguredAuthoritative()
        self.zone_transfer = zone_transfer or UnconfiguredZoneTransfer()
        self.rdap = rdap or UnconfiguredRdap()
        # Registrable (organizational) domain for a hostname, from the public suffix list;
        # None when unconfigured or the name is off the list. Lets checks apply DMARC's
        # organizational-domain fallback without importing the PSL themselves.
        self.org_domain = org_domain

    def close(self) -> None:
        self.http.close()
