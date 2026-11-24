"""Shared, zero-network DNS, HTTP, and authoritative-wire fakes for E2E and scale tests.

No real sockets are opened: `ScopeGuard`, `AuthoritativeTxtLookup`, `AuthoritativeLookup`, and
`RdapClient` execute their real logic over `MutableDnsZone` and `FakeScopeHttp`.
"""

from collections.abc import Callable, Iterator, Mapping, Sequence
from contextlib import nullcontext
from dataclasses import dataclass, field
from urllib.parse import urlsplit
from uuid import UUID

import dns.exception
import dns.flags
import dns.message
import dns.name
import dns.rcode
import dns.rdata
import dns.rdataclass
import dns.rdatatype
import pytest

from attacksurf.domain.net import (
    DnsLookup,
    DnsQuery,
    DnsRecordType,
    DnsStatus,
    HttpBody,
)
from attacksurf.domain.scope import ScopeError, ScopePolicyError
from attacksurf.infra import authoritative_dns


@dataclass
class MutableDnsZone:
    """In-memory DNS zone supporting record queries, NXDOMAINs, and zone transfers."""

    records: dict[tuple[str, str], list[str]] = field(default_factory=dict)
    nxdomain: set[str] = field(default_factory=set)
    axfr_records: dict[str, int] = field(default_factory=dict)

    def set_records(self, name: str, rdtype: str | DnsRecordType, values: Sequence[str]) -> None:
        key = (self._norm(name), self._rtype(rdtype))
        if values:
            self.records[key] = list(values)
            self.nxdomain.discard(key[0])
        else:
            self.records.pop(key, None)

    def clear_name(self, name: str, *, nxdomain: bool = False) -> None:
        host = self._norm(name)
        for key in [k for k in self.records if k[0] == host]:
            del self.records[key]
        if nxdomain:
            self.nxdomain.add(host)

    def resolve_ipv4(self, host: str) -> tuple[str, ...]:
        return tuple(self.records.get((self._norm(host), "A"), ()))

    def resolve_name(self, host: str) -> tuple[str, ...]:
        norm = self._norm(host)
        seen: set[str] = set()
        current = norm
        for _ in range(5):
            if current in seen:
                break
            seen.add(current)
            cnames = self.records.get((current, "CNAME"), ())
            if cnames:
                current = self._norm(cnames[0])
                continue
            break
        v4 = self.records.get((current, "A"), ())
        v6 = self.records.get((current, "AAAA"), ())
        return (*v4, *v6)

    def lookup_many(self, queries: Sequence[DnsQuery]) -> tuple[DnsLookup, ...]:
        results: list[DnsLookup] = []
        for query in queries:
            norm = self._norm(query.name)
            if norm in self.nxdomain:
                results.append(DnsLookup(query=query, status=DnsStatus.NXDOMAIN))
                continue
            values = tuple(self.records.get((norm, query.record_type.value), ()))
            status = DnsStatus.OK if values else DnsStatus.NO_ANSWER
            results.append(DnsLookup(query=query, status=status, values=values))
        return tuple(results)

    def lookup_records(self, name: str, rdtype: str) -> tuple[str, tuple[str, ...]]:
        norm = self._norm(name)
        return norm, tuple(self.records.get((norm, self._rtype(rdtype)), ()))

    def lookup_records_checking_disabled(
        self, name: str, rdtype: str
    ) -> tuple[str, tuple[str, ...]]:
        return self.lookup_records(name, rdtype)

    @staticmethod
    def _norm(name: str) -> str:
        return name.strip().rstrip(".").lower()

    @staticmethod
    def _rtype(rdtype: str | DnsRecordType) -> str:
        return rdtype.value if isinstance(rdtype, DnsRecordType) else rdtype.upper()


class FakeWireTransport:
    """Builds real `dns.message.Message` replies from a `MutableDnsZone` without sockets."""

    def __init__(self, zone: MutableDnsZone) -> None:
        self.zone = zone

    def query_udp(
        self,
        query: dns.message.Message,
        where: str,
        *,
        port: int = 53,
        timeout: float | None = None,
        ignore_errors: bool = False,
    ) -> dns.message.Message:
        response = dns.message.make_response(query)
        response.flags |= dns.flags.AA
        if not query.question:
            return response
        question = query.question[0]
        qname = question.name.to_text(omit_final_dot=True).lower()
        rdtype = dns.rdatatype.to_text(question.rdtype).upper()
        if qname in self.zone.nxdomain:
            response.set_rcode(dns.rcode.NXDOMAIN)
            return response
        values = self.zone.records.get((qname, rdtype), ())
        if values:
            rrset = response.find_rrset(
                response.answer,
                question.name,
                dns.rdataclass.IN,
                question.rdtype,
                create=True,
            )
            for raw in values:
                text = _wire_rdata_text(rdtype, raw)
                rrset.add(dns.rdata.from_text("IN", rdtype, text), 60)
        return response

    def query_tcp(
        self,
        query: dns.message.Message,
        where: str,
        *,
        port: int = 53,
        timeout: float | None = None,
    ) -> dns.message.Message:
        return self.query_udp(query, where, port=port, timeout=timeout)

    def query_xfr(
        self,
        where: str,
        zone: dns.name.Name | str,
        *,
        port: int = 53,
        timeout: float | None = None,
        lifetime: float | None = None,
        relativize: bool = True,
    ) -> Iterator[dns.message.Message]:
        name_text = (
            (zone.to_text(omit_final_dot=True) if isinstance(zone, dns.name.Name) else zone)
            .rstrip(".")
            .lower()
        )
        count = self.zone.axfr_records.get(name_text, 0)
        if count <= 0:
            raise dns.exception.DNSException("AXFR refused")
        msg = dns.message.Message()
        qname = zone if isinstance(zone, dns.name.Name) else dns.name.from_text(zone)
        rrset = msg.find_rrset(msg.answer, qname, dns.rdataclass.IN, dns.rdatatype.A, create=True)
        for idx in range(count):
            rrset.add(dns.rdata.from_text("IN", "A", f"198.51.100.{(idx % 250) + 1}"), 60)
        return iter((msg,))


def _wire_rdata_text(rdtype: str, raw: str) -> str:
    if rdtype == "TXT":
        escaped = raw.replace("\\", "\\\\").replace('"', '\\"')
        return f'"{escaped}"'
    return raw


def patch_dnspython_wire(
    monkeypatch: pytest.MonkeyPatch, zone: MutableDnsZone
) -> FakeWireTransport:
    """Redirect `authoritative_dns`'s dnspython UDP/TCP/XFR calls to `zone`."""
    wire = FakeWireTransport(zone)
    monkeypatch.setattr(authoritative_dns.dns.query, "udp", wire.query_udp)
    monkeypatch.setattr(authoritative_dns.dns.query, "tcp", wire.query_tcp)
    monkeypatch.setattr(authoritative_dns.dns.query, "xfr", wire.query_xfr)
    return wire


class FakeScopeHttp:
    """Zero-network `ScopeHttp` honoring ScopeGuard redirect/allowlist hooks."""

    def __init__(
        self,
        routes: dict[str, HttpBody | Callable[[str], HttpBody]] | None = None,
        *,
        resolver: MutableDnsZone | None = None,
    ) -> None:
        self.routes = routes or {}
        self.resolver = resolver
        self.requests: list[str] = []
        self.header_requests: list[tuple[str, Mapping[str, str] | None]] = []
        self.method_requests: list[tuple[str, str]] = []

    def get(self, url: str, *, limit: int, headers: Mapping[str, str] | None = None) -> HttpBody:
        return self._dispatch(url, limit=limit, headers=headers, method="GET")

    def head(self, url: str, *, headers: Mapping[str, str] | None = None) -> HttpBody:
        return self._dispatch(url, limit=0, headers=headers, method="HEAD")

    def close(self) -> None:
        pass

    def with_redirect_policy(
        self,
        resolver: object,
        *,
        redirect_allowed: Callable[[str], bool],
        request_allowed: Callable[[str, str], bool] | None = None,
        max_redirects: int,
        stop_on_out_of_scope_redirect: bool = False,
        rate_limiter: object = None,
        rate_limit_org_id: UUID | None = None,
        user_agent: str | None = None,
    ) -> "_BoundFakeHttp":
        return _BoundFakeHttp(
            self,
            resolver,
            redirect_allowed,
            max_redirects,
            request_allowed=request_allowed,
            stop_on_out_of_scope_redirect=stop_on_out_of_scope_redirect,
            rate_limiter=rate_limiter,
            rate_limit_org_id=rate_limit_org_id,
            user_agent=user_agent,
        )

    def _dispatch(
        self,
        url: str,
        *,
        limit: int,
        headers: Mapping[str, str] | None = None,
        method: str = "GET",
    ) -> HttpBody:
        self.requests.append(url)
        self.header_requests.append((url, dict(headers) if headers is not None else None))
        self.method_requests.append((method, url))
        handler = self.routes.get(url)
        if handler is None:
            return HttpBody(status_code=404, content=b"" if method == "HEAD" else b"Not Found")
        body = handler(url) if callable(handler) else handler
        if method == "HEAD":
            return HttpBody(
                status_code=body.status_code,
                content=b"",
                truncated=False,
                headers=body.headers,
                final_url=body.final_url,
                redirect_chain=body.redirect_chain,
            )
        if len(body.content) > limit:
            return HttpBody(
                status_code=body.status_code,
                content=body.content[:limit],
                truncated=True,
                headers=body.headers,
            )
        return body


class _BoundFakeHttp:
    def __init__(
        self,
        inner: FakeScopeHttp,
        resolver: object,
        redirect_allowed: Callable[[str], bool],
        max_redirects: int,
        *,
        request_allowed: Callable[[str, str], bool] | None = None,
        stop_on_out_of_scope_redirect: bool = False,
        rate_limiter: object = None,
        rate_limit_org_id: UUID | None = None,
        user_agent: str | None = None,
    ) -> None:
        self._inner = inner
        self._resolver = resolver
        self._allowed = redirect_allowed
        self._request_allowed = request_allowed
        self._max_redirects = max_redirects
        self._stop_on_out_of_scope_redirect = stop_on_out_of_scope_redirect
        self._rate_limiter = rate_limiter
        self._rate_limit_org_id = rate_limit_org_id
        self._user_agent = user_agent

    def get(self, url: str, *, limit: int, headers: Mapping[str, str] | None = None) -> HttpBody:
        return self._perform("GET", url, limit=limit, headers=headers)

    def head(self, url: str, *, headers: Mapping[str, str] | None = None) -> HttpBody:
        return self._perform("HEAD", url, limit=0, headers=headers)

    def _perform(
        self,
        method: str,
        url: str,
        *,
        limit: int,
        headers: Mapping[str, str] | None = None,
    ) -> HttpBody:
        if not self._allowed(url):
            raise ScopeError("The target is out of scope.")
        if self._request_allowed is not None and not self._request_allowed(method, url):
            raise ScopePolicyError("The request method or path is outside the scanner grant.")
        host = urlsplit(url).hostname
        if host and hasattr(self._resolver, "resolve_name"):
            self._resolver.resolve_name(host)  # type: ignore[attr-defined]
        limiter_ctx = (
            self._rate_limiter.acquire(self._rate_limit_org_id, host)  # type: ignore[attr-defined]
            if self._rate_limiter is not None
            and self._rate_limit_org_id is not None
            and host is not None
            else nullcontext()
        )
        with limiter_ctx:
            body = self._inner._dispatch(url, limit=limit, headers=headers, method=method)
            return HttpBody(
                body.status_code,
                body.content,
                body.truncated,
                body.headers,
                final_url=body.final_url or url,
                redirect_chain=body.redirect_chain,
            )

    def close(self) -> None:
        pass
