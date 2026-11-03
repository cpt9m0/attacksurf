"""Authoritative TXT lookups for ownership proof (#14, ADR 0014).

`infra/dns.py` deliberately queries only the configured stub resolver: talking to a nameserver
named in a response is an SSRF primitive. The ownership proof needs the opposite — a caching
resolver can serve a stale TXT record long after an owner removed it, so the check must ask the
zone's own servers. This module is the one place that exception is allowed, and it keeps it
narrow: the nameservers come from the resolver, every one of their addresses must be public
(validated with the same policy as targets), and answers are read, never followed (an NS or
CNAME inside the answer is ignored). The proof itself is a token only the zone's owners can
publish, so reading from a hijacked NS can at worst produce a false "not found", never a false
"verified".
"""

import struct
from typing import Protocol

import dns.exception
import dns.flags
import dns.message
import dns.name
import dns.query
import dns.rdatatype

from attacksurf.domain.net import TxtError
from attacksurf.domain.scope import ScopeError, check_addresses
from attacksurf.domain.verification import MAX_TXT_BYTES, MAX_TXT_RECORDS

TX_TIMEOUT_SECONDS = 2.0
MAX_NAMESERVERS = 3
MAX_NS_ADDRESSES = 4
# A truncated answer must fit over TCP; anything bigger is not a TXT record we wrote.
MAX_RESPONSE_BYTES = 64 * 1024


class StubRecords(Protocol):
    """The stub's record lookup; `DnsPythonResolver.lookup_records` implements it."""

    def lookup_records(self, name: str, rdtype: str) -> tuple[str, ...]: ...


class AuthoritativeTxtLookup:
    """`TxtLookup` that asks the zone's nameservers directly, over validated addresses."""

    def __init__(self, resolver: StubRecords, *, timeout: float = TX_TIMEOUT_SECONDS):
        self._resolver = resolver
        self._timeout = timeout

    def lookup_txt(self, host: str, name: str) -> tuple[str, ...]:
        """TXT values at `name`, from `host`'s nameservers. Raises `TxtError` on any failure."""
        zone = _absolute(host)
        qname = _absolute(name)
        if not qname.is_subdomain(zone):
            raise TxtError()
        nameservers = self._nameservers(zone)
        if not nameservers:
            raise TxtError()
        for server in nameservers:
            try:
                answer = _query(qname, server, self._timeout)
            except dns.exception.DNSException:
                continue  # try the next nameserver; all failing is a lookup error
            return _txt_values(answer, qname)
        raise TxtError()

    def _nameservers(self, zone: dns.name.Name) -> tuple[tuple[str, int], ...]:
        """Validated (address, port) pairs for the zone's authoritative servers.

        `check_addresses` rejects loopback, private, link-local and metadata ranges, so a zone
        that delegates to an internal address can't be used to probe our network.
        """
        try:
            ns_names = self._resolve(zone.to_text(omit_final_dot=True), "NS")
        except dns.exception.DNSException:
            raise TxtError() from None
        servers: list[tuple[str, int]] = []
        for ns_text in ns_names[:MAX_NAMESERVERS]:
            ns_name = ns_text[:-1] if ns_text.endswith(".") else ns_text  # the stub takes no dot
            try:
                addresses = self._resolve(ns_name, "A") + self._resolve(ns_name, "AAAA")
            except dns.exception.DNSException:
                continue  # one unreachable NS doesn't fail a zone the others answer for
            for address in addresses[:MAX_NS_ADDRESSES]:
                if _is_public(address):  # never queue an address the policy blocks
                    servers.append((address, 53))
        return tuple(servers)

    def _resolve(self, host: str, rdtype: str) -> tuple[str, ...]:
        return self._resolver.lookup_records(host, rdtype)


def _is_public(address: str) -> bool:
    """The same policy as scan targets: no private, loopback, link-local or metadata address."""
    try:
        check_addresses((address,))
    except ScopeError:
        return False
    return True


def _absolute(name: str) -> dns.name.Name:
    try:
        return dns.name.from_text(name)
    except dns.exception.DNSException:
        raise TxtError() from None


def _query(qname: dns.name.Name, server: tuple[str, int], timeout: float) -> dns.message.Message:
    query = dns.message.make_query(qname, dns.rdatatype.TXT, want_dnssec=False)
    query.flags &= ~dns.flags.RD  # authoritative servers don't need recursion, and we're not one
    address, port = server
    try:
        response = dns.query.udp(query, address, port=port, timeout=timeout, ignore_errors=False)
        if response.flags & dns.flags.TC:
            response = dns.query.tcp(query, address, port=port, timeout=timeout)
    except (OSError, struct.error) as exc:
        raise dns.exception.DNSException(str(exc)) from exc
    _check_size(response)
    return response


def _check_size(response: dns.message.Message) -> None:
    if len(response.to_wire()) > MAX_RESPONSE_BYTES:
        raise dns.exception.FormError("oversized DNS response")


def _txt_values(response: dns.message.Message, qname: dns.name.Name) -> tuple[str, ...]:
    """TXT values in the answer section's record for `qname`, chunks of one record joined.

    Only the direct TXT record counts: a CNAME in the answer is not followed, so a name can't
    borrow a record from a domain nobody proved.
    """
    values: list[str] = []
    total = 0
    for rrset in response.answer:
        if rrset.rdtype != dns.rdatatype.TXT or rrset.name != qname:
            continue
        for record in rrset:
            value = b"".join(record.strings).decode("utf-8", errors="replace")
            total += len(value)
            if total > MAX_TXT_BYTES or len(values) >= MAX_TXT_RECORDS:
                return tuple(values)
            values.append(value)
    return tuple(values)
