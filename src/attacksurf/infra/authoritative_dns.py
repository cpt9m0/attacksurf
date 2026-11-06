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
import dns.rcode
import dns.rdatatype

from attacksurf.domain.net import DnsError, TxtError
from attacksurf.domain.scope import ScopeError, check_addresses
from attacksurf.domain.verification import MAX_TXT_BYTES, MAX_TXT_RECORDS
from attacksurf.infra import public_suffix

TX_TIMEOUT_SECONDS = 2.0
MAX_NAMESERVERS = 3
MAX_NS_ADDRESSES = 4
# How many labels to strip while looking for the enclosing zone (eng.example.com -> example.com).
MAX_ZONE_WALK = 3
# Answers that mean "this server could not answer", not "the record is absent".
FAILURE_RCODES = frozenset(
    {
        dns.rcode.SERVFAIL,
        dns.rcode.REFUSED,
        dns.rcode.NOTIMP,
        dns.rcode.FORMERR,
    }
)
# A truncated answer must fit over TCP; anything bigger is not a TXT record we wrote.
MAX_RESPONSE_BYTES = 64 * 1024


class StubRecords(Protocol):
    """The stub's record lookup; `DnsPythonResolver.lookup_records` implements it.

    Raises `domain.net.DnsError` (never a dnspython exception) when the stub can't answer.
    """

    def lookup_records(self, name: str, rdtype: str) -> tuple[str, tuple[str, ...]]:
        """(owner name the stub answered for, values); the owner exposes followed CNAMEs."""
        ...


class AuthoritativeTxtLookup:
    """`TxtLookup` that asks the zone's nameservers directly, over validated addresses."""

    def __init__(self, resolver: StubRecords, *, timeout: float = TX_TIMEOUT_SECONDS):
        self._resolver = resolver
        self._timeout = timeout

    def lookup_txt(self, host: str, name: str) -> tuple[str, ...]:
        """TXT values at `name`, from the nameservers of the zone enclosing `host`.

        The record is always read at `name` itself; only the *zone* may be a parent, because a
        root like `eng.example.com` usually has no NS record of its own (its records live in
        `example.com`). Raises `TxtError` on any failure.
        """
        qname = _absolute(name)
        zone = self._zone(host)
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
            if answer.rcode() in FAILURE_RCODES:
                continue  # a failing server proves nothing about the record: ask another
            return _txt_values(answer, qname)
        raise TxtError()

    def _zone(self, host: str | dns.name.Name) -> dns.name.Name:
        """The closest zone at or above `host` that has an NS RRset.

        Stops at the Public Suffix boundary: `example.com` is where a walk from a deeper name
        ends when nothing delegated, and the PSL itself (a bare `com`) is never queried.
        """
        name = host if isinstance(host, dns.name.Name) else _absolute(host)
        # Never walk past the registrable domain: above it is the PSL itself (a bare `com`).
        stop = dns.name.from_text(
            public_suffix.registrable(name.to_text(omit_final_dot=True)) or name.to_text()
        )
        for _ in range(MAX_ZONE_WALK + 1):
            if name == stop or self._has_ns(name):
                return name
            parent = name.parent()
            if parent == name:
                break
            name = parent
        return stop

    def _has_ns(self, name: dns.name.Name) -> bool:
        """True only if `name` itself has NS records.

        A name that is a CNAME can't be a zone: the stub would follow the alias, so an answer
        owned by another name means "not a zone here", never "a zone pointed elsewhere".
        """
        # A failed lookup cannot establish the absence of a delegation. Walking past it
        # could query the parent and mistake a referral for a missing proof.
        return bool(self._ns_at(name))

    def _nameservers(self, zone: dns.name.Name) -> tuple[tuple[str, int], ...]:
        """Validated (address, port) pairs for the zone's authoritative servers.

        `check_addresses` rejects loopback, private, link-local and metadata ranges, so a zone
        that delegates to an internal address can't be used to probe our network.
        """
        ns_names = self._ns_at(zone)
        servers: list[tuple[str, int]] = []
        for ns_text in ns_names[:MAX_NAMESERVERS]:
            ns_name = ns_text[:-1] if ns_text.endswith(".") else ns_text  # the stub takes no dot
            try:
                addresses = self._addresses(ns_name)
            except TxtError:
                continue  # one unreachable NS doesn't fail a zone the others answer for
            for address in addresses[:MAX_NS_ADDRESSES]:
                if _is_public(address):  # never queue an address the policy blocks
                    servers.append((address, 53))
        return tuple(servers)

    def _addresses(self, host: str) -> tuple[str, ...]:
        return self._resolve(host, "A")[1] + self._resolve(host, "AAAA")[1]

    def _ns_at(self, name: dns.name.Name) -> tuple[str, ...]:
        """The NS records owned by `name` itself; empty when the stub answered for an alias.

        Without the owner check, a subdomain that CNAMEs elsewhere (`www` -> an attacker's
        apex) would be served by the alias target's nameservers, which could then answer for
        the *original* name's proof record — a proof published nowhere the org controls.
        """
        owner, values = self._resolve(name.to_text(omit_final_dot=True), "NS")
        return values if owner == name.to_text(omit_final_dot=True) else ()

    def _resolve(self, host: str, rdtype: str) -> tuple[str, tuple[str, ...]]:
        """Stub answers, translated: `DnsError` (the adapter's failure) becomes a lookup error."""
        try:
            return self._resolver.lookup_records(host, rdtype)
        except DnsError:
            raise TxtError() from None


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
