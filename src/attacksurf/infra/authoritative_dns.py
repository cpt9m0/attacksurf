"""Authoritative DNS for scanners (#19) and ownership proofs (#14, ADR 0014).

`infra/dns.py` deliberately queries only the configured stub resolver: talking to a nameserver
named in a response is an SSRF primitive. Two checks need the opposite. The ownership proof needs
the zone's own servers because a caching resolver can serve a stale TXT record long after an owner
removed it. The DNS hygiene checks (#19) need each server's own answer to compare SOA data and to
spot lame delegations, and the zone-transfer check needs a real AXFR attempt. This module is the
one place that exception is allowed, and it keeps it narrow: nameservers come from the resolver,
every one of their addresses must be public (the same policy as scan targets), and answers are
read, never followed (an NS or CNAME inside an answer is ignored). Probes are read-only single
queries; only `AuthoritativeLookup.transfer` sends an AXFR, and only for a name that owns NS
records itself, so a parent zone can never be transferred on a child's behalf (ADR 0026).
"""

import struct
from collections.abc import Sequence
from dataclasses import dataclass

import dns.exception
import dns.flags
import dns.message
import dns.name
import dns.query
import dns.rcode
import dns.rdatatype

from attacksurf.domain.net import (
    AuthoritativeAnswer,
    DnsError,
    DnsRecordType,
    DnsStatus,
    RecordResolver,
    TxtError,
    ZoneAnswers,
    ZoneTransferAttempt,
)
from attacksurf.domain.scope import ScopeError, check_addresses
from attacksurf.domain.verification import MAX_TXT_BYTES, MAX_TXT_RECORDS
from attacksurf.infra import public_suffix

TX_TIMEOUT_SECONDS = 2.0
MAX_NAMESERVERS = 3
MAX_NS_ADDRESSES = 4
# Names we report for a zone; only MAX_NAMESERVERS of them are actually probed.
MAX_NS_NAMES = 10
MAX_ANSWER_VALUES = 20
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
# A truncated answer must fit over TCP; anything bigger is not a record we asked for.
MAX_RESPONSE_BYTES = 64 * 1024


@dataclass(frozen=True)
class _Server:
    ns: str
    address: str
    port: int = 53


class AuthoritativeTxtLookup:
    """`TxtLookup` that asks the zone's nameservers directly, over validated addresses."""

    def __init__(self, resolver: RecordResolver, *, timeout: float = TX_TIMEOUT_SECONDS):
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
                answer = _query(qname, DnsRecordType.TXT, server, self._timeout)
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
        return bool(_ns_at(self._resolver, name))

    def _nameservers(self, zone: dns.name.Name) -> tuple[tuple[str, int], ...]:
        """Validated (address, port) pairs for the zone's authoritative servers.

        `check_addresses` rejects loopback, private, link-local and metadata ranges, so a zone
        that delegates to an internal address can't be used to probe our network.
        """
        servers: list[tuple[str, int]] = []
        for ns_name in _ns_names(_ns_at(self._resolver, zone))[:MAX_NAMESERVERS]:
            for address in _addresses(self._resolver, ns_name)[:MAX_NS_ADDRESSES]:
                if _is_public(address):  # never queue an address the policy blocks
                    servers.append((address, 53))
        return tuple(servers)


class AuthoritativeLookup:
    """Read-only SOA/DNSKEY probes and bounded AXFR attempts for hygiene checks (#19)."""

    def __init__(self, resolver: RecordResolver, *, timeout: float = TX_TIMEOUT_SECONDS) -> None:
        self._resolver = resolver
        self._timeout = timeout

    def query(self, name: str, record_type: DnsRecordType) -> ZoneAnswers:
        """One read-only query per nameserver of `name`'s zone, over validated addresses."""
        zone = _zone_of(self._resolver, name)
        if zone is None:
            return ZoneAnswers(zone=name)
        try:
            names = _ns_names(_ns_at(self._resolver, _absolute(zone)))
        except TxtError:
            return ZoneAnswers(zone=zone)
        servers = _servers(self._resolver, names)
        answers = tuple(self._answer(server, name, record_type) for server in servers)
        return ZoneAnswers(zone=zone, servers=names, answers=answers)

    def attempt(self, zone: str) -> tuple[ZoneTransferAttempt, ...]:
        """One AXFR per nameserver, only when `zone` owns NS records itself.

        A name without NS records is not a zone apex: its data belongs to a parent zone that the
        caller did not prove ownership of, so nothing is attempted.
        """
        qname = _absolute(zone)
        try:
            names = _ns_names(_ns_at(self._resolver, qname))
        except TxtError:
            return ()
        if not names:
            return ()
        return tuple(
            self._attempt_transfer(server, qname) for server in _servers(self._resolver, names)
        )

    def _answer(
        self, server: _Server, name: str, record_type: DnsRecordType
    ) -> AuthoritativeAnswer:
        qname = _absolute(name)
        try:
            response = _query(qname, record_type, (server.address, server.port), self._timeout)
        except dns.exception.DNSException:
            # Unreachable, timed out or malformed: no evidence either way, so `rcode` stays "".
            return AuthoritativeAnswer(
                server=server.ns, address=server.address, status=DnsStatus.ERROR
            )
        rcode = dns.rcode.to_text(response.rcode()).lower()
        values = _answer_values(response, qname, record_type)
        if values:
            status = DnsStatus.OK
        elif rcode == "nxdomain":
            status = DnsStatus.NXDOMAIN
        else:
            status = DnsStatus.NO_ANSWER
        return AuthoritativeAnswer(
            server=server.ns,
            address=server.address,
            status=status,
            authoritative=bool(response.flags & dns.flags.AA),
            rcode=rcode,
            values=values,
        )

    def _attempt_transfer(self, server: _Server, qname: dns.name.Name) -> ZoneTransferAttempt:
        """Ask one server for the zone, keeping only whether it agreed and how many records came.

        Only the first message is read: a server that starts a transfer has proven it allows one,
        and the zone contents must never be buffered or stored.
        """
        try:
            messages = dns.query.xfr(
                server.address,
                qname,
                port=server.port,
                timeout=self._timeout,
                lifetime=self._timeout,
                relativize=False,
            )
            try:
                first = next(messages)
            finally:
                messages.close()
        except (StopIteration, dns.exception.DNSException, OSError, struct.error):
            return ZoneTransferAttempt(server=server.ns, address=server.address, allowed=False)
        records = sum(len(rrset) for rrset in first.answer)
        return ZoneTransferAttempt(
            server=server.ns, address=server.address, allowed=records > 0, records=records
        )


def _zone_of(resolver: RecordResolver, name: str) -> str | None:
    """The zone a name belongs to: the name itself when it owns NS data, else its registrable
    domain. A CNAME owner can never own NS data, so an aliased name is never mistaken for a
    delegation (RFC 1034 section 3.6.2)."""
    normalized = name.strip().rstrip(".").lower()
    try:
        owner, values = resolver.lookup_records(normalized, "NS")
    except DnsError:
        # A failed lookup cannot establish that a delegation exists. Falling back to the
        # registrable domain is still a read-only probe of the org's own zone.
        return public_suffix.registrable(normalized)
    if values and owner.rstrip(".").lower() == normalized:
        return normalized
    return public_suffix.registrable(normalized)


def _servers(resolver: RecordResolver, names: Sequence[str]) -> tuple[_Server, ...]:
    """One validated public address per nameserver, for at most MAX_NAMESERVERS of them."""
    servers: list[_Server] = []
    for ns_name in names[:MAX_NAMESERVERS]:
        for address in _addresses(resolver, ns_name):
            if _is_public(address):
                servers.append(_Server(ns_name, address))
                break  # one address per server is enough for a single probe
    return tuple(servers)


def _ns_names(values: Sequence[str]) -> tuple[str, ...]:
    """Normalized, deduplicated nameserver hostnames (trailing dot stripped, capped)."""
    names: list[str] = []
    for raw in values:
        host = raw.strip().rstrip(".").lower()
        if host and host not in names:
            names.append(host)
        if len(names) >= MAX_NS_NAMES:
            break
    return tuple(names)


def _ns_at(resolver: RecordResolver, name: dns.name.Name) -> tuple[str, ...]:
    """The NS records owned by `name` itself; empty when the stub answered for an alias.

    Without the owner check, a subdomain that CNAMEs elsewhere (`www` -> an attacker's apex)
    would be served by the alias target's nameservers, which could then answer for the original
    name's data.
    """
    owner, values = _resolve(resolver, name.to_text(omit_final_dot=True), "NS")
    return values if owner == name.to_text(omit_final_dot=True) else ()


def _addresses(resolver: RecordResolver, host: str) -> tuple[str, ...]:
    """A and AAAA answers; one failed family doesn't hide the other."""
    values: list[str] = []
    for rdtype in ("A", "AAAA"):
        try:
            values.extend(_resolve(resolver, host, rdtype)[1])
        except TxtError:
            continue
    return tuple(values)


def _resolve(resolver: RecordResolver, host: str, rdtype: str) -> tuple[str, tuple[str, ...]]:
    """Stub answers, translated: `DnsError` (the adapter's failure) becomes a lookup error.

    A failure is retried once with checking disabled: a validating resolver rejects a bogus
    zone (SERVFAIL), and that zone's own nameservers are what the check must reach.
    """
    try:
        return resolver.lookup_records(host, rdtype)
    except DnsError:
        pass
    try:
        return resolver.lookup_records_checking_disabled(host, rdtype)
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


def _query(
    qname: dns.name.Name,
    record_type: DnsRecordType,
    server: tuple[str, int],
    timeout: float,
) -> dns.message.Message:
    query = dns.message.make_query(
        qname, dns.rdatatype.from_text(record_type.value), want_dnssec=False
    )
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


def _answer_values(
    response: dns.message.Message, qname: dns.name.Name, record_type: DnsRecordType
) -> tuple[str, ...]:
    """Presentation-form records of `record_type` owned by `qname`, capped.

    RRSIGs and other accompanying records are ignored; only a direct answer for the name counts.
    """
    rdtype = dns.rdatatype.from_text(record_type.value)
    values: list[str] = []
    for rrset in response.answer:
        if rrset.name != qname or rrset.rdtype != rdtype:
            continue
        values.extend(str(record) for record in rrset)
        if len(values) >= MAX_ANSWER_VALUES:
            break
    return tuple(values[:MAX_ANSWER_VALUES])


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
