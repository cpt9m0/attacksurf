"""Authoritative lookups: validated nameservers, no referral following, bounded answers.

No test opens a socket: `dns.query.udp`/`tcp`/`xfr` and the stub resolver's `resolve` are
replaced, and the tests assert which addresses *would* have been contacted.
"""

from collections.abc import Sequence

import dns.exception
import dns.flags
import dns.message
import dns.name
import dns.rcode
import dns.rdata
import dns.rdataclass
import dns.rdatatype
import pytest

from attacksurf.domain.net import DnsError, DnsLookup, DnsQuery, DnsRecordType, DnsStatus, TxtError
from attacksurf.infra import authoritative_dns
from attacksurf.infra.authoritative_dns import AuthoritativeLookup, AuthoritativeTxtLookup


class Aliased:
    """An answer the stub obtained by following a CNAME: the rrset is owned by another name."""

    def __init__(self, owner: str, values: list[str] | None = None) -> None:
        self.owner = owner
        self.values = values or []


class StubResolver:
    """Stands in for the stub resolver: canned answers per (name, type), plus their owner.

    `answers` values may be a list (owner = the queried name), or `Aliased(owner, values)` to
    imitate the stub following a CNAME to another name.
    """

    def __init__(
        self, answers: dict[tuple[str, str], list[str] | Exception | Aliased | None]
    ) -> None:
        self.answers = answers

    def lookup_records(self, name: str, rdtype: str) -> tuple[str, tuple[str, ...]]:
        # DnsPythonResolver turns every dnspython failure into DnsError; mirror that here.
        outcome = self.answers.get((name, rdtype))
        if isinstance(outcome, Exception):
            raise outcome if isinstance(outcome, DnsError) else DnsError()
        if isinstance(outcome, Aliased):
            return outcome.owner, tuple(outcome.values)
        return name, tuple(outcome or ())

    def resolve_ipv4(self, host: str) -> tuple[str, ...]:
        raise AssertionError("authoritative probes only use lookup_records")

    def resolve_name(self, host: str) -> tuple[str, ...]:
        raise AssertionError("authoritative probes only use lookup_records")

    def lookup_many(self, queries: Sequence[DnsQuery]) -> tuple[DnsLookup, ...]:
        raise AssertionError("authoritative probes only use lookup_records")


class FakeWire:
    """Records the servers that would be queried and answers with canned messages."""

    def __init__(self, responses: dict[str, dns.message.Message | Exception]) -> None:
        self.responses = responses
        self.udp_calls: list[tuple[str, int]] = []
        self.tcp_calls: list[tuple[str, int]] = []

    def _pick(self, address: str) -> dns.message.Message:
        outcome = self.responses[address]
        if isinstance(outcome, Exception):
            raise outcome
        return outcome

    def query_udp(self, query: dns.message.Message, address: str, *, port: int, **kw: object):
        self.udp_calls.append((address, port))
        return self._pick(address)

    def query_tcp(self, query: dns.message.Message, address: str, *, port: int, **kw: object):
        self.tcp_calls.append((address, port))
        return self._pick(address)


def _response(qname: str, values: list[tuple[str, ...]], *, truncated: bool = False):
    """A reply carrying TXT records for `qname`; `values` are the chunks of each record."""
    response = dns.message.make_response(dns.message.make_query(qname, dns.rdatatype.TXT))
    if truncated:
        response.flags |= dns.flags.TC
        return response
    for chunks in values:
        record = dns.rdata.from_text("IN", "TXT", " ".join(f'"{chunk}"' for chunk in chunks))
        rrset = response.find_rrset(
            response.answer,
            dns.name.from_text(qname),
            dns.rdataclass.IN,
            dns.rdatatype.TXT,
            create=True,
        )
        rrset.add(record, 60)
    return response


def _lookup(
    monkeypatch: pytest.MonkeyPatch,
    *,
    answers: dict[tuple[str, str], list[str] | Exception | Aliased | None],
    responses: dict[str, dns.message.Message | Exception],
) -> tuple[AuthoritativeTxtLookup, FakeWire]:
    wire = FakeWire(responses)
    monkeypatch.setattr(authoritative_dns.dns.query, "udp", wire.query_udp)
    monkeypatch.setattr(authoritative_dns.dns.query, "tcp", wire.query_tcp)
    resolver = StubResolver(
        {
            ("example.com", "NS"): ["ns1.example.net", "ns2.example.net"],
            ("ns1.example.net", "A"): ["93.184.216.34"],
            ("ns1.example.net", "AAAA"): [],
            ("ns2.example.net", "A"): ["93.184.216.35"],
            ("ns2.example.net", "AAAA"): [],
        }
        | answers
    )
    return AuthoritativeTxtLookup(resolver), wire


def test_txt_chunks_of_one_record_are_joined(monkeypatch: pytest.MonkeyPatch) -> None:
    qname = "_attacksurf-verify.example.com"
    lookup, wire = _lookup(
        monkeypatch,
        answers={},
        responses={
            "93.184.216.34": _response(qname, [("attacksurf-verification=", "tok", "en")]),
        },
    )

    assert lookup.lookup_txt("example.com", qname) == ("attacksurf-verification=token",)
    assert wire.udp_calls == [("93.184.216.34", 53)]


def test_the_next_nameserver_is_asked_when_the_first_fails(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    qname = "_attacksurf-verify.example.com"
    lookup, wire = _lookup(
        monkeypatch,
        answers={},
        responses={
            "93.184.216.34": dns.exception.Timeout(),
            "93.184.216.35": _response(qname, [("attacksurf-verification=abc",)]),
        },
    )

    assert lookup.lookup_txt("example.com", qname) == ("attacksurf-verification=abc",)
    assert [address for address, _ in wire.udp_calls] == ["93.184.216.34", "93.184.216.35"]


def test_a_private_nameserver_is_skipped_in_favour_of_the_public_one(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A zone delegating to an internal address would be an SSRF primitive."""
    qname = "_attacksurf-verify.example.com"
    lookup, wire = _lookup(
        monkeypatch,
        answers={("ns1.example.net", "A"): ["10.0.0.5"]},
        responses={"93.184.216.35": _response(qname, [("attacksurf-verification=abc",)])},
    )

    assert lookup.lookup_txt("example.com", qname) == ("attacksurf-verification=abc",)
    assert [address for address, _ in wire.udp_calls] == ["93.184.216.35"]


def test_a_zone_served_only_by_internal_addresses_is_never_contacted(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    lookup, wire = _lookup(
        monkeypatch,
        answers={
            ("ns1.example.net", "A"): ["169.254.169.254"],
            ("ns2.example.net", "A"): ["127.0.0.1"],
            ("ns2.example.net", "AAAA"): ["::1"],
        },
        responses={},
    )

    with pytest.raises(TxtError):
        lookup.lookup_txt("example.com", "_attacksurf-verify.example.com")
    assert wire.udp_calls == []
    assert wire.tcp_calls == []


def test_a_truncated_udp_answer_is_retried_over_tcp(monkeypatch: pytest.MonkeyPatch) -> None:
    qname = "_attacksurf-verify.example.com"
    lookup, _ = _lookup(monkeypatch, answers={}, responses={})
    full = FakeWire({"93.184.216.34": _response(qname, [("attacksurf-verification=abc",)])})
    truncated = FakeWire({"93.184.216.34": _response(qname, [], truncated=True)})
    wire = FakeWire({})

    def udp(query: object, address: str, *, port: int, **kw: object) -> dns.message.Message:
        wire.udp_calls.append((address, port))
        return truncated.query_udp(query, address, port=port)  # type: ignore[arg-type]

    def tcp(query: object, address: str, *, port: int, **kw: object) -> dns.message.Message:
        wire.tcp_calls.append((address, port))
        return full.query_tcp(query, address, port=port)  # type: ignore[arg-type]

    monkeypatch.setattr(authoritative_dns.dns.query, "udp", udp)
    monkeypatch.setattr(authoritative_dns.dns.query, "tcp", tcp)

    assert lookup.lookup_txt("example.com", qname) == ("attacksurf-verification=abc",)
    assert wire.tcp_calls == [("93.184.216.34", 53)]


def test_a_zone_without_nameservers_is_a_lookup_error(monkeypatch: pytest.MonkeyPatch) -> None:
    lookup, _ = _lookup(monkeypatch, answers={("example.com", "NS"): []}, responses={})

    with pytest.raises(TxtError):
        lookup.lookup_txt("example.com", "_attacksurf-verify.example.com")


def test_a_name_outside_the_zone_is_rejected_before_any_query(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    lookup, wire = _lookup(monkeypatch, answers={}, responses={})

    with pytest.raises(TxtError):
        lookup.lookup_txt("example.com", "_attacksurf-verify.example.net")
    assert wire.udp_calls == []


def test_a_cname_in_the_answer_is_not_followed(monkeypatch: pytest.MonkeyPatch) -> None:
    """Another domain's record can't be borrowed: only a direct TXT for the name counts."""
    qname = "_attacksurf-verify.example.com"
    response = _response(qname, [])
    response.find_rrset(
        response.answer,
        dns.name.from_text("other.example."),
        dns.rdataclass.IN,
        dns.rdatatype.TXT,
        create=True,
    ).add(dns.rdata.from_text("IN", "TXT", '"attacksurf-verification=abc"'), 60)
    lookup, _ = _lookup(monkeypatch, answers={}, responses={"93.184.216.34": response})

    assert lookup.lookup_txt("example.com", qname) == ()


def test_a_stub_resolver_failure_is_a_lookup_error(monkeypatch: pytest.MonkeyPatch) -> None:
    """Regression: the production adapter raises `DnsError`, not a dnspython exception."""
    lookup, wire = _lookup(monkeypatch, answers={("example.com", "NS"): DnsError()}, responses={})

    with pytest.raises(TxtError):
        lookup.lookup_txt("example.com", "_attacksurf-verify.example.com")
    assert wire.udp_calls == []


def test_a_failed_nameserver_lookup_falls_back_to_the_next(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    qname = "_attacksurf-verify.example.com"
    lookup, wire = _lookup(
        monkeypatch,
        answers={("ns1.example.net", "A"): DnsError()},  # ns1: A fails, AAAA still tried
        responses={"93.184.216.35": _response(qname, [("attacksurf-verification=abc",)])},
    )

    assert lookup.lookup_txt("example.com", qname) == ("attacksurf-verification=abc",)
    assert [address for address, _ in wire.udp_calls] == ["93.184.216.35"]


def test_a_failure_response_is_retried_on_the_next_nameserver(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """SERVFAIL/REFUSED is "could not answer", never "the record is absent" (would revoke)."""
    qname = "_attacksurf-verify.example.com"
    servfail = _response(qname, [])
    servfail.set_rcode(dns.rcode.SERVFAIL)
    lookup, wire = _lookup(
        monkeypatch,
        answers={},
        responses={
            "93.184.216.34": servfail,
            "93.184.216.35": _response(qname, [("attacksurf-verification=abc",)]),
        },
    )

    assert lookup.lookup_txt("example.com", qname) == ("attacksurf-verification=abc",)
    assert [address for address, _ in wire.udp_calls] == ["93.184.216.34", "93.184.216.35"]


def test_a_zone_whose_nameservers_all_fail_is_a_lookup_error(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    qname = "_attacksurf-verify.example.com"
    refused = _response(qname, [])
    refused.set_rcode(dns.rcode.REFUSED)
    lookup, _ = _lookup(
        monkeypatch,
        answers={},
        responses={"93.184.216.34": refused, "93.184.216.35": refused},
    )

    with pytest.raises(TxtError):
        lookup.lookup_txt("example.com", qname)


def test_a_subdomain_root_uses_the_enclosing_zone(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A root like `eng.example.com` usually has no NS of its own; its records live above."""
    qname = "_attacksurf-verify.eng.example.com"
    lookup, wire = _lookup(
        monkeypatch,
        answers={},  # eng.example.com has no NS; example.com does
        responses={"93.184.216.34": _response(qname, [("attacksurf-verification=abc",)])},
    )

    assert lookup.lookup_txt("eng.example.com", qname) == ("attacksurf-verification=abc",)
    assert [address for address, _ in wire.udp_calls] == ["93.184.216.34"]


def test_zone_discovery_failure_does_not_fall_back_to_the_parent(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    qname = "_attacksurf-verify.eng.example.com"
    lookup, wire = _lookup(
        monkeypatch,
        answers={("eng.example.com", "NS"): DnsError()},
        responses={"93.184.216.34": _response(qname, [])},
    )

    with pytest.raises(TxtError):
        lookup.lookup_txt("eng.example.com", qname)
    assert wire.udp_calls == []


def test_a_delegated_subdomain_root_uses_its_own_zone(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    qname = "_attacksurf-verify.eng.example.com"
    lookup, _ = _lookup(
        monkeypatch,
        answers={
            ("eng.example.com", "NS"): ["ns1.example.net"],
            ("example.com", "NS"): ["ns2.example.net"],  # and the parent, which must not win
        },
        responses={"93.184.216.34": _response(qname, [("attacksurf-verification=abc",)])},
    )

    assert lookup.lookup_txt("eng.example.com", qname) == ("attacksurf-verification=abc",)


def test_the_zone_walk_stops_at_the_registrable_domain(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """`a.b.example.com` with no NS anywhere stops at `example.com`, never at `com`."""
    qname = "_attacksurf-verify.a.b.example.com"
    lookup, _ = _lookup(
        monkeypatch,
        answers={("example.com", "NS"): ["ns1.example.net"]},
        responses={"93.184.216.34": _response(qname, [("attacksurf-verification=abc",)])},
    )

    assert lookup.lookup_txt("a.b.example.com", qname) == ("attacksurf-verification=abc",)


def test_a_cname_targets_nameservers_are_not_treated_as_the_zones(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """`www.attacker.com` CNAMEs to a zone whose NS the stub hands back for the alias."""
    qname = "_attacksurf-verify.www.attacker.com"
    lookup, wire = _lookup(
        monkeypatch,
        answers={
            # The stub followed www.attacker.com -> evil.example.com and returned its NS.
            ("www.attacker.com", "NS"): Aliased("evil.example.com", ["ns1.evil.example.com"]),
            ("ns1.evil.example.com", "A"): ["93.184.216.77"],
        },
        # The forged answer the alias target would serve, if it were ever asked.
        responses={
            "93.184.216.77": _response(qname, [("attacksurf-verification=attacker-token",)])
        },
    )

    with pytest.raises(TxtError):
        lookup.lookup_txt("www.attacker.com", qname)

    # The alias target's servers were never contacted, so they can't answer for the proof.
    assert wire.udp_calls == []


def test_an_alias_target_cannot_answer_the_proof_record(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The alias's servers must never be asked for the original name's record.

    The host is a root that is itself a CNAME, so nothing above it is a zone either: without
    the owner check the attacker's server would be queried and its forged answer accepted.
    """
    qname = "_attacksurf-verify.attacker.com"
    lookup, wire = _lookup(
        monkeypatch,
        answers={
            ("attacker.com", "NS"): Aliased("evil.example.com", ["ns1.evil.example.com"]),
            # A real public address: TEST-NET ranges are blocked by policy, either way.
            ("ns1.evil.example.com", "A"): ["93.184.216.77"],
        },
        responses={
            "93.184.216.77": _response(qname, [("attacksurf-verification=attacker-token",)])
        },
    )

    # Either way the proof must not verify; without the owner check this is the attack path.
    with pytest.raises(TxtError):
        lookup.lookup_txt("attacker.com", qname)
    assert wire.udp_calls == []


def test_a_real_delegation_still_uses_its_own_nameservers(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    qname = "_attacksurf-verify.example.com"
    lookup, wire = _lookup(
        monkeypatch,
        answers={},
        responses={"93.184.216.34": _response(qname, [("attacksurf-verification=abc",)])},
    )

    assert lookup.lookup_txt("example.com", qname) == ("attacksurf-verification=abc",)
    assert [address for address, _ in wire.udp_calls] == ["93.184.216.34"]


# --- Read-only SOA/DNSKEY probes and zone transfers (#19) ------------------------------------

SOA = "ns1.example.net. hostmaster.example.net. 2024010101 3600 600 604800 300"


def _records_response(
    qname: str,
    rdtype: str,
    values: list[str],
    *,
    authoritative: bool = True,
    rcode: dns.rcode.Rcode = dns.rcode.NOERROR,
) -> dns.message.Message:
    response = dns.message.make_response(dns.message.make_query(qname, rdtype))
    if authoritative:
        response.flags |= dns.flags.AA
    if rcode != dns.rcode.NOERROR:
        response.set_rcode(rcode)
    if values:
        rrset = response.find_rrset(
            response.answer,
            dns.name.from_text(qname),
            dns.rdataclass.IN,
            dns.rdatatype.from_text(rdtype),
            create=True,
        )
        for value in values:
            rrset.add(dns.rdata.from_text("IN", rdtype, value), 300)
    return response


def _authoritative(
    monkeypatch: pytest.MonkeyPatch,
    *,
    answers: dict[tuple[str, str], list[str] | Exception | Aliased | None] | None = None,
    responses: dict[str, dns.message.Message | Exception] | None = None,
) -> tuple[AuthoritativeLookup, FakeWire, StubResolver]:
    wire = FakeWire(responses or {})
    monkeypatch.setattr(authoritative_dns.dns.query, "udp", wire.query_udp)
    monkeypatch.setattr(authoritative_dns.dns.query, "tcp", wire.query_tcp)
    resolver = StubResolver(
        {
            ("example.com", "NS"): ["ns1.example.net", "ns2.example.net"],
            ("ns1.example.net", "A"): ["93.184.216.34"],
            ("ns1.example.net", "AAAA"): [],
            ("ns2.example.net", "A"): ["93.184.216.35"],
            ("ns2.example.net", "AAAA"): [],
        }
        | (answers or {})
    )
    return AuthoritativeLookup(resolver), wire, resolver


def test_query_returns_one_answer_per_nameserver(monkeypatch: pytest.MonkeyPatch) -> None:
    lookup, wire, _ = _authoritative(
        monkeypatch,
        responses={
            "93.184.216.34": _records_response("example.com", "SOA", [SOA]),
            "93.184.216.35": _records_response("example.com", "SOA", [SOA]),
        },
    )

    answers = lookup.query("example.com", DnsRecordType.SOA)

    assert answers.zone == "example.com"
    assert answers.servers == ("ns1.example.net", "ns2.example.net")
    assert [answer.server for answer in answers.answers] == [
        "ns1.example.net",
        "ns2.example.net",
    ]
    assert all(answer.status is DnsStatus.OK for answer in answers.answers)
    assert all(answer.authoritative for answer in answers.answers)
    assert all(answer.values == (SOA,) for answer in answers.answers)
    assert [address for address, _ in wire.udp_calls] == ["93.184.216.34", "93.184.216.35"]


def test_query_uses_the_registrable_domain_when_the_name_has_no_ns(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    lookup, _, _ = _authoritative(
        monkeypatch,
        answers={("www.example.com", "NS"): []},
        responses={
            "93.184.216.34": _records_response("www.example.com", "SOA", [SOA]),
            "93.184.216.35": _records_response("www.example.com", "SOA", [SOA]),
        },
    )

    answers = lookup.query("www.example.com", DnsRecordType.SOA)

    assert answers.zone == "example.com"
    assert answers.servers == ("ns1.example.net", "ns2.example.net")


def test_an_aliased_name_is_not_treated_as_a_zone(monkeypatch: pytest.MonkeyPatch) -> None:
    lookup, _, _ = _authoritative(
        monkeypatch,
        answers={("www.example.com", "NS"): Aliased("other.example.net", ["ns9.example.net"])},
        responses={
            "93.184.216.34": _records_response("www.example.com", "SOA", [SOA]),
            "93.184.216.35": _records_response("www.example.com", "SOA", [SOA]),
        },
    )

    answers = lookup.query("www.example.com", DnsRecordType.SOA)

    assert answers.zone == "example.com"


def test_a_failed_zone_lookup_falls_back_to_the_registrable_domain(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    lookup, _, _ = _authoritative(
        monkeypatch,
        answers={("www.example.com", "NS"): DnsError()},
        responses={
            "93.184.216.34": _records_response("www.example.com", "SOA", [SOA]),
            "93.184.216.35": _records_response("www.example.com", "SOA", [SOA]),
        },
    )

    assert lookup.query("www.example.com", DnsRecordType.SOA).zone == "example.com"


def test_a_zone_without_nameservers_has_no_answers(monkeypatch: pytest.MonkeyPatch) -> None:
    lookup, wire, _ = _authoritative(monkeypatch, answers={("example.com", "NS"): []})

    answers = lookup.query("example.com", DnsRecordType.SOA)

    assert answers.servers == ()
    assert answers.answers == ()
    assert wire.udp_calls == []


def test_private_nameserver_addresses_are_skipped(monkeypatch: pytest.MonkeyPatch) -> None:
    lookup, wire, _ = _authoritative(
        monkeypatch,
        answers={("ns1.example.net", "A"): ["10.0.0.5"]},
        responses={"93.184.216.35": _records_response("example.com", "SOA", [SOA])},
    )

    answers = lookup.query("example.com", DnsRecordType.SOA)

    assert [answer.server for answer in answers.answers] == ["ns2.example.net"]
    assert [address for address, _ in wire.udp_calls] == ["93.184.216.35"]


def test_an_unreachable_server_has_no_rcode(monkeypatch: pytest.MonkeyPatch) -> None:
    lookup, _, _ = _authoritative(
        monkeypatch,
        responses={
            "93.184.216.34": dns.exception.Timeout(),
            "93.184.216.35": _records_response("example.com", "SOA", [SOA]),
        },
    )

    first = lookup.query("example.com", DnsRecordType.SOA).answers[0]

    assert first.status is DnsStatus.ERROR
    assert first.rcode == ""
    assert first.authoritative is False


def test_a_refused_answer_keeps_its_rcode(monkeypatch: pytest.MonkeyPatch) -> None:
    lookup, _, _ = _authoritative(
        monkeypatch,
        responses={
            "93.184.216.34": _records_response(
                "example.com", "SOA", [], authoritative=False, rcode=dns.rcode.REFUSED
            ),
            "93.184.216.35": _records_response("example.com", "SOA", [SOA]),
        },
    )

    first = lookup.query("example.com", DnsRecordType.SOA).answers[0]

    assert first.rcode == "refused"
    assert first.authoritative is False


def test_transfer_returns_nothing_when_the_name_has_no_ns(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    lookup, _, _ = _authoritative(monkeypatch, answers={("www.example.com", "NS"): []})

    assert lookup.attempt("www.example.com") == ()


class FakeTransfer:
    """Records AXFR calls and hands out one iterator per attempt."""

    def __init__(self, messages: list[dns.message.Message], error: Exception | None = None):
        self.messages = messages
        self.error = error
        self.calls: list[tuple[str, str, int]] = []
        self.closed = 0

    def __call__(
        self,
        address: str,
        zone: object,
        *,
        port: int,
        timeout: float,
        lifetime: float,
        relativize: bool,
    ) -> object:
        self.calls.append((address, str(zone), port))
        if self.error is not None:
            raise self.error
        return self._generator()

    def _generator(self) -> object:
        try:
            yield from self.messages
        finally:
            self.closed += 1


def _transfer_message(qname: str = "example.com") -> dns.message.Message:
    message = dns.message.make_response(dns.message.make_query(qname, "AXFR"))
    message.find_rrset(
        message.answer,
        dns.name.from_text(qname),
        dns.rdataclass.IN,
        dns.rdatatype.SOA,
        create=True,
    ).add(dns.rdata.from_text("IN", "SOA", SOA), 300)
    txt = message.find_rrset(
        message.answer,
        dns.name.from_text(qname),
        dns.rdataclass.IN,
        dns.rdatatype.TXT,
        create=True,
    )
    txt.add(dns.rdata.from_text("IN", "TXT", '"one"'), 300)
    txt.add(dns.rdata.from_text("IN", "TXT", '"two"'), 300)
    return message


def test_transfer_reports_an_allowed_transfer(monkeypatch: pytest.MonkeyPatch) -> None:
    lookup, _, _ = _authoritative(monkeypatch)
    transfer = FakeTransfer([_transfer_message()])
    monkeypatch.setattr(authoritative_dns.dns.query, "xfr", transfer)

    attempts = lookup.attempt("example.com")

    assert [attempt.allowed for attempt in attempts] == [True, True]
    assert [attempt.records for attempt in attempts] == [3, 3]
    assert [attempt.server for attempt in attempts] == ["ns1.example.net", "ns2.example.net"]
    assert transfer.closed == 2


def test_a_refused_transfer_is_not_allowed(monkeypatch: pytest.MonkeyPatch) -> None:
    lookup, _, _ = _authoritative(monkeypatch)
    transfer = FakeTransfer([], error=dns.exception.FormError("refused"))
    monkeypatch.setattr(authoritative_dns.dns.query, "xfr", transfer)

    attempts = lookup.attempt("example.com")

    assert [attempt.allowed for attempt in attempts] == [False, False]
    assert [attempt.records for attempt in attempts] == [0, 0]


def test_transfer_never_reads_past_the_first_message(monkeypatch: pytest.MonkeyPatch) -> None:
    lookup, _, _ = _authoritative(monkeypatch)

    class OneShot:
        def __init__(self, message: dns.message.Message) -> None:
            self.message = message
            self.read = 0
            self.closed = False

        def __iter__(self) -> "OneShot":
            return self

        def __next__(self) -> dns.message.Message:
            self.read += 1
            if self.read > 1:
                raise AssertionError("the adapter read a second message")
            return self.message

        def close(self) -> None:
            self.closed = True

    iterators: list[OneShot] = []

    def xfr(*_args: object, **_kwargs: object) -> OneShot:
        iterator = OneShot(_transfer_message())
        iterators.append(iterator)
        return iterator

    monkeypatch.setattr(authoritative_dns.dns.query, "xfr", xfr)

    attempts = lookup.attempt("example.com")

    assert [attempt.allowed for attempt in attempts] == [True, True]
    assert all(iterator.read == 1 and iterator.closed for iterator in iterators)


def test_transfer_never_touches_a_parent_zone(monkeypatch: pytest.MonkeyPatch) -> None:
    lookup, _, _ = _authoritative(monkeypatch, answers={("www.example.com", "NS"): []})
    transfer = FakeTransfer([_transfer_message()])
    monkeypatch.setattr(authoritative_dns.dns.query, "xfr", transfer)

    assert lookup.attempt("www.example.com") == ()
    assert transfer.calls == []
