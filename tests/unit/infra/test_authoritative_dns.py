"""Authoritative TXT lookups: validated nameservers, no referral following, bounded answers.

No test opens a socket: `dns.query.udp`/`tcp` and the stub resolver's `resolve` are replaced,
and the tests assert which addresses *would* have been contacted.
"""

import dns.exception
import dns.flags
import dns.message
import dns.name
import dns.rdata
import dns.rdataclass
import dns.rdatatype
import pytest

from attacksurf.domain.net import TxtError
from attacksurf.infra import authoritative_dns
from attacksurf.infra.authoritative_dns import AuthoritativeTxtLookup


class StubResolver:
    """Stands in for the stub resolver: canned NS/A answers per (name, type)."""

    def __init__(self, answers: dict[tuple[str, str], list[str] | Exception | None]) -> None:
        self.answers = answers

    def lookup_records(self, name: str, rdtype: str) -> tuple[str, ...]:
        outcome = self.answers.get((name, rdtype))
        if isinstance(outcome, Exception):
            raise outcome
        return tuple(outcome or ())


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
    answers: dict[tuple[str, str], list[str] | Exception | None],
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


def test_a_resolver_failure_is_a_lookup_error(monkeypatch: pytest.MonkeyPatch) -> None:
    lookup, _ = _lookup(
        monkeypatch, answers={("example.com", "NS"): dns.exception.Timeout()}, responses={}
    )

    with pytest.raises(TxtError):
        lookup.lookup_txt("example.com", "_attacksurf-verify.example.com")
