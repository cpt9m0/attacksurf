"""`dns.ns`: single nameserver, lame delegation and inconsistent SOA detection (#19)."""

from attacksurf.domain.findings import Confidence
from attacksurf.domain.net import DnsRecordType, DnsStatus
from attacksurf.domain.scanners import ScanOutput
from attacksurf.scanners.dns.ns import DnsNameservers
from tests.unit.scanners.dns.helpers import (
    ROOT,
    FakeAuthoritative,
    answer,
    by_rule,
    evidence_values,
    run,
    zone,
)

SOA_1 = "ns1.acme.example. hostmaster.acme.example. 2024010101 3600 600 604800 300"
SOA_2 = "ns2.acme.example. hostmaster.acme.example. 2024010102 3600 600 604800 300"


def probe(answers: FakeAuthoritative) -> ScanOutput:
    return run(DnsNameservers(), authoritative=answers)


def test_a_single_nameserver_is_reported() -> None:
    output = probe(
        FakeAuthoritative(zone(servers=("ns1.acme.example",), answers=(answer(values=(SOA_1,)),)))
    )

    finding = by_rule(output)["dns.ns.single_nameserver"]

    assert finding.evidence[0].data["record"] == "NS"
    assert evidence_values(finding) == ["ns1.acme.example"]


def test_two_authoritative_nameservers_are_clean() -> None:
    output = probe(
        FakeAuthoritative(
            zone(
                servers=("ns1.acme.example", "ns2.acme.example"),
                answers=(
                    answer(server="ns1.acme.example", values=(SOA_1,)),
                    answer(server="ns2.acme.example", values=(SOA_1,)),
                ),
            )
        )
    )

    assert output.findings == ()


def test_a_non_authoritative_answer_is_a_lame_delegation() -> None:
    output = probe(
        FakeAuthoritative(
            zone(
                servers=("ns1.acme.example", "ns2.acme.example"),
                answers=(
                    answer(server="ns1.acme.example", values=(SOA_1,)),
                    answer(server="ns2.acme.example", authoritative=False, values=(SOA_1,)),
                ),
            )
        )
    )

    finding = by_rule(output)["dns.ns.lame_delegation"]

    assert finding.location == "ns2.acme.example"
    assert finding.confidence is Confidence.MEDIUM
    assert "authoritative=no" in evidence_values(finding)[0]


def test_a_refused_answer_is_a_lame_delegation() -> None:
    output = probe(
        FakeAuthoritative(
            zone(
                servers=("ns1.acme.example", "ns2.acme.example"),
                answers=(
                    answer(server="ns1.acme.example", values=(SOA_1,)),
                    answer(
                        server="ns2.acme.example",
                        status=DnsStatus.ERROR,
                        authoritative=False,
                        rcode="refused",
                    ),
                ),
            )
        )
    )

    assert by_rule(output)["dns.ns.lame_delegation"].location == "ns2.acme.example"


def test_an_unreachable_server_is_not_lame() -> None:
    output = probe(
        FakeAuthoritative(
            zone(
                servers=("ns1.acme.example", "ns2.acme.example"),
                answers=(
                    answer(server="ns1.acme.example", values=(SOA_1,)),
                    answer(
                        server="ns2.acme.example",
                        status=DnsStatus.ERROR,
                        authoritative=False,
                        rcode="",
                    ),
                ),
            )
        )
    )

    assert output.findings == ()


def test_different_soa_serials_are_reported() -> None:
    output = probe(
        FakeAuthoritative(
            zone(
                servers=("ns1.acme.example", "ns2.acme.example"),
                answers=(
                    answer(server="ns1.acme.example", values=(SOA_1,)),
                    answer(server="ns2.acme.example", values=(SOA_2,)),
                ),
            )
        )
    )

    finding = by_rule(output)["dns.ns.inconsistent_soa"]

    assert finding.confidence is Confidence.MEDIUM
    assert finding.remediation_context["count"] == "2"
    assert len(evidence_values(finding)) == 2


def test_a_soa_without_a_numeric_serial_is_ignored() -> None:
    output = probe(
        FakeAuthoritative(
            zone(
                servers=("ns1.acme.example", "ns2.acme.example"),
                answers=(
                    answer(server="ns1.acme.example", values=(SOA_1,)),
                    answer(
                        server="ns2.acme.example",
                        values=("ns2.acme.example. hostmaster.acme.example. x 1 2 3 4",),
                    ),
                ),
            )
        )
    )

    assert "dns.ns.inconsistent_soa" not in by_rule(output)


def test_a_non_apex_name_is_skipped() -> None:
    output = probe(FakeAuthoritative(zone(zone_name="example", answers=(answer(values=(SOA_1,)),))))

    assert output.findings == ()


def test_the_scanner_queries_the_soa_of_the_asset() -> None:
    authoritative = FakeAuthoritative(zone(answers=(answer(values=(SOA_1,)),)))

    run(DnsNameservers(), authoritative=authoritative)

    assert authoritative.calls == [(ROOT, DnsRecordType.SOA)]
