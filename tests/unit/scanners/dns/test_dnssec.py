"""`dns.dnssec`: DS/DNSKEY linkage, not-enabled and broken-chain detection (#19)."""

import pytest

from attacksurf.domain.findings import Confidence
from attacksurf.domain.jobs import TransientJobError
from attacksurf.domain.net import DnsRecordType, DnsStatus
from attacksurf.domain.rules import RULES
from attacksurf.domain.scanners import ScanOutput
from attacksurf.scanners.dns.dnssec import DnsDnssec
from tests.unit.scanners.dns.helpers import (
    ROOT,
    FakeAuthoritative,
    FakeDns,
    answer,
    by_rule,
    run,
    zone,
)

# Generated once with dnspython's `dns.dnssec.make_ds` over KEY at acme.example.
KEY = "257 3 13 AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8="
OTHER_KEY = "257 3 13 AQIDBAUGBwgJCgsMDQ4PEBESExQVFhcYGRobHB0eHyA="
DS = "62734 13 2 bd8e1ab59a22b80a4a3d59cb4e0af137ae21846a9d20b2dbd93bbf427d7573b2"
DS_SHA384 = (
    "62734 13 4 "
    "db50910a686c29daec5cea358eb93890b7d79b354e836c29429e5124ebaf447a2124fdbf0b63b12c43db0f2b509ed692"
)
UNSUPPORTED_DS = "62734 13 3 abcdef"


def probe(
    *,
    ds: tuple[str, ...] | DnsStatus = DnsStatus.NO_ANSWER,
    dnskey: tuple[str, ...] = (),
    ds_status: DnsStatus | None = None,
    zone_name: str = ROOT,
    authoritative: bool = True,
    rcode: str = "noerror",
    status: DnsStatus = DnsStatus.OK,
) -> tuple[ScanOutput, FakeDns, FakeAuthoritative]:
    dns = FakeDns(
        {
            (ROOT, DnsRecordType.DS): (ds_status if ds_status is not None else ds),
        }
    )
    authoritative_dns = FakeAuthoritative(
        zone(
            zone_name,
            answers=(
                answer(
                    status=status,
                    authoritative=authoritative,
                    rcode=rcode,
                    values=dnskey,
                ),
            ),
        )
    )
    output = run(DnsDnssec(), dns=dns, authoritative=authoritative_dns)
    return output, dns, authoritative_dns


def test_dnssec_not_enabled_without_a_ds_record() -> None:
    output, _, _ = probe()

    finding = by_rule(output)["dns.dnssec.not_enabled"]

    assert finding.confidence is Confidence.LOW
    assert finding.severity is None  # rule default: info
    assert RULES["dns.dnssec.not_enabled"].default_severity.value == "info"
    assert finding.evidence[0].data["record"] == "DS"


def test_dnssec_healthy_when_a_dnskey_matches_the_ds() -> None:
    output, _, _ = probe(ds=(DS,), dnskey=(KEY,))

    assert output.findings == ()


def test_dnssec_accepts_a_sha384_ds() -> None:
    output, _, _ = probe(ds=(DS_SHA384,), dnskey=(KEY,))

    assert output.findings == ()


def test_dnssec_broken_when_the_zone_publishes_no_dnskey() -> None:
    output, _, _ = probe(ds=(DS,), dnskey=(), status=DnsStatus.NO_ANSWER)

    finding = by_rule(output)["dns.dnssec.broken_chain"]

    assert finding.confidence is Confidence.MEDIUM
    assert finding.evidence[1].data["values"] == []


def test_dnssec_broken_when_no_dnskey_matches_the_ds() -> None:
    output, _, _ = probe(ds=(DS,), dnskey=(OTHER_KEY,))

    finding = by_rule(output)["dns.dnssec.broken_chain"]

    assert finding.confidence is Confidence.HIGH
    assert finding.evidence[1].data["values"] == [OTHER_KEY]


def test_dnssec_ignores_an_unsupported_digest() -> None:
    output, _, _ = probe(ds=(UNSUPPORTED_DS,), dnskey=(OTHER_KEY,))

    assert output.findings == ()


def test_dnssec_fails_open_when_no_server_answered() -> None:
    output, _, _ = probe(ds=(DS,), dnskey=(KEY,), rcode="", status=DnsStatus.ERROR)

    assert output.findings == ()


def test_dnssec_skips_a_name_that_is_not_the_zone_apex() -> None:
    output, dns, _ = probe(zone_name="example", ds=(DS,), dnskey=(KEY,))

    assert output.findings == ()
    assert dns.calls == []  # the DS lookup is not even attempted


def test_dnssec_ds_lookup_error_is_retryable() -> None:
    dns = FakeDns({(ROOT, DnsRecordType.DS): DnsStatus.ERROR})
    authoritative = FakeAuthoritative(zone(ROOT, answers=(answer(values=(KEY,)),)))

    with pytest.raises(TransientJobError):
        run(DnsDnssec(), dns=dns, authoritative=authoritative)


def test_dnssec_ignores_a_non_zone_key() -> None:
    # Flags 0 (no ZONE bit): the record is not a zone key and must not satisfy the DS.
    non_zone = "0 3 13 AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8="

    output, _, _ = probe(ds=(DS,), dnskey=(non_zone,))

    assert by_rule(output)["dns.dnssec.broken_chain"].confidence is Confidence.MEDIUM
