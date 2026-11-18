"""`dns.axfr`: zone-transfer exposure on verified zone apexes (#19)."""

from attacksurf.domain.net import ZoneTransferAttempt
from attacksurf.scanners.dns.axfr import DnsZoneTransfer
from tests.unit.scanners.dns.helpers import (
    ROOT,
    FakeZoneTransfer,
    by_rule,
    evidence_values,
    run,
)


def attempt(server: str = "ns1.acme.example", *, allowed: bool = True, records: int = 42):
    return ZoneTransferAttempt(
        server=server, address="93.184.216.34", allowed=allowed, records=records
    )


def test_an_allowed_transfer_is_reported() -> None:
    output = run(DnsZoneTransfer(), zone_transfer=FakeZoneTransfer((attempt(),)))

    finding = by_rule(output)["dns.axfr.allowed"]

    assert finding.location == "ns1.acme.example"
    assert finding.evidence[0].data["records"] == 42
    assert evidence_values(finding) == ["ns1.acme.example"]
    assert finding.remediation_context == {
        "zone": ROOT,
        "server": "ns1.acme.example",
        "records": "42",
    }


def test_a_refused_transfer_is_clean() -> None:
    output = run(DnsZoneTransfer(), zone_transfer=FakeZoneTransfer((attempt(allowed=False),)))

    assert output.findings == ()


def test_no_attempts_is_clean() -> None:
    assert run(DnsZoneTransfer(), zone_transfer=FakeZoneTransfer()).findings == ()


def test_one_finding_per_allowing_server() -> None:
    output = run(
        DnsZoneTransfer(),
        zone_transfer=FakeZoneTransfer(
            (
                attempt("ns1.acme.example", records=2),
                attempt("ns2.acme.example", allowed=False),
                attempt("ns3.acme.example", records=7),
            )
        ),
    )

    assert [finding.location for finding in output.findings] == [
        "ns1.acme.example",
        "ns3.acme.example",
    ]


def test_only_the_asset_itself_is_attempted() -> None:
    zone_transfer = FakeZoneTransfer((attempt(),))

    run(DnsZoneTransfer(), zone_transfer=zone_transfer)

    assert zone_transfer.calls == [ROOT]


def test_the_plugin_is_an_active_check_with_a_zone_transfer_grant() -> None:
    assert DnsZoneTransfer.requires_verification is True
    assert DnsZoneTransfer.grant.zone_transfer is True
    assert DnsZoneTransfer.queue == "passive"  # the active queue is reserved until #70
