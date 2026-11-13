"""`dns.caa`: missing CAA publication, with registrable-domain inheritance (#19)."""

import pytest

from attacksurf.domain.jobs import TransientJobError
from attacksurf.domain.net import DnsRecordType, DnsStatus
from attacksurf.scanners.dns.caa import DnsCertificateAuthority
from tests.unit.scanners.dns.helpers import (
    ROOT,
    FakeDns,
    by_rule,
    run,
)


def test_a_domain_without_caa_is_reported() -> None:
    dns = FakeDns({(ROOT, DnsRecordType.CAA): DnsStatus.NO_ANSWER})

    output = run(DnsCertificateAuthority(), dns=dns)

    finding = by_rule(output)["dns.caa.missing"]

    assert finding.remediation_context["zone"] == ROOT
    assert finding.evidence[0].data["record"] == "CAA"
    assert dns.calls == [(ROOT, DnsRecordType.CAA)]


def test_a_published_caa_record_is_clean() -> None:
    dns = FakeDns({(ROOT, DnsRecordType.CAA): ('0 issue "letsencrypt.org"',)})

    assert run(DnsCertificateAuthority(), dns=dns).findings == ()


def test_caa_inherited_from_the_registrable_domain_is_clean() -> None:
    asset = "eng.acme.example"
    dns = FakeDns(
        {
            (asset, DnsRecordType.CAA): (),
            ("acme.example", DnsRecordType.CAA): ('0 issue "letsencrypt.org"',),
        }
    )

    assert run(DnsCertificateAuthority(), asset, dns=dns, org_domain="acme.example").findings == ()


def test_a_failed_query_fails_open() -> None:
    asset = "eng.acme.example"
    dns = FakeDns(
        {
            (asset, DnsRecordType.CAA): DnsStatus.ERROR,
            ("acme.example", DnsRecordType.CAA): DnsStatus.NO_ANSWER,
        }
    )

    output = run(DnsCertificateAuthority(), asset, dns=dns, org_domain="acme.example")

    assert output.findings == ()


def test_every_query_erroring_is_retryable() -> None:
    with pytest.raises(TransientJobError):
        run(DnsCertificateAuthority(), dns=FakeDns(all_errors=True))


def test_the_registrable_zone_is_named_for_a_subdomain_asset() -> None:
    asset = "eng.acme.example"
    dns = FakeDns(
        {
            (asset, DnsRecordType.CAA): (),
            ("acme.example", DnsRecordType.CAA): (),
        }
    )

    finding = by_rule(run(DnsCertificateAuthority(), asset, dns=dns, org_domain="acme.example"))[
        "dns.caa.missing"
    ]

    assert finding.remediation_context["zone"] == "acme.example"


def test_caa_on_an_intermediate_ancestor_is_clean() -> None:
    """RFC 8659 section 3: every ancestor between the name and the root may publish CAA."""
    asset = "app.team.acme.example"
    dns = FakeDns(
        {
            (asset, DnsRecordType.CAA): (),
            ("team.acme.example", DnsRecordType.CAA): ('0 issue "letsencrypt.org"',),
        }
    )

    output = run(DnsCertificateAuthority(), asset, dns=dns, org_domain="acme.example")

    assert output.findings == ()
    assert dns.calls == [
        (asset, DnsRecordType.CAA),
        ("team.acme.example", DnsRecordType.CAA),
        ("acme.example", DnsRecordType.CAA),
    ]


def test_every_ancestor_is_queried_before_reporting_missing() -> None:
    asset = "app.team.acme.example"
    dns = FakeDns()

    finding = by_rule(run(DnsCertificateAuthority(), asset, dns=dns, org_domain="acme.example"))[
        "dns.caa.missing"
    ]

    assert finding.evidence[0].data["name"] == asset
    assert [name for name, _ in dns.calls] == [
        asset,
        "team.acme.example",
        "acme.example",
    ]


def test_a_name_too_deep_for_the_budget_fails_open() -> None:
    """An ancestor the budget could not check might still publish CAA: absence is unproven."""
    asset = "a.b.c.d.e.f.acme.example"
    dns = FakeDns()

    output = run(DnsCertificateAuthority(), asset, dns=dns, org_domain="acme.example")

    assert output.findings == ()
    assert len(dns.calls) == 6
