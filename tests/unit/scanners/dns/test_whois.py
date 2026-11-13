"""`dns.whois`: registration expiry and registrar lock via RDAP (#19)."""

from datetime import UTC, datetime, timedelta

from attacksurf.domain.findings import Severity
from attacksurf.domain.net import DomainRegistration
from attacksurf.scanners.dns.whois import DnsRegistration
from tests.unit.scanners.dns.helpers import (
    ROOT,
    FakeRdap,
    by_rule,
    run,
)

LOCK = "client transfer prohibited"


def registration(
    *,
    days: int | None = 60,
    statuses: tuple[str, ...] = (LOCK,),
    registrar: str | None = "Example Registrar",
) -> DomainRegistration:
    expires = None if days is None else datetime.now(UTC) + timedelta(days=days, hours=1)
    return DomainRegistration(
        domain=ROOT, registrar=registrar, expires_at=expires, statuses=statuses
    )


def test_expiry_within_seven_days_is_high() -> None:
    output = run(DnsRegistration(), rdap=FakeRdap(registration(days=3)))

    finding = by_rule(output)["dns.whois.expiring_soon"]

    assert finding.severity is Severity.HIGH
    assert finding.remediation_context["days"] == "3"
    assert finding.remediation_context["registrar"] == "Example Registrar"


def test_expiry_within_thirty_days_uses_the_medium_default() -> None:
    output = run(DnsRegistration(), rdap=FakeRdap(registration(days=20)))

    finding = by_rule(output)["dns.whois.expiring_soon"]

    assert finding.severity is None  # rule default: medium


def test_an_expired_registration_is_high() -> None:
    output = run(DnsRegistration(), rdap=FakeRdap(registration(days=-1)))

    assert by_rule(output)["dns.whois.expiring_soon"].severity is Severity.HIGH


def test_expiry_further_out_is_clean() -> None:
    output = run(DnsRegistration(), rdap=FakeRdap(registration(days=60)))

    assert output.findings == ()


def test_a_missing_transfer_lock_is_reported() -> None:
    output = run(
        DnsRegistration(), rdap=FakeRdap(registration(statuses=("client delete prohibited",)))
    )

    finding = by_rule(output)["dns.whois.registrar_lock_missing"]

    assert finding.remediation_context["registrar"] == "Example Registrar"
    statuses = finding.evidence[0].data["statuses"]
    assert isinstance(statuses, list)
    assert "client delete prohibited" in statuses


def test_a_server_transfer_lock_also_counts() -> None:
    output = run(
        DnsRegistration(), rdap=FakeRdap(registration(statuses=("server transfer prohibited",)))
    )

    assert output.findings == ()


def test_an_empty_status_list_is_not_treated_as_a_missing_lock() -> None:
    output = run(DnsRegistration(), rdap=FakeRdap(registration(statuses=())))

    assert output.findings == ()


def test_no_registration_data_is_clean() -> None:
    assert run(DnsRegistration(), rdap=FakeRdap(None)).findings == ()


def test_both_findings_can_fire() -> None:
    output = run(
        DnsRegistration(),
        rdap=FakeRdap(registration(days=2, statuses=("client delete prohibited",))),
    )

    assert set(by_rule(output)) == {
        "dns.whois.expiring_soon",
        "dns.whois.registrar_lock_missing",
    }


def test_the_registrable_domain_is_looked_up() -> None:
    rdap = FakeRdap(registration())

    run(DnsRegistration(), "eng.acme.example", rdap=rdap, org_domain="acme.example")

    assert rdap.calls == ["acme.example"]


def test_a_missing_registrar_name_falls_back_to_the_registrar() -> None:
    output = run(DnsRegistration(), rdap=FakeRdap(registration(days=2, registrar=None)))

    assert by_rule(output)["dns.whois.expiring_soon"].remediation_context["registrar"] == (
        "the registrar"
    )
