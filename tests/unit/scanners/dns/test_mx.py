"""`dns.mx`: MX targets that are aliases or do not resolve (#19)."""

import pytest

from attacksurf.domain.jobs import TransientJobError
from attacksurf.domain.net import DnsRecordType, DnsStatus
from attacksurf.scanners.dns.mx import DnsMailExchangers
from tests.unit.scanners.dns.helpers import (
    ROOT,
    FakeDns,
    by_rule,
    evidence_values,
    run,
)

MAIL = "mail.acme.example"
ALIAS = "mail.provider.example"


def answers() -> dict[tuple[str, DnsRecordType], tuple[str, ...] | DnsStatus]:
    return {
        (ROOT, DnsRecordType.MX): (f"10 {MAIL}.",),
        (MAIL, DnsRecordType.CNAME): DnsStatus.NO_ANSWER,
        (MAIL, DnsRecordType.A): ("93.184.216.34",),
        (MAIL, DnsRecordType.AAAA): DnsStatus.NO_ANSWER,
    }


def test_mx_target_that_is_a_cname_is_reported() -> None:
    values = answers()
    values[(MAIL, DnsRecordType.CNAME)] = (f"{ALIAS}.",)

    output = run(DnsMailExchangers(), dns=FakeDns(values))

    finding = by_rule(output)["dns.mx.points_to_cname"]

    assert finding.location == MAIL
    assert evidence_values(finding, 1) == [f"{ALIAS}."]


def test_mx_target_without_addresses_is_unresolvable() -> None:
    values = answers()
    values[(MAIL, DnsRecordType.A)] = DnsStatus.NO_ANSWER

    output = run(DnsMailExchangers(), dns=FakeDns(values))

    finding = by_rule(output)["dns.mx.unresolvable"]

    assert finding.location == MAIL
    assert finding.remediation_context["target"] == MAIL


def test_a_cname_target_is_not_also_reported_as_unresolvable() -> None:
    values = answers()
    values[(MAIL, DnsRecordType.CNAME)] = (f"{ALIAS}.",)
    values[(MAIL, DnsRecordType.A)] = DnsStatus.NO_ANSWER

    output = run(DnsMailExchangers(), dns=FakeDns(values))

    assert set(by_rule(output)) == {"dns.mx.points_to_cname"}


def test_a_null_mx_accepts_no_mail_and_is_clean() -> None:
    dns = FakeDns({(ROOT, DnsRecordType.MX): ("0 .",)})

    output = run(DnsMailExchangers(), dns=dns)

    assert output.findings == ()
    assert dns.calls == [(ROOT, DnsRecordType.MX)]


def test_a_domain_without_mx_records_is_clean() -> None:
    output = run(DnsMailExchangers(), dns=FakeDns({(ROOT, DnsRecordType.MX): ()}))

    assert output.findings == ()


def test_healthy_mx_targets_are_clean() -> None:
    output = run(DnsMailExchangers(), dns=FakeDns(answers()))

    assert output.findings == ()


def test_mx_falls_back_to_the_registrable_domain() -> None:
    asset = "eng.acme.example"
    dns = FakeDns(
        {
            (asset, DnsRecordType.MX): (),
            ("acme.example", DnsRecordType.MX): (f"10 {MAIL}.",),
            (MAIL, DnsRecordType.A): ("93.184.216.34",),
        }
    )

    output = run(DnsMailExchangers(), asset, dns=dns, org_domain="acme.example")

    assert output.findings == ()
    assert (asset, DnsRecordType.MX) in dns.calls
    assert ("acme.example", DnsRecordType.MX) in dns.calls


def test_fallback_mx_evidence_names_the_registrable_domain() -> None:
    """The parent publishes the MX RRset; the finding must not claim the subdomain does."""
    asset = "eng.acme.example"
    dns = FakeDns(
        {
            (asset, DnsRecordType.MX): (),
            ("acme.example", DnsRecordType.MX): (f"10 {MAIL}.",),
            (MAIL, DnsRecordType.A): DnsStatus.NO_ANSWER,
            (MAIL, DnsRecordType.AAAA): DnsStatus.NO_ANSWER,
        }
    )

    finding = by_rule(run(DnsMailExchangers(), asset, dns=dns, org_domain="acme.example"))[
        "dns.mx.unresolvable"
    ]

    assert finding.location == MAIL
    assert finding.evidence[0].data["name"] == "acme.example"
    assert finding.remediation_context["domain"] == "acme.example"


def test_a_failed_target_lookup_is_skipped() -> None:
    values = answers()
    values[(MAIL, DnsRecordType.A)] = DnsStatus.ERROR
    values[(MAIL, DnsRecordType.AAAA)] = DnsStatus.ERROR

    output = run(DnsMailExchangers(), dns=FakeDns(values))

    assert output.findings == ()


def test_all_mx_lookups_erroring_is_retryable() -> None:
    with pytest.raises(TransientJobError):
        run(DnsMailExchangers(), dns=FakeDns(all_errors=True))


def test_a_malformed_mx_record_is_ignored() -> None:
    dns = FakeDns({(ROOT, DnsRecordType.MX): ("not-a-preference mail.acme.example.",)})

    output = run(DnsMailExchangers(), dns=dns)

    assert output.findings == ()
    assert dns.calls == [(ROOT, DnsRecordType.MX)]
