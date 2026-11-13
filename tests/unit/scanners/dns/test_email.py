"""`dns.email`: SPF/DMARC/DKIM/MTA-STS evaluation from DNS TXT records."""

from collections.abc import Sequence
from uuid import uuid4

import pytest

from attacksurf.domain.assets import AssetType
from attacksurf.domain.findings import Confidence, Severity
from attacksurf.domain.jobs import TransientJobError
from attacksurf.domain.net import (
    DnsLookup,
    DnsQuery,
    DnsRecordType,
    DnsStatus,
    HttpBody,
    ScannerRuntime,
)
from attacksurf.domain.rules import RULES
from attacksurf.domain.scanners import AssetRef, RawFinding, ScanContext, ScanOutput
from attacksurf.scanners.dns.email import DKIM_SELECTORS, DnsEmail

ROOT = "acme.example"
ASSET = "acme.example"
DMARC_NAME = f"_dmarc.{ASSET}"
MTA_STS_NAME = f"_mta-sts.{ASSET}"

STRICT_SPF = "v=spf1 include:_spf.example.net -all"
STRICT_DMARC = "v=DMARC1; p=reject; rua=mailto:dmarc@acme.example"
DKIM_KEY = "v=DKIM1; k=rsa; p=MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQCiL7"
MTA_STS = "v=STSv1; id=20261113"


class FakeDns:
    def __init__(
        self,
        answers: dict[tuple[str, DnsRecordType], tuple[str, ...] | DnsStatus] | None = None,
        *,
        errors: set[tuple[str, DnsRecordType]] | None = None,
        all_errors: bool = False,
        default_status: DnsStatus = DnsStatus.NO_ANSWER,
    ) -> None:
        self.answers = answers or {}
        self.errors = errors or set()
        self.all_errors = all_errors
        self.default_status = default_status
        self.calls: list[tuple[str, DnsRecordType]] = []

    def resolve_ipv4(self, host: str) -> tuple[str, ...]:
        raise AssertionError("dns.email must use lookup_many")

    def resolve_name(self, host: str) -> tuple[str, ...]:
        raise AssertionError("dns.email must use lookup_many")

    def lookup_many(self, queries: Sequence[DnsQuery]) -> tuple[DnsLookup, ...]:
        results: list[DnsLookup] = []
        for query in queries:
            self.calls.append((query.name, query.record_type))
            key = (query.name, query.record_type)
            if self.all_errors or key in self.errors:
                results.append(DnsLookup(query, (), DnsStatus.ERROR))
                continue
            outcome = self.answers.get(key, self.default_status)
            if isinstance(outcome, DnsStatus):
                results.append(DnsLookup(query, (), outcome))
            else:
                results.append(DnsLookup(query, outcome, DnsStatus.OK))
        return tuple(results)


class FakeHttp:
    def get(self, url: str, *, limit: int) -> HttpBody:
        raise AssertionError("dns.email is DNS-only and must not use HTTP")

    def close(self) -> None:
        pass


def run(
    answers: dict[tuple[str, DnsRecordType], tuple[str, ...] | DnsStatus],
    *,
    errors: set[tuple[str, DnsRecordType]] | None = None,
    all_errors: bool = False,
    default_status: DnsStatus = DnsStatus.NO_ANSWER,
) -> tuple[ScanOutput, FakeDns]:
    dns = FakeDns(answers, errors=errors, all_errors=all_errors, default_status=default_status)
    ctx = ScanContext(
        uuid4(),
        uuid4(),
        AssetRef(type=AssetType.DOMAIN, value=ROOT),
        "dns_passive",
        runtime=ScannerRuntime(dns, FakeHttp()),
    )
    return DnsEmail().run(ctx, AssetRef(type=AssetType.DOMAIN, value=ASSET)), dns


def healthy_answers() -> dict[tuple[str, DnsRecordType], tuple[str, ...] | DnsStatus]:
    answers: dict[tuple[str, DnsRecordType], tuple[str, ...] | DnsStatus] = {
        (ASSET, DnsRecordType.TXT): (STRICT_SPF,),
        (DMARC_NAME, DnsRecordType.TXT): (STRICT_DMARC,),
        (MTA_STS_NAME, DnsRecordType.TXT): (MTA_STS,),
        (f"default._domainkey.{ASSET}", DnsRecordType.TXT): (DKIM_KEY,),
    }
    return answers


def by_rule(output: ScanOutput) -> dict[str, RawFinding]:
    return {finding.rule_id: finding for finding in output.findings}


def test_scanner_targets_root_domains_only() -> None:
    # Email auth is a mail-domain property; discovered hosts would only get noise.
    assert DnsEmail.asset_types == frozenset({AssetType.DOMAIN})


def test_healthy_domain_has_no_findings() -> None:
    output, dns = run(healthy_answers())

    assert output.findings == ()
    assert output.assets == ()
    assert output.relations == ()
    assert output.observations == ()
    # apex TXT + _dmarc + _mta-sts + one TXT per DKIM selector, no follow-ups.
    assert len(dns.calls) == 3 + len(DKIM_SELECTORS)


def test_bare_domain_reports_all_missing_records() -> None:
    output, _dns = run({})

    assert set(by_rule(output)) == {
        "dns.email.spf_missing",
        "dns.email.dmarc_missing",
        "dns.email.dkim_not_found",
        "dns.email.mta_sts_missing",
    }


def test_all_issue_rule_ids_exist_in_the_shipped_catalog() -> None:
    for rule_id in (
        "dns.email.spf_missing",
        "dns.email.spf_multiple_records",
        "dns.email.spf_permissive",
        "dns.email.spf_too_many_lookups",
        "dns.email.dmarc_missing",
        "dns.email.dmarc_policy_none",
        "dns.email.dmarc_no_reporting",
        "dns.email.dmarc_pct_partial",
        "dns.email.dkim_not_found",
        "dns.email.mta_sts_missing",
    ):
        assert rule_id in RULES


def test_multiple_spf_records_are_one_finding() -> None:
    answers = healthy_answers()
    answers[(ASSET, DnsRecordType.TXT)] = (
        "v=spf1 include:_spf.example.net -all",
        "v=spf1 ip4:192.0.2.0/24 -all",
    )

    assert set(by_rule(run(answers)[0])) == {"dns.email.spf_multiple_records"}


def test_spf_plus_all_is_high_and_neutral_all_is_medium() -> None:
    answers = healthy_answers()
    answers[(ASSET, DnsRecordType.TXT)] = ("v=spf1 include:_spf.example.net +all",)
    output, _dns = run(answers)
    permissive = by_rule(output)["dns.email.spf_permissive"]

    assert permissive.severity is None  # rule default HIGH applies
    assert RULES["dns.email.spf_permissive"].default_severity is Severity.HIGH

    answers[(ASSET, DnsRecordType.TXT)] = ("v=spf1 include:_spf.example.net ?all",)
    downgraded = by_rule(run(answers)[0])["dns.email.spf_permissive"]

    assert downgraded.severity is Severity.MEDIUM


def test_spf_strict_endings_have_no_permissive_finding() -> None:
    for ending in ("-all", "~all"):
        answers = healthy_answers()
        answers[(ASSET, DnsRecordType.TXT)] = (f"v=spf1 include:_spf.example.net {ending}",)

        assert "dns.email.spf_permissive" not in by_rule(run(answers)[0])


def test_spf_more_than_ten_dns_terms_is_a_finding() -> None:
    includes = " ".join(f"include:{n}.example.net" for n in range(11))
    answers = healthy_answers()
    answers[(ASSET, DnsRecordType.TXT)] = (f"v=spf1 {includes} -all",)

    finding = by_rule(run(answers)[0])["dns.email.spf_too_many_lookups"]

    assert finding.remediation_context["count"] == "11"


def test_spf_ten_dns_terms_is_allowed_and_redirect_counts() -> None:
    includes = " ".join(f"include:{n}.example.net" for n in range(9))
    answers = healthy_answers()
    answers[(ASSET, DnsRecordType.TXT)] = (f"v=spf1 {includes} redirect=_spf.example.net -all",)

    assert "dns.email.spf_too_many_lookups" not in by_rule(run(answers)[0])

    answers[(ASSET, DnsRecordType.TXT)] = (f"v=spf1 {includes} mx redirect=_spf.example.net -all",)

    assert "dns.email.spf_too_many_lookups" in by_rule(run(answers)[0])


def test_spf_without_all_or_redirect_is_implicitly_neutral() -> None:
    answers = healthy_answers()
    answers[(ASSET, DnsRecordType.TXT)] = ("v=spf1 include:_spf.example.net",)

    finding = by_rule(run(answers)[0])["dns.email.spf_permissive"]

    assert finding.severity is Severity.MEDIUM
    assert finding.remediation_context["ending"] == "?all"


def test_spf_redirect_makes_the_all_mechanism_moot() -> None:
    answers = healthy_answers()
    answers[(ASSET, DnsRecordType.TXT)] = ("v=spf1 redirect=_spf.example.net +all",)

    assert "dns.email.spf_permissive" not in by_rule(run(answers)[0])


def test_spf_record_matching_is_case_insensitive() -> None:
    answers = healthy_answers()
    answers[(ASSET, DnsRecordType.TXT)] = ("V=SPF1 Include:_spf.example.net -ALL",)

    assert "dns.email.spf_missing" not in by_rule(run(answers)[0])


def test_dmarc_monitor_policy_is_a_finding() -> None:
    answers = healthy_answers()
    answers[(DMARC_NAME, DnsRecordType.TXT)] = ("v=DMARC1; p=none; rua=mailto:dmarc@acme.example",)

    assert set(by_rule(run(answers)[0])) == {"dns.email.dmarc_policy_none"}


def test_dmarc_monitor_policy_without_reporting_reports_both() -> None:
    answers = healthy_answers()
    answers[(DMARC_NAME, DnsRecordType.TXT)] = ("v=DMARC1; p=none",)

    assert set(by_rule(run(answers)[0])) == {
        "dns.email.dmarc_policy_none",
        "dns.email.dmarc_no_reporting",
    }


def test_dmarc_without_reporting_is_a_finding() -> None:
    answers = healthy_answers()
    answers[(DMARC_NAME, DnsRecordType.TXT)] = ("v=DMARC1; p=quarantine",)

    assert set(by_rule(run(answers)[0])) == {"dns.email.dmarc_no_reporting"}


def test_dmarc_partial_pct_is_a_finding() -> None:
    answers = healthy_answers()
    answers[(DMARC_NAME, DnsRecordType.TXT)] = (
        "v=DMARC1; p=reject; rua=mailto:dmarc@acme.example; pct=50",
    )

    assert set(by_rule(run(answers)[0])) == {"dns.email.dmarc_pct_partial"}


def test_dmarc_multiple_records_count_as_missing() -> None:
    answers = healthy_answers()
    answers[(DMARC_NAME, DnsRecordType.TXT)] = (
        "v=DMARC1; p=reject; rua=mailto:dmarc@acme.example",
        "v=DMARC1; p=none",
    )

    assert set(by_rule(run(answers)[0])) == {"dns.email.dmarc_missing"}


def test_dkim_any_selector_hit_clears_the_finding() -> None:
    answers = healthy_answers()
    del answers[(f"default._domainkey.{ASSET}", DnsRecordType.TXT)]
    answers[(f"selector2._domainkey.{ASSET}", DnsRecordType.TXT)] = (DKIM_KEY,)

    assert "dns.email.dkim_not_found" not in by_rule(run(answers)[0])


def test_dkim_key_without_a_version_tag_still_counts() -> None:
    answers = healthy_answers()
    answers[(f"default._domainkey.{ASSET}", DnsRecordType.TXT)] = ("k=rsa; p=MIGfMA0GCSqGSIb3",)

    assert "dns.email.dkim_not_found" not in by_rule(run(answers)[0])


def test_dkim_revoked_key_still_counts_as_missing() -> None:
    answers = healthy_answers()
    answers[(f"default._domainkey.{ASSET}", DnsRecordType.TXT)] = ("v=DKIM1; k=rsa; p=",)

    finding = by_rule(run(answers)[0])["dns.email.dkim_not_found"]

    assert finding.confidence is Confidence.LOW


def test_dkim_all_selector_errors_fail_open() -> None:
    answers = healthy_answers()
    del answers[(f"default._domainkey.{ASSET}", DnsRecordType.TXT)]
    errors = {(f"{s}._domainkey.{ASSET}", DnsRecordType.TXT) for s in DKIM_SELECTORS}

    assert "dns.email.dkim_not_found" not in by_rule(run(answers, errors=errors)[0])


def test_mta_sts_present_clears_the_info_finding() -> None:
    assert "dns.email.mta_sts_missing" not in by_rule(run(healthy_answers())[0])


def test_parked_domain_without_mx_still_gets_spf_and_dmarc_findings() -> None:
    # A parked domain (no MX) hardens with `v=spf1 -all` + `p=reject`: the missing-record
    # findings whose remediation recommends exactly that must still fire.
    answers = healthy_answers()
    answers[(ASSET, DnsRecordType.TXT)] = DnsStatus.NO_ANSWER
    answers[(DMARC_NAME, DnsRecordType.TXT)] = DnsStatus.NO_ANSWER

    found = by_rule(run(answers)[0])

    assert "dns.email.spf_missing" in found
    assert "dns.email.dmarc_missing" in found


def test_all_dns_errors_retry_the_run() -> None:
    with pytest.raises(TransientJobError, match="Email security check failed"):
        run({}, all_errors=True)


def test_single_query_error_skips_only_that_check() -> None:
    answers = healthy_answers()
    errors = {(ASSET, DnsRecordType.TXT)}

    found = by_rule(run(answers, errors=errors)[0])

    assert not {rule for rule in found if ".spf_" in rule}
    # The unrelated DMARC check still ran against the healthy record and passed.
    assert not {rule for rule in found if ".dmarc_" in rule}


def test_evidence_carries_the_raw_txt_records() -> None:
    output, _dns = run({})

    spf = by_rule(output)["dns.email.spf_missing"]

    assert spf.evidence[0].kind.value == "dns_record"
    assert spf.evidence[0].data["name"] == ASSET
