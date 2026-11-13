"""`dns.takeover`: dangling CNAME / NS detection from DNS records only (#18)."""

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
from attacksurf.domain.scope import HttpPermission
from attacksurf.scanners.dns.fingerprints import load_fingerprints, match_service
from attacksurf.scanners.dns.takeover import DnsTakeover

ROOT = "acme.example"
ASSET = "blog.acme.example"
BEANSTALK = "myapp.elasticbeanstalk.com"


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
        raise AssertionError("dns.takeover must use lookup_many")

    def resolve_name(self, host: str) -> tuple[str, ...]:
        raise AssertionError("dns.takeover must use lookup_many")

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
        raise AssertionError("dns.takeover is DNS-only and must not use HTTP")

    def close(self) -> None:
        pass


def run(
    answers: dict[tuple[str, DnsRecordType], tuple[str, ...] | DnsStatus],
    *,
    errors: set[tuple[str, DnsRecordType]] | None = None,
    all_errors: bool = False,
    asset: str = ASSET,
    asset_type: AssetType = AssetType.SUBDOMAIN,
) -> tuple[ScanOutput, FakeDns]:
    dns = FakeDns(answers, errors=errors, all_errors=all_errors)
    ctx = ScanContext(
        uuid4(),
        uuid4(),
        AssetRef(type=AssetType.DOMAIN, value=ROOT),
        "dns_passive",
        runtime=ScannerRuntime(dns, FakeHttp()),
    )
    return DnsTakeover().run(ctx, AssetRef(type=asset_type, value=asset)), dns


def by_rule(output: ScanOutput) -> dict[str, RawFinding]:
    return {finding.rule_id: finding for finding in output.findings}


def test_scanner_is_passive_dns_only_for_domains_and_subdomains() -> None:
    assert DnsTakeover.asset_types == frozenset({AssetType.DOMAIN, AssetType.SUBDOMAIN})
    assert DnsTakeover.queue == "passive"
    assert DnsTakeover.requires_verification is False
    assert DnsTakeover.grant.http is HttpPermission.NONE


def test_issue_rule_ids_exist_in_the_shipped_catalog() -> None:
    assert RULES["dns.takeover.dangling_cname"].default_severity is Severity.HIGH
    assert RULES["dns.takeover.fingerprint_match"].default_severity is Severity.HIGH
    assert RULES["dns.takeover.dangling_ns"].default_severity is Severity.CRITICAL


def test_dataset_is_the_pinned_vulnerable_subset() -> None:
    fingerprints = load_fingerprints()

    assert len(fingerprints) == 24
    for fingerprint in fingerprints:
        assert fingerprint.cname
        assert fingerprint.nxdomain or fingerprint.fingerprint or fingerprint.http_status
    s3 = match_service(fingerprints, "mybucket.s3.amazonaws.com")
    assert s3 is not None
    assert s3.service == "AWS/S3"
    assert match_service(fingerprints, "gone.example.net") is None
    # Not-vulnerable / edge-case services never ship: GitHub Pages must not be flagged.
    assert match_service(fingerprints, "user.github.io") is None


def test_ns_check_is_withheld_for_an_aliased_name() -> None:
    # RFC 1034 section 3.6.2: a CNAME owner holds no other data, so the NS answer here is the
    # alias target's zone. Attributing it to this asset would invent a critical finding.
    answers: dict[tuple[str, DnsRecordType], tuple[str, ...] | DnsStatus] = {
        (ASSET, DnsRecordType.CNAME): ("target.example.net",),
        (ASSET, DnsRecordType.NS): ("ns1.gone.example.net",),
        ("ns1.gone.example.net", DnsRecordType.A): DnsStatus.NXDOMAIN,
    }

    output, dns = run(answers)

    assert output.findings == ()
    assert (ASSET, DnsRecordType.NS) in dns.calls


def test_dangling_cname_on_nxdomain_service_is_a_high_finding() -> None:
    answers: dict[tuple[str, DnsRecordType], tuple[str, ...] | DnsStatus] = {
        (ASSET, DnsRecordType.CNAME): (BEANSTALK,),
        (BEANSTALK, DnsRecordType.A): DnsStatus.NXDOMAIN,
    }

    output, dns = run(answers)
    finding = by_rule(output)["dns.takeover.dangling_cname"]

    assert set(by_rule(output)) == {"dns.takeover.dangling_cname"}
    assert finding.confidence is Confidence.HIGH
    assert finding.location == BEANSTALK
    assert finding.remediation_context["service"] == "AWS/Elastic Beanstalk"
    assert finding.evidence[0].kind.value == "dns_record"
    assert finding.evidence[0].data["values"] == [ASSET, BEANSTALK]
    assert finding.evidence[1].data["status"] == "nxdomain"
    assert len(dns.calls) <= DnsTakeover.grant.dns_lookups


def test_dangling_cname_matches_the_terminal_hop_of_a_chain() -> None:
    answers: dict[tuple[str, DnsRecordType], tuple[str, ...] | DnsStatus] = {
        (ASSET, DnsRecordType.CNAME): ("alias.example.net",),
        ("alias.example.net", DnsRecordType.CNAME): (BEANSTALK,),
        (BEANSTALK, DnsRecordType.A): DnsStatus.NXDOMAIN,
    }

    finding = by_rule(run(answers)[0])["dns.takeover.dangling_cname"]

    assert finding.location == BEANSTALK
    assert finding.evidence[0].data["values"] == [ASSET, "alias.example.net", BEANSTALK]


def test_known_service_that_still_resolves_has_no_finding() -> None:
    answers: dict[tuple[str, DnsRecordType], tuple[str, ...] | DnsStatus] = {
        (ASSET, DnsRecordType.CNAME): (BEANSTALK,),
        (BEANSTALK, DnsRecordType.A): ("203.0.113.10",),
    }

    assert run(answers)[0].findings == ()


def test_nxdomain_on_an_unknown_service_has_no_finding() -> None:
    # A dead CNAME to an arbitrary host is a broken link, not a takeover candidate:
    # claimability is only known for dataset services.
    answers: dict[tuple[str, DnsRecordType], tuple[str, ...] | DnsStatus] = {
        (ASSET, DnsRecordType.CNAME): ("gone.example.net",),
        ("gone.example.net", DnsRecordType.A): DnsStatus.NXDOMAIN,
    }

    assert run(answers)[0].findings == ()


def test_body_signature_service_is_left_to_the_http_scanner() -> None:
    # AWS/S3 resolves even when the bucket is gone; only the HTTP body proves it, so the
    # DNS-only scanner must not fire for resolving services.
    answers: dict[tuple[str, DnsRecordType], tuple[str, ...] | DnsStatus] = {
        (ASSET, DnsRecordType.CNAME): ("mybucket.s3.amazonaws.com",),
        ("mybucket.s3.amazonaws.com", DnsRecordType.A): ("203.0.113.10",),
    }

    assert run(answers)[0].findings == ()


def test_no_cname_and_no_ns_has_no_findings() -> None:
    assert run({})[0].findings == ()


def test_cname_loop_terminates_without_a_finding() -> None:
    answers: dict[tuple[str, DnsRecordType], tuple[str, ...] | DnsStatus] = {
        (ASSET, DnsRecordType.CNAME): ("loop.example.net",),
        ("loop.example.net", DnsRecordType.CNAME): (ASSET,),
    }

    assert run(answers)[0].findings == ()


def test_dangling_ns_is_a_critical_finding_per_dead_nameserver() -> None:
    answers: dict[tuple[str, DnsRecordType], tuple[str, ...] | DnsStatus] = {
        (ASSET, DnsRecordType.NS): ("ns1.gone.example.net", "ns2.example.net"),
        ("ns1.gone.example.net", DnsRecordType.A): DnsStatus.NXDOMAIN,
        ("ns2.example.net", DnsRecordType.A): ("203.0.113.53",),
    }

    output, _dns = run(answers)
    findings = [f for f in output.findings if f.rule_id == "dns.takeover.dangling_ns"]

    assert len(findings) == 1
    assert findings[0].location == "ns1.gone.example.net"
    assert findings[0].confidence is Confidence.MEDIUM
    assert findings[0].remediation_context["target"] == "ns1.gone.example.net"
    assert findings[0].evidence[0].data["values"] == ["ns1.gone.example.net", "ns2.example.net"]


def test_ns_lookup_error_fails_open_for_that_host_only() -> None:
    answers: dict[tuple[str, DnsRecordType], tuple[str, ...] | DnsStatus] = {
        (ASSET, DnsRecordType.CNAME): (BEANSTALK,),
        (BEANSTALK, DnsRecordType.A): DnsStatus.NXDOMAIN,
        (ASSET, DnsRecordType.NS): ("ns1.gone.example.net",),
    }
    errors = {("ns1.gone.example.net", DnsRecordType.A)}

    found = by_rule(run(answers, errors=errors)[0])

    assert set(found) == {"dns.takeover.dangling_cname"}


def test_all_dns_errors_retry_the_run() -> None:
    with pytest.raises(TransientJobError, match="Subdomain takeover check failed"):
        run({}, all_errors=True)


def test_single_query_error_skips_only_that_check() -> None:
    answers: dict[tuple[str, DnsRecordType], tuple[str, ...] | DnsStatus] = {
        (ASSET, DnsRecordType.NS): ("ns1.gone.example.net",),
        ("ns1.gone.example.net", DnsRecordType.A): DnsStatus.NXDOMAIN,
    }
    errors = {(ASSET, DnsRecordType.CNAME)}

    found = by_rule(run(answers, errors=errors)[0])

    assert set(found) == {"dns.takeover.dangling_ns"}
