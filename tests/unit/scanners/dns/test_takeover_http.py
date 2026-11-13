"""`dns.takeover.http`: fingerprint-match via one verified GET (#18)."""

from collections.abc import Sequence
from pathlib import Path
from uuid import uuid4

import pytest

from attacksurf.domain.assets import AssetType
from attacksurf.domain.findings import Confidence
from attacksurf.domain.jobs import TransientJobError
from attacksurf.domain.net import (
    DnsLookup,
    DnsQuery,
    DnsRecordType,
    DnsStatus,
    HttpBody,
    ScannerRuntime,
)
from attacksurf.domain.scanners import AssetRef, ScanContext, ScanOutput
from attacksurf.domain.scope import HttpPermission, ScopeError
from attacksurf.scanners.dns.takeover_http import MAX_BODY_BYTES, DnsTakeoverHttp

ROOT = "acme.example"
ASSET = "assets.acme.example"
S3_TARGET = "acme-assets.s3.amazonaws.com"
FIXTURE = Path(__file__).parents[3] / "fixtures" / "dns" / "takeover" / "s3-no-such-bucket.xml"


class FakeDns:
    def __init__(
        self,
        answers: dict[tuple[str, DnsRecordType], tuple[str, ...] | DnsStatus] | None = None,
        *,
        all_errors: bool = False,
    ) -> None:
        self.answers = answers or {}
        self.all_errors = all_errors
        self.calls: list[tuple[str, DnsRecordType]] = []

    def resolve_ipv4(self, host: str) -> tuple[str, ...]:
        return ()

    def resolve_name(self, host: str) -> tuple[str, ...]:
        return ("203.0.113.10",)

    def lookup_many(self, queries: Sequence[DnsQuery]) -> tuple[DnsLookup, ...]:
        results: list[DnsLookup] = []
        for query in queries:
            self.calls.append((query.name, query.record_type))
            if self.all_errors:
                results.append(DnsLookup(query, (), DnsStatus.ERROR))
                continue
            outcome = self.answers.get((query.name, query.record_type), DnsStatus.NO_ANSWER)
            if isinstance(outcome, DnsStatus):
                results.append(DnsLookup(query, (), outcome))
            else:
                results.append(DnsLookup(query, outcome, DnsStatus.OK))
        return tuple(results)


class FakeHttp:
    def __init__(self, body: HttpBody | Exception | None = None) -> None:
        self.body = body if body is not None else HttpBody(200, b"welcome")
        self.calls: list[tuple[str, int]] = []

    def get(self, url: str, *, limit: int) -> HttpBody:
        self.calls.append((url, limit))
        if isinstance(self.body, Exception):
            raise self.body
        return self.body

    def close(self) -> None:
        pass


def run(
    answers: dict[tuple[str, DnsRecordType], tuple[str, ...] | DnsStatus],
    http: FakeHttp,
    *,
    all_errors: bool = False,
) -> tuple[ScanOutput, FakeDns, FakeHttp]:
    dns = FakeDns(answers, all_errors=all_errors)
    ctx = ScanContext(
        uuid4(),
        uuid4(),
        AssetRef(type=AssetType.DOMAIN, value=ROOT),
        "dns_passive",
        runtime=ScannerRuntime(dns, http),
    )
    output = DnsTakeoverHttp().run(ctx, AssetRef(type=AssetType.SUBDOMAIN, value=ASSET))
    return output, dns, http


def s3_answers() -> dict[tuple[str, DnsRecordType], tuple[str, ...] | DnsStatus]:
    return {(ASSET, DnsRecordType.CNAME): (S3_TARGET,)}


def test_scanner_is_a_verified_target_http_check_on_the_passive_queue() -> None:
    # The registry refuses TARGET grants without verification, and profiles only accept
    # the passive queue: both must hold for this plugin to run at all.
    assert DnsTakeoverHttp.asset_types == frozenset({AssetType.DOMAIN, AssetType.SUBDOMAIN})
    assert DnsTakeoverHttp.queue == "passive"
    assert DnsTakeoverHttp.requires_verification is True
    assert DnsTakeoverHttp.grant.http is HttpPermission.TARGET


def test_known_vulnerable_fixture_produces_a_high_finding_with_evidence() -> None:
    # Acceptance criterion for #18: CNAME chain + response snippet as evidence.
    body = HttpBody(404, FIXTURE.read_bytes())

    output, _dns, http = run(s3_answers(), FakeHttp(body))

    assert len(output.findings) == 1
    finding = output.findings[0]
    assert finding.rule_id == "dns.takeover.fingerprint_match"
    assert finding.confidence is Confidence.HIGH
    assert finding.location == S3_TARGET
    assert finding.remediation_context["service"] == "AWS/S3"
    assert finding.evidence[0].kind.value == "dns_record"
    assert finding.evidence[0].data["values"] == [ASSET, S3_TARGET]
    assert finding.evidence[1].kind.value == "http_response"
    assert finding.evidence[1].data["status_code"] == 404
    assert "The specified bucket does not exist" in str(finding.evidence[1].data["body_snippet"])
    # One single GET against the asset itself, plain HTTP, capped body.
    assert http.calls == [(f"http://{ASSET}/", MAX_BODY_BYTES)]


def test_no_service_match_means_no_http_request() -> None:
    http = FakeHttp(HttpBody(404, FIXTURE.read_bytes()))
    answers: dict[tuple[str, DnsRecordType], tuple[str, ...] | DnsStatus] = {
        (ASSET, DnsRecordType.CNAME): ("gone.example.net",)
    }

    output, _dns, http = run(answers, http)

    assert output.findings == ()
    assert http.calls == []


def test_no_cname_means_no_http_request() -> None:
    http = FakeHttp()

    output, _dns, http = run({}, http)

    assert output.findings == ()
    assert http.calls == []


def test_resolving_service_without_the_signature_has_no_finding() -> None:
    output, _dns, _http = run(s3_answers(), FakeHttp(HttpBody(200, b"<html>real site</html>")))

    assert output.findings == ()


def test_status_code_signature_matches_without_a_body_fingerprint() -> None:
    answers: dict[tuple[str, DnsRecordType], tuple[str, ...] | DnsStatus] = {
        (ASSET, DnsRecordType.CNAME): ("acme.helprace.com",)
    }

    output, _dns, _http = run(answers, FakeHttp(HttpBody(301, b"")))

    assert [f.rule_id for f in output.findings] == ["dns.takeover.fingerprint_match"]
    assert output.findings[0].evidence[1].data["status_code"] == 301


def test_http_failure_is_no_finding_not_a_failed_job() -> None:
    for failure in (ScopeError("The target is out of scope."), ScopeError("timed out")):
        output, _dns, _http = run(s3_answers(), FakeHttp(failure))

        assert output.findings == ()


def test_truncated_body_can_still_match_on_the_capped_prefix() -> None:
    body = HttpBody(404, FIXTURE.read_bytes(), truncated=True)

    output, _dns, _http = run(s3_answers(), FakeHttp(body))

    assert len(output.findings) == 1


def test_hostile_body_bytes_do_not_break_matching_or_evidence() -> None:
    body = HttpBody(404, b"\xff\xfe The specified bucket does not exist \x00 ok")

    output, _dns, _http = run(s3_answers(), FakeHttp(body))

    assert len(output.findings) == 1
    snippet = str(output.findings[0].evidence[1].data["body_snippet"])
    assert "\x00" not in snippet


def test_all_dns_errors_retry_the_run() -> None:
    with pytest.raises(TransientJobError, match="Subdomain takeover check failed"):
        run({}, FakeHttp(), all_errors=True)
