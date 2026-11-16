"""Shared fakes for the #19 DNS hygiene scanner tests (no network, no database)."""

from collections.abc import Sequence
from uuid import uuid4

from attacksurf.domain.assets import AssetType
from attacksurf.domain.net import (
    AuthoritativeAnswer,
    DnsLookup,
    DnsQuery,
    DnsRecordType,
    DnsStatus,
    DomainRegistration,
    HttpBody,
    ScannerRuntime,
    ZoneAnswers,
    ZoneTransferAttempt,
)
from attacksurf.domain.scanners import AssetRef, RawFinding, ScanContext, Scanner, ScanOutput

ROOT = "acme.example"


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
        raise AssertionError("the scanner must use lookup_many")

    def resolve_name(self, host: str) -> tuple[str, ...]:
        raise AssertionError("the scanner must use lookup_many")

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
        raise AssertionError("the scanner is not allowed HTTP")

    def close(self) -> None:
        pass


class FakeAuthoritative:
    def __init__(self, answers: ZoneAnswers) -> None:
        self.answers = answers
        self.calls: list[tuple[str, DnsRecordType]] = []

    def query(self, name: str, record_type: DnsRecordType) -> ZoneAnswers:
        self.calls.append((name, record_type))
        return self.answers


class FakeZoneTransfer:
    def __init__(self, attempts: Sequence[ZoneTransferAttempt] = ()) -> None:
        self.attempts = tuple(attempts)
        self.calls: list[str] = []

    def attempt(self, zone: str) -> tuple[ZoneTransferAttempt, ...]:
        self.calls.append(zone)
        return self.attempts


class FakeRdap:
    def __init__(self, registration: DomainRegistration | None) -> None:
        self.registration = registration
        self.calls: list[str] = []

    def lookup(self, domain: str) -> DomainRegistration | None:
        self.calls.append(domain)
        return self.registration


def run(
    scanner: Scanner,
    asset: str = ROOT,
    *,
    dns: FakeDns | None = None,
    authoritative: FakeAuthoritative | None = None,
    zone_transfer: FakeZoneTransfer | None = None,
    rdap: FakeRdap | None = None,
    org_domain: str | None = None,
) -> ScanOutput:
    runtime = ScannerRuntime(
        dns or FakeDns(),
        FakeHttp(),
        org_domain=(lambda _name, _org=org_domain: _org) if org_domain is not None else None,
        authoritative=authoritative,
        zone_transfer=zone_transfer,
        rdap=rdap,
    )
    ctx = ScanContext(
        uuid4(),
        uuid4(),
        AssetRef(type=AssetType.DOMAIN, value=asset),
        "dns_passive",
        runtime=runtime,
    )
    return scanner.run(ctx, AssetRef(type=AssetType.DOMAIN, value=asset))


def by_rule(output: ScanOutput) -> dict[str, RawFinding]:
    return {finding.rule_id: finding for finding in output.findings}


def evidence_values(finding: RawFinding, index: int = 0) -> list[str]:
    """The string values of one DNS-record evidence object, type-narrowed for tests."""
    values = finding.evidence[index].data.get("values")
    if not isinstance(values, list):
        return []
    return [value for value in values if isinstance(value, str)]


def zone(
    zone_name: str = ROOT,
    *,
    servers: Sequence[str] = ("ns1.acme.example",),
    answers: Sequence[AuthoritativeAnswer] = (),
) -> ZoneAnswers:
    return ZoneAnswers(zone=zone_name, servers=tuple(servers), answers=tuple(answers))


def answer(
    server: str = "ns1.acme.example",
    *,
    address: str = "93.184.216.34",
    status: DnsStatus = DnsStatus.OK,
    authoritative: bool = True,
    rcode: str = "noerror",
    values: Sequence[str] = (),
) -> AuthoritativeAnswer:
    return AuthoritativeAnswer(
        server=server,
        address=address,
        status=status,
        authoritative=authoritative,
        rcode=rcode,
        values=tuple(values),
    )
