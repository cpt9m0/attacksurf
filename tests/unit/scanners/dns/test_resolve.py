"""`dns.resolve`: record persistence, the CNAME/IP graph, lifecycle and private-IP findings."""

from collections.abc import Sequence
from typing import cast
from uuid import uuid4

import pytest

from attacksurf.domain.assets import AssetType, RelationKind
from attacksurf.domain.jobs import TransientJobError
from attacksurf.domain.net import (
    DnsLookup,
    DnsQuery,
    DnsRecordType,
    DnsStatus,
    HttpBody,
    IpInfo,
    ScannerRuntime,
)
from attacksurf.domain.scanners import AssetRef, ScanContext, ScannerError, ScanOutput
from attacksurf.scanners.dns.resolve import (
    MAX_ADDRESSES,
    MAX_RECORDS_PER_TYPE,
    PRIVATE_IP_RULE,
    DnsResolve,
)

ROOT = "acme.example"
ASSET = "www.acme.example"


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
        raise AssertionError("dns.resolve must use lookup_many")

    def resolve_name(self, host: str) -> tuple[str, ...]:
        raise AssertionError("dns.resolve must use lookup_many")

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
        raise AssertionError("dns.resolve must not use HTTP")

    def close(self) -> None:
        pass


class FakeIntel:
    def __init__(self, info: dict[str, IpInfo] | None = None) -> None:
        self.info = info or {}

    def lookup(self, address: str) -> IpInfo | None:
        return self.info.get(address)


def context(
    dns: FakeDns,
    *,
    wildcard: bool = False,
    runtime: bool = True,
    intel: FakeIntel | None = None,
) -> ScanContext:
    return ScanContext(
        uuid4(),
        uuid4(),
        AssetRef(type=AssetType.DOMAIN, value=ROOT),
        "dns_passive",
        runtime=ScannerRuntime(dns, FakeHttp(), ip_intel=intel) if runtime else None,
        target_is_wildcard=wildcard,
    )


def asset(value: str = ASSET) -> AssetRef:
    return AssetRef(type=AssetType.SUBDOMAIN, value=value)


def dns_details(output: ScanOutput) -> dict[str, object]:
    raw = output.observations[0].details["dns"]
    assert isinstance(raw, dict)
    return cast(dict[str, object], raw)


def run(
    answers: dict[tuple[str, DnsRecordType], tuple[str, ...] | DnsStatus],
    *,
    errors: set[tuple[str, DnsRecordType]] | None = None,
    all_errors: bool = False,
    default_status: DnsStatus = DnsStatus.NO_ANSWER,
    wildcard: bool = False,
    intel: FakeIntel | None = None,
) -> tuple[ScanOutput, FakeDns]:
    dns = FakeDns(answers, errors=errors, all_errors=all_errors, default_status=default_status)
    return (
        DnsResolve().run(
            context(dns, wildcard=wildcard, intel=intel),
            asset(),
        ),
        dns,
    )


def test_resolve_creates_ip_assets_and_resolves_to_relations() -> None:
    output, _dns = run(
        {
            (ASSET, DnsRecordType.A): ("93.184.216.34",),
            (ASSET, DnsRecordType.AAAA): ("2606:2800:220:1::1",),
        }
    )

    assert [(item.type, item.value) for item in output.assets] == [
        (AssetType.IP, "93.184.216.34"),
        (AssetType.IP, "2606:2800:220:1::1"),
    ]
    assert {(rel.kind, rel.from_asset.value, rel.to_asset.value) for rel in output.relations} == {
        (RelationKind.RESOLVES_TO, ASSET, "93.184.216.34"),
        (RelationKind.RESOLVES_TO, ASSET, "2606:2800:220:1::1"),
    }
    assert dns_details(output) == {
        "a": ["93.184.216.34"],
        "aaaa": ["2606:2800:220:1::1"],
    }


def test_resolve_follows_cname_chain_and_only_graphs_in_root_hops() -> None:
    output, dns = run(
        {
            (ASSET, DnsRecordType.CNAME): ("cdn.acme.example.",),
            ("cdn.acme.example", DnsRecordType.CNAME): ("edge.other.net.",),
            ("edge.other.net", DnsRecordType.A): ("93.184.216.35",),
        }
    )

    assert [(item.type, item.value) for item in output.assets] == [
        (AssetType.SUBDOMAIN, "cdn.acme.example"),
        (AssetType.IP, "93.184.216.35"),
    ]
    assert {(rel.kind, rel.from_asset.value, rel.to_asset.value) for rel in output.relations} == {
        (RelationKind.CNAME_TO, ASSET, "cdn.acme.example"),
        (RelationKind.RESOLVES_TO, ASSET, "93.184.216.35"),
    }
    assert dns_details(output)["cname_chain"] == [
        ASSET,
        "cdn.acme.example",
        "edge.other.net",
    ]
    assert ("edge.other.net", DnsRecordType.CNAME) in dns.calls


def test_resolve_graphs_a_cname_to_the_scan_root() -> None:
    output, _dns = run({(ASSET, DnsRecordType.CNAME): (ROOT + ".",)})

    assert output.assets == ()
    assert {(rel.kind, rel.to_asset.value) for rel in output.relations} == {
        (RelationKind.CNAME_TO, ROOT)
    }


def test_resolve_stores_every_record_type() -> None:
    output, _dns = run(
        {
            (ASSET, DnsRecordType.MX): ("10 mail.acme.example.",),
            (ASSET, DnsRecordType.NS): ("ns1.acme.example.",),
            (ASSET, DnsRecordType.TXT): ("v=spf1 -all",),
            (ASSET, DnsRecordType.CAA): ('0 issue "letsencrypt.org"',),
            (ASSET, DnsRecordType.SOA): ("ns1.acme.example. hostmaster.acme.example. 1 2 3 4 5",),
        }
    )

    details = dns_details(output)
    assert details["mx"] == ["10 mail.acme.example."]
    assert details["ns"] == ["ns1.acme.example"]
    assert details["txt"] == ["v=spf1 -all"]
    assert details["caa"] == ['0 issue "letsencrypt.org"']
    assert details["soa"] == ["ns1.acme.example. hostmaster.acme.example. 1 2 3 4 5"]


def test_resolve_caps_records_and_addresses() -> None:
    addresses = tuple(f"93.184.216.{index}" for index in range(1, 26))
    output, _dns = run(
        {
            (ASSET, DnsRecordType.A): addresses,
            (ASSET, DnsRecordType.TXT): tuple(f"txt-{index}" for index in range(10)),
        }
    )

    details = dns_details(output)
    a_values = details["a"]
    txt_values = details["txt"]
    assert isinstance(a_values, list)
    assert isinstance(txt_values, list)
    assert len([item for item in output.assets if item.type is AssetType.IP]) == MAX_ADDRESSES
    assert len(a_values) == MAX_RECORDS_PER_TYPE
    assert len(txt_values) == MAX_RECORDS_PER_TYPE
    assert all(isinstance(value, str) and len(value) <= 256 for value in txt_values)


def test_resolve_marks_a_non_resolving_subdomain_inactive() -> None:
    output, _dns = run({}, default_status=DnsStatus.NXDOMAIN)

    assert output.assets == ()
    assert output.relations == ()
    assert output.observations[0].active is False


def test_resolve_keeps_an_asset_with_only_txt_active() -> None:
    output, _dns = run({(ASSET, DnsRecordType.TXT): ("v=spf1 -all",)})

    assert output.observations[0].active is True
    assert output.assets == ()


def test_resolve_does_not_deactivate_on_a_partial_lookup_error() -> None:
    output, _dns = run(
        {},
        errors={(ASSET, DnsRecordType.A)},
        default_status=DnsStatus.NXDOMAIN,
    )

    assert output.observations[0].active is None
    assert output.observations[0].details == {}


def test_resolve_raises_transient_when_every_query_fails() -> None:
    with pytest.raises(TransientJobError, match="DNS resolution failed"):
        run({}, all_errors=True)


def test_resolve_flags_private_addresses() -> None:
    output, _dns = run({(ASSET, DnsRecordType.A): ("10.0.0.5",)})

    assert [(item.type, item.value) for item in output.assets] == [(AssetType.IP, "10.0.0.5")]
    assert dns_details(output)["private_ips"] == ["10.0.0.5"]
    finding = output.findings[0]
    assert finding.rule_id == PRIVATE_IP_RULE
    assert finding.location == "10.0.0.5"
    assert finding.evidence[0].kind.value == "dns_record"
    assert finding.evidence[0].data["value"] == "10.0.0.5"


def test_resolve_enriches_ip_details() -> None:
    output, _dns = run(
        {(ASSET, DnsRecordType.A): ("93.184.216.34",)},
        intel=FakeIntel({"93.184.216.34": IpInfo(asn=13335, org="CLOUDFLARENET", country="US")}),
    )

    ip_observation = next(item for item in output.observations if item.asset.type is AssetType.IP)
    assert ip_observation.details["ip"] == {
        "asn": 13335,
        "org": "CLOUDFLARENET",
        "country": "US",
    }


def test_resolve_adds_reverse_dns_to_ip_details() -> None:
    output, _dns = run(
        {
            (ASSET, DnsRecordType.A): ("93.184.216.34",),
            ("34.216.184.93.in-addr.arpa", DnsRecordType.PTR): ("host.acme.example.",),
        }
    )

    ip_observation = next(item for item in output.observations if item.asset.type is AssetType.IP)
    assert ip_observation.details["ip"] == {"ptr": "host.acme.example"}


def test_resolve_does_not_deactivate_a_wildcard_zone() -> None:
    output, _dns = run({}, default_status=DnsStatus.NXDOMAIN, wildcard=True)

    assert output.observations[0].active is None


def test_resolve_stops_a_cname_loop() -> None:
    output, _dns = run(
        {
            (ASSET, DnsRecordType.CNAME): ("a.acme.example.",),
            ("a.acme.example", DnsRecordType.CNAME): (ASSET + ".",),
        }
    )

    assert dns_details(output)["cname_chain"] == [ASSET, "a.acme.example"]
    assert [item.value for item in output.assets] == ["a.acme.example"]


def test_resolve_ignores_invalid_addresses() -> None:
    output, _dns = run({(ASSET, DnsRecordType.A): ("not-an-address",)})

    assert output.assets == ()
    assert output.findings == ()
    assert output.observations[0].active is True


def test_resolve_without_runtime_fails_safely() -> None:
    ctx = context(FakeDns(), runtime=False)

    with pytest.raises(ScannerError, match="runtime"):
        DnsResolve().run(ctx, asset())
