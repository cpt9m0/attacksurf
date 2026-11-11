"""`dns.discovery.ct` orchestration: sources, cache, cap and wildcard detection (no network)."""

import json
from pathlib import Path
from uuid import uuid4

import pytest

from attacksurf.domain.assets import AssetType, RelationKind
from attacksurf.domain.jobs import TransientJobError
from attacksurf.domain.net import DnsError, HttpBody, ScannerRuntime
from attacksurf.domain.scanners import AssetRef, ScanContext, ScannerError
from attacksurf.domain.scope import ScopeError
from attacksurf.scanners.dns.discovery import CACHE_TTL_SECONDS, MAX_WILDCARD_CHECKS, CtDiscovery
from tests.fakes import FakeCache

FIXTURES = Path(__file__).resolve().parents[3] / "fixtures" / "dns" / "discovery"
ROOT = "acme.example"


def fixture(name: str) -> bytes:
    return (FIXTURES / name).read_bytes()


class FakeDns:
    def __init__(
        self,
        wildcards: set[str] | None = None,
        *,
        error: type[Exception] | None = None,
    ) -> None:
        self.wildcards = wildcards or set()
        self.error = error
        self.calls: list[str] = []

    def resolve_name(self, host: str) -> tuple[str, ...]:
        self.calls.append(host)
        if self.error is not None:
            raise self.error()
        _label, _, zone = host.partition(".")
        return ("93.184.216.34",) if zone in self.wildcards else ()

    def resolve_ipv4(self, host: str) -> tuple[str, ...]:
        return self.resolve_name(host)


class FakeHttp:
    def __init__(self, *responses: HttpBody | Exception) -> None:
        self.responses = list(responses)
        self.calls: list[str] = []

    def get(self, url: str, *, limit: int) -> HttpBody:
        self.calls.append(url)
        response = self.responses.pop(0)
        if isinstance(response, Exception):
            raise response
        return response

    def close(self) -> None:
        pass


def response(name: str, *, headers: dict[str, str] | None = None) -> HttpBody:
    return HttpBody(status_code=200, content=fixture(name), headers=headers)


def context(
    *,
    dns: FakeDns | None = None,
    http: FakeHttp | None = None,
    cache: FakeCache | None = None,
    limit: int | None = None,
    runtime: bool = True,
) -> tuple[ScanContext, FakeDns, FakeHttp, FakeCache]:
    dns = dns or FakeDns()
    http = http or FakeHttp(response("crt_sh_example.json"))
    cache = cache or FakeCache()
    ctx = ScanContext(
        uuid4(),
        uuid4(),
        AssetRef(type=AssetType.DOMAIN, value=ROOT),
        "dns_passive",
        runtime=ScannerRuntime(dns, http, cache=cache) if runtime else None,
        max_discovered_assets=limit,
    )
    return ctx, dns, http, cache


def root() -> AssetRef:
    return AssetRef(type=AssetType.DOMAIN, value=ROOT)


def test_scan_emits_subdomains_and_relations_under_the_cap() -> None:
    ctx, _dns, _http, _cache = context(limit=3)

    output = CtDiscovery().run(ctx, root())

    assert [asset.value for asset in output.assets] == [
        "api.acme.example",
        "certspotter.acme.example",
        "dev.acme.example",
    ]
    assert all(asset.type is AssetType.SUBDOMAIN for asset in output.assets)
    assert {(relation.kind, relation.to_asset.value) for relation in output.relations} == {
        (RelationKind.SUBDOMAIN_OF, ROOT)
    }
    assert output.findings == ()


def test_scan_uses_a_cache_hit_without_contacting_a_source() -> None:
    payload = json.dumps(
        {"names": ["cached.acme.example"], "wildcard_zones": [ROOT]}, separators=(",", ":")
    )
    cache = FakeCache({f"ct:v1:{ROOT}": payload})
    ctx, _dns, http, _cache = context(cache=cache, dns=FakeDns(wildcards={ROOT}))

    output = CtDiscovery().run(ctx, root())

    assert [asset.value for asset in output.assets] == ["cached.acme.example"]
    assert output.wildcard_zones == (root(),)
    assert http.calls == []


def test_scan_stores_a_complete_result_and_reuses_it() -> None:
    ctx, _dns, http, cache = context(http=FakeHttp(response("crt_sh_example.json")))

    first = CtDiscovery().run(ctx, root())

    cached = json.loads(cache.values[f"ct:v1:{ROOT}"])
    assert cached["names"] == [asset.value for asset in first.assets]
    assert cache.ttls[f"ct:v1:{ROOT}"] == CACHE_TTL_SECONDS
    assert len(http.calls) == 1

    second = CtDiscovery().run(ctx, root())

    assert second.assets == first.assets
    assert len(http.calls) == 1


def test_scan_does_not_cache_a_partial_fallback_result() -> None:
    http = FakeHttp(
        HttpBody(status_code=503, content=b""),
        response("certspotter_example.json"),
        HttpBody(status_code=503, content=b""),
    )
    ctx, _dns, _http, cache = context(http=http)

    output = CtDiscovery().run(ctx, root())

    assert [asset.value for asset in output.assets] == [
        "api.acme.example",
        "shop.acme.example",
        "www.acme.example",
    ]
    assert cache.values == {}


def test_scan_raises_transient_when_both_sources_fail() -> None:
    ctx, _dns, _http, _cache = context(
        http=FakeHttp(
            HttpBody(status_code=503, content=b""), HttpBody(status_code=429, content=b"")
        )
    )

    with pytest.raises(TransientJobError, match="unavailable"):
        CtDiscovery().run(ctx, root())


def test_scan_marks_the_root_and_discovered_wildcard_zones() -> None:
    ctx, _dns, _http, _cache = context(dns=FakeDns(wildcards={ROOT, "dev.acme.example"}))

    output = CtDiscovery().run(ctx, root())

    assert output.wildcard_zones == (
        root(),
        AssetRef(type=AssetType.SUBDOMAIN, value="dev.acme.example"),
    )


def test_scan_does_not_mark_a_wildcard_zone_dropped_by_the_cap() -> None:
    payload = json.dumps(
        {"names": ["api.acme.example"], "wildcard_zones": ["dev.acme.example"]},
        separators=(",", ":"),
    )
    ctx, _dns, _http, _cache = context(
        cache=FakeCache({f"ct:v1:{ROOT}": payload}),
        dns=FakeDns(wildcards={"dev.acme.example"}),
        limit=1,
    )

    output = CtDiscovery().run(ctx, root())

    assert [asset.value for asset in output.assets] == ["api.acme.example"]
    assert output.wildcard_zones == ()


@pytest.mark.parametrize("error", [DnsError, ScopeError])
def test_scan_treats_a_failed_wildcard_probe_as_no_wildcard(error: type[Exception]) -> None:
    ctx, _dns, http, _cache = context(dns=FakeDns(error=error))

    output = CtDiscovery().run(ctx, root())

    assert output.assets
    assert output.wildcard_zones == ()
    assert http.calls


def test_wildcard_checks_are_capped() -> None:
    zones = [f"z{index}.acme.example" for index in range(20)]
    payload = json.dumps(
        {"names": ["api.acme.example"], "wildcard_zones": zones}, separators=(",", ":")
    )
    dns = FakeDns(wildcards={ROOT, *zones})
    ctx, _dns, _http, _cache = context(cache=FakeCache({f"ct:v1:{ROOT}": payload}), dns=dns)

    output = CtDiscovery().run(ctx, root())

    assert len(dns.calls) <= MAX_WILDCARD_CHECKS
    assert len(output.wildcard_zones) <= MAX_WILDCARD_CHECKS


def test_scan_rejects_a_corrupt_cache_payload() -> None:
    ctx, _dns, http, cache = context(cache=FakeCache({f"ct:v1:{ROOT}": "not json"}))

    output = CtDiscovery().run(ctx, root())

    assert output.assets
    assert len(http.calls) == 1
    assert cache.values[f"ct:v1:{ROOT}"]


def test_scan_filters_foreign_names_from_a_cache_payload() -> None:
    payload = json.dumps(
        {"names": ["evil.example", "www.acme.example"], "wildcard_zones": ["evil.example"]},
        separators=(",", ":"),
    )
    ctx, _dns, _http, _cache = context(cache=FakeCache({f"ct:v1:{ROOT}": payload}))

    output = CtDiscovery().run(ctx, root())

    assert [asset.value for asset in output.assets] == ["www.acme.example"]
    assert output.wildcard_zones == ()


def test_scan_without_a_runtime_fails_safely() -> None:
    ctx, _dns, _http, _cache = context(runtime=False)

    with pytest.raises(ScannerError, match="runtime"):
        CtDiscovery().run(ctx, root())


def test_empty_source_result_is_valid_and_cached() -> None:
    ctx, _dns, _http, cache = context(http=FakeHttp(HttpBody(status_code=200, content=b"[]")))

    output = CtDiscovery().run(ctx, root())

    assert output.assets == ()
    assert json.loads(cache.values[f"ct:v1:{ROOT}"])["names"] == []
