"""Unit tests for `web.components` known-vulnerable component matching (#75)."""

from datetime import UTC, date, datetime
from uuid import uuid4

import pytest

from attacksurf.domain.assets import AssetType
from attacksurf.domain.findings import Confidence, EvidenceKind, Severity
from attacksurf.domain.net import ScannerRuntime
from attacksurf.domain.scanners import MAX_EVIDENCE_BYTES, AssetRef, ScanContext, ScannerError
from attacksurf.domain.vulnintel import ProductVulnerability
from attacksurf.scanners.web.components import (
    MAX_EVIDENCE_CVES,
    TECHNOLOGY_CPES,
    WebComponents,
    severity_for_vulnerabilities,
)
from attacksurf.scanners.web.fingerprint import load_fingerprints
from attacksurf.services.scan_results import _evidence_digest


class _StubDns:
    def resolve_ipv4(self, host: str) -> tuple[str, ...]:
        return ()

    def resolve_name(self, host: str) -> tuple[str, ...]:
        return ()

    def lookup_many(self, queries: object) -> tuple[()]:
        return ()


class _StubHttp:
    def get(self, url: str, *, limit: int) -> object:
        raise AssertionError("web.components must never issue HTTP requests")

    def close(self) -> None:
        pass


class _FakeVulnIntel:
    def __init__(
        self, catalog: dict[tuple[str, str, str], tuple[ProductVulnerability, ...]]
    ) -> None:
        self._catalog = catalog
        self.calls: list[tuple[str, str, str]] = []

    def match_product(
        self, vendor: str, product: str, version: str
    ) -> tuple[ProductVulnerability, ...]:
        key = (vendor, product, version)
        self.calls.append(key)
        return self._catalog.get(key, ())


def _vuln(
    cve_id: str,
    *,
    cvss: float | None = 7.5,
    in_kev: bool = False,
    epss: float | None = 0.42,
    description: str = "Buffer handling issue.",
) -> ProductVulnerability:
    return ProductVulnerability(
        cve_id=cve_id,
        description=description,
        published_at=datetime(2021, 5, 25, tzinfo=UTC),
        cvss_v3_score=cvss,
        cvss_v3_vector=None,
        cvss_v4_score=None,
        cvss_v4_vector=None,
        in_kev=in_kev,
        kev_date_added=date(2022, 3, 1) if in_kev else None,
        epss_score=epss,
        epss_percentile=0.91 if epss is not None else None,
    )


def _ctx(
    details: dict[str, object] | None,
    intel: _FakeVulnIntel | None,
) -> ScanContext:
    runtime = ScannerRuntime(_StubDns(), _StubHttp(), vuln_intel=intel) if intel else None  # type: ignore[arg-type]
    return ScanContext(
        org_id=uuid4(),
        scan_id=uuid4(),
        root_asset=AssetRef(type=AssetType.DOMAIN, value="acme.example"),
        profile="web_active",
        runtime=runtime,
        target_details=details or {},  # type: ignore[arg-type]
    )


def test_technology_cpe_mapping_covers_documented_products_and_matches_fingerprints() -> None:
    fingerprint_names = {sig.name.lower() for sig in load_fingerprints()}
    for tech_name, cpes in TECHNOLOGY_CPES.items():
        assert tech_name in fingerprint_names, f"Missing fingerprint entry for {tech_name!r}"
        assert cpes
        for vendor, product in cpes:
            assert vendor
            assert product
            assert vendor == vendor.lower()
            assert product == product.lower()
    for required in (
        "nginx",
        "apache http server",
        "iis",
        "php",
        "apache tomcat",
        "wordpress",
        "drupal",
        "joomla",
        "jquery",
        "jenkins",
        "gitlab",
        "grafana",
        "atlassian confluence",
        "outlook web app",
    ):
        assert required in TECHNOLOGY_CPES


def test_web_components_requires_runtime() -> None:
    with pytest.raises(ScannerError, match="runtime"):
        WebComponents().run(
            _ctx({}, None), AssetRef(type=AssetType.URL, value="https://acme.example/")
        )


def test_web_components_flags_nginx_cves_and_raises_severity_for_kev() -> None:
    url_ref = AssetRef(type=AssetType.URL, value="https://acme.example/")
    details: dict[str, object] = {
        "technologies": [
            {
                "name": "Nginx",
                "version": "1.18.0",
                "categories": ["Web servers"],
                "confidence": 100,
            }
        ]
    }
    non_kev_intel = _FakeVulnIntel(
        {
            ("f5", "nginx", "1.18.0"): (_vuln("CVE-2021-23017", cvss=7.5, in_kev=False),),
        }
    )
    out = WebComponents().run(_ctx(details, non_kev_intel), url_ref)
    assert len(out.findings) == 1
    finding = out.findings[0]
    assert finding.rule_id == "web.components.known_vulnerable"
    assert finding.severity is Severity.HIGH
    assert finding.confidence is Confidence.MEDIUM
    assert finding.location == "nginx"
    assert finding.evidence[0].kind is EvidenceKind.RAW
    assert finding.evidence[0].data["product"] == "Nginx"
    assert finding.evidence[0].data["version"] == "1.18.0"
    assert finding.evidence[0].data["kev_count"] == 0

    kev_intel = _FakeVulnIntel(
        {
            ("f5", "nginx", "1.18.0"): (_vuln("CVE-2021-23017", cvss=7.5, in_kev=False),),
            ("nginx", "nginx", "1.18.0"): (
                _vuln("CVE-2021-23017", cvss=7.5, in_kev=False),
                _vuln("CVE-2021-3618", cvss=5.9, in_kev=True, epss=0.88),
            ),
        }
    )
    kev_out = WebComponents().run(_ctx(details, kev_intel), url_ref)
    kev_finding = kev_out.findings[0]
    assert kev_finding.severity is Severity.CRITICAL
    assert kev_finding.confidence is Confidence.MEDIUM
    cves = kev_finding.evidence[0].data["cves"]
    assert isinstance(cves, list)
    # Deduplicated across both CPE aliases, KEV sorted first.
    assert [c["cve_id"] for c in cves] == ["CVE-2021-3618", "CVE-2021-23017"]  # type: ignore[index]


@pytest.mark.parametrize(
    ("cvss", "in_kev", "expected"),
    [
        (2.0, False, Severity.LOW),
        (2.0, True, Severity.MEDIUM),
        (5.5, False, Severity.MEDIUM),
        (5.5, True, Severity.HIGH),
        (8.0, False, Severity.HIGH),
        (8.0, True, Severity.CRITICAL),
        (9.8, False, Severity.CRITICAL),
        (9.8, True, Severity.CRITICAL),
        (None, False, Severity.LOW),
        (None, True, Severity.MEDIUM),
    ],
)
def test_severity_for_vulnerabilities_cvss_and_kev_bump(
    cvss: float | None, in_kev: bool, expected: Severity
) -> None:
    assert severity_for_vulnerabilities((_vuln("CVE-2024-0001", cvss=cvss, in_kev=in_kev),)) is (
        expected
    )


def test_web_components_ignores_unversioned_unmapped_and_non_matching_technologies() -> None:
    url_ref = AssetRef(type=AssetType.URL, value="https://acme.example/")
    details: dict[str, object] = {
        "technologies": [
            {"name": "Nginx", "version": None},
            {"name": "PHP", "version": "*"},
            {"name": "CustomInternalFramework", "version": "1.0.0"},
            {"name": "WordPress", "version": "6.5.2"},
            "malformed-entry",
        ]
    }
    intel = _FakeVulnIntel({})
    out = WebComponents().run(_ctx(details, intel), url_ref)
    assert out.findings == ()
    assert intel.calls == [("wordpress", "wordpress", "6.5.2")]


def test_web_components_caps_cve_evidence_at_limit_and_byte_budget() -> None:
    url_ref = AssetRef(type=AssetType.URL, value="https://acme.example/")
    details: dict[str, object] = {"technologies": [{"name": "Nginx", "version": "1.14.0"}]}
    vulns = tuple(
        _vuln(f"CVE-2024-{i:04d}", cvss=7.5, description="X" * 500)
        for i in range(MAX_EVIDENCE_CVES + 10)
    )
    intel = _FakeVulnIntel({("f5", "nginx", "1.14.0"): vulns})
    out = WebComponents().run(_ctx(details, intel), url_ref)
    assert len(out.findings) == 1
    ev = out.findings[0].evidence[0]
    assert len(ev.model_dump_json().encode()) < MAX_EVIDENCE_BYTES
    assert ev.data["total_cves"] == MAX_EVIDENCE_CVES + 10
    assert ev.data["cves_truncated"] is True
    assert len(ev.data["cves"]) == MAX_EVIDENCE_CVES  # type: ignore[arg-type]
    assert out.findings[0].remediation_context["cve_summary"].endswith("(+27 more)")


def test_web_components_normalizes_dokuwiki_release_label() -> None:
    url_ref = AssetRef(type=AssetType.URL, value="https://wiki.acme.example/")
    details: dict[str, object] = {
        "technologies": [{"name": "DokuWiki", "version": "Release 2024-02-06"}]
    }
    intel = _FakeVulnIntel(
        {("dokuwiki", "dokuwiki", "2024-02-06"): (_vuln("CVE-2024-4100", cvss=6.1),)}
    )
    out = WebComponents().run(_ctx(details, intel), url_ref)
    assert intel.calls == [("dokuwiki", "dokuwiki", "2024-02-06")]
    assert len(out.findings) == 1
    assert out.findings[0].evidence[0].data["version"] == "2024-02-06"


def test_web_components_vuln_set_sha256_is_independent_of_epss_cutoff_reordering() -> None:
    url_ref = AssetRef(type=AssetType.URL, value="https://acme.example/")
    details: dict[str, object] = {"technologies": [{"name": "Nginx", "version": "1.14.0"}]}
    day1_vulns = tuple(
        _vuln(f"CVE-2024-{i:04d}", cvss=7.5, epss=0.9 - (i * 0.01))
        for i in range(MAX_EVIDENCE_CVES + 5)
    )
    # Day 2: CVE #24 overtakes the cutoff via EPSS without any CVSS, KEV, or membership change.
    day2_vulns = tuple(
        _vuln(
            f"CVE-2024-{i:04d}",
            cvss=7.5,
            epss=0.99 if i == MAX_EVIDENCE_CVES + 4 else 0.9 - (i * 0.01),
        )
        for i in range(MAX_EVIDENCE_CVES + 5)
    )

    out1 = WebComponents().run(
        _ctx(details, _FakeVulnIntel({("f5", "nginx", "1.14.0"): day1_vulns})), url_ref
    )
    out2 = WebComponents().run(
        _ctx(details, _FakeVulnIntel({("f5", "nginx", "1.14.0"): day2_vulns})), url_ref
    )

    ev1 = out1.findings[0].evidence[0]
    ev2 = out2.findings[0].evidence[0]
    ids1 = [c["cve_id"] for c in ev1.data["cves"]]  # type: ignore[union-attr]
    ids2 = [c["cve_id"] for c in ev2.data["cves"]]  # type: ignore[union-attr]
    assert ids1 != ids2
    assert ev1.data["vuln_set_sha256"] == ev2.data["vuln_set_sha256"]
    assert _evidence_digest(out1.findings[0].evidence) == _evidence_digest(
        out2.findings[0].evidence
    )
