"""Unit tests for `web.wordpress` (#79)."""

import json
import logging
from collections.abc import Callable, Mapping
from datetime import UTC, date, datetime
from urllib.parse import urlsplit
from uuid import uuid4

import pytest

from attacksurf.domain.assets import AssetType
from attacksurf.domain.findings import EvidenceKind, Severity
from attacksurf.domain.jobs import TransientJobError
from attacksurf.domain.net import DnsError, HttpBody, ScannerRuntime
from attacksurf.domain.rules.catalog import build_catalog
from attacksurf.domain.rules.web import WEB_RULES
from attacksurf.domain.scanners import AssetRef, ScanContext
from attacksurf.domain.scope import ScopeError
from attacksurf.domain.vulnintel import ProductVulnerability
from attacksurf.scanners.web.wordpress import WORDPRESS_PATHS, WebWordpress
from tests.scanner_fixtures import StubDns


class _StubHttp:
    def __init__(
        self,
        routes: Mapping[str, HttpBody | Callable[[str], HttpBody] | Exception],
        *,
        default_body: Callable[[str], HttpBody] | None = None,
    ) -> None:
        self._routes = routes
        self._default_body = default_body
        self.calls: list[tuple[str, str]] = []

    def get(self, url: str, *, limit: int, headers: Mapping[str, str] | None = None) -> HttpBody:
        del headers
        self.calls.append(("GET", url))
        path = urlsplit(url).path or "/"
        entry = self._routes.get(path)
        if isinstance(entry, Exception):
            raise entry
        if entry is None:
            if self._default_body is not None:
                return self._default_body(path)
            return HttpBody(status_code=404, content=b"Not Found")
        body = entry(path) if callable(entry) else entry
        if len(body.content) > limit:
            return HttpBody(
                status_code=body.status_code,
                content=body.content[:limit],
                truncated=True,
                headers=body.headers,
            )
        return body

    def head(self, url: str, *, headers: Mapping[str, str] | None = None) -> HttpBody:
        del headers
        self.calls.append(("HEAD", url))
        return HttpBody(status_code=405, content=b"")

    def close(self) -> None:
        pass


class _StubVulnIntel:
    def __init__(
        self, catalog: Mapping[tuple[str, str, str], tuple[ProductVulnerability, ...]]
    ) -> None:
        self._catalog = catalog
        self.queries: list[tuple[str, str, str]] = []

    def match_product(
        self, vendor: str, product: str, version: str
    ) -> tuple[ProductVulnerability, ...]:
        self.queries.append((vendor, product, version))
        return self._catalog.get((vendor, product, version), ())


def _vuln(cve_id: str, *, cvss: float = 7.5, in_kev: bool = False) -> ProductVulnerability:
    return ProductVulnerability(
        cve_id=cve_id,
        description=f"Test vulnerability {cve_id}",
        published_at=datetime(2025, 1, 15, tzinfo=UTC),
        cvss_v3_score=cvss,
        cvss_v3_vector=None,
        cvss_v4_score=None,
        cvss_v4_vector=None,
        in_kev=in_kev,
        kev_date_added=date(2025, 2, 1) if in_kev else None,
        epss_score=0.4,
        epss_percentile=0.85,
    )


def _ctx(
    http: _StubHttp,
    *,
    technologies: list[dict[str, object]] | None = None,
    wordpress: dict[str, object] | None = None,
    vuln_intel: _StubVulnIntel | None = None,
    final_url: str | None = None,
) -> ScanContext:
    details: dict[str, object] = {}
    if technologies is not None:
        details["technologies"] = technologies
    if wordpress is not None:
        details["wordpress"] = wordpress
    if final_url is not None:
        details["web"] = {"final_url": final_url}
    return ScanContext(
        org_id=uuid4(),
        scan_id=uuid4(),
        root_asset=AssetRef(type=AssetType.DOMAIN, value="acme.com"),
        profile="web_active",
        runtime=ScannerRuntime(
            dns=StubDns(),
            http=http,  # type: ignore[arg-type]
            vuln_intel=vuln_intel,
        ),
        target_details=details,  # type: ignore[arg-type]
    )


def test_wordpress_grant_matches_adr_0033_and_rules_compile() -> None:
    scanner = WebWordpress()
    assert scanner.name == "web.wordpress"
    assert scanner.requires_verification is True
    assert scanner.grant.http_methods == frozenset({"GET"})
    assert scanner.grant.http_paths == WORDPRESS_PATHS
    assert scanner.grant.soft_404_probe is True
    assert scanner.grant.follow_redirects is False

    catalog = build_catalog(WEB_RULES)
    for rule_id in (
        "web.wordpress.xmlrpc_enabled",
        "web.wordpress.user_listing",
        "web.wordpress.debug_log",
        "web.exposure.directory_listing",
    ):
        assert rule_id in catalog


def test_non_wordpress_target_makes_zero_http_requests() -> None:
    http = _StubHttp({})
    out = WebWordpress().run(
        _ctx(http, technologies=[{"name": "Nginx", "version": "1.26.2"}]),
        AssetRef(type=AssetType.URL, value="https://acme.com/"),
    )

    assert out.findings == ()
    assert out.observations == ()
    assert http.calls == []


def test_hardened_wordpress_and_soft_404_catch_all_produce_no_findings() -> None:
    http = _StubHttp(
        {
            "/feed/": HttpBody(
                status_code=200,
                content=b"<rss><channel><title>Hardened</title></channel></rss>",
                headers={"Content-Type": "application/rss+xml"},
            ),
            "/xmlrpc.php": HttpBody(status_code=403, content=b"Forbidden"),
            "/wp-json/wp/v2/users": HttpBody(
                status_code=401,
                content=b'{"code":"rest_not_logged_in"}',
                headers={"Content-Type": "application/json"},
            ),
            "/wp-content/debug.log": HttpBody(status_code=404, content=b"Not Found"),
            "/wp-content/uploads/": HttpBody(status_code=403, content=b"Forbidden"),
        }
    )
    out = WebWordpress().run(
        _ctx(
            http,
            technologies=[{"name": "WordPress", "version": None}],
            wordpress={"plugins": {}, "themes": {}},
        ),
        AssetRef(type=AssetType.URL, value="https://acme.com/"),
    )
    assert out.findings == ()
    assert len(out.observations) == 1
    assert out.observations[0].details == {
        "wordpress": {"core_version": None, "plugins": {}, "themes": {}}
    }

    catch_http = _StubHttp(
        {},
        default_body=lambda path: HttpBody(
            status_code=200,
            content=f"<html><body><h1>Soft 404 {path}</h1></body></html>".encode(),
            headers={"Content-Type": "text/html"},
        ),
    )
    catch_out = WebWordpress().run(
        _ctx(
            catch_http,
            technologies=[{"name": "WordPress", "version": None}],
            wordpress={"plugins": {}, "themes": {}},
        ),
        AssetRef(type=AssetType.URL, value="https://acme.com/"),
    )
    assert catch_out.findings == ()


def test_wordpress_exposure_rules_and_no_pii_or_secret_leakage(
    caplog: pytest.LogCaptureFixture,
) -> None:
    pii_slug = "admin_canary_slug"
    pii_name = "Alice Secret Admin"
    log_secret = "postgres://wpuser:TopSecretDbPass99@10.0.0.5/wp"
    users_payload = json.dumps(
        [
            {
                "id": 1,
                "name": pii_name,
                "slug": pii_slug,
                "link": f"https://acme.com/author/{pii_slug}/",
            },
            {"id": 2, "name": "Editor Canary", "slug": "editor_canary"},
        ]
    ).encode()
    debug_log_payload = (
        "[24-Nov-2026 10:15:00 UTC] PHP Fatal error: Uncaught Exception: "
        f"DSN={log_secret} in /var/www/html/wp-content/plugins/bad.php on line 42\n"
        "[24-Nov-2026 10:15:01 UTC] PHP Notice: Undefined index: debug in "
        "/var/www/html/wp-includes/option.php on line 88\n"
    ).encode()
    uploads_html = (
        b"<html><head><title>Index of /wp-content/uploads</title></head>"
        b"<body><h1>Index of /wp-content/uploads/</h1><pre>"
        b'<a href="../">Parent Directory</a>\n'
        b'<a href="2025/">2025/</a>\n'
        b'<a href="2026/">2026/</a>\n'
        b'<a href="export.csv">export.csv</a>\n'
        b"</pre></body></html>"
    )

    http = _StubHttp(
        {
            "/xmlrpc.php": HttpBody(
                status_code=405,
                content=b"XML-RPC server accepts POST requests only.",
                headers={"Content-Type": "text/plain", "Allow": "POST"},
            ),
            "/wp-json/wp/v2/users": HttpBody(
                status_code=200,
                content=users_payload,
                headers={"Content-Type": "application/json", "X-WP-Total": "7"},
            ),
            "/wp-content/debug.log": HttpBody(
                status_code=200,
                content=debug_log_payload,
                headers={"Content-Type": "text/plain"},
            ),
            "/wp-content/uploads/": HttpBody(
                status_code=200,
                content=uploads_html,
                headers={"Content-Type": "text/html"},
            ),
        }
    )

    with caplog.at_level(logging.DEBUG):
        out = WebWordpress().run(
            _ctx(
                http,
                technologies=[{"name": "WordPress", "version": None}],
                wordpress={"plugins": {}, "themes": {}},
            ),
            AssetRef(type=AssetType.URL, value="https://acme.com/"),
        )

    by_rule = {f.rule_id: f for f in out.findings}
    assert set(by_rule) == {
        "web.wordpress.xmlrpc_enabled",
        "web.wordpress.user_listing",
        "web.wordpress.debug_log",
        "web.exposure.directory_listing",
    }
    assert by_rule["web.wordpress.xmlrpc_enabled"].evidence[0].data["allow"] == "POST"
    assert by_rule["web.wordpress.user_listing"].evidence[0].data == {
        "path": "/wp-json/wp/v2/users",
        "url": "https://acme.com/wp-json/wp/v2/users",
        "status_code": 200,
        "user_count": 7,
    }
    assert by_rule["web.wordpress.debug_log"].severity is None
    assert by_rule["web.wordpress.debug_log"].evidence[0].data["line_count"] == 2
    assert by_rule["web.wordpress.debug_log"].evidence[0].data["matched_levels"] == [
        "fatal",
        "notice",
    ]
    assert by_rule["web.exposure.directory_listing"].location == "/wp-content/uploads/"
    assert by_rule["web.exposure.directory_listing"].evidence[0].data["entry_count"] == 3

    serialized = json.dumps(out.model_dump(mode="json"))
    for canary in (pii_slug, pii_name, "editor_canary", log_secret, "/var/www/html"):
        assert canary not in serialized
        assert canary not in caplog.text


def test_wordpress_core_plugin_theme_cve_matching_without_enumeration() -> None:
    vuln_intel = _StubVulnIntel(
        {
            ("wordpress", "wordpress", "6.4.1"): (_vuln("CVE-2024-9001", cvss=8.8, in_kev=True),),
            ("rocklobster", "contact_form_7", "5.8.0"): (_vuln("CVE-2024-9002", cvss=6.5),),
            ("elementor", "hello_elementor", "3.0.1"): (_vuln("CVE-2024-9003", cvss=5.3),),
            ("woocommerce", "woocommerce", "8.9.0"): (_vuln("CVE-2024-9999", cvss=9.1),),
        }
    )

    page_html = (
        b"<html><head>"
        b'<meta name="generator" content="WordPress 6.4.1" />'
        b'<link rel="stylesheet" href="/wp-content/plugins/contact-form-7/styles.css?ver=5.8.0" />'
        b'<script src="/wp-content/plugins/woocommerce/app.js?ver=8.9.0"></script>'
        b'<link rel="stylesheet" href="/wp-content/themes/hello-elementor/style.css?ver=3.0.1" />'
        b"</head><body>WP</body></html>"
    )
    feed_xml = (
        b'<?xml version="1.0"?><rss><channel>'
        b"<generator>https://wordpress.org/?v=6.4.1</generator>"
        b"</channel></rss>"
    )

    http = _StubHttp(
        {
            "/": HttpBody(
                status_code=200,
                content=page_html,
                headers={"Content-Type": "text/html"},
            ),
            "/feed/": HttpBody(
                status_code=200,
                content=feed_xml,
                headers={"Content-Type": "application/rss+xml"},
            ),
        }
    )

    out = WebWordpress().run(
        _ctx(
            http,
            technologies=[
                {"name": "WordPress", "version": None},
                {"name": "WooCommerce", "version": "8.9.0"},
            ],
            vuln_intel=vuln_intel,
        ),
        AssetRef(type=AssetType.URL, value="https://acme.com/"),
    )

    assert all(f.rule_id == "web.components.known_vulnerable" for f in out.findings)
    by_loc = {f.location: f for f in out.findings}
    assert set(by_loc) == {
        "wordpress",
        "wordpress:plugin:contact-form-7",
        "wordpress:theme:hello-elementor",
    }
    assert by_loc["wordpress"].severity is Severity.CRITICAL  # HIGH 8.8 bumped on KEV
    assert by_loc["wordpress:plugin:contact-form-7"].evidence[0].kind is EvidenceKind.RAW
    assert by_loc["wordpress:theme:hello-elementor"].remediation_context["version"] == "3.0.1"

    called_paths = {urlsplit(url).path for _, url in http.calls}
    for path in called_paths:
        if not path.startswith("/attacksurf-not-found-"):
            assert path in WORDPRESS_PATHS


def test_wordpress_network_and_scope_errors_raise_transient_job_error() -> None:
    dns_fail = _StubHttp({"/xmlrpc.php": DnsError("dns timeout")})
    with pytest.raises(TransientJobError, match="WordPress check failed"):
        WebWordpress().run(
            _ctx(
                dns_fail,
                technologies=[{"name": "WordPress", "version": "6.5.2"}],
                wordpress={"plugins": {}, "themes": {}},
            ),
            AssetRef(type=AssetType.URL, value="https://acme.com/"),
        )

    scope_fail = _StubHttp({"/xmlrpc.php": ScopeError("denied")})
    with pytest.raises(TransientJobError, match="WordPress check failed"):
        WebWordpress().run(
            _ctx(
                scope_fail,
                technologies=[{"name": "WordPress", "version": "6.5.2"}],
                wordpress={"plugins": {}, "themes": {}},
            ),
            AssetRef(type=AssetType.URL, value="https://acme.com/"),
        )
