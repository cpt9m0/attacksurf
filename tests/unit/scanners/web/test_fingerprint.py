"""Unit tests for passive web technology fingerprinting (#73)."""

import json
import time

import httpx
import pytest

from attacksurf.scanners.web.fingerprint import (
    MAX_HTML_REGEX_BYTES,
    FingerprintError,
    detect_version_banners,
    extract_cookie_names,
    fingerprint_response,
    load_fingerprints,
    parse_fingerprints,
)


def test_vendored_dataset_loads_cleanly_with_expected_size_and_implies() -> None:
    sigs = load_fingerprints()
    assert len(sigs) == 66
    by_name = {sig.name: sig for sig in sigs}
    assert "Nginx" in by_name
    assert "WordPress" in by_name
    assert "PHP" in by_name
    assert "jQuery" in by_name
    for sig in sigs:
        assert sig.categories
        for implied in sig.implies:
            assert implied in by_name


@pytest.mark.parametrize(
    ("raw", "match"),
    [
        ("not-json", "invalid JSON"),
        ("[]", "empty"),
        ('[{"name": "Foo", "categories": ["CMS"], "implies": ["Missing"]}]', "unknown technology"),
        (
            '[{"name": "Dup", "categories": ["CMS"]}, {"name": "Dup", "categories": ["CMS"]}]',
            "duplicate",
        ),
        ('[{"name": "BadRx", "categories": ["CMS"], "html": ["([unclosed"]}]', "invalid regex"),
        (
            '[{"name": "BadConf", "categories": ["CMS"], "html": ["ok\\\\;confidence:101"]}]',
            "out of range",
        ),
        (
            '[{"name": "BadMod", "categories": ["CMS"], "html": ["ok\\\\;unknown:1"]}]',
            "unsupported modifier",
        ),
        (
            '[{"name": "BadCookieHdr", "categories": ["CMS"], "headers": {"set-cookie": ["foo"]}}]',
            "use the cookies channel",
        ),
    ],
)
def test_parse_fingerprints_rejects_corrupt_documents(raw: str, match: str) -> None:
    with pytest.raises(FingerprintError, match=match):
        parse_fingerprints(raw)


def test_fingerprint_nginx_with_version_and_banner_disclosure() -> None:
    headers = httpx.Headers([("Server", "nginx/1.26.2"), ("Content-Type", "text/html")])
    techs = fingerprint_response(headers, b"<html><body>Welcome</body></html>", "text/html")

    by_name = {t.name: t for t in techs}
    assert "Nginx" in by_name
    nginx = by_name["Nginx"]
    assert nginx.version == "1.26.2"
    assert "Web servers" in nginx.categories
    assert nginx.confidence == 100
    assert nginx.to_dict() == {
        "name": "Nginx",
        "version": "1.26.2",
        "categories": list(nginx.categories),
        "confidence": 100,
    }
    assert detect_version_banners(headers) == {"Server": "nginx/1.26.2"}


def test_fingerprint_wordpress_generator_meta_implies_php_and_jquery() -> None:
    html = (
        b"<html><head>"
        b'<meta name="generator" content="WordPress 6.5.2">'
        b'<script src="/assets/vendor/jquery-3.7.1.min.js"></script>'
        b"</head><body><p>Blog</p></body></html>"
    )
    headers = {"content-type": "text/html; charset=utf-8"}

    techs = fingerprint_response(headers, html, "text/html; charset=utf-8")
    by_name = {t.name: t for t in techs}

    assert by_name["WordPress"].version == "6.5.2"
    assert "CMS" in by_name["WordPress"].categories
    assert by_name["WordPress"].confidence == 100
    assert by_name["PHP"].version is None
    assert by_name["PHP"].confidence == 100
    assert by_name["jQuery"].version == "3.7.1"
    assert detect_version_banners(headers) == {}


def test_fingerprint_no_version_response_extracts_names_without_version_banner() -> None:
    headers = httpx.Headers(
        [
            ("Server", "nginx"),
            ("X-Powered-By", "Express"),
            ("Content-Type", "text/html"),
        ]
    )
    techs = fingerprint_response(headers, b"<html><body>Hello</body></html>", "text/html")
    by_name = {t.name: t for t in techs}

    assert by_name["Nginx"].version is None
    assert by_name["Express"].version is None
    assert by_name["Node.js"].version is None
    assert detect_version_banners(headers) == {}


def test_fingerprint_cookie_names_only_never_exposes_values_and_checks_multivalue_headers() -> None:
    headers = httpx.Headers(
        [
            ("Set-Cookie", "PHPSESSID=secret-session-value-xyz; Path=/; HttpOnly"),
            ("X-Powered-By", "Express"),
            ("X-Powered-By", "PHP/8.2.15"),
            ("Content-Type", "text/html"),
        ]
    )
    assert extract_cookie_names(headers) == ("PHPSESSID",)

    techs = fingerprint_response(headers, b"<html></html>", "text/html")
    serialized = json.dumps([t.to_dict() for t in techs])
    assert "secret-session-value-xyz" not in serialized

    by_name = {t.name: t for t in techs}
    assert by_name["PHP"].version == "8.2.15"
    assert by_name["Express"].version is None
    assert detect_version_banners(headers) == {"X-Powered-By": "PHP/8.2.15"}


def test_detect_version_banners_ignores_unversioned_server_identifiers() -> None:
    for server_val in ("cloudflare", "AmazonS3", "ECAcc (dcb/7F82)", "Apache", "gws"):
        assert detect_version_banners({"Server": server_val}) == {}, server_val
    assert detect_version_banners({"Server": "Apache/2.4.58 (Debian)"}) == {
        "Server": "Apache/2.4.58 (Debian)"
    }


def test_fingerprint_skips_html_signals_on_non_html_content_type() -> None:
    payload = b'{"html": "<meta name=\\"generator\\" content=\\"WordPress 6.5.2\\">"}'
    techs = fingerprint_response(
        {"Content-Type": "application/json", "Server": "nginx/1.26.2"},
        payload,
        "application/json",
    )
    by_name = {t.name: t for t in techs}
    assert set(by_name) == {"Nginx"}


def test_fingerprint_performance_on_large_html_payload() -> None:
    padding = ("<div>" + ("a" * 95) + "</div>\n").encode()
    body = padding * (MAX_HTML_REGEX_BYTES // len(padding) + 50)
    start = time.monotonic()
    fingerprint_response({"Server": "nginx/1.26.2"}, body, "text/html")
    elapsed = time.monotonic() - start
    assert elapsed < 1.0


def test_fingerprint_flask_does_not_inherit_werkzeug_version() -> None:
    techs = fingerprint_response(
        {"Server": "Werkzeug/3.1.3 Python/3.12.0", "Content-Type": "text/html"},
        b"<html></html>",
        "text/html",
    )
    by_name = {t.name: t for t in techs}
    assert by_name["Flask"].version is None
    assert by_name["Python"].version == "3.12.0"


def test_fingerprint_cookie_only_phpmyadmin_and_aspnet_core() -> None:
    pma_techs = fingerprint_response(
        {"Set-Cookie": "phpMyAdmin_https=secret-pma-token; Path=/; HttpOnly"},
        b"",
        "text/html",
    )
    assert "phpMyAdmin" in {t.name for t in pma_techs}
    assert "secret-pma-token" not in json.dumps([t.to_dict() for t in pma_techs])

    asp_techs = fingerprint_response(
        {"Set-Cookie": ".AspNetCore.Antiforgery.abc=secret-asp-token; Path=/; HttpOnly"},
        b"",
        "text/html",
    )
    assert "Microsoft ASP.NET" in {t.name for t in asp_techs}
    assert "secret-asp-token" not in json.dumps([t.to_dict() for t in asp_techs])


def test_fingerprint_bootstrap_and_adversarial_near_misses_stay_linear() -> None:
    html = (
        b"<html><head>"
        b'<link rel="stylesheet" href="/static/bootstrap-5.3.3.min.css">'
        b'<script src="/js/bootstrap-5.3.3.bundle.min.js"></script>'
        b"</head><body></body></html>"
    )
    techs = fingerprint_response({"Content-Type": "text/html"}, html, "text/html")
    by_name = {t.name: t for t in techs}
    assert by_name["Bootstrap"].version == "5.3.3"

    adversarial_bodies = [
        ("<link href=bootstrap" + ("1" * 2000)).encode(),
        ("<link " * 2000).encode(),
        ("Powered by <a" + (" " * 5000)).encode(),
        ("<div " + ("x-data " * 2000)).encode(),
        ("<![CDATA[" + ("x" * 10000)).encode(),
        (
            f'<script src="/bootstrap-{"1" * 400}">'
            f'</script><script src="vue-{"1." * 200}"></script>'
        ).encode(),
    ]
    start = time.monotonic()
    for payload in adversarial_bodies:
        fingerprint_response({"Content-Type": "text/html"}, payload, "text/html")
    assert time.monotonic() - start < 0.5


def test_fingerprint_handles_malformed_html_marked_section_without_crashing() -> None:
    malformed = ("<title>Acme</title>" + (" " * 70_000) + "<![foo]><div>body</div>").encode()
    techs = fingerprint_response(
        {"Server": "nginx/1.26.2", "Content-Type": "text/html"},
        malformed,
        "text/html",
    )
    by_name = {t.name: t for t in techs}
    assert by_name["Nginx"].version == "1.26.2"


def test_fingerprint_sonarqube_script_src_query_delimiter() -> None:
    hit_html = b'<script src="/js/bundles/sonar.js?v=6.7.7"></script>'
    techs = fingerprint_response({"Content-Type": "text/html"}, hit_html, "text/html")
    assert {t.name: t.version for t in techs}["SonarQube"] == "6.7.7"

    miss_html = b'<script src="/js/bundles/sonar.jsv=6.7.7"></script>'
    miss_techs = fingerprint_response({"Content-Type": "text/html"}, miss_html, "text/html")
    assert "SonarQube" not in {t.name for t in miss_techs}
