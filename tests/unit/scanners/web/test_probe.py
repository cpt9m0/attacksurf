"""Unit tests for `web.probe` HTTP service discovery scanner (#72)."""

import hashlib
import json
from uuid import uuid4

import httpx
import pytest

from attacksurf.domain.assets import AssetType, RelationKind
from attacksurf.domain.findings import Confidence, EvidenceKind, Severity
from attacksurf.domain.jobs import TransientJobError
from attacksurf.domain.net import DnsError, HttpBody, ScannerRuntime
from attacksurf.domain.scanners import MAX_ASSET_DETAILS_BYTES, AssetRef, ScanContext, ScannerError
from attacksurf.domain.scope import ScopeError
from attacksurf.scanners.web.probe import (
    MAX_BODY_EXCERPT_CHARS,
    MAX_TITLE_CHARS,
    ProbeResult,
    WebProbe,
    build_http_response_evidence,
    extract_html_title,
    redact_set_cookie,
)


class _StubDns:
    def resolve_ipv4(self, host: str) -> tuple[str, ...]:
        return ("93.184.216.34",)

    def resolve_name(self, host: str) -> tuple[str, ...]:
        return ("93.184.216.34",)

    def lookup_many(self, queries: object) -> tuple[()]:
        return ()


class _StubHttp:
    def __init__(self, responses: dict[str, HttpBody | Exception]) -> None:
        self._responses = responses
        self.calls: list[tuple[str, int]] = []

    def get(self, url: str, *, limit: int) -> HttpBody:
        self.calls.append((url, limit))
        outcome = self._responses.get(url)
        if outcome is None:
            raise ScopeError("Unreachable.")
        if isinstance(outcome, Exception):
            raise outcome
        return outcome

    def close(self) -> None:
        pass


def _ctx(http: _StubHttp | None, *, max_discovered_assets: int | None = None) -> ScanContext:
    runtime = ScannerRuntime(_StubDns(), http) if http is not None else None
    return ScanContext(
        org_id=uuid4(),
        scan_id=uuid4(),
        root_asset=AssetRef(type=AssetType.DOMAIN, value="acme.example"),
        profile="web_active",
        runtime=runtime,
        max_discovered_assets=max_discovered_assets,
    )


def test_web_probe_requires_configured_runtime() -> None:
    with pytest.raises(ScannerError, match="runtime"):
        WebProbe().run(_ctx(None), AssetRef(type=AssetType.DOMAIN, value="acme.example"))


def test_web_probe_discovers_https_url_redacts_cookies_and_merges_http_redirect() -> None:
    html = (
        f"<html><head><title>  {'Acme Portal ' * 30} </title></head><body>Hello World</body></html>"
    ).encode()
    headers = httpx.Headers(
        [
            ("content-type", "text/html; charset=utf-8"),
            ("server", "nginx/1.26.2"),
            ("set-cookie", "sessionid=super-secret-value; Path=/; HttpOnly; Secure"),
        ]
    )
    http = _StubHttp(
        {
            "https://acme.example/": HttpBody(
                200,
                html,
                False,
                headers,
                final_url="https://www.acme.example/",
                redirect_chain=(("https://acme.example/", 301),),
            ),
            "http://acme.example/": HttpBody(
                200,
                html,
                False,
                headers,
                final_url="https://www.acme.example/",
                redirect_chain=(("http://acme.example/", 301), ("https://acme.example/", 301)),
            ),
        }
    )

    out = WebProbe().run(_ctx(http), AssetRef(type=AssetType.DOMAIN, value="acme.example"))

    expected_url = AssetRef(type=AssetType.URL, value="https://www.acme.example/")
    assert out.assets == (expected_url,)
    assert len(out.relations) == 1
    assert out.relations[0].kind is RelationKind.SERVES
    assert out.relations[0].to_asset == expected_url

    obs = out.observations[0]
    assert obs.asset == expected_url
    assert obs.active is True
    web = obs.details["web"]
    assert isinstance(web, dict)
    assert web["final_url"] == "https://www.acme.example/"
    assert web["status_code"] == 200
    assert len(str(web["title"])) == MAX_TITLE_CHARS
    assert web["content_type"] == "text/html; charset=utf-8"
    assert web["body_sha256"] == hashlib.sha256(html).hexdigest()
    headers_dict = web["headers"]
    assert isinstance(headers_dict, dict)
    assert headers_dict["server"] == "nginx/1.26.2"
    assert "set-cookie" not in headers_dict
    assert web["cookies"] == ["sessionid=<redacted>; Path=/; HttpOnly; Secure"]
    assert "super-secret-value" not in repr(out)
    techs = obs.details["technologies"]
    assert isinstance(techs, list)
    assert any(
        isinstance(t, dict) and t["name"] == "Nginx" and t["version"] == "1.26.2" for t in techs
    )
    assert len(out.findings) == 1
    banner_finding = out.findings[0]
    assert banner_finding.rule_id == "web.disclosure.version_banner"
    assert banner_finding.severity is Severity.INFO
    assert banner_finding.confidence is Confidence.HIGH
    assert banner_finding.asset == expected_url
    assert banner_finding.remediation_context["headers"] == "Server"
    assert len(http.calls) == 2
    web_host = obs.details["web_host"]
    assert isinstance(web_host, dict)
    assert web_host["https_reachable"] is True
    assert web_host["http_probe"] == {
        "reachable": True,
        "status_code": 301,
        "final_url": "https://www.acme.example/",
        "redirects_to_https": True,
    }


def test_web_probe_discovers_http_only_host() -> None:
    http = _StubHttp(
        {
            "https://legacy.acme.example/": DnsError("connection refused"),
            "http://legacy.acme.example/": HttpBody(
                200,
                b"<title>Intranet Portal</title>",
                False,
                {"content-type": "text/html"},
                final_url="http://legacy.acme.example/",
            ),
        }
    )

    out = WebProbe().run(
        _ctx(http), AssetRef(type=AssetType.SUBDOMAIN, value="legacy.acme.example")
    )

    url_ref = AssetRef(type=AssetType.URL, value="http://legacy.acme.example/")
    assert out.assets == (url_ref,)
    web = out.observations[0].details["web"]
    web_host = out.observations[0].details["web_host"]
    assert isinstance(web, dict)
    assert isinstance(web_host, dict)
    assert web_host["https_reachable"] is False
    assert web["title"] == "Intranet Portal"


def test_web_probe_records_stopped_out_of_scope_redirect_without_following() -> None:
    http = _StubHttp(
        {
            "https://acme.example/": HttpBody(
                302,
                b"",
                False,
                {"location": "https://external-idp.example/login"},
                final_url="https://acme.example/",
                redirect_chain=(),
            ),
            "http://acme.example/": ScopeError("Unreachable."),
        }
    )

    out = WebProbe().run(_ctx(http), AssetRef(type=AssetType.DOMAIN, value="acme.example"))

    assert out.assets == (AssetRef(type=AssetType.URL, value="https://acme.example/"),)
    web = out.observations[0].details["web"]
    assert isinstance(web, dict)
    assert web["status_code"] == 302
    assert web["redirect_stopped_out_of_scope"] is True


def test_web_probe_keeps_distinct_http_url_and_honors_discovery_cap() -> None:
    http = _StubHttp(
        {
            "https://acme.example/": HttpBody(
                200, b"https", False, {}, final_url="https://acme.example/"
            ),
            "http://acme.example/": HttpBody(
                200, b"http", False, {}, final_url="http://acme.example/"
            ),
        }
    )

    uncapped = WebProbe().run(_ctx(http), AssetRef(type=AssetType.DOMAIN, value="acme.example"))
    assert len(uncapped.assets) == 2

    capped = WebProbe().run(
        _ctx(http, max_discovered_assets=1),
        AssetRef(type=AssetType.DOMAIN, value="acme.example"),
    )
    assert len(capped.assets) == 1
    assert capped.assets[0].value == "https://acme.example/"

    zero = WebProbe().run(
        _ctx(http, max_discovered_assets=0),
        AssetRef(type=AssetType.DOMAIN, value="acme.example"),
    )
    assert zero.assets == ()


def test_web_probe_marks_unreachable_url_inactive_and_refreshes_reachable_url() -> None:
    url_ref = AssetRef(type=AssetType.URL, value="https://acme.example/app")

    down = WebProbe().run(_ctx(_StubHttp({})), url_ref)
    assert down.assets == ()
    assert down.observations[0].asset == url_ref
    assert down.observations[0].active is False

    up_http = _StubHttp(
        {
            "https://acme.example/app": HttpBody(
                200,
                b"<title>App</title>",
                False,
                {"content-type": "text/html"},
                final_url="https://acme.example/app",
            )
        }
    )
    up = WebProbe().run(_ctx(up_http), url_ref)
    assert up.observations[0].active is True
    assert "web_host" not in up.observations[0].details
    assert up.observations[0].details["web"]["title"] == "App"  # type: ignore[index]


def test_web_probe_retains_distinct_https_destination_from_http_redirect() -> None:
    http = _StubHttp(
        {
            "https://acme.example/": HttpBody(
                200, b"<title>Apex</title>", False, {}, final_url="https://acme.example/"
            ),
            "http://acme.example/": HttpBody(
                200,
                b"<title>WWW</title>",
                False,
                {},
                final_url="https://www.acme.example/",
                redirect_chain=(("http://acme.example/", 301),),
            ),
        }
    )

    out = WebProbe().run(_ctx(http), AssetRef(type=AssetType.DOMAIN, value="acme.example"))

    assert [a.value for a in out.assets] == [
        "https://acme.example/",
        "https://www.acme.example/",
    ]


def test_web_probe_trims_huge_metadata_to_fit_observation_byte_budget() -> None:
    headers_list = (
        [("server", "nginx")]
        + [(f"x-extra-{i}", "v" * 250) for i in range(29)]
        + [("set-cookie", f"c{i}={'s' * 200}; Path=/; HttpOnly") for i in range(20)]
    )
    long_hops = tuple((f"https://acme.example/{'a' * 1900}-{i}", 302) for i in range(4))
    http = _StubHttp(
        {
            "https://acme.example/": HttpBody(
                200,
                b"<title>Big</title>",
                False,
                httpx.Headers(headers_list),
                final_url="https://acme.example/final",
                redirect_chain=long_hops,
            ),
            "http://acme.example/": ScopeError("Unreachable."),
        }
    )

    out = WebProbe().run(_ctx(http), AssetRef(type=AssetType.DOMAIN, value="acme.example"))

    encoded = json.dumps(out.observations[0].details, ensure_ascii=False).encode()
    assert len(encoded) <= MAX_ASSET_DETAILS_BYTES
    web = out.observations[0].details["web"]
    assert isinstance(web, dict)
    assert web["final_url"] == "https://acme.example/final"
    assert web["headers"]["server"] == "nginx"  # type: ignore[index]


def test_web_probe_propagates_transient_job_error() -> None:
    http = _StubHttp({"https://acme.example/": TransientJobError("rate limit")})
    with pytest.raises(TransientJobError, match="rate limit"):
        WebProbe().run(_ctx(http), AssetRef(type=AssetType.DOMAIN, value="acme.example"))


def test_build_http_response_evidence_caps_body_and_includes_headers() -> None:
    huge_body = "A" * (MAX_BODY_EXCERPT_CHARS * 3)
    probe = ProbeResult(
        initial_url="https://acme.example/",
        final_url="https://acme.example/",
        redirect_chain=(),
        redirect_stopped_out_of_scope=False,
        status_code=200,
        title="Home",
        content_type="text/html",
        body_sha256="0" * 64,
        body_bytes=len(huge_body),
        body_truncated=False,
        headers={"server": "nginx", "content-type": "text/html"},
        cookies=("sid=<redacted>; Secure",),
        body_excerpt=huge_body[:MAX_BODY_EXCERPT_CHARS],
    )

    ev = build_http_response_evidence(probe)

    assert ev.kind is EvidenceKind.HTTP_RESPONSE
    assert ev.data["headers"] == {"server": "nginx", "content-type": "text/html"}
    assert ev.data["cookies"] == ["sid=<redacted>; Secure"]
    assert len(str(ev.data["body_snippet"])) == MAX_BODY_EXCERPT_CHARS
    assert redact_set_cookie("tok=xyz123; Path=/; Evil=ignored; Secure") == (
        "tok=<redacted>; Path=/; Secure"
    )
    assert extract_html_title(b'{"json": true}', "application/json") == ""


def test_web_probe_fingerprints_wordpress_meta_without_version_banner_or_extra_requests() -> None:
    html = (
        b"<html><head>"
        b'<meta name="generator" content="WordPress 6.5.2">'
        b'<script src="/assets/jquery-3.7.1.min.js"></script>'
        b"</head><body><p>Blog</p></body></html>"
    )
    http = _StubHttp(
        {
            "https://blog.acme.example/": HttpBody(
                200,
                html,
                False,
                {"content-type": "text/html", "server": "nginx"},
                final_url="https://blog.acme.example/",
            ),
            "http://blog.acme.example/": ScopeError("Unreachable."),
        }
    )

    out = WebProbe().run(_ctx(http), AssetRef(type=AssetType.SUBDOMAIN, value="blog.acme.example"))

    assert len(http.calls) == 2  # https + http only; fingerprinting makes zero extra calls
    assert out.findings == ()
    techs = out.observations[0].details["technologies"]
    assert isinstance(techs, list)
    by_name = {t["name"]: t for t in techs if isinstance(t, dict)}
    assert by_name["WordPress"]["version"] == "6.5.2"
    assert by_name["jQuery"]["version"] == "3.7.1"
    assert by_name["Nginx"]["version"] is None
    assert by_name["PHP"]["version"] is None

    url_ref = AssetRef(type=AssetType.URL, value="https://blog.acme.example/")
    refresh_http = _StubHttp(
        {
            "https://blog.acme.example/": HttpBody(
                200,
                html,
                False,
                {"content-type": "text/html", "server": "nginx/1.24.0"},
                final_url="https://blog.acme.example/",
            )
        }
    )
    refreshed = WebProbe().run(_ctx(refresh_http), url_ref)
    assert len(refresh_http.calls) == 1
    assert [f.rule_id for f in refreshed.findings] == ["web.disclosure.version_banner"]


def test_web_probe_keeps_priority_version_headers_and_drops_capped_findings() -> None:
    headers_list = [(f"x-filler-{i}", "value") for i in range(35)] + [
        ("server", "nginx/1.26.2"),
        ("x-powered-by", "PHP/8.2.15"),
    ]
    http = _StubHttp(
        {
            "https://acme.example/": HttpBody(
                200,
                b"<html></html>",
                False,
                httpx.Headers(headers_list),
                final_url="https://acme.example/",
            ),
            "http://acme.example/": HttpBody(
                200,
                b"<html></html>",
                False,
                {"server": "Apache/2.4.58"},
                final_url="http://acme.example/",
            ),
        }
    )

    out = WebProbe().run(
        _ctx(http, max_discovered_assets=1),
        AssetRef(type=AssetType.DOMAIN, value="acme.example"),
    )

    assert [a.value for a in out.assets] == ["https://acme.example/"]
    web = out.observations[0].details["web"]
    assert isinstance(web, dict)
    web_headers = web["headers"]
    assert isinstance(web_headers, dict)
    assert web_headers["server"] == "nginx/1.26.2"
    assert web_headers["x-powered-by"] == "PHP/8.2.15"
    assert len(out.findings) == 1
    assert out.findings[0].asset == AssetRef(type=AssetType.URL, value="https://acme.example/")
    assert out.findings[0].remediation_context["headers"] == "Server, X-Powered-By"
