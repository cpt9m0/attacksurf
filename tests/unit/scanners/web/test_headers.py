"""Unit tests for `web.headers` and `web.cors` (#77)."""

from collections.abc import Mapping
from uuid import uuid4

import httpx
import pytest

from attacksurf.domain.assets import AssetType
from attacksurf.domain.findings import EvidenceKind, Severity
from attacksurf.domain.jobs import TransientJobError
from attacksurf.domain.net import DnsError, HttpBody, ScannerRuntime
from attacksurf.domain.rules.catalog import build_catalog
from attacksurf.domain.rules.web import WEB_RULES
from attacksurf.domain.scanners import AssetRef, ScanContext
from attacksurf.domain.scope import ScopeError
from attacksurf.scanners.web.headers import (
    FOREIGN_ORIGIN,
    MIN_HSTS_MAX_AGE_SECONDS,
    WebCors,
    WebHeaders,
)
from attacksurf.scanners.web.probe import redact_set_cookie, sanitize_headers
from tests.scanner_fixtures import StubDns


class _StubHttp:
    def __init__(self, response: HttpBody | Exception) -> None:
        self.response = response
        self.requests: list[tuple[str, int, dict[str, str] | None]] = []

    def get(self, url: str, *, limit: int, headers: Mapping[str, str] | None = None) -> HttpBody:
        self.requests.append((url, limit, dict(headers) if headers is not None else None))
        if isinstance(self.response, Exception):
            raise self.response
        return self.response

    def close(self) -> None:
        pass


def _ctx(
    *,
    web_details: dict[str, object] | None = None,
    response: HttpBody | Exception | None = None,
) -> tuple[ScanContext, _StubHttp]:
    http = _StubHttp(response or HttpBody(status_code=200, content=b""))
    target_details = {"web": web_details} if web_details is not None else {}
    ctx = ScanContext(
        org_id=uuid4(),
        scan_id=uuid4(),
        root_asset=AssetRef(type=AssetType.DOMAIN, value="acme.com"),
        profile="web_active",
        runtime=ScannerRuntime(dns=StubDns(), http=http),  # type: ignore[arg-type]
        target_details=target_details,  # type: ignore[arg-type]
    )
    return ctx, http


def _hardened_web_details() -> dict[str, object]:
    return {
        "final_url": "https://acme.com/",
        "redirect_chain": [],
        "redirect_stopped_out_of_scope": False,
        "status_code": 200,
        "content_type": "text/html",
        "headers": {
            "strict-transport-security": "max-age=31536000; includeSubDomains",
            "content-security-policy": (
                "default-src 'self'; script-src 'self' 'nonce-r4nd0m' 'unsafe-inline'; "
                "frame-ancestors 'none'"
            ),
            "x-content-type-options": "nosniff",
            "x-frame-options": "DENY",
            "date": "Tue, 24 Nov 2026 00:00:00 GMT",
        },
        "cookies": [
            "sessionid=<redacted>; Path=/; Secure; HttpOnly; SameSite=Lax",
            "theme=<redacted>; Path=/",
        ],
    }


def test_hardened_site_fixture_produces_no_header_or_cors_findings() -> None:
    ctx, http = _ctx(
        web_details=_hardened_web_details(),
        response=HttpBody(
            status_code=200,
            content=b"ok",
            headers={
                "Access-Control-Allow-Origin": "https://acme.com",
                "Access-Control-Allow-Credentials": "true",
            },
        ),
    )
    url_asset = AssetRef(type=AssetType.URL, value="https://acme.com/")

    hdr_out = WebHeaders().run(ctx, url_asset)
    cors_out = WebCors().run(ctx, url_asset)

    assert hdr_out.findings == ()
    assert cors_out.findings == ()
    assert http.requests == [
        ("https://acme.com/", 16 * 1024, {"Origin": FOREIGN_ORIGIN}),
    ]
    assert hdr_out.observations[0].details == {
        "security_headers": {
            "final_url": "https://acme.com/",
            "hsts": True,
            "csp": True,
            "clickjacking_protected": True,
            "nosniff": True,
            "redirects_to_https": None,
        }
    }


def test_web_headers_flags_hsts_missing_on_https() -> None:
    details = _hardened_web_details()
    details["headers"] = {
        "content-security-policy": "default-src 'self'; frame-ancestors 'none'",
        "x-content-type-options": "nosniff",
    }
    ctx, _ = _ctx(web_details=details)

    out = WebHeaders().run(ctx, AssetRef(type=AssetType.URL, value="https://acme.com/"))

    assert [f.rule_id for f in out.findings] == ["web.headers.hsts_missing"]
    assert out.findings[0].evidence[0].kind is EvidenceKind.HTTP_RESPONSE
    assert out.findings[0].evidence[0].data["headers"] == {}


def test_web_headers_flags_hsts_weak_when_below_six_months() -> None:
    details = _hardened_web_details()
    raw_headers = details["headers"]
    assert isinstance(raw_headers, dict)
    headers: dict[str, str] = dict(raw_headers)
    headers["strict-transport-security"] = f"max-age={MIN_HSTS_MAX_AGE_SECONDS - 1}"
    details["headers"] = headers
    ctx, _ = _ctx(web_details=details)

    out = WebHeaders().run(ctx, AssetRef(type=AssetType.URL, value="https://acme.com/"))

    assert [f.rule_id for f in out.findings] == ["web.headers.hsts_weak"]
    ev = out.findings[0].evidence[0].data
    assert ev["max_age"] == MIN_HSTS_MAX_AGE_SECONDS - 1
    assert ev["headers"] == {"strict-transport-security": f"max-age={MIN_HSTS_MAX_AGE_SECONDS - 1}"}


def test_web_headers_flags_csp_missing_and_clickjacking_when_both_absent() -> None:
    details = _hardened_web_details()
    details["headers"] = {
        "strict-transport-security": "max-age=31536000",
        "x-content-type-options": "nosniff",
    }
    ctx, _ = _ctx(web_details=details)

    out = WebHeaders().run(ctx, AssetRef(type=AssetType.URL, value="https://acme.com/"))

    assert {f.rule_id for f in out.findings} == {
        "web.headers.csp_missing",
        "web.headers.clickjacking",
    }


@pytest.mark.parametrize(
    ("csp_value", "expected_tokens"),
    [
        ("default-src 'self'; script-src 'self' 'unsafe-inline'", ["'unsafe-inline'"]),
        ("default-src 'self'; script-src 'self' 'unsafe-eval'", ["'unsafe-eval'"]),
        ("default-src 'self' 'unsafe-inline' 'unsafe-eval'", ["'unsafe-inline'", "'unsafe-eval'"]),
        ("script-src 'self' 'unsafe-eval' 'nonce-abc123'", ["'unsafe-eval'"]),
    ],
)
def test_web_headers_flags_csp_unsafe_without_nonce_or_with_eval(
    csp_value: str, expected_tokens: list[str]
) -> None:
    details = _hardened_web_details()
    details["headers"] = {
        "strict-transport-security": "max-age=31536000",
        "content-security-policy": csp_value,
        "x-frame-options": "SAMEORIGIN",
        "x-content-type-options": "nosniff",
    }
    ctx, _ = _ctx(web_details=details)

    out = WebHeaders().run(ctx, AssetRef(type=AssetType.URL, value="https://acme.com/"))

    assert [f.rule_id for f in out.findings] == ["web.headers.csp_unsafe"]
    ev = out.findings[0].evidence[0].data
    assert ev["unsafe_tokens"] == expected_tokens
    assert set(ev["headers"]) == {"content-security-policy"}  # type: ignore[arg-type]


def test_web_headers_accepts_frame_ancestors_without_xfo_and_skips_csp_on_json() -> None:
    ctx, _ = _ctx(
        web_details={
            "final_url": "https://acme.com/api",
            "status_code": 200,
            "content_type": "application/json",
            "headers": {
                "strict-transport-security": "max-age=31536000",
                "x-content-type-options": "nosniff",
            },
            "cookies": [],
        }
    )

    out = WebHeaders().run(ctx, AssetRef(type=AssetType.URL, value="https://acme.com/api"))
    assert out.findings == ()

    html_ctx, _ = _ctx(
        web_details={
            "final_url": "https://acme.com/",
            "status_code": 200,
            "content_type": "text/html",
            "headers": {
                "strict-transport-security": "max-age=31536000",
                "content-security-policy": (
                    "default-src 'self'; script-src 'sha256-xyz' 'unsafe-inline'; "
                    "frame-ancestors 'self'"
                ),
                "x-content-type-options": "nosniff",
            },
            "cookies": [],
        }
    )
    assert (
        WebHeaders().run(html_ctx, AssetRef(type=AssetType.URL, value="https://acme.com/")).findings
        == ()
    )


def test_web_headers_flags_nosniff_missing() -> None:
    details = _hardened_web_details()
    details["headers"] = {
        "strict-transport-security": "max-age=31536000",
        "content-security-policy": "default-src 'self'; frame-ancestors 'none'",
        "x-frame-options": "DENY",
    }
    ctx, _ = _ctx(web_details=details)

    out = WebHeaders().run(ctx, AssetRef(type=AssetType.URL, value="https://acme.com/"))

    assert [f.rule_id for f in out.findings] == ["web.headers.nosniff_missing"]


def test_web_headers_flags_insecure_session_cookies_only() -> None:
    details = _hardened_web_details()
    details["cookies"] = [
        "prefs=<redacted>; Path=/",
        "csrftoken=<redacted>; Path=/; Secure",
        "PHPSESSID=<redacted>; Path=/",
        "auth_token=raw-secret-must-not-leak; Path=/; Secure",
    ]
    ctx, _ = _ctx(web_details=details)

    out = WebHeaders().run(ctx, AssetRef(type=AssetType.URL, value="https://acme.com/"))

    assert [f.rule_id for f in out.findings] == ["web.cookies.insecure_flags"]
    cookies = out.findings[0].evidence[0].data["cookies"]
    assert cookies == [
        {
            "name": "PHPSESSID",
            "missing": ["Secure", "HttpOnly", "SameSite"],
            "cookie": "PHPSESSID=<redacted>; Path=/",
        },
        {
            "name": "auth_token",
            "missing": ["HttpOnly", "SameSite"],
            "cookie": "auth_token=<redacted>; Path=/; Secure",
        },
    ]


def test_web_headers_flags_http_port_80_without_https_redirect_and_ignores_http_hsts() -> None:
    ctx, _ = _ctx(
        web_details={
            "final_url": "http://acme.com/",
            "redirect_chain": [],
            "redirect_stopped_out_of_scope": False,
            "status_code": 200,
            "content_type": "text/html",
            "headers": {
                "content-security-policy": "default-src 'self'; frame-ancestors 'none'",
                "x-content-type-options": "nosniff",
            },
            "cookies": [],
        }
    )

    out = WebHeaders().run(ctx, AssetRef(type=AssetType.URL, value="http://acme.com/"))

    assert [f.rule_id for f in out.findings] == ["web.https.no_redirect"]
    summary = out.observations[0].details["security_headers"]
    assert isinstance(summary, dict)
    assert summary["redirects_to_https"] is False

    redirected_ctx, _ = _ctx(
        web_details={
            "final_url": "https://acme.com/",
            "redirect_chain": [{"url": "http://acme.com/", "status": 301}],
            "redirect_stopped_out_of_scope": False,
            "status_code": 200,
            "content_type": "text/html",
            "headers": _hardened_web_details()["headers"],
            "cookies": [],
        }
    )
    redir_out = WebHeaders().run(
        redirected_ctx, AssetRef(type=AssetType.URL, value="http://acme.com/")
    )
    assert redir_out.findings == ()
    redir_summary = redir_out.observations[0].details["security_headers"]
    assert isinstance(redir_summary, dict)
    assert redir_summary["redirects_to_https"] is True


def test_web_headers_returns_empty_when_probe_details_absent() -> None:
    ctx, _ = _ctx(web_details=None)
    out = WebHeaders().run(ctx, AssetRef(type=AssetType.URL, value="https://acme.com/"))
    assert out.findings == ()
    assert out.observations == ()


def test_web_cors_flags_reflected_origin_with_credentials() -> None:
    ctx, http = _ctx(
        web_details={"final_url": "https://acme.com/app"},
        response=HttpBody(
            status_code=200,
            content=b'{"user":"alice"}',
            headers={
                "Access-Control-Allow-Origin": FOREIGN_ORIGIN,
                "Access-Control-Allow-Credentials": "true",
                "Vary": "Origin",
                "X-Powered-By": "unrelated",
            },
            final_url="https://acme.com/app",
        ),
    )

    out = WebCors().run(ctx, AssetRef(type=AssetType.URL, value="https://acme.com/"))

    assert http.requests == [("https://acme.com/app", 16 * 1024, {"Origin": FOREIGN_ORIGIN})]
    assert [f.rule_id for f in out.findings] == ["web.cors.wildcard_credentials"]
    ev = out.findings[0].evidence[0].data
    assert ev["origin_sent"] == FOREIGN_ORIGIN
    assert ev["headers"] == {
        "access-control-allow-origin": FOREIGN_ORIGIN,
        "access-control-allow-credentials": "true",
        "vary": "Origin",
    }


def test_web_cors_ignores_wildcard_without_credentials_and_retries_network_errors() -> None:
    ctx, _ = _ctx(
        response=HttpBody(
            status_code=200,
            content=b"{}",
            headers={"Access-Control-Allow-Origin": "*"},
        )
    )
    out = WebCors().run(ctx, AssetRef(type=AssetType.URL, value="https://acme.com/"))
    assert out.findings == ()

    dns_fail_ctx, _ = _ctx(response=DnsError("timeout"))
    with pytest.raises(TransientJobError):
        WebCors().run(dns_fail_ctx, AssetRef(type=AssetType.URL, value="https://acme.com/"))

    scope_fail_ctx, _ = _ctx(response=ScopeError("blocked"))
    with pytest.raises(TransientJobError):
        WebCors().run(scope_fail_ctx, AssetRef(type=AssetType.URL, value="https://acme.com/"))


def test_web_headers_handles_comma_joined_csp_and_duplicate_xfo_headers() -> None:
    ctx, _ = _ctx(
        web_details={
            "final_url": "https://acme.com/",
            "status_code": 200,
            "content_type": "text/html",
            "headers": {
                "strict-transport-security": "max-age=31536000",
                "content-security-policy": (
                    "default-src 'self' 'unsafe-inline', script-src 'self'; frame-ancestors 'none'"
                ),
                "x-frame-options": "DENY, DENY",
                "x-content-type-options": "nosniff",
            },
            "cookies": [],
        }
    )

    out = WebHeaders().run(ctx, AssetRef(type=AssetType.URL, value="https://acme.com/"))
    assert out.findings == ()

    unsafe_both_ctx, _ = _ctx(
        web_details={
            "final_url": "https://acme.com/",
            "status_code": 200,
            "content_type": "text/html",
            "headers": {
                "strict-transport-security": "max-age=31536000",
                "content-security-policy": (
                    "default-src 'self' 'unsafe-inline', script-src 'unsafe-inline'"
                ),
                "x-frame-options": "DENY, SAMEORIGIN",
                "x-content-type-options": "nosniff",
            },
            "cookies": [],
        }
    )
    unsafe_out = WebHeaders().run(
        unsafe_both_ctx, AssetRef(type=AssetType.URL, value="https://acme.com/")
    )
    assert [f.rule_id for f in unsafe_out.findings] == ["web.headers.csp_unsafe"]


def test_web_cors_ignores_unallowed_final_url_port() -> None:
    ctx, http = _ctx(
        web_details={"final_url": "https://acme.com:9443/app"},
        response=HttpBody(status_code=200, content=b"{}", headers={}),
    )

    WebCors().run(ctx, AssetRef(type=AssetType.URL, value="https://acme.com/"))

    assert http.requests == [("https://acme.com/", 16 * 1024, {"Origin": FOREIGN_ORIGIN})]


def test_web_cors_ignores_wildcard_even_with_credentials_true() -> None:
    ctx, _ = _ctx(
        response=HttpBody(
            status_code=200,
            content=b"{}",
            headers={
                "Access-Control-Allow-Origin": "*",
                "Access-Control-Allow-Credentials": "true",
            },
        )
    )

    out = WebCors().run(ctx, AssetRef(type=AssetType.URL, value="https://acme.com/"))
    assert out.findings == ()


def test_web_headers_evaluates_script_src_elem_and_eval_separately() -> None:
    inline_elem_ctx, _ = _ctx(
        web_details={
            "final_url": "https://acme.com/",
            "status_code": 200,
            "content_type": "text/html",
            "headers": {
                "strict-transport-security": "max-age=31536000",
                "content-security-policy": (
                    "default-src 'self'; script-src 'self'; "
                    "script-src-elem 'unsafe-inline'; frame-ancestors 'none'"
                ),
                "x-content-type-options": "nosniff",
            },
            "cookies": [],
        }
    )
    inline_out = WebHeaders().run(
        inline_elem_ctx, AssetRef(type=AssetType.URL, value="https://acme.com/")
    )
    assert [f.rule_id for f in inline_out.findings] == ["web.headers.csp_unsafe"]
    assert inline_out.findings[0].evidence[0].data["unsafe_tokens"] == ["'unsafe-inline'"]

    eval_only_ctx, _ = _ctx(
        web_details={
            "final_url": "https://acme.com/",
            "status_code": 200,
            "content_type": "text/html",
            "headers": {
                "strict-transport-security": "max-age=31536000",
                "content-security-policy": (
                    "default-src 'self'; script-src 'unsafe-eval'; "
                    "script-src-elem 'self'; frame-ancestors 'none'"
                ),
                "x-content-type-options": "nosniff",
            },
            "cookies": [],
        }
    )
    eval_out = WebHeaders().run(
        eval_only_ctx, AssetRef(type=AssetType.URL, value="https://acme.com/")
    )
    assert [f.rule_id for f in eval_out.findings] == ["web.headers.csp_unsafe"]
    assert eval_out.findings[0].evidence[0].data["unsafe_tokens"] == ["'unsafe-eval'"]


def test_web_headers_skips_csp_and_clickjacking_when_csp_header_truncated() -> None:
    ctx, _ = _ctx(
        web_details={
            "final_url": "https://acme.com/",
            "status_code": 200,
            "content_type": "text/html",
            "headers": {
                "strict-transport-security": "max-age=31536000",
                "content-security-policy": "default-src 'self' https://cdn.example.com",
                "x-content-type-options": "nosniff",
            },
            "headers_truncated": ["content-security-policy"],
            "cookies": [],
        }
    )

    out = WebHeaders().run(ctx, AssetRef(type=AssetType.URL, value="https://acme.com/"))

    assert out.findings == ()
    summary = out.observations[0].details["security_headers"]
    assert isinstance(summary, dict)
    assert summary["csp"] is None
    assert summary["clickjacking_protected"] is None


def test_web_headers_honors_frame_ancestors_wildcard_over_x_frame_options() -> None:
    ctx, _ = _ctx(
        web_details={
            "final_url": "https://acme.com/",
            "status_code": 200,
            "content_type": "text/html",
            "headers": {
                "strict-transport-security": "max-age=31536000",
                "content-security-policy": "default-src 'self'; frame-ancestors *",
                "x-frame-options": "DENY",
                "x-content-type-options": "nosniff",
            },
            "cookies": [],
        }
    )

    out = WebHeaders().run(ctx, AssetRef(type=AssetType.URL, value="https://acme.com/"))

    assert [f.rule_id for f in out.findings] == ["web.headers.clickjacking"]


def test_web_headers_and_cors_handle_urls_exceeding_max_location_length() -> None:
    long_url = "https://acme.com/" + ("a" * 650)
    ctx, _ = _ctx(
        web_details={
            "final_url": long_url,
            "status_code": 200,
            "content_type": "text/html",
            "headers": {},
            "cookies": [],
        },
        response=HttpBody(
            status_code=200,
            content=b"ok",
            headers={
                "Access-Control-Allow-Origin": FOREIGN_ORIGIN,
                "Access-Control-Allow-Credentials": "true",
            },
            final_url=long_url,
        ),
    )

    url_asset = AssetRef(type=AssetType.URL, value=long_url)
    hdr_out = WebHeaders().run(ctx, url_asset)
    cors_out = WebCors().run(ctx, url_asset)

    assert hdr_out.findings
    assert all(f.location == "" for f in hdr_out.findings)
    assert all(f.remediation_context["url"] == long_url for f in hdr_out.findings)
    assert [f.location for f in cors_out.findings] == [""]
    assert cors_out.findings[0].remediation_context["url"] == long_url


def test_web_headers_evaluates_script_src_attr_separately() -> None:
    ctx, _ = _ctx(
        web_details={
            "final_url": "https://acme.com/",
            "status_code": 200,
            "content_type": "text/html",
            "headers": {
                "strict-transport-security": "max-age=31536000",
                "content-security-policy": (
                    "default-src 'self'; script-src 'self'; "
                    "script-src-attr 'unsafe-inline'; frame-ancestors 'none'"
                ),
                "x-content-type-options": "nosniff",
            },
            "cookies": [],
        }
    )

    out = WebHeaders().run(ctx, AssetRef(type=AssetType.URL, value="https://acme.com/"))

    assert [f.rule_id for f in out.findings] == ["web.headers.csp_unsafe"]
    assert out.findings[0].evidence[0].data["unsafe_tokens"] == ["'unsafe-inline'"]


def test_web_headers_intersects_multiple_frame_ancestors_policies() -> None:
    ctx, _ = _ctx(
        web_details={
            "final_url": "https://acme.com/",
            "status_code": 200,
            "content_type": "text/html",
            "headers": {
                "strict-transport-security": "max-age=31536000",
                "content-security-policy": (
                    "default-src 'self'; frame-ancestors *, frame-ancestors 'none'"
                ),
                "x-content-type-options": "nosniff",
            },
            "cookies": [],
        }
    )

    out = WebHeaders().run(ctx, AssetRef(type=AssetType.URL, value="https://acme.com/"))

    assert out.findings == ()


def test_web_headers_ignores_expired_and_deleted_session_cookies() -> None:
    details = _hardened_web_details()
    details["cookies"] = [
        "sessionid=<redacted>; Max-Age=0; Path=/",
        "auth_token=<redacted>; Expires=Thu, 01 Jan 1970 00:00:00 GMT; Path=/",
        "sid=<redacted>; Max-Age=3600; Expires=Thu, 01 Jan 1970 00:00:00 GMT; Path=/",
    ]
    ctx, _ = _ctx(web_details=details)

    out = WebHeaders().run(ctx, AssetRef(type=AssetType.URL, value="https://acme.com/"))

    assert [f.rule_id for f in out.findings] == ["web.cookies.insecure_flags"]
    assert out.findings[0].evidence[0].data["cookies"] == [
        {
            "name": "sid",
            "missing": ["Secure", "HttpOnly", "SameSite"],
            "cookie": "sid=<redacted>; Max-Age=3600; Expires=Thu, 01 Jan 1970 00:00:00 GMT; Path=/",
        }
    ]


def test_web_cors_ignores_redirect_responses_with_location() -> None:
    ctx, _ = _ctx(
        response=HttpBody(
            status_code=302,
            content=b"",
            headers={
                "Location": "/login",
                "Access-Control-Allow-Origin": FOREIGN_ORIGIN,
                "Access-Control-Allow-Credentials": "true",
            },
        )
    )

    out = WebCors().run(ctx, AssetRef(type=AssetType.URL, value="https://acme.com/"))
    assert out.findings == ()


def test_web_cors_ignores_non_lowercase_credentials_header() -> None:
    ctx, _ = _ctx(
        response=HttpBody(
            status_code=200,
            content=b"{}",
            headers={
                "Access-Control-Allow-Origin": FOREIGN_ORIGIN,
                "Access-Control-Allow-Credentials": "True",
            },
        )
    )

    out = WebCors().run(ctx, AssetRef(type=AssetType.URL, value="https://acme.com/"))
    assert out.findings == ()


def test_web_headers_ignores_malformed_cookie_max_age() -> None:
    details = _hardened_web_details()
    details["cookies"] = ["sessionid=<redacted>; Max-Age=--1; Path=/"]
    ctx, _ = _ctx(web_details=details)

    out = WebHeaders().run(ctx, AssetRef(type=AssetType.URL, value="https://acme.com/"))

    assert [f.rule_id for f in out.findings] == ["web.cookies.insecure_flags"]


def test_web_headers_accepts_long_hardened_cookie_and_skips_truncated_cookies() -> None:
    long_name = "sessionid_" + ("a" * 50)
    long_cookie = (
        f"{long_name}=secret; Domain={'s' * 64}; Path=/{'p' * 63}; Partitioned; "
        f"Expires=Wed, 21 Oct 2030 07:28:00 GMT; Secure; HttpOnly; SameSite=Strict"
    )
    assert len(long_cookie) > 256
    details = _hardened_web_details()
    details["cookies"] = [
        redact_set_cookie(long_cookie),
        "auth_session=<redacted>; Expires=...",
    ]
    details["cookies_truncated"] = ["auth_session"]
    ctx, _ = _ctx(web_details=details)

    out = WebHeaders().run(ctx, AssetRef(type=AssetType.URL, value="https://acme.com/"))
    assert out.findings == ()


@pytest.mark.parametrize(
    "header_value",
    [
        "max-age=31536000s; includeSubDomains",
        'max-age="31536000; includeSubDomains',
        "max-age=31536000; max-age=31536000",
    ],
)
def test_web_headers_flags_malformed_hsts_max_age_values(header_value: str) -> None:
    details = _hardened_web_details()
    raw_headers = details["headers"]
    assert isinstance(raw_headers, dict)
    headers: dict[str, str] = dict(raw_headers)
    headers["strict-transport-security"] = header_value
    details["headers"] = headers
    ctx, _ = _ctx(web_details=details)

    out = WebHeaders().run(ctx, AssetRef(type=AssetType.URL, value="https://acme.com/"))

    assert [f.rule_id for f in out.findings] == ["web.headers.hsts_weak"]
    assert out.findings[0].evidence[0].data["max_age"] is None


def test_web_headers_rejects_malformed_nonce_and_honors_strict_dynamic() -> None:
    malformed_ctx, _ = _ctx(
        web_details={
            "final_url": "https://acme.com/",
            "status_code": 200,
            "content_type": "text/html",
            "headers": {
                "strict-transport-security": "max-age=31536000",
                "content-security-policy": (
                    "default-src 'self'; script-src 'self' 'unsafe-inline' 'nonce-***'; "
                    "frame-ancestors 'none'"
                ),
                "x-content-type-options": "nosniff",
            },
            "cookies": [],
        }
    )
    malformed_out = WebHeaders().run(
        malformed_ctx, AssetRef(type=AssetType.URL, value="https://acme.com/")
    )
    assert [f.rule_id for f in malformed_out.findings] == ["web.headers.csp_unsafe"]
    assert malformed_out.findings[0].evidence[0].data["unsafe_tokens"] == ["'unsafe-inline'"]

    strict_ctx, _ = _ctx(
        web_details={
            "final_url": "https://acme.com/",
            "status_code": 200,
            "content_type": "text/html",
            "headers": {
                "strict-transport-security": "max-age=31536000",
                "content-security-policy": (
                    "default-src 'self'; script-src 'unsafe-inline' 'strict-dynamic'; "
                    "frame-ancestors 'none'"
                ),
                "x-content-type-options": "nosniff",
            },
            "cookies": [],
        }
    )
    strict_out = WebHeaders().run(
        strict_ctx, AssetRef(type=AssetType.URL, value="https://acme.com/")
    )
    assert strict_out.findings == ()


def test_web_headers_honors_truncation_for_non_csp_headers() -> None:
    ctx, _ = _ctx(
        web_details={
            "final_url": "https://acme.com/",
            "status_code": 200,
            "content_type": "text/html",
            "headers": {
                "content-security-policy": "default-src 'self'",
            },
            "headers_truncated": [
                "strict-transport-security",
                "x-content-type-options",
                "x-frame-options",
            ],
            "cookies": [],
        }
    )

    out = WebHeaders().run(ctx, AssetRef(type=AssetType.URL, value="https://acme.com/"))

    assert out.findings == ()
    summary = out.observations[0].details["security_headers"]
    assert isinstance(summary, dict)
    assert summary["hsts"] is None
    assert summary["nosniff"] is None
    assert summary["clickjacking_protected"] is None


def test_web_headers_treats_empty_frame_ancestors_as_blocking() -> None:
    ctx, _ = _ctx(
        web_details={
            "final_url": "https://acme.com/",
            "status_code": 200,
            "content_type": "text/html",
            "headers": {
                "strict-transport-security": "max-age=31536000",
                "content-security-policy": "default-src 'self'; frame-ancestors",
                "x-content-type-options": "nosniff",
            },
            "cookies": [],
        }
    )

    out = WebHeaders().run(ctx, AssetRef(type=AssetType.URL, value="https://acme.com/"))

    assert out.findings == ()
    summary = out.observations[0].details["security_headers"]
    assert isinstance(summary, dict)
    assert summary["clickjacking_protected"] is True


@pytest.mark.parametrize(
    ("frame_ancestors", "expected_rules"),
    [
        ("https://*", ["web.headers.clickjacking"]),
        ("https://*:*", ["web.headers.clickjacking"]),
        ("https://*.acme.com", []),
    ],
)
def test_web_headers_evaluates_wildcard_hosts_in_frame_ancestors(
    frame_ancestors: str, expected_rules: list[str]
) -> None:
    ctx, _ = _ctx(
        web_details={
            "final_url": "https://acme.com/",
            "status_code": 200,
            "content_type": "text/html",
            "headers": {
                "strict-transport-security": "max-age=31536000",
                "content-security-policy": f"default-src 'self'; frame-ancestors {frame_ancestors}",
                "x-content-type-options": "nosniff",
            },
            "cookies": [],
        }
    )

    out = WebHeaders().run(ctx, AssetRef(type=AssetType.URL, value="https://acme.com/"))

    assert [f.rule_id for f in out.findings] == expected_rules


def test_web_headers_accepts_combined_duplicate_nosniff_headers() -> None:
    ctx, _ = _ctx(
        web_details={
            "final_url": "https://acme.com/",
            "status_code": 200,
            "content_type": "text/html",
            "headers": {
                "strict-transport-security": "max-age=31536000",
                "content-security-policy": "default-src 'self'; frame-ancestors 'none'",
                "x-content-type-options": "nosniff, nosniff",
            },
            "cookies": [],
        }
    )

    out = WebHeaders().run(ctx, AssetRef(type=AssetType.URL, value="https://acme.com/"))

    assert out.findings == ()
    summary = out.observations[0].details["security_headers"]
    assert isinstance(summary, dict)
    assert summary["nosniff"] is True


def test_web_headers_honors_first_hsts_field_from_sanitized_duplicate_headers() -> None:
    sanitized, _ = sanitize_headers(
        httpx.Headers(
            [
                ("content-type", "text/html"),
                ("strict-transport-security", "max-age=31536000"),
                ("strict-transport-security", "max-age=31536000"),
                ("content-security-policy", "default-src 'self'; frame-ancestors 'none'"),
                ("x-content-type-options", "nosniff"),
            ]
        )
    )
    ctx, _ = _ctx(
        web_details={
            "final_url": "https://acme.com/",
            "status_code": 200,
            "content_type": "text/html",
            "headers": sanitized,
            "cookies": [],
        }
    )

    out = WebHeaders().run(ctx, AssetRef(type=AssetType.URL, value="https://acme.com/"))

    assert out.findings == ()
    summary = out.observations[0].details["security_headers"]
    assert isinstance(summary, dict)
    assert summary["hsts"] is True

    comma_ctx, _ = _ctx(
        web_details={
            "final_url": "https://acme.com/",
            "status_code": 200,
            "content_type": "text/html",
            "headers": {
                "strict-transport-security": "max-age=31536000, includeSubDomains",
                "content-security-policy": "default-src 'self'; frame-ancestors 'none'",
                "x-content-type-options": "nosniff",
            },
            "cookies": [],
        }
    )
    comma_out = WebHeaders().run(comma_ctx, AssetRef(type=AssetType.URL, value="https://acme.com/"))
    assert [f.rule_id for f in comma_out.findings] == ["web.headers.hsts_weak"]


def test_web_rules_catalog_includes_all_issue_77_rules_with_expected_severities() -> None:
    catalog = build_catalog(WEB_RULES)
    expected = {
        "web.headers.hsts_missing": Severity.LOW,
        "web.headers.hsts_weak": Severity.LOW,
        "web.headers.csp_missing": Severity.LOW,
        "web.headers.csp_unsafe": Severity.LOW,
        "web.headers.clickjacking": Severity.LOW,
        "web.headers.nosniff_missing": Severity.INFO,
        "web.cookies.insecure_flags": Severity.LOW,
        "web.https.no_redirect": Severity.LOW,
        "web.cors.wildcard_credentials": Severity.MEDIUM,
    }
    for rule_id, severity in expected.items():
        assert catalog[rule_id].default_severity is severity
