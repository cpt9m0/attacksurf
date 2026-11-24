"""Security header, cookie flag, HTTPS redirect, and CORS checks (`web.headers`, `web.cors`)."""

import re
from collections.abc import Mapping, Sequence
from urllib.parse import urlsplit

from pydantic import JsonValue

from attacksurf.domain.assets import AssetType
from attacksurf.domain.findings import Confidence, EvidenceKind
from attacksurf.domain.jobs import TransientJobError
from attacksurf.domain.net import DnsError, HttpBody
from attacksurf.domain.scanners import (
    ALLOWED_WEB_PORTS,
    AssetObservation,
    AssetRef,
    RawEvidence,
    RawFinding,
    ScanContext,
    ScannerError,
    ScannerGrant,
    ScanOutput,
)
from attacksurf.domain.scope import HttpPermission, ScopeError
from attacksurf.scanners.registry import register_scanner

MIN_HSTS_MAX_AGE_SECONDS = 15_552_000  # 180 days (~6 months)
HTTP_DEFAULT_PORT = 80
HTTP_OK_MIN = 200
HTTP_OK_MAX = 299
HTML_CONTENT_TYPES = frozenset({"text/html", "application/xhtml+xml"})
VALID_XFO_VALUES = frozenset({"DENY", "SAMEORIGIN"})
FOREIGN_ORIGIN = "https://cors-probe.invalid"
CORS_MAX_BODY_BYTES = 16 * 1024
CORS_DNS_LOOKUPS = 4
MAX_EVIDENCE_COOKIES = 10
MAX_VALUE_CHARS = 512
MAX_CSP_VALUE_CHARS = 4096
_WILDCARD_FRAME_ANCESTORS = frozenset({"*", "http:", "https:"})

_HSTS_MAX_AGE_RE = re.compile(r'(?:^|;)\s*max-age\s*=\s*"?(\d+)"?', re.IGNORECASE)
_NONCE_OR_HASH_RE = re.compile(
    r"^'(?:nonce-[^']+|sha(?:256|384|512)-[^']+)'$",
    re.IGNORECASE,
)
_SESSION_COOKIE_NAME_RE = re.compile(
    r"(?:sess|phpsessid|jsessionid|aspsessionid|connect\.sid|"
    r"(?:^|[_.-])sid(?:$|[_.-])|auth|jwt|(?:^|[_.-])id_?token|"
    r"(?:access|refresh|session)[_.-]?token|remember[_.-]?me|sso)",
    re.IGNORECASE,
)


def _lowercase_headers(raw_headers: object) -> dict[str, str]:
    if not isinstance(raw_headers, Mapping):
        return {}
    result: dict[str, str] = {}
    for key, val in raw_headers.items():
        if isinstance(key, str) and isinstance(val, str):
            norm_key = key.lower()
            cap = MAX_CSP_VALUE_CHARS if norm_key == "content-security-policy" else MAX_VALUE_CHARS
            result[norm_key] = val.strip()[:cap]
    return result


def _subset_headers(headers: Mapping[str, str], *names: str) -> dict[str, JsonValue]:
    return {name: headers[name] for name in names if name in headers}


def _header_evidence(
    *,
    final_url: str,
    status_code: int | None,
    headers: Mapping[str, JsonValue],
    extra: Mapping[str, JsonValue] | None = None,
) -> tuple[RawEvidence, ...]:
    payload: dict[str, JsonValue] = {
        "final_url": final_url,
        "status_code": status_code,
        "headers": dict(headers),
    }
    if extra:
        payload.update(extra)
    return (RawEvidence(kind=EvidenceKind.HTTP_RESPONSE, data=payload),)


def _parse_csp_policies(raw_csp: str) -> list[dict[str, tuple[str, ...]]]:
    policies: list[dict[str, tuple[str, ...]]] = []
    for raw_policy in raw_csp.split(","):
        directives: dict[str, tuple[str, ...]] = {}
        for raw_directive in raw_policy.split(";"):
            tokens = raw_directive.strip().split()
            if not tokens:
                continue
            name = tokens[0].lower()
            # CSP3 §2.2.1: duplicate directives are ignored after the first occurrence.
            if name not in directives:
                directives[name] = tuple(tokens[1:])
        if directives:
            policies.append(directives)
    return policies


def _inline_script_tokens(directives: Mapping[str, tuple[str, ...]]) -> tuple[str, ...] | None:
    for directive in ("script-src-elem", "script-src", "default-src"):
        if directive in directives:
            return directives[directive]
    return None


def _eval_script_tokens(directives: Mapping[str, tuple[str, ...]]) -> tuple[str, ...] | None:
    for directive in ("script-src", "default-src"):
        if directive in directives:
            return directives[directive]
    return None


def _csp_unsafe_tokens(policies: Sequence[Mapping[str, tuple[str, ...]]]) -> tuple[str, ...]:
    # CSP3 intersects multiple policies independently per execution capability.
    unsafe: list[str] = []
    inline_policies = [
        vals for policy in policies if (vals := _inline_script_tokens(policy)) is not None
    ]
    if inline_policies and all(
        "'unsafe-inline'" in {token.lower() for token in vals}
        and not any(_NONCE_OR_HASH_RE.match(token) for token in vals)
        for vals in inline_policies
    ):
        unsafe.append("'unsafe-inline'")
    eval_policies = [
        vals for policy in policies if (vals := _eval_script_tokens(policy)) is not None
    ]
    if eval_policies and all(
        "'unsafe-eval'" in {token.lower() for token in vals} for vals in eval_policies
    ):
        unsafe.append("'unsafe-eval'")
    return tuple(unsafe)


def _has_valid_xfo(raw_xfo: str) -> bool:
    tokens = [part.strip().upper() for part in raw_xfo.split(",") if part.strip()]
    return bool(tokens) and all(token in VALID_XFO_VALUES for token in tokens)


def _has_clickjacking_protection(
    headers: Mapping[str, str],
    policies: Sequence[Mapping[str, tuple[str, ...]]],
) -> bool:
    fa_directives = [
        [token.lower() for token in fa]
        for directives in policies
        if (fa := directives.get("frame-ancestors")) is not None
    ]
    if fa_directives:
        # CSP3 §7.7.1: browsers ignore X-Frame-Options whenever frame-ancestors is present.
        return all(
            bool(tokens) and not any(token in _WILDCARD_FRAME_ANCESTORS for token in tokens)
            for tokens in fa_directives
        )
    return _has_valid_xfo(headers.get("x-frame-options", ""))


def _redact_cookie_preview(entry: str) -> str:
    parts = [part.strip() for part in entry.split(";") if part.strip()]
    if not parts:
        return ""
    name_part, sep, _val = parts[0].partition("=")
    head = f"{name_part.strip()}=<redacted>" if sep else "<redacted>"
    return "; ".join([head, *parts[1:]])[:MAX_VALUE_CHARS]


def _inspect_cookie(entry: str) -> dict[str, JsonValue] | None:
    parts = [part.strip() for part in entry.split(";") if part.strip()]
    if not parts:
        return None
    name = parts[0].partition("=")[0].strip()
    if not name or not _SESSION_COOKIE_NAME_RE.search(name):
        return None
    flags: set[str] = set()
    samesite_val = ""
    for attr in parts[1:]:
        attr_key, _eq, attr_val = attr.partition("=")
        key_lower = attr_key.strip().lower()
        flags.add(key_lower)
        if key_lower == "samesite":
            samesite_val = attr_val.strip().lower()
    missing: list[str] = []
    if "secure" not in flags:
        missing.append("Secure")
    if "httponly" not in flags:
        missing.append("HttpOnly")
    if samesite_val not in {"lax", "strict", "none"}:
        missing.append("SameSite")
    if not missing:
        return None
    return {
        "name": name,
        "missing": list(missing),
        "cookie": _redact_cookie_preview(entry),
    }


def _check_hsts(
    findings: list[RawFinding],
    *,
    final_url: str,
    final_scheme: str,
    status_code: int | None,
    headers: Mapping[str, str],
) -> bool:
    if final_scheme != "https":
        return False
    hsts = headers.get("strict-transport-security", "").strip()
    relevant = _subset_headers(headers, "strict-transport-security")
    if not hsts:
        findings.append(
            RawFinding(
                rule_id="web.headers.hsts_missing",
                location="",
                confidence=Confidence.HIGH,
                remediation_context={"url": final_url},
                evidence=_header_evidence(
                    final_url=final_url,
                    status_code=status_code,
                    headers=relevant,
                ),
            )
        )
        return False

    match = _HSTS_MAX_AGE_RE.search(hsts)
    max_age = int(match.group(1)) if match else None
    if max_age is None or max_age < MIN_HSTS_MAX_AGE_SECONDS:
        findings.append(
            RawFinding(
                rule_id="web.headers.hsts_weak",
                location="",
                confidence=Confidence.HIGH,
                remediation_context={"url": final_url},
                evidence=_header_evidence(
                    final_url=final_url,
                    status_code=status_code,
                    headers=relevant,
                    extra={
                        "max_age": max_age,
                        "minimum_recommended": MIN_HSTS_MAX_AGE_SECONDS,
                    },
                ),
            )
        )
        return False
    return True


def _check_csp_and_framing(
    findings: list[RawFinding],
    *,
    final_url: str,
    is_html: bool,
    status_code: int | None,
    headers: Mapping[str, str],
    csp_truncated: bool,
) -> tuple[bool | None, bool | None]:
    if csp_truncated:
        return None, None
    raw_csp = headers.get("content-security-policy", "").strip()
    policies = _parse_csp_policies(raw_csp) if raw_csp else []
    frame_ok = _has_clickjacking_protection(headers, policies)
    if not is_html:
        return bool(raw_csp), frame_ok

    csp_headers = _subset_headers(headers, "content-security-policy")
    csp_ok = False
    if not raw_csp:
        findings.append(
            RawFinding(
                rule_id="web.headers.csp_missing",
                location="",
                confidence=Confidence.HIGH,
                remediation_context={"url": final_url},
                evidence=_header_evidence(
                    final_url=final_url,
                    status_code=status_code,
                    headers=csp_headers,
                ),
            )
        )
    else:
        unsafe = _csp_unsafe_tokens(policies)
        if unsafe:
            findings.append(
                RawFinding(
                    rule_id="web.headers.csp_unsafe",
                    location="",
                    confidence=Confidence.HIGH,
                    remediation_context={
                        "url": final_url,
                        "tokens": ", ".join(unsafe),
                    },
                    evidence=_header_evidence(
                        final_url=final_url,
                        status_code=status_code,
                        headers=csp_headers,
                        extra={"unsafe_tokens": list(unsafe)},
                    ),
                )
            )
        else:
            csp_ok = True

    if not frame_ok:
        framing_headers = _subset_headers(
            headers,
            "x-frame-options",
            "content-security-policy",
        )
        findings.append(
            RawFinding(
                rule_id="web.headers.clickjacking",
                location="",
                confidence=Confidence.HIGH,
                remediation_context={"url": final_url},
                evidence=_header_evidence(
                    final_url=final_url,
                    status_code=status_code,
                    headers=framing_headers,
                ),
            )
        )
    return csp_ok, frame_ok


def _check_nosniff(
    findings: list[RawFinding],
    *,
    final_url: str,
    status_code: int | None,
    headers: Mapping[str, str],
) -> bool:
    nosniff = headers.get("x-content-type-options", "").strip().lower() == "nosniff"
    if not nosniff:
        findings.append(
            RawFinding(
                rule_id="web.headers.nosniff_missing",
                location="",
                confidence=Confidence.HIGH,
                remediation_context={"url": final_url},
                evidence=_header_evidence(
                    final_url=final_url,
                    status_code=status_code,
                    headers=_subset_headers(headers, "x-content-type-options"),
                ),
            )
        )
    return nosniff


def _check_cookies(
    findings: list[RawFinding],
    *,
    final_url: str,
    status_code: int | None,
    raw_cookies: object,
) -> None:
    if not isinstance(raw_cookies, list):
        return
    insecure = [
        item
        for entry in raw_cookies
        if isinstance(entry, str) and (item := _inspect_cookie(entry)) is not None
    ][:MAX_EVIDENCE_COOKIES]
    if not insecure:
        return
    names = ", ".join(str(item["name"]) for item in insecure)
    findings.append(
        RawFinding(
            rule_id="web.cookies.insecure_flags",
            location="",
            confidence=Confidence.HIGH,
            remediation_context={"url": final_url, "cookies": names},
            evidence=(
                RawEvidence(
                    kind=EvidenceKind.HTTP_RESPONSE,
                    data={
                        "final_url": final_url,
                        "status_code": status_code,
                        "cookies": list(insecure),
                    },
                ),
            ),
        )
    )


def _check_http_redirect(
    findings: list[RawFinding],
    *,
    target_url: str,
    final_url: str,
    status_code: int | None,
    redirect_stopped_out_of_scope: bool,
    headers: Mapping[str, str],
) -> bool | None:
    parsed_target = urlsplit(target_url)
    if parsed_target.scheme.lower() != "http":
        return None
    if parsed_target.port not in (None, HTTP_DEFAULT_PORT):
        return None
    if redirect_stopped_out_of_scope or status_code is None:
        return None
    final_scheme = urlsplit(final_url).scheme.lower()
    if final_scheme == "https":
        return True
    if final_scheme == "http" and HTTP_OK_MIN <= status_code <= HTTP_OK_MAX:
        findings.append(
            RawFinding(
                rule_id="web.https.no_redirect",
                location="",
                confidence=Confidence.HIGH,
                remediation_context={"url": target_url},
                evidence=_header_evidence(
                    final_url=final_url,
                    status_code=status_code,
                    headers=_subset_headers(headers, "location"),
                    extra={"target_url": target_url},
                ),
            )
        )
        return False
    return None


@register_scanner
class WebHeaders:
    """Analyze response headers, cookies, and HTTP->HTTPS redirects stored by `web.probe`."""

    name = "web.headers"
    asset_types = frozenset({AssetType.URL})
    queue = "passive"
    requires_verification = False
    timeout_seconds = 10.0
    grant = ScannerGrant()

    def run(self, ctx: ScanContext, asset: AssetRef) -> ScanOutput:
        web = ctx.target_details.get("web")
        if not isinstance(web, Mapping):
            return ScanOutput()

        final_url = str(web.get("final_url") or asset.value)
        final_scheme = urlsplit(final_url).scheme.lower() or urlsplit(asset.value).scheme.lower()
        raw_status = web.get("status_code")
        status_code = raw_status if isinstance(raw_status, int) else None
        stopped_out_of_scope = bool(web.get("redirect_stopped_out_of_scope"))
        content_type = str(web.get("content_type") or "")
        media_type = content_type.split(";", 1)[0].strip().lower()
        is_html = media_type in HTML_CONTENT_TYPES
        headers = _lowercase_headers(web.get("headers"))
        raw_truncated = web.get("headers_truncated")
        truncated_headers = (
            {item.lower() for item in raw_truncated if isinstance(item, str)}
            if isinstance(raw_truncated, list)
            else set()
        )
        csp_truncated = "content-security-policy" in truncated_headers

        findings: list[RawFinding] = []
        hsts_ok = _check_hsts(
            findings,
            final_url=final_url,
            final_scheme=final_scheme,
            status_code=status_code,
            headers=headers,
        )
        if stopped_out_of_scope:
            csp_ok: bool | None = None if csp_truncated else False
            frame_ok: bool | None = (
                None if csp_truncated else _has_clickjacking_protection(headers, ())
            )
            nosniff_ok = headers.get("x-content-type-options", "").strip().lower() == "nosniff"
        else:
            csp_ok, frame_ok = _check_csp_and_framing(
                findings,
                final_url=final_url,
                is_html=is_html,
                status_code=status_code,
                headers=headers,
                csp_truncated=csp_truncated,
            )
            nosniff_ok = _check_nosniff(
                findings,
                final_url=final_url,
                status_code=status_code,
                headers=headers,
            )

        _check_cookies(
            findings,
            final_url=final_url,
            status_code=status_code,
            raw_cookies=web.get("cookies"),
        )
        redirects_to_https = _check_http_redirect(
            findings,
            target_url=asset.value,
            final_url=final_url,
            status_code=status_code,
            redirect_stopped_out_of_scope=stopped_out_of_scope,
            headers=headers,
        )

        summary: dict[str, JsonValue] = {
            "final_url": final_url,
            "hsts": hsts_ok,
            "csp": csp_ok,
            "clickjacking_protected": frame_ok,
            "nosniff": nosniff_ok,
            "redirects_to_https": redirects_to_https,
        }
        return ScanOutput(
            findings=tuple(findings),
            observations=(
                AssetObservation(
                    asset=AssetRef(type=asset.type, value=asset.value),
                    details={"security_headers": summary},
                    active=None,
                ),
            ),
        )


def _cors_target_url(ctx: ScanContext, asset: AssetRef) -> str:
    web = ctx.target_details.get("web")
    if isinstance(web, Mapping):
        raw_final = web.get("final_url")
        if isinstance(raw_final, str) and raw_final:
            parsed_final = urlsplit(raw_final)
            parsed_asset = urlsplit(asset.value)
            if (
                parsed_final.scheme.lower() in {"http", "https"}
                and parsed_final.hostname == parsed_asset.hostname
                and (parsed_final.port is None or parsed_final.port in ALLOWED_WEB_PORTS)
            ):
                return raw_final
    return asset.value


def _is_cors_vulnerable(body: HttpBody) -> tuple[bool, dict[str, JsonValue]]:
    headers = _lowercase_headers(body.headers)
    acao = headers.get("access-control-allow-origin", "").strip()
    acac = headers.get("access-control-allow-credentials", "").strip().lower()
    # Fetch CORS rejects wildcard `*` with credentials mode `include`, so only reflected
    # foreign origins with credentials expose authenticated responses cross-origin.
    vulnerable = acac == "true" and acao == FOREIGN_ORIGIN
    relevant = _subset_headers(
        headers,
        "access-control-allow-origin",
        "access-control-allow-credentials",
        "vary",
    )
    return vulnerable, relevant


@register_scanner
class WebCors:
    """Issue one GET with a foreign Origin header to detect permissive CORS + credentials."""

    name = "web.cors"
    asset_types = frozenset({AssetType.URL})
    queue = "active"
    requires_verification = True
    timeout_seconds = 15.0
    grant = ScannerGrant(
        http=HttpPermission.TARGET,
        http_ports=ALLOWED_WEB_PORTS,
        follow_redirects=False,
        dns_lookups=CORS_DNS_LOOKUPS,
    )

    def run(self, ctx: ScanContext, asset: AssetRef) -> ScanOutput:
        runtime = ctx.runtime
        if runtime is None:
            raise ScannerError("Scanner runtime is not configured.")
        target_url = _cors_target_url(ctx, asset)
        try:
            body = runtime.http.get(
                target_url,
                limit=CORS_MAX_BODY_BYTES,
                headers={"Origin": FOREIGN_ORIGIN},
            )
        except (DnsError, ScopeError):
            raise TransientJobError("CORS check failed.") from None

        vulnerable, relevant_headers = _is_cors_vulnerable(body)
        if not vulnerable:
            return ScanOutput()

        final_url = body.final_url or target_url
        return ScanOutput(
            findings=(
                RawFinding(
                    rule_id="web.cors.wildcard_credentials",
                    location="",
                    confidence=Confidence.HIGH,
                    remediation_context={"url": target_url},
                    evidence=_header_evidence(
                        final_url=final_url,
                        status_code=body.status_code,
                        headers=relevant_headers,
                        extra={"origin_sent": FOREIGN_ORIGIN},
                    ),
                ),
            )
        )
