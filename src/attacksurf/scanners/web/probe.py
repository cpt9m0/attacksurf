"""Active HTTP service discovery and metadata probing (`web.probe`, #72).

For each active verified host (`domain` or `subdomain`), tries `https://<host>/` and then
`http://<host>/`, follows only verified in-scope redirects, records normalized `url` assets plus
`serves` edges and capped `Asset.details["web"]`, and marks non-responding discovered `url` assets
inactive on rescan.
"""

import hashlib
import json
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from html.parser import HTMLParser
from typing import cast

from pydantic import JsonValue

from attacksurf.domain.assets import AssetError, AssetType, RelationKind, normalize_asset_value
from attacksurf.domain.findings import EvidenceKind
from attacksurf.domain.net import DnsError, HttpBody
from attacksurf.domain.scanners import (
    MAX_ASSET_DETAILS_BYTES,
    AssetObservation,
    AssetRef,
    DiscoveredRelation,
    RawEvidence,
    ScanContext,
    ScannerError,
    ScannerGrant,
    ScanOutput,
)
from attacksurf.domain.scope import HttpPermission, ScopeError
from attacksurf.scanners.registry import register_scanner

MAX_BODY_BYTES = 256 * 1024
MAX_BODY_EXCERPT_CHARS = 1024
MAX_TITLE_CHARS = 200
MAX_TITLE_PARSE_BYTES = 64 * 1024
MAX_HEADERS = 30
MAX_HEADER_VALUE_CHARS = 256
MAX_COOKIES = 20
DNS_LOOKUPS = 16
REDIRECT_CODES = frozenset({301, 302, 303, 307, 308})
_HTML_CONTENT_TYPES = frozenset({"text/html", "application/xhtml+xml"})
_SAFE_COOKIE_ATTRS = frozenset(
    {"path", "domain", "expires", "max-age", "secure", "httponly", "samesite", "partitioned"}
)


@dataclass(frozen=True)
class ProbeResult:
    """Normalized HTTP response captured by `web.probe`."""

    initial_url: str
    final_url: str
    redirect_chain: tuple[tuple[str, int], ...]
    redirect_stopped_out_of_scope: bool
    status_code: int
    title: str
    content_type: str
    body_sha256: str
    body_bytes: int
    body_truncated: bool
    headers: dict[str, str]
    cookies: tuple[str, ...]
    body_excerpt: str


class _TitleParser(HTMLParser):
    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self._in_title = False
        self._done = False
        self.chunks: list[str] = []

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        del attrs
        if not self._done and tag.lower() == "title":
            self._in_title = True

    def handle_endtag(self, tag: str) -> None:
        if tag.lower() == "title" and self._in_title:
            self._in_title = False
            self._done = True

    def handle_data(self, data: str) -> None:
        if self._in_title:
            self.chunks.append(data)


def extract_html_title(content: bytes, content_type: str) -> str:
    """Extract and trim `<title>` text for HTML responses; empty for non-HTML or missing."""
    media_type = content_type.split(";", 1)[0].strip().lower()
    if media_type and media_type not in _HTML_CONTENT_TYPES:
        return ""
    text = content[:MAX_TITLE_PARSE_BYTES].decode("utf-8", errors="replace").replace("\x00", "")
    if not media_type and "<title" not in text.lower():
        return ""
    parser = _TitleParser()
    parser.feed(text)
    parser.close()
    collapsed = " ".join("".join(parser.chunks).split())
    return collapsed[:MAX_TITLE_CHARS]


def redact_set_cookie(raw_cookie: str) -> str:
    """Keep cookie name and security attributes while replacing its value with `<redacted>`."""
    parts = [part.strip() for part in raw_cookie.split(";") if part.strip()]
    if not parts:
        return ""
    name_part, sep, _value = parts[0].partition("=")
    name = name_part.strip().replace("\x00", "")[:64]
    if not sep or not name:
        return "<redacted>"
    tokens = [f"{name}=<redacted>"]
    for attr in parts[1:]:
        attr_key, eq, attr_val = attr.partition("=")
        clean_key = attr_key.strip()
        if clean_key.lower() not in _SAFE_COOKIE_ATTRS:
            continue
        if eq:
            tokens.append(f"{clean_key}={attr_val.strip()[:64]}")
        else:
            tokens.append(clean_key)
    return "; ".join(tokens)[:MAX_HEADER_VALUE_CHARS]


def sanitize_headers(headers: Mapping[str, str]) -> tuple[dict[str, str], tuple[str, ...]]:
    """Return lowercase capped response headers (without Set-Cookie) and redacted Set-Cookies."""
    get_list = getattr(headers, "get_list", None)
    raw_cookies: list[str] = []
    if callable(get_list):
        list_fn = cast(Callable[[str], list[str]], get_list)
        raw_cookies = list(list_fn("set-cookie"))
    else:
        raw_cookies = [v for k, v in headers.items() if k.lower() == "set-cookie"]

    cookies = tuple(
        redacted for raw in raw_cookies[:MAX_COOKIES] if (redacted := redact_set_cookie(raw))
    )

    cleaned: dict[str, str] = {}
    for key, val in headers.items():
        norm_key = key.strip().lower()[:128]
        if not norm_key or norm_key == "set-cookie" or norm_key in cleaned:
            continue
        cleaned[norm_key] = val.strip().replace("\x00", "")[:MAX_HEADER_VALUE_CHARS]
        if len(cleaned) >= MAX_HEADERS:
            break
    return cleaned, cookies


def build_http_response_evidence(probe: ProbeResult) -> RawEvidence:
    """Construct `HTTP_RESPONSE` finding evidence with headers and capped body excerpt."""
    chain_data: list[JsonValue] = [
        {"url": hop_url, "status": hop_status} for hop_url, hop_status in probe.redirect_chain
    ]
    return RawEvidence(
        kind=EvidenceKind.HTTP_RESPONSE,
        data={
            "url": probe.final_url,
            "status_code": probe.status_code,
            "headers": dict(probe.headers),
            "cookies": list(probe.cookies),
            "redirect_chain": chain_data,
            "body_snippet": probe.body_excerpt,
            "body_truncated": probe.body_truncated,
        },
    )


def _normalize_url_safe(raw: str, fallback: str) -> str:
    try:
        return normalize_asset_value(AssetType.URL, raw)
    except AssetError:
        return fallback


def _to_probe_result(initial_url: str, body: HttpBody) -> ProbeResult:
    final_url = _normalize_url_safe(body.final_url or initial_url, initial_url)
    chain = tuple(
        (_normalize_url_safe(hop_url, hop_url), hop_status)
        for hop_url, hop_status in body.redirect_chain
    )
    headers, cookies = sanitize_headers(body.headers)
    content_type = headers.get("content-type", "")
    location = headers.get("location", "")
    stopped_oos = body.status_code in REDIRECT_CODES and bool(location)
    excerpt = (
        body.content[: MAX_BODY_EXCERPT_CHARS * 4]
        .decode("utf-8", errors="replace")
        .replace("\x00", "\\0")[:MAX_BODY_EXCERPT_CHARS]
    )
    return ProbeResult(
        initial_url=initial_url,
        final_url=final_url,
        redirect_chain=chain,
        redirect_stopped_out_of_scope=stopped_oos,
        status_code=body.status_code,
        title=extract_html_title(body.content, content_type),
        content_type=content_type,
        body_sha256=hashlib.sha256(body.content).hexdigest(),
        body_bytes=len(body.content),
        body_truncated=body.truncated,
        headers=headers,
        cookies=cookies,
        body_excerpt=excerpt,
    )


def _probe_url(ctx: ScanContext, url: str) -> ProbeResult | None:
    runtime = ctx.runtime
    if runtime is None:
        raise ScannerError("Scanner runtime is not configured.")
    try:
        body = runtime.http.get(url, limit=MAX_BODY_BYTES)
    except (DnsError, ScopeError):
        return None
    return _to_probe_result(url, body)


_PRIORITY_HEADERS = frozenset(
    {
        "server",
        "x-powered-by",
        "content-type",
        "location",
        "strict-transport-security",
        "content-security-policy",
        "x-frame-options",
        "x-content-type-options",
        "referrer-policy",
    }
)


def _details_bytes(details: dict[str, JsonValue]) -> int:
    return len(json.dumps(details, ensure_ascii=False, allow_nan=False).encode())


def _web_details(probe: ProbeResult) -> dict[str, JsonValue]:
    chain_data: list[JsonValue] = [
        {"url": hop_url, "status": hop_status} for hop_url, hop_status in probe.redirect_chain
    ]
    return {
        "final_url": probe.final_url,
        "redirect_chain": chain_data,
        "redirect_stopped_out_of_scope": probe.redirect_stopped_out_of_scope,
        "status_code": probe.status_code,
        "title": probe.title,
        "content_type": probe.content_type,
        "body_sha256": probe.body_sha256,
        "body_bytes": probe.body_bytes,
        "body_truncated": probe.body_truncated,
        "headers": dict(probe.headers),
        "cookies": list(probe.cookies),
    }


def _fit_observation_details(
    web: dict[str, JsonValue],
    web_host: dict[str, JsonValue] | None = None,
) -> dict[str, JsonValue]:
    """Assemble `Asset.details` within `MAX_ASSET_DETAILS_BYTES`, trimming optional metadata."""
    details: dict[str, JsonValue] = {"web": web}
    if web_host is not None:
        details["web_host"] = web_host
    if _details_bytes(details) <= MAX_ASSET_DETAILS_BYTES:
        return details

    cookies = web.get("cookies")
    if isinstance(cookies, list):
        while cookies and _details_bytes(details) > MAX_ASSET_DETAILS_BYTES:
            cookies.pop()

    headers = web.get("headers")
    if isinstance(headers, dict) and _details_bytes(details) > MAX_ASSET_DETAILS_BYTES:
        drop_order = [k for k in headers if k not in _PRIORITY_HEADERS]
        drop_order.extend(k for k in headers if k in _PRIORITY_HEADERS)
        for key in reversed(drop_order):
            if _details_bytes(details) <= MAX_ASSET_DETAILS_BYTES:
                break
            headers.pop(key, None)

    chain = web.get("redirect_chain")
    if isinstance(chain, list):
        while chain and _details_bytes(details) > MAX_ASSET_DETAILS_BYTES:
            chain.pop(0)

    if _details_bytes(details) > MAX_ASSET_DETAILS_BYTES:
        details.pop("web_host", None)
    if _details_bytes(details) > MAX_ASSET_DETAILS_BYTES:
        web["title"] = ""
    return details


@register_scanner
class WebProbe:
    """Discover HTTP(S) services on verified hosts and refresh observed `url` assets."""

    name = "web.probe"
    asset_types = frozenset({AssetType.DOMAIN, AssetType.SUBDOMAIN, AssetType.URL})
    queue = "active"
    requires_verification = True
    timeout_seconds = 60.0
    grant = ScannerGrant(
        http=HttpPermission.TARGET,
        http_ports=frozenset({80, 443}),
        follow_redirects=True,
        dns_lookups=DNS_LOOKUPS,
    )

    def run(self, ctx: ScanContext, asset: AssetRef) -> ScanOutput:
        if ctx.runtime is None:
            raise ScannerError("Scanner runtime is not configured.")
        if asset.type is AssetType.URL:
            return self._probe_existing_url(ctx, asset)
        return self._probe_host(ctx, asset)

    def _probe_existing_url(self, ctx: ScanContext, asset: AssetRef) -> ScanOutput:
        res = _probe_url(ctx, asset.value)
        if res is None:
            return ScanOutput(observations=(AssetObservation(asset=asset, active=False),))
        details = _fit_observation_details(_web_details(res))
        return ScanOutput(
            observations=(AssetObservation(asset=asset, details=details, active=True),)
        )

    def _probe_host(self, ctx: ScanContext, asset: AssetRef) -> ScanOutput:
        cap = ctx.max_discovered_assets
        if cap is not None and cap <= 0:
            return ScanOutput()

        https_res = _probe_url(ctx, f"https://{asset.value}/")
        http_res = _probe_url(ctx, f"http://{asset.value}/")
        if https_res is None and http_res is None:
            return ScanOutput()

        candidates: list[tuple[str, dict[str, JsonValue], dict[str, JsonValue]]] = []
        if https_res is not None:
            http_summary: dict[str, JsonValue] = (
                {
                    "reachable": True,
                    "status_code": (
                        http_res.redirect_chain[0][1]
                        if http_res.redirect_chain
                        else http_res.status_code
                    ),
                    "final_url": http_res.final_url,
                    "redirects_to_https": http_res.final_url.startswith("https://"),
                }
                if http_res is not None
                else {"reachable": False}
            )
            candidates.append(
                (
                    https_res.final_url,
                    _web_details(https_res),
                    {"https_reachable": True, "http_probe": http_summary},
                )
            )
            if http_res is not None and http_res.final_url != https_res.final_url:
                candidates.append(
                    (http_res.final_url, _web_details(http_res), {"https_reachable": True})
                )
        elif http_res is not None:
            candidates.append(
                (http_res.final_url, _web_details(http_res), {"https_reachable": False})
            )

        if cap is not None:
            candidates = candidates[:cap]

        assets: list[AssetRef] = []
        relations: list[DiscoveredRelation] = []
        observations: list[AssetObservation] = []
        seen_urls: set[str] = set()
        for url, web, web_host in candidates:
            if url in seen_urls:
                continue
            seen_urls.add(url)
            url_ref = AssetRef(type=AssetType.URL, value=url)
            assets.append(url_ref)
            relations.append(
                DiscoveredRelation(from_asset=asset, to_asset=url_ref, kind=RelationKind.SERVES)
            )
            observations.append(
                AssetObservation(
                    asset=url_ref,
                    details=_fit_observation_details(web, web_host),
                    active=True,
                )
            )
        return ScanOutput(
            assets=tuple(assets),
            relations=tuple(relations),
            observations=tuple(observations),
        )
