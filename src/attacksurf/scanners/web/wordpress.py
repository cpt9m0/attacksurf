"""WordPress exposure, user listing, debug log, XML-RPC, and NVD matching (`web.wordpress`, #79)."""

import hashlib
import json
import re
import secrets
from collections.abc import Mapping
from dataclasses import dataclass
from types import MappingProxyType
from typing import cast
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
from attacksurf.domain.vulnintel import is_valid_version
from attacksurf.scanners.registry import register_scanner
from attacksurf.scanners.web.components import (
    build_component_finding,
    match_cpes,
    normalize_component_version,
)
from attacksurf.scanners.web.fingerprint import (
    MAX_HTML_PARSE_BYTES,
    MAX_WP_PLUGINS,
    MAX_WP_THEMES,
    extract_wordpress_assets,
    extract_wordpress_generator,
)

BODY_LIMIT = 128 * 1024
PAGE_BODY_LIMIT = MAX_HTML_PARSE_BYTES
DNS_LOOKUPS = 16
HTTP_OK = 200
HTTP_METHOD_NOT_ALLOWED = 405
SOFT_404_SIZE_MIN_SLACK = 32
SOFT_404_SIZE_RATIO = 0.05

PATH_ROOT = "/"
PATH_FEED = "/feed/"
PATH_XMLRPC = "/xmlrpc.php"
PATH_USERS = "/wp-json/wp/v2/users"
PATH_DEBUG_LOG = "/wp-content/debug.log"
PATH_UPLOADS = "/wp-content/uploads/"

WORDPRESS_PATHS: frozenset[str] = frozenset(
    {
        PATH_ROOT,
        PATH_FEED,
        PATH_XMLRPC,
        PATH_USERS,
        PATH_DEBUG_LOG,
        PATH_UPLOADS,
    }
)

_HTML_TYPES = frozenset({"text/html", "application/xhtml+xml"})
_WS_RE = re.compile(r"\s+")
_WP_SLUG_RE = re.compile(r"^[a-z0-9][a-z0-9_-]{0,63}$")
_FEED_GENERATOR_RE = re.compile(
    r"<generator>\s*https?://wordpress\.org/\?v=([0-9][0-9A-Za-z._-]{0,31})\s*</generator>",
    re.IGNORECASE,
)
_DEBUG_LOG_TS_RE = re.compile(
    r"^\[\d{2}-[A-Za-z]{3}-\d{4}\s+\d{2}:\d{2}:\d{2}(?:\s+\S+)?\]\s+PHP\s+",
    re.MULTILINE,
)
_DEBUG_PHP_ERR_RE = re.compile(
    r"PHP\s+(Fatal error|Warning|Notice|Deprecated|Parse error):",
    re.IGNORECASE,
)
_DIR_ENTRY_HREF_RE = re.compile(r'<a\s+[^>]*href=["\']([^"\']+)["\']', re.IGNORECASE)

# Curated WordPress plugin & theme CPE overrides (NVD catalog, zero WPScan commercial API usage).
WP_PLUGIN_CPES: Mapping[str, tuple[tuple[str, str], ...]] = MappingProxyType(
    {
        "advanced-custom-fields": (
            ("advancedcustomfields", "advanced_custom_fields"),
            ("wpengine", "advanced_custom_fields"),
        ),
        "akismet": (("automattic", "akismet"),),
        "all-in-one-seo-pack": (
            ("aioseo", "all_in_one_seo"),
            ("semperfiwebdesign", "all_in_one_seo_pack"),
        ),
        "classic-editor": (("wordpress", "classic_editor"),),
        "contact-form-7": (("rocklobster", "contact_form_7"), ("contactform7", "contact_form_7")),
        "elementor": (("elementor", "elementor_website_builder"), ("elementor", "elementor")),
        "gravityforms": (("gravityforms", "gravityforms"),),
        "jetpack": (("automattic", "jetpack"),),
        "js_composer": (("wpbakery", "page_builder"), ("wpbakery", "js_composer")),
        "litespeed-cache": (("litespeedtech", "litespeed_cache"),),
        "ninja-forms": (("ninjaforms", "ninja_forms"),),
        "really-simple-ssl": (("really-simple-plugins", "really_simple_ssl"),),
        "revslider": (("themepunch", "slider_revolution"), ("themepunch", "revslider")),
        "updraftplus": (("updraftplus", "updraftplus"),),
        "woocommerce": (("woocommerce", "woocommerce"), ("automattic", "woocommerce")),
        "wordfence": (("wordfence", "wordfence_security"),),
        "wordpress-seo": (("yoast", "yoast_seo"), ("yoast", "wordpress_seo")),
        "wp-mail-smtp": (("wpmailsmtp", "wp_mail_smtp"),),
        "wp-super-cache": (("automattic", "wp_super_cache"),),
        "wpforms-lite": (("wpforms", "wpforms"),),
    }
)

WP_THEME_CPES: Mapping[str, tuple[tuple[str, str], ...]] = MappingProxyType(
    {
        "astra": (("brainstormforce", "astra"),),
        "avada": (("theme-fusion", "avada"), ("avada", "avada")),
        "divi": (("elegantthemes", "divi"),),
        "generatepress": (("generatepress", "generatepress"),),
        "hello-elementor": (("elementor", "hello_elementor"),),
        "oceanwp": (("oceanwp", "oceanwp"),),
    }
)


@dataclass(frozen=True)
class _Soft404Baseline:
    status_code: int
    media_type: str
    body_len: int
    raw_sha256: str
    norm_sha256: str


@dataclass(frozen=True)
class _TechnologySnapshot:
    is_wordpress: bool
    wp_version: str | None
    versioned_techs: frozenset[str]


def _header(body: HttpBody, name: str) -> str:
    for key, val in body.headers.items():
        if key.lower() == name:
            return val.strip()
    return ""


def _media_type(body: HttpBody) -> str:
    return _header(body, "content-type").split(";", 1)[0].strip().lower()


def _content_length(body: HttpBody) -> int:
    raw = _header(body, "content-length")
    if raw and raw.isascii() and raw.isdigit():
        return int(raw)
    return len(body.content)


def _looks_like_html(body: HttpBody) -> bool:
    if _media_type(body) in _HTML_TYPES:
        return True
    head = body.content[:256].decode("utf-8", errors="replace").lstrip().lower()
    return head.startswith("<!doctype html") or head.startswith("<html")


def _normalized_hash(content: bytes, *, strip_segments: tuple[str, ...] = ()) -> str:
    text = content.decode("utf-8", errors="replace").lower()
    for seg in strip_segments:
        if seg:
            text = text.replace(seg.lower(), "")
    collapsed = _WS_RE.sub(" ", text).strip()
    return hashlib.sha256(collapsed.encode("utf-8")).hexdigest()


def _matches_baseline_size(body_len: int, baseline_len: int) -> bool:
    slack = max(SOFT_404_SIZE_MIN_SLACK, int(baseline_len * SOFT_404_SIZE_RATIO))
    return abs(body_len - baseline_len) <= slack


def _is_soft_404(body: HttpBody, path: str, baseline: _Soft404Baseline) -> bool:
    if body.status_code != HTTP_OK:
        return True
    if baseline.status_code != HTTP_OK:
        return False
    if hashlib.sha256(body.content).hexdigest() == baseline.raw_sha256:
        return True
    norm_hash = _normalized_hash(body.content, strip_segments=(path, path.strip("/")))
    if norm_hash == baseline.norm_sha256:
        return True
    media_type = _media_type(body)
    return (
        media_type == baseline.media_type
        and media_type in _HTML_TYPES
        and _matches_baseline_size(len(body.content), baseline.body_len)
    )


def _inspect_technologies(target_details: Mapping[str, JsonValue]) -> _TechnologySnapshot:
    raw = target_details.get("technologies")
    if not isinstance(raw, list):
        return _TechnologySnapshot(False, None, frozenset())
    is_wp = False
    wp_version: str | None = None
    versioned: set[str] = set()
    for item in raw:
        if not isinstance(item, Mapping):
            continue
        raw_name = item.get("name")
        if not isinstance(raw_name, str) or not raw_name.strip():
            continue
        key = raw_name.strip().lower()
        raw_ver = item.get("version")
        clean_ver = normalize_component_version(raw_ver) if isinstance(raw_ver, str) else None
        valid_ver = clean_ver if clean_ver and is_valid_version(clean_ver) else None
        if valid_ver is not None:
            versioned.add(key)
        if key == "wordpress":
            is_wp = True
            wp_version = valid_ver
    return _TechnologySnapshot(is_wp, wp_version, frozenset(versioned))


def _origin_url(ctx: ScanContext, asset: AssetRef) -> str:
    parsed_asset = urlsplit(asset.value)
    target = asset.value
    web = ctx.target_details.get("web")
    if isinstance(web, Mapping) and not web.get("redirect_stopped_out_of_scope"):
        raw_final = web.get("final_url")
        if isinstance(raw_final, str) and raw_final:
            parsed_final = urlsplit(raw_final)
            if (
                parsed_final.scheme.lower() in {"http", "https"}
                and parsed_final.hostname == parsed_asset.hostname
                and (parsed_final.port is None or parsed_final.port in ALLOWED_WEB_PORTS)
            ):
                target = raw_final
    parts = urlsplit(target)
    return f"{parts.scheme.lower()}://{parts.netloc}"


def _get(ctx: ScanContext, url: str, *, limit: int = BODY_LIMIT) -> HttpBody:
    runtime = ctx.runtime
    if runtime is None:
        raise ScannerError("Scanner runtime is not configured.")
    try:
        return runtime.http.get(url, limit=limit)
    except (DnsError, ScopeError):
        raise TransientJobError("WordPress check failed.") from None


def _fetch_baseline(ctx: ScanContext, origin: str) -> _Soft404Baseline:
    sentinel = f"attacksurf-not-found-{secrets.token_hex(8)}"
    body = _get(ctx, f"{origin}/{sentinel}")
    return _Soft404Baseline(
        status_code=body.status_code,
        media_type=_media_type(body),
        body_len=len(body.content),
        raw_sha256=hashlib.sha256(body.content).hexdigest(),
        norm_sha256=_normalized_hash(body.content, strip_segments=(f"/{sentinel}", sentinel)),
    )


def _clean_asset_map(raw: object, *, limit: int) -> dict[str, str]:
    if not isinstance(raw, Mapping):
        return {}
    cleaned: dict[str, str] = {}
    for raw_slug, raw_ver in sorted(raw.items()):
        if not isinstance(raw_slug, str) or not isinstance(raw_ver, str):
            continue
        slug = raw_slug.strip().lower()
        ver = normalize_component_version(raw_ver)
        if _WP_SLUG_RE.fullmatch(slug) and is_valid_version(ver):
            cleaned[slug] = ver
            if len(cleaned) >= limit:
                break
    return cleaned


def _cpes_for_slug(
    slug: str, overrides: Mapping[str, tuple[tuple[str, str], ...]]
) -> tuple[tuple[str, str], ...]:
    if slug in overrides:
        return overrides[slug]
    norm = slug.replace("-", "_")
    candidates = [(f"{norm}_project", norm), (norm, norm)]
    if norm != slug:
        candidates.append((slug, slug))
    return tuple(candidates)


def _check_xmlrpc(ctx: ScanContext, origin: str, baseline: _Soft404Baseline) -> RawFinding | None:
    url = f"{origin}{PATH_XMLRPC}"
    body = _get(ctx, url)
    if body.status_code not in {HTTP_OK, HTTP_METHOD_NOT_ALLOWED} or _looks_like_html(body):
        return None
    if body.status_code == HTTP_OK and _is_soft_404(body, PATH_XMLRPC, baseline):
        return None
    text = body.content.decode("utf-8", errors="replace").lower()
    if "xml-rpc server accepts post requests only" not in text:
        return None
    evidence: dict[str, JsonValue] = {
        "path": PATH_XMLRPC,
        "url": url,
        "status_code": body.status_code,
    }
    allow = _header(body, "allow")
    if allow:
        evidence["allow"] = allow[:64]
    return RawFinding(
        rule_id="web.wordpress.xmlrpc_enabled",
        location=PATH_XMLRPC,
        confidence=Confidence.HIGH,
        remediation_context={"url": url},
        evidence=(RawEvidence(kind=EvidenceKind.HTTP_RESPONSE, data=evidence),),
    )


def _check_user_listing(
    ctx: ScanContext, origin: str, baseline: _Soft404Baseline
) -> RawFinding | None:
    url = f"{origin}{PATH_USERS}"
    body = _get(ctx, url)
    if _looks_like_html(body) or _is_soft_404(body, PATH_USERS, baseline):
        return None
    try:
        parsed = json.loads(body.content.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError):
        return None
    if not isinstance(parsed, list) or not parsed:
        return None
    user_items = [
        item
        for item in parsed
        if isinstance(item, dict)
        and isinstance(item.get("id"), int)
        and not isinstance(item.get("id"), bool)
        and any(key in item for key in ("slug", "name", "link"))
    ]
    if not user_items:
        return None
    raw_total = _header(body, "x-wp-total")
    header_total = int(raw_total) if raw_total.isascii() and raw_total.isdigit() else 0
    user_count = max(len(user_items), header_total)
    return RawFinding(
        rule_id="web.wordpress.user_listing",
        location=PATH_USERS,
        confidence=Confidence.HIGH,
        remediation_context={"url": url, "user_count": str(user_count)},
        evidence=(
            RawEvidence(
                kind=EvidenceKind.HTTP_RESPONSE,
                data={
                    "path": PATH_USERS,
                    "url": url,
                    "status_code": body.status_code,
                    "user_count": user_count,
                },
            ),
        ),
    )


def _check_debug_log(
    ctx: ScanContext, origin: str, baseline: _Soft404Baseline
) -> RawFinding | None:
    url = f"{origin}{PATH_DEBUG_LOG}"
    body = _get(ctx, url)
    if _looks_like_html(body) or _is_soft_404(body, PATH_DEBUG_LOG, baseline):
        return None
    text = body.content.decode("utf-8", errors="replace")
    lowered = text.lower()
    has_ts = _DEBUG_LOG_TS_RE.search(text) is not None
    level_matches = _DEBUG_PHP_ERR_RE.findall(text)
    has_wp_ctx = any(
        marker in lowered for marker in ("wp-content", "wp-includes", "wp-admin", " on line ")
    )
    if not (has_ts or (level_matches and has_wp_ctx)):
        return None
    matched_levels = sorted({lvl.split()[0].lower() for lvl in level_matches})
    return RawFinding(
        rule_id="web.wordpress.debug_log",
        location=PATH_DEBUG_LOG,
        confidence=Confidence.HIGH,
        remediation_context={"url": url},
        evidence=(
            RawEvidence(
                kind=EvidenceKind.HTTP_RESPONSE,
                data={
                    "path": PATH_DEBUG_LOG,
                    "url": url,
                    "status_code": body.status_code,
                    "content_type": _media_type(body),
                    "content_length": _content_length(body),
                    "line_count": len(text.splitlines()),
                    "truncated": body.truncated,
                    "matched_levels": cast(list[JsonValue], matched_levels),
                },
            ),
        ),
    )


def _check_uploads_listing(
    ctx: ScanContext, origin: str, baseline: _Soft404Baseline
) -> RawFinding | None:
    url = f"{origin}{PATH_UPLOADS}"
    body = _get(ctx, url)
    if _is_soft_404(body, PATH_UPLOADS, baseline):
        return None
    text = body.content.decode("utf-8", errors="replace")
    lowered = text.lower()
    if "index of /wp-content/uploads" not in lowered:
        return None
    if not any(tok in lowered for tok in ("parent directory", "<pre>", "<table", "<ul")):
        return None
    entry_count = sum(
        1
        for href in _DIR_ENTRY_HREF_RE.findall(text)
        if not href.startswith(("?", "/", "#", "../", "http://", "https://"))
    )
    return RawFinding(
        rule_id="web.exposure.directory_listing",
        location=PATH_UPLOADS,
        confidence=Confidence.HIGH,
        remediation_context={"path": PATH_UPLOADS, "url": url},
        evidence=(
            RawEvidence(
                kind=EvidenceKind.HTTP_RESPONSE,
                data={
                    "path": PATH_UPLOADS,
                    "url": url,
                    "status_code": body.status_code,
                    "content_type": _media_type(body),
                    "content_length": _content_length(body),
                    "entry_count": entry_count,
                },
            ),
        ),
    )


def _collect_passive_assets(
    ctx: ScanContext, origin: str, baseline: _Soft404Baseline
) -> tuple[dict[str, str], dict[str, str], str | None]:
    raw_wp = ctx.target_details.get("wordpress")
    if isinstance(raw_wp, Mapping):
        return (
            _clean_asset_map(raw_wp.get("plugins"), limit=MAX_WP_PLUGINS),
            _clean_asset_map(raw_wp.get("themes"), limit=MAX_WP_THEMES),
            None,
        )
    page = _get(ctx, f"{origin}{PATH_ROOT}", limit=PAGE_BODY_LIMIT)
    if _is_soft_404(page, PATH_ROOT, baseline) or not _looks_like_html(page):
        return {}, {}, None
    media_type = _media_type(page)
    plugins, themes = extract_wordpress_assets(page.content, media_type)
    gen = extract_wordpress_generator(page.content, media_type)
    page_ver = normalize_component_version(gen) if gen else None
    valid_page_ver = page_ver if page_ver and is_valid_version(page_ver) else None
    return (
        _clean_asset_map(plugins, limit=MAX_WP_PLUGINS),
        _clean_asset_map(themes, limit=MAX_WP_THEMES),
        valid_page_ver,
    )


def _fetch_feed_version(ctx: ScanContext, origin: str, baseline: _Soft404Baseline) -> str | None:
    body = _get(ctx, f"{origin}{PATH_FEED}")
    if _looks_like_html(body) or _is_soft_404(body, PATH_FEED, baseline):
        return None
    text = body.content.decode("utf-8", errors="replace")
    match = _FEED_GENERATOR_RE.search(text)
    if match is None:
        return None
    ver = normalize_component_version(match.group(1))
    return ver if is_valid_version(ver) else None


@register_scanner
class WebWordpress:
    """Check WordPress sites for core/plugin/theme CVEs and common misconfigurations."""

    name = "web.wordpress"
    asset_types = frozenset({AssetType.URL})
    queue = "active"
    requires_verification = True
    timeout_seconds = 60.0
    grant = ScannerGrant(
        http=HttpPermission.TARGET,
        http_ports=ALLOWED_WEB_PORTS,
        http_methods=frozenset({"GET"}),
        http_paths=WORDPRESS_PATHS,
        soft_404_probe=True,
        follow_redirects=False,
        dns_lookups=DNS_LOOKUPS,
    )

    def run(self, ctx: ScanContext, asset: AssetRef) -> ScanOutput:
        if ctx.runtime is None:
            raise ScannerError("Scanner runtime is not configured.")
        tech_snap = _inspect_technologies(ctx.target_details)
        if not tech_snap.is_wordpress:
            return ScanOutput()

        origin = _origin_url(ctx, asset)
        baseline = _fetch_baseline(ctx, origin)
        plugins, themes, page_version = _collect_passive_assets(ctx, origin, baseline)
        feed_version = _fetch_feed_version(ctx, origin, baseline)
        core_version = tech_snap.wp_version or feed_version or page_version

        findings: list[RawFinding] = []
        if core_version is not None:
            core_cpes = (("wordpress", "wordpress"),)
            core_vulns = match_cpes(ctx, core_cpes, core_version)
            if core_vulns:
                findings.append(
                    build_component_finding(
                        asset,
                        name="WordPress",
                        version=core_version,
                        cpes=core_cpes,
                        vulns=core_vulns,
                        location="wordpress",
                    )
                )

        for slug, ver in plugins.items():
            if slug == "woocommerce" and "woocommerce" in tech_snap.versioned_techs:
                continue
            cpes = _cpes_for_slug(slug, WP_PLUGIN_CPES)
            vulns = match_cpes(ctx, cpes, ver)
            if vulns:
                findings.append(
                    build_component_finding(
                        asset,
                        name=f"WordPress plugin {slug}",
                        version=ver,
                        cpes=cpes,
                        vulns=vulns,
                        location=f"wordpress:plugin:{slug}",
                    )
                )

        for slug, ver in themes.items():
            cpes = _cpes_for_slug(slug, WP_THEME_CPES)
            vulns = match_cpes(ctx, cpes, ver)
            if vulns:
                findings.append(
                    build_component_finding(
                        asset,
                        name=f"WordPress theme {slug}",
                        version=ver,
                        cpes=cpes,
                        vulns=vulns,
                        location=f"wordpress:theme:{slug}",
                    )
                )

        for checker in (
            _check_xmlrpc,
            _check_user_listing,
            _check_debug_log,
            _check_uploads_listing,
        ):
            finding = checker(ctx, origin, baseline)
            if finding is not None:
                findings.append(finding)

        observation = AssetObservation(
            asset=asset,
            details={
                "wordpress": {
                    "core_version": core_version,
                    "plugins": cast(dict[str, JsonValue], dict(plugins)),
                    "themes": cast(dict[str, JsonValue], dict(themes)),
                }
            },
            active=None,
        )
        return ScanOutput(observations=(observation,), findings=tuple(findings))
