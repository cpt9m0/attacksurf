"""Fixed-path exposed sensitive files, debug endpoints, and admin panels (`web.exposures`, #78)."""

import hashlib
import json
import re
import secrets
from collections.abc import Callable
from dataclasses import dataclass
from typing import cast
from urllib.parse import urlsplit

from pydantic import JsonValue

from attacksurf.domain.assets import AssetType
from attacksurf.domain.findings import Confidence, EvidenceKind, Severity
from attacksurf.domain.jobs import TransientJobError
from attacksurf.domain.net import DnsError, HttpBody
from attacksurf.domain.scanners import (
    ALLOWED_WEB_PORTS,
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

MAX_EXPOSURE_BODY_BYTES = 128 * 1024
DNS_LOOKUPS = 40
HTTP_OK = 200
HTTP_UNAUTHORIZED = 401
HTTP_NOT_FOUND = 404
MAX_GIT_HEAD_BYTES = 256
MAX_SNIPPET_CHARS = 180
MAX_ENV_KEY_NAMES = 50
MAX_LIST_ITEMS = 25
SOFT_404_SIZE_MIN_SLACK = 32
SOFT_404_SIZE_RATIO = 0.05
MIN_ENV_KEYS_GENERIC = 2

_HTML_TYPES = frozenset({"text/html", "application/xhtml+xml"})
_ZIP_TYPES = frozenset(
    {"application/zip", "application/x-zip-compressed", "application/octet-stream"}
)
_GZIP_TYPES = frozenset(
    {
        "application/gzip",
        "application/x-gzip",
        "application/x-tar",
        "application/x-compressed-tar",
        "application/octet-stream",
    }
)
_SQL_TYPES = frozenset(
    {"application/sql", "text/sql", "text/x-sql", "text/plain", "application/octet-stream"}
)
_HEAPDUMP_TYPES = frozenset(
    {
        "application/octet-stream",
        "application/x-heapdump",
        "application/hprof",
        "application/vnd.spring-boot.actuator.v2+json",
    }
)

_GIT_HEAD_REF_RE = re.compile(r"^(?:ref:\s+refs/\S+|[0-9a-f]{40})\s*$", re.IGNORECASE)
_GIT_SECTION_RE = re.compile(r'^\s*\[([A-Za-z0-9_.-]+)(?:\s+"[^"]*")?\]\s*(?:[#;].*)?$')
_GIT_KV_RE = re.compile(r"^\s*([A-Za-z0-9_.-]+)\s*=")
_SAFE_GIT_SECTIONS = frozenset(
    {"branch", "core", "credential", "http", "init", "lfs", "remote", "submodule", "user"}
)
_SAFE_GIT_CORE_KEYS = frozenset(
    {"bare", "filemode", "ignorecase", "logallrefupdates", "repositoryformatversion", "symlinks"}
)
_SVN_ENTRIES_RE = re.compile(r"^(?:\d+\r?\n\r?\ndir\b|.*<wc-entries\b|SQLite format 3)", re.DOTALL)
_DS_STORE_MAGIC = b"\x00\x00\x00\x01Bud1"
_ENV_LINE_RE = re.compile(r"^(?:export\s+)?([A-Za-z_][A-Za-z0-9_]*)\s*=")
_HIGH_SIGNAL_ENV_KEY_RE = re.compile(
    r"(?:SECRET|TOKEN|KEY|PASSWORD|PASSWD|DATABASE_URL|DSN|PRIVATE|CREDENTIAL)",
    re.IGNORECASE,
)
_PHP_VERSION_RE = re.compile(r"PHP\s+Version\s+([0-9][0-9A-Za-z.+~_-]{0,32})", re.IGNORECASE)
_APACHE_SERVER_RE = re.compile(r"Server\s+Version:\s*([^\n<]{1,120})", re.IGNORECASE)
_SECURITY_CONTACT_RE = re.compile(r"(?im)^Contact:\s+\S+")
_PASSWORD_INPUT_RE = re.compile(r"""type\s*=\s*["']?password["'\s>]""", re.IGNORECASE)
_WS_RE = re.compile(r"\s+")

_SECURITY_TXT_PATHS = ("/.well-known/security.txt", "/security.txt")
_ADMIN_PAIR_FOLLOWUP = "/admin/"
_ADMIN_PAIR_PRIMARY = "/admin"


@dataclass(frozen=True)
class _Soft404Baseline:
    status_code: int
    media_type: str
    body_len: int
    raw_sha256: str
    norm_sha256: str
    sentinel_segment: str


@dataclass(frozen=True)
class _ProbeSpec:
    path: str
    method: str
    rule_id: str | None
    validator: str
    severity: Severity | None = None


_SPECS: tuple[_ProbeSpec, ...] = (
    _ProbeSpec("/.git/HEAD", "GET", "web.exposure.git_repo", "git_head"),
    _ProbeSpec("/.git/config", "GET", "web.exposure.git_repo", "git_config"),
    _ProbeSpec("/.svn/entries", "GET", "web.exposure.git_repo", "svn_entries"),
    _ProbeSpec("/.DS_Store", "GET", "web.exposure.backup_archive", "ds_store", Severity.LOW),
    _ProbeSpec("/backup.zip", "HEAD", "web.exposure.backup_archive", "zip_archive"),
    _ProbeSpec("/backup.tar.gz", "HEAD", "web.exposure.backup_archive", "gzip_archive"),
    _ProbeSpec("/backup.tgz", "HEAD", "web.exposure.backup_archive", "gzip_archive"),
    _ProbeSpec("/backup.sql", "HEAD", "web.exposure.backup_archive", "sql_archive"),
    _ProbeSpec("/dump.sql", "HEAD", "web.exposure.backup_archive", "sql_archive"),
    _ProbeSpec("/db.sql", "HEAD", "web.exposure.backup_archive", "sql_archive"),
    _ProbeSpec("/site.zip", "HEAD", "web.exposure.backup_archive", "zip_archive"),
    _ProbeSpec("/www.zip", "HEAD", "web.exposure.backup_archive", "zip_archive"),
    _ProbeSpec("/.env", "GET", "web.exposure.env_file", "env_file"),
    _ProbeSpec("/.env.local", "GET", "web.exposure.env_file", "env_file"),
    _ProbeSpec("/.env.production", "GET", "web.exposure.env_file", "env_file"),
    _ProbeSpec("/.env.bak", "GET", "web.exposure.env_file", "env_file"),
    _ProbeSpec(
        "/server-status", "GET", "web.exposure.debug_endpoint", "server_status", Severity.MEDIUM
    ),
    _ProbeSpec("/phpinfo.php", "GET", "web.exposure.debug_endpoint", "phpinfo", Severity.MEDIUM),
    _ProbeSpec("/actuator/env", "GET", "web.exposure.debug_endpoint", "actuator_env"),
    _ProbeSpec("/actuator/heapdump", "HEAD", "web.exposure.debug_endpoint", "actuator_heapdump"),
    _ProbeSpec("/debug/pprof/", "GET", "web.exposure.debug_endpoint", "debug_pprof"),
    _ProbeSpec("/swagger.json", "GET", "web.exposure.api_docs", "openapi_json"),
    _ProbeSpec("/openapi.json", "GET", "web.exposure.api_docs", "openapi_json"),
    _ProbeSpec("/v3/api-docs", "GET", "web.exposure.api_docs", "openapi_json"),
    _ProbeSpec("/swagger-ui.html", "GET", "web.exposure.api_docs", "swagger_ui"),
    _ProbeSpec("/.well-known/security.txt", "GET", None, "security_txt"),
    _ProbeSpec("/security.txt", "GET", None, "security_txt"),
    _ProbeSpec("/admin", "GET", "web.exposure.admin_panel", "admin_panel"),
    _ProbeSpec("/admin/", "GET", "web.exposure.admin_panel", "admin_panel"),
    _ProbeSpec("/login", "GET", "web.exposure.admin_panel", "admin_panel"),
    _ProbeSpec("/wp-admin/", "GET", "web.exposure.admin_panel", "admin_panel"),
    _ProbeSpec("/phpmyadmin/", "GET", "web.exposure.admin_panel", "admin_panel"),
    _ProbeSpec("/adminer.php", "GET", "web.exposure.admin_panel", "admin_panel"),
)

EXPOSURE_PATHS: frozenset[str] = frozenset(spec.path for spec in _SPECS)


def _header(body: HttpBody, name: str) -> str:
    for key, val in body.headers.items():
        if key.lower() == name:
            return val.strip()
    return ""


def _media_type(body: HttpBody) -> str:
    return _header(body, "content-type").split(";", 1)[0].strip().lower()


def _content_length_header(body: HttpBody) -> int | None:
    raw = _header(body, "content-length")
    if raw and raw.isascii() and raw.isdigit():
        return int(raw)
    return None


def _normalized_hash(content: bytes, *, strip_segments: tuple[str, ...] = ()) -> str:
    text = content.decode("utf-8", errors="replace").lower()
    for seg in strip_segments:
        if seg:
            text = text.replace(seg.lower(), "")
    collapsed = _WS_RE.sub(" ", text).strip()
    return hashlib.sha256(collapsed.encode("utf-8")).hexdigest()


def _looks_like_html(body: HttpBody) -> bool:
    if _media_type(body) in _HTML_TYPES:
        return True
    head = body.content[:256].decode("utf-8", errors="replace").lstrip().lower()
    return head.startswith("<!doctype html") or head.startswith("<html")


def _matches_baseline_size(body_len: int, baseline_len: int) -> bool:
    slack = max(SOFT_404_SIZE_MIN_SLACK, int(baseline_len * SOFT_404_SIZE_RATIO))
    return abs(body_len - baseline_len) <= slack


def _is_soft_404_get(body: HttpBody, path: str, baseline: _Soft404Baseline) -> bool:
    if body.status_code != HTTP_OK:
        return True
    if baseline.status_code != HTTP_OK:
        return False
    raw_hash = hashlib.sha256(body.content).hexdigest()
    if raw_hash == baseline.raw_sha256:
        return True
    path_seg = path.strip("/")
    norm_hash = _normalized_hash(body.content, strip_segments=(path, path_seg))
    if norm_hash == baseline.norm_sha256:
        return True
    media_type = _media_type(body)
    return (
        media_type == baseline.media_type
        and media_type in _HTML_TYPES
        and _matches_baseline_size(len(body.content), baseline.body_len)
    )


def _validate_git_head(body: HttpBody) -> dict[str, JsonValue] | None:
    if _looks_like_html(body) or len(body.content) > MAX_GIT_HEAD_BYTES:
        return None
    text = body.content.decode("utf-8", errors="replace").strip()
    if not text or "\n" in text or _GIT_HEAD_REF_RE.fullmatch(text) is None:
        return None
    return {"excerpt": text[:MAX_SNIPPET_CHARS]}


def _validate_git_config(body: HttpBody) -> dict[str, JsonValue] | None:
    if _looks_like_html(body):
        return None
    text = body.content.decode("utf-8", errors="replace")
    lowered = text.lower()
    if "[core]" not in lowered:
        return None
    markers = ("repositoryformatversion", "filemode", "bare", "[remote ")
    if not any(tok in lowered for tok in markers):
        return None
    sections: set[str] = set()
    core_keys: set[str] = set()
    remote_count = 0
    current_section: str | None = None
    for line in text.splitlines():
        sec_match = _GIT_SECTION_RE.match(line)
        if sec_match:
            current_section = sec_match.group(1).lower()
            if current_section == "remote":
                remote_count += 1
            if current_section in _SAFE_GIT_SECTIONS:
                sections.add(current_section)
            continue
        if current_section == "core":
            kv_match = _GIT_KV_RE.match(line)
            if kv_match:
                key = kv_match.group(1).lower()
                if key in _SAFE_GIT_CORE_KEYS:
                    core_keys.add(key)
    return {
        "sections": cast(list[JsonValue], sorted(sections)),
        "core_keys": cast(list[JsonValue], sorted(core_keys)),
        "remote_count": remote_count,
    }


def _validate_svn_entries(body: HttpBody) -> dict[str, JsonValue] | None:
    if _looks_like_html(body):
        return None
    text = body.content[:256].decode("latin-1")
    if _SVN_ENTRIES_RE.match(text) is None:
        return None
    format_name = "sqlite-wc" if text.startswith("SQLite format 3") else "svn-entries"
    return {"format": format_name}


def _validate_ds_store(body: HttpBody) -> dict[str, JsonValue] | None:
    if _looks_like_html(body) or not body.content.startswith(_DS_STORE_MAGIC):
        return None
    return {"format": "apple-ds-store"}


def _validate_env_file(body: HttpBody) -> dict[str, JsonValue] | None:
    if _looks_like_html(body):
        return None
    text = body.content.decode("utf-8", errors="replace")
    keys: list[str] = []
    seen: set[str] = set()
    for line in text.splitlines():
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        match = _ENV_LINE_RE.match(stripped)
        if not match:
            continue
        key = match.group(1)
        if key not in seen:
            seen.add(key)
            keys.append(key)
    if not keys:
        return None
    if len(keys) < MIN_ENV_KEYS_GENERIC and not any(
        _HIGH_SIGNAL_ENV_KEY_RE.search(key) for key in keys
    ):
        return None
    sorted_keys = sorted(keys)
    return {
        "key_names": cast(list[JsonValue], sorted_keys[:MAX_ENV_KEY_NAMES]),
        "key_count": len(sorted_keys),
    }


def _validate_server_status(body: HttpBody) -> dict[str, JsonValue] | None:
    text = body.content.decode("utf-8", errors="replace")
    if "Apache Server Status" not in text:
        return None
    if not any(tok in text for tok in ("Server Version:", "Total accesses:", "Current Time:")):
        return None
    ver_match = _APACHE_SERVER_RE.search(text)
    if ver_match:
        return {"server_version": ver_match.group(1).strip()}
    return {"marker": "Apache Server Status"}


def _validate_phpinfo(body: HttpBody) -> dict[str, JsonValue] | None:
    text = body.content.decode("utf-8", errors="replace")
    lowered = text.lower()
    if "phpinfo()" not in lowered:
        return None
    if not any(
        tok in lowered for tok in ("php version", "zend engine", "configuration file (php.ini)")
    ):
        return None
    ver_match = _PHP_VERSION_RE.search(text)
    return {"php_version": ver_match.group(1) if ver_match else "unknown"}


def _validate_actuator_env(body: HttpBody) -> dict[str, JsonValue] | None:
    if _looks_like_html(body):
        return None
    try:
        parsed = json.loads(body.content.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError):
        return None
    if not isinstance(parsed, dict):
        return None
    if "propertySources" not in parsed and "activeProfiles" not in parsed:
        return None
    sources_raw = parsed.get("propertySources")
    source_names = (
        [
            str(src["name"])[:120]
            for src in sources_raw
            if isinstance(src, dict) and isinstance(src.get("name"), str)
        ][:MAX_LIST_ITEMS]
        if isinstance(sources_raw, list)
        else []
    )
    profiles_raw = parsed.get("activeProfiles")
    profiles = (
        [str(item)[:64] for item in profiles_raw if isinstance(item, str)][:MAX_LIST_ITEMS]
        if isinstance(profiles_raw, list)
        else []
    )
    return {
        "active_profiles": cast(list[JsonValue], profiles),
        "property_source_names": cast(list[JsonValue], source_names),
    }


def _validate_debug_pprof(body: HttpBody) -> dict[str, JsonValue] | None:
    text = body.content.decode("utf-8", errors="replace")
    if "Types of profiles available:" not in text and "/debug/pprof/goroutine" not in text:
        return None
    return {"marker": "go-pprof"}


def _validate_openapi_json(body: HttpBody) -> dict[str, JsonValue] | None:
    if _looks_like_html(body):
        return None
    try:
        parsed = json.loads(body.content.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError):
        return None
    if not isinstance(parsed, dict):
        return None
    version = parsed.get("openapi") or parsed.get("swagger")
    if not isinstance(version, str) or not version:
        return None
    if "paths" not in parsed and "info" not in parsed:
        return None
    info = parsed.get("info")
    title = info.get("title") if isinstance(info, dict) else None
    paths = parsed.get("paths")
    return {
        "spec_version": version[:32],
        "title": str(title)[:120] if isinstance(title, str) else None,
        "path_count": len(paths) if isinstance(paths, dict) else 0,
    }


def _validate_swagger_ui(body: HttpBody) -> dict[str, JsonValue] | None:
    text = body.content.decode("utf-8", errors="replace")
    lowered = text.lower()
    if "swagger-ui" not in lowered:
        return None
    if "swaggeruibundle" not in lowered and "swagger ui" not in lowered:
        return None
    return {"marker": "swagger-ui"}


def _validate_security_txt(body: HttpBody) -> dict[str, JsonValue] | None:
    if _looks_like_html(body):
        return None
    media_type = _media_type(body)
    if media_type and media_type not in {"text/plain", "text/x-plain"}:
        return None
    text = body.content.decode("utf-8", errors="replace")
    if _SECURITY_CONTACT_RE.search(text) is None:
        return None
    return {"has_contact": True}


def _validate_head_artifact(
    body: HttpBody,
    baseline: _Soft404Baseline,
    allowed_types: frozenset[str],
) -> dict[str, JsonValue] | None:
    if body.status_code != HTTP_OK:
        return None
    media_type = _media_type(body)
    if media_type in _HTML_TYPES:
        return None
    content_length = _content_length_header(body)
    if content_length is None or content_length <= 0:
        return None
    if (
        baseline.status_code == HTTP_OK
        and media_type == baseline.media_type
        and _matches_baseline_size(content_length, baseline.body_len)
    ):
        return None
    disposition = _header(body, "content-disposition").lower()
    is_attachment = disposition.startswith("attachment")
    if media_type not in allowed_types and not is_attachment:
        return None
    return {"attachment": is_attachment}


def _validate_admin_panel(
    body: HttpBody, path: str, baseline: _Soft404Baseline
) -> dict[str, JsonValue] | None:
    if body.status_code == HTTP_UNAUTHORIZED and baseline.status_code != HTTP_UNAUTHORIZED:
        www_auth = _header(body, "www-authenticate")
        return {"auth_scheme": www_auth.split(None, 1)[0][:32]} if www_auth else None
    if _is_soft_404_get(body, path, baseline) or not _looks_like_html(body):
        return None
    text = body.content.decode("utf-8", errors="replace")
    if _PASSWORD_INPUT_RE.search(text) is not None:
        return {"marker": "password-form"}
    lowered = text.lower()
    markers = ("phpmyadmin", "adminer", "wp-login", "wp-submit")
    matched = next((tok for tok in markers if tok in lowered), None)
    return {"marker": matched} if matched else None


_GET_VALIDATORS: dict[str, Callable[[HttpBody], dict[str, JsonValue] | None]] = {
    "git_head": _validate_git_head,
    "git_config": _validate_git_config,
    "svn_entries": _validate_svn_entries,
    "ds_store": _validate_ds_store,
    "env_file": _validate_env_file,
    "server_status": _validate_server_status,
    "phpinfo": _validate_phpinfo,
    "actuator_env": _validate_actuator_env,
    "debug_pprof": _validate_debug_pprof,
    "openapi_json": _validate_openapi_json,
    "swagger_ui": _validate_swagger_ui,
    "security_txt": _validate_security_txt,
}

_HEAD_TYPES: dict[str, frozenset[str]] = {
    "zip_archive": _ZIP_TYPES,
    "gzip_archive": _GZIP_TYPES,
    "sql_archive": _SQL_TYPES,
    "actuator_heapdump": _HEAPDUMP_TYPES,
}


def _origin_url(ctx: ScanContext, asset: AssetRef) -> str:
    parsed_asset = urlsplit(asset.value)
    target = asset.value
    web = ctx.target_details.get("web")
    if isinstance(web, dict) and not web.get("redirect_stopped_out_of_scope"):
        raw_final = web.get("final_url")
        if isinstance(raw_final, str) and raw_final:
            parsed_final = urlsplit(raw_final)
            if (
                parsed_final.scheme.lower() in {"http", "https"}
                and parsed_final.hostname == parsed_asset.hostname
                and (parsed_final.port is None or parsed_final.port in ALLOWED_WEB_PORTS)
            ):
                parsed_asset = parsed_final
                target = raw_final
    parts = urlsplit(target)
    return f"{parts.scheme.lower()}://{parts.netloc}"


def _build_evidence(
    *,
    path: str,
    url: str,
    method: str,
    body: HttpBody,
    extra: dict[str, JsonValue],
) -> RawEvidence:
    content_length = _content_length_header(body)
    if content_length is None and method == "GET":
        content_length = len(body.content)
    data: dict[str, JsonValue] = {
        "path": path,
        "url": url,
        "method": method,
        "status_code": body.status_code,
        "content_type": _media_type(body),
        "content_length": content_length,
    }
    data.update(extra)
    return RawEvidence(kind=EvidenceKind.HTTP_RESPONSE, data=data)


def _fetch_baseline(ctx: ScanContext, origin: str) -> _Soft404Baseline:
    runtime = ctx.runtime
    if runtime is None:
        raise ScannerError("Scanner runtime is not configured.")
    sentinel = f"attacksurf-not-found-{secrets.token_hex(8)}"
    try:
        body = runtime.http.get(f"{origin}/{sentinel}", limit=MAX_EXPOSURE_BODY_BYTES)
    except (DnsError, ScopeError):
        raise TransientJobError("Exposure check failed.") from None
    return _Soft404Baseline(
        status_code=body.status_code,
        media_type=_media_type(body),
        body_len=len(body.content),
        raw_sha256=hashlib.sha256(body.content).hexdigest(),
        norm_sha256=_normalized_hash(body.content, strip_segments=(f"/{sentinel}", sentinel)),
        sentinel_segment=sentinel,
    )


def _evaluate_probe(
    spec: _ProbeSpec,
    body: HttpBody,
    baseline: _Soft404Baseline,
) -> dict[str, JsonValue] | None:
    if spec.method == "HEAD":
        return _validate_head_artifact(body, baseline, _HEAD_TYPES[spec.validator])
    if spec.validator == "admin_panel":
        return _validate_admin_panel(body, spec.path, baseline)
    if _is_soft_404_get(body, spec.path, baseline):
        return None
    validator = _GET_VALIDATORS[spec.validator]
    return validator(body)


@register_scanner
class WebExposures:
    """Probe a fixed, reviewed list of sensitive file, debug, and admin paths on verified hosts."""

    name = "web.exposures"
    asset_types = frozenset({AssetType.URL})
    queue = "active"
    requires_verification = True
    timeout_seconds = 120.0
    grant = ScannerGrant(
        http=HttpPermission.TARGET,
        http_ports=ALLOWED_WEB_PORTS,
        http_methods=frozenset({"GET", "HEAD"}),
        http_paths=EXPOSURE_PATHS,
        soft_404_probe=True,
        follow_redirects=False,
        dns_lookups=DNS_LOOKUPS,
    )

    def run(self, ctx: ScanContext, asset: AssetRef) -> ScanOutput:
        runtime = ctx.runtime
        if runtime is None:
            raise ScannerError("Scanner runtime is not configured.")

        origin = _origin_url(ctx, asset)
        baseline = _fetch_baseline(ctx, origin)
        findings: list[RawFinding] = []
        admin_root_found = False
        security_txt_found = False
        security_txt_checks: list[JsonValue] = []

        for spec in _SPECS:
            if spec.path == _ADMIN_PAIR_FOLLOWUP and admin_root_found:
                continue
            if spec.path == _SECURITY_TXT_PATHS[1] and security_txt_found:
                continue

            url = f"{origin}{spec.path}"
            try:
                body = (
                    runtime.http.head(url)
                    if spec.method == "HEAD"
                    else runtime.http.get(url, limit=MAX_EXPOSURE_BODY_BYTES)
                )
            except (DnsError, ScopeError):
                raise TransientJobError("Exposure check failed.") from None

            matched = _evaluate_probe(spec, body, baseline)
            if spec.path in _SECURITY_TXT_PATHS:
                security_txt_checks.append({"path": spec.path, "status_code": body.status_code})
                if matched is not None:
                    security_txt_found = True
                continue

            if matched is None or spec.rule_id is None:
                continue
            if spec.path == _ADMIN_PAIR_PRIMARY:
                admin_root_found = True

            findings.append(
                RawFinding(
                    rule_id=spec.rule_id,
                    location=spec.path,
                    confidence=Confidence.HIGH,
                    severity=spec.severity,
                    remediation_context={"path": spec.path, "url": url},
                    evidence=(
                        _build_evidence(
                            path=spec.path,
                            url=url,
                            method=spec.method,
                            body=body,
                            extra=matched,
                        ),
                    ),
                )
            )

        if not security_txt_found:
            findings.append(
                RawFinding(
                    rule_id="web.security.security_txt_missing",
                    location="",
                    confidence=Confidence.HIGH,
                    remediation_context={"url": origin},
                    evidence=(
                        RawEvidence(
                            kind=EvidenceKind.HTTP_RESPONSE,
                            data={"url": origin, "checked_paths": security_txt_checks},
                        ),
                    ),
                )
            )

        return ScanOutput(findings=tuple(findings))
