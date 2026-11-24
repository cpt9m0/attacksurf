"""Passive web technology fingerprinting over already-fetched HTTP responses (#73).

Vendored signatures come from `enthec/webappanalyzer` (GPL-3.0; see `fingerprints-NOTICE.md`
beside this module). Matching operates exclusively on headers, Set-Cookie *names* (never
values), HTML `<meta>` tags, `<script src>` attributes, and capped HTML bodies — zero extra
network requests are made.
"""

import json
import re
from collections import deque
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from functools import cache
from html.parser import HTMLParser
from importlib.resources import files
from typing import cast
from urllib.parse import parse_qs, urlsplit

from pydantic import JsonValue

MAX_HTML_PARSE_BYTES = 256 * 1024
MAX_HTML_REGEX_BYTES = 128 * 1024
MAX_SCRIPT_SRCS = 200
MAX_META_VALUES_PER_NAME = 20
MAX_COOKIE_NAMES = 64
MAX_COOKIE_NAME_CHARS = 128
MAX_HEADER_VALUE_CHARS = 256
MAX_TECHNOLOGIES = 50
MAX_VERSION_CHARS = 64
MAX_PATTERN_CHARS = 512
MIN_CONFIDENCE = 0
MAX_CONFIDENCE = 100
DEFAULT_CONFIDENCE = 100

_HTML_CONTENT_TYPES = frozenset({"text/html", "application/xhtml+xml"})
_VERSION_BANNER_HEADERS = (("server", "Server"), ("x-powered-by", "X-Powered-By"))
_VERSION_BANNER_RE = re.compile(
    r"(?:/v?\d+(?:\.\d+)*|[\s(]v?\d+\.\d+(?:\.\d+)*)(?=$|[\s);,/+-])",
    re.IGNORECASE,
)
_TERNARY_GROUP_RE = re.compile(r"\\(\d+)\?([^:]*):([^\\]*)")
_BACKREF_RE = re.compile(r"\\(\d+)")
MAX_WP_PLUGINS = 30
MAX_WP_THEMES = 10
MAX_WP_ASSET_URLS = 300
_WP_ASSET_PATH_RE = re.compile(
    r"/wp-content/(plugins|themes)/([a-z0-9][a-z0-9_-]{0,63})/",
    re.IGNORECASE,
)
_WP_VERSION_RE = re.compile(r"^[0-9][0-9A-Za-z._-]{0,31}$")
_WP_GENERATOR_RE = re.compile(r"^WordPress\s+([0-9][0-9A-Za-z._-]{0,31})(?:\s|$)", re.IGNORECASE)


class FingerprintError(ValueError):
    """Raised when the vendored web fingerprint dataset is malformed or unreadable."""


@dataclass(frozen=True, slots=True)
class PatternSpec:
    """Compiled Wappalyzer-style detection rule (`regex=None` means presence-only)."""

    regex: re.Pattern[str] | None
    version: str | None
    confidence: int


@dataclass(frozen=True, slots=True)
class TechSignature:
    """Normalized passive fingerprint rules for one web technology."""

    name: str
    categories: tuple[str, ...]
    headers: dict[str, tuple[PatternSpec, ...]]
    cookies: tuple[PatternSpec, ...]
    meta: dict[str, tuple[PatternSpec, ...]]
    script_src: tuple[PatternSpec, ...]
    html: tuple[PatternSpec, ...]
    implies: tuple[str, ...]


@dataclass(frozen=True, slots=True)
class Technology:
    """One technology detected on a URL response."""

    name: str
    version: str | None
    categories: tuple[str, ...]
    confidence: int

    def to_dict(self) -> dict[str, JsonValue]:
        """Serialize to the canonical `Asset.details['technologies']` JSON shape."""
        return {
            "name": self.name,
            "version": self.version,
            "categories": list(self.categories),
            "confidence": self.confidence,
        }


@dataclass(slots=True)
class _Accumulator:
    confidence: int = 0
    version: str | None = None
    version_confidence: int = 0
    version_parts: int = 0

    def record(self, *, confidence: int, version: str | None) -> None:
        self.confidence = min(MAX_CONFIDENCE, self.confidence + confidence)
        if not version:
            return
        parts = len(version.split("."))
        if self.version is None or (confidence, parts, len(version)) > (
            self.version_confidence,
            self.version_parts,
            len(self.version),
        ):
            self.version = version
            self.version_confidence = confidence
            self.version_parts = parts


class _SignalHTMLParser(HTMLParser):
    """Extract `<meta>` contents and `<script src>` URLs from untrusted HTML safely."""

    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.meta: dict[str, list[str]] = {}
        self.script_srcs: list[str] = []

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        tag_name = tag.lower()
        attr_map: dict[str, str] = {}
        for raw_key, raw_val in attrs:
            if raw_val is not None:
                key = raw_key.lower()
                if key not in attr_map:
                    attr_map[key] = raw_val
        if tag_name == "meta":
            meta_name = (
                attr_map.get("name") or attr_map.get("property") or attr_map.get("http-equiv") or ""
            )
            norm_name = meta_name.strip().lower()
            content = attr_map.get("content", "")
            if norm_name and len(self.meta.get(norm_name, ())) < MAX_META_VALUES_PER_NAME:
                self.meta.setdefault(norm_name, []).append(content[:MAX_HEADER_VALUE_CHARS])
        elif tag_name == "script":
            src = attr_map.get("src", "").strip()
            if src and len(self.script_srcs) < MAX_SCRIPT_SRCS:
                self.script_srcs.append(src[: MAX_HEADER_VALUE_CHARS * 2])


@cache
def load_fingerprints() -> tuple[TechSignature, ...]:
    """Load, validate, and compile the vendored web fingerprint dataset once per process."""
    try:
        raw = (files(__package__) / "fingerprints.json").read_text(encoding="utf-8")
    except (OSError, UnicodeDecodeError) as exc:
        raise FingerprintError("web fingerprint dataset is unreadable") from exc
    return parse_fingerprints(raw)


def parse_fingerprints(raw: str) -> tuple[TechSignature, ...]:
    """Validate and compile a JSON web fingerprint document."""
    try:
        entries = json.loads(raw)
    except json.JSONDecodeError as exc:
        raise FingerprintError("web fingerprint dataset is invalid JSON") from exc
    if not isinstance(entries, list) or not entries:
        raise FingerprintError("web fingerprint dataset is empty")

    signatures: list[TechSignature] = []
    seen_names: set[str] = set()
    for entry in entries:
        sig = _parse_entry(entry)
        if sig.name in seen_names:
            raise FingerprintError(f"duplicate web fingerprint entry: {sig.name!r}")
        seen_names.add(sig.name)
        signatures.append(sig)

    for sig in signatures:
        for target in sig.implies:
            if target not in seen_names:
                raise FingerprintError(f"{sig.name!r} implies unknown technology {target!r}")
    return tuple(signatures)


def extract_response_headers(headers: Mapping[str, str]) -> dict[str, tuple[str, ...]]:
    """Collect lowercase header values (excluding `set-cookie`), preserving multi-value headers."""
    get_list = getattr(headers, "get_list", None)
    grouped: dict[str, list[str]] = {}
    keys_seen: set[str] = set()
    for raw_key, raw_val in headers.items():
        key = raw_key.strip().lower()
        if not key or key == "set-cookie":
            continue
        if callable(get_list):
            if key in keys_seen:
                continue
            keys_seen.add(key)
            list_fn = cast(Callable[[str], list[str]], get_list)
            grouped[key] = [v for v in list_fn(raw_key) if isinstance(v, str)]
        else:
            grouped.setdefault(key, []).append(raw_val)
    return {k: tuple(v) for k, v in grouped.items()}


def extract_cookie_names(headers: Mapping[str, str]) -> tuple[str, ...]:
    """Return distinct cookie names from `Set-Cookie` headers without keeping values."""
    get_list = getattr(headers, "get_list", None)
    raw_cookies: list[str]
    if callable(get_list):
        list_fn = cast(Callable[[str], list[str]], get_list)
        raw_cookies = [v for v in list_fn("set-cookie") if isinstance(v, str)]
    else:
        raw_cookies = [v for k, v in headers.items() if k.lower() == "set-cookie"]

    names: list[str] = []
    seen: set[str] = set()
    for raw in raw_cookies[:MAX_COOKIE_NAMES]:
        name_part, sep, _value = raw.partition("=")
        name = name_part.strip().replace("\x00", "")[:MAX_COOKIE_NAME_CHARS]
        if not sep or not name or name in seen:
            continue
        seen.add(name)
        names.append(name)
    return tuple(names)


def detect_version_banners(headers: Mapping[str, str]) -> dict[str, str]:
    """Return `Server` / `X-Powered-By` headers that expose an explicit software version."""
    grouped = extract_response_headers(headers)
    disclosed: dict[str, str] = {}
    for key, label in _VERSION_BANNER_HEADERS:
        for raw_val in grouped.get(key, ()):
            cleaned = raw_val.strip().replace("\x00", "")[:MAX_HEADER_VALUE_CHARS]
            if cleaned and _VERSION_BANNER_RE.search(cleaned):
                disclosed[label] = cleaned
                break
    return disclosed


def fingerprint_response(
    headers: Mapping[str, str],
    body: bytes,
    content_type: str = "",
    *,
    signatures: tuple[TechSignature, ...] | None = None,
) -> tuple[Technology, ...]:
    """Detect technologies and versions from captured HTTP headers and body bytes."""
    catalog = load_fingerprints() if signatures is None else signatures
    grouped_headers = extract_response_headers(headers)
    cookie_names = extract_cookie_names(headers)
    meta, script_srcs, html_text = _extract_html_signals(body, content_type)

    matches: dict[str, _Accumulator] = {}
    for sig in catalog:
        acc = _Accumulator()
        _match_mapping(grouped_headers, sig.headers, acc)
        _match_values(cookie_names, sig.cookies, acc)
        _match_mapping(meta, sig.meta, acc)
        _match_values(script_srcs, sig.script_src, acc)
        if html_text and sig.html:
            _match_values((html_text,), sig.html, acc)
        if acc.confidence > 0:
            matches[sig.name] = acc

    by_name = {sig.name: sig for sig in catalog}
    _apply_implies(matches, by_name)

    ordered = sorted(
        (
            Technology(
                name=name,
                version=acc.version,
                categories=by_name[name].categories,
                confidence=acc.confidence,
            )
            for name, acc in matches.items()
        ),
        key=lambda tech: (-tech.confidence, tech.name.lower()),
    )
    return tuple(ordered[:MAX_TECHNOLOGIES])


def _extract_html_signals(
    body: bytes, content_type: str
) -> tuple[dict[str, tuple[str, ...]], tuple[str, ...], str]:
    media_type = content_type.split(";", 1)[0].strip().lower()
    if media_type and media_type not in _HTML_CONTENT_TYPES:
        return {}, (), ""
    if not body:
        return {}, (), ""
    parse_text = body[:MAX_HTML_PARSE_BYTES].decode("utf-8", errors="replace").replace("\x00", "")
    if not media_type and "<" not in parse_text:
        return {}, (), ""

    parser = _SignalHTMLParser()
    try:
        parser.feed(parse_text)
        parser.close()
    except AssertionError:
        # Python 3.12 HTMLParser raises AssertionError on malformed marked sections (<![foo]>).
        pass
    regex_text = body[:MAX_HTML_REGEX_BYTES].decode("utf-8", errors="replace").replace("\x00", "")
    meta = {k: tuple(v) for k, v in parser.meta.items()}
    return meta, tuple(parser.script_srcs), regex_text


def _match_mapping(
    observed: Mapping[str, tuple[str, ...]],
    rules: Mapping[str, tuple[PatternSpec, ...]],
    acc: _Accumulator,
) -> None:
    for key, specs in rules.items():
        values = observed.get(key)
        if values is None:
            continue
        _match_values(values, specs, acc)


def _match_values(
    values: tuple[str, ...], specs: tuple[PatternSpec, ...], acc: _Accumulator
) -> None:
    for spec in specs:
        if spec.regex is None:
            acc.record(confidence=spec.confidence, version=spec.version)
            continue
        for value in values:
            hit = spec.regex.search(value)
            if hit is not None:
                version = _resolve_version(spec.version, hit)
                acc.record(confidence=spec.confidence, version=version)
                break


def _apply_implies(matches: dict[str, _Accumulator], by_name: Mapping[str, TechSignature]) -> None:
    queue: deque[str] = deque(matches)
    seen: set[str] = set()
    while queue:
        name = queue.popleft()
        if name in seen:
            continue
        seen.add(name)
        parent_conf = matches[name].confidence
        sig = by_name[name]
        for implied_name in sig.implies:
            target = matches.get(implied_name)
            if target is None:
                target = _Accumulator()
                target.record(confidence=parent_conf, version=None)
                matches[implied_name] = target
            elif target.confidence < parent_conf:
                target.confidence = parent_conf
            queue.append(implied_name)


def _resolve_version(template: str | None, match: re.Match[str]) -> str | None:
    if not template:
        return None

    def _group_val(group_num: int) -> str:
        if 1 <= group_num <= match.re.groups:
            return match.group(group_num) or ""
        return ""

    resolved = _TERNARY_GROUP_RE.sub(
        lambda m: m.group(2) if _group_val(int(m.group(1))) else m.group(3),
        template,
    )
    resolved = _BACKREF_RE.sub(lambda m: _group_val(int(m.group(1))), resolved)
    cleaned = resolved.strip().replace("\x00", "")[:MAX_VERSION_CHARS]
    return cleaned or None


def _parse_entry(entry: object) -> TechSignature:
    if not isinstance(entry, dict):
        raise FingerprintError("web fingerprint entry must be an object")
    name = entry.get("name")
    categories = entry.get("categories")
    if not isinstance(name, str) or not name:
        raise FingerprintError("web fingerprint entry missing name")
    if not isinstance(categories, list) or not all(isinstance(c, str) and c for c in categories):
        raise FingerprintError(f"{name!r} has invalid categories")

    implies_raw = entry.get("implies", [])
    if not isinstance(implies_raw, list) or not all(isinstance(i, str) and i for i in implies_raw):
        raise FingerprintError(f"{name!r} has invalid implies list")

    headers = _parse_pattern_map(entry.get("headers", {}), field=f"{name}.headers")
    if "set-cookie" in headers:
        raise FingerprintError(
            f"{name}.headers must not contain 'set-cookie'; use the cookies channel"
        )
    return TechSignature(
        name=name,
        categories=tuple(categories),
        headers=headers,
        cookies=_parse_pattern_list(entry.get("cookies", []), field=f"{name}.cookies"),
        meta=_parse_pattern_map(entry.get("meta", {}), field=f"{name}.meta"),
        script_src=_parse_pattern_list(entry.get("script_src", []), field=f"{name}.script_src"),
        html=_parse_pattern_list(entry.get("html", []), field=f"{name}.html"),
        implies=tuple(implies_raw),
    )


def _parse_pattern_map(raw: object, *, field: str) -> dict[str, tuple[PatternSpec, ...]]:
    if not isinstance(raw, dict):
        raise FingerprintError(f"{field} must be an object")
    parsed: dict[str, tuple[PatternSpec, ...]] = {}
    for key, val in raw.items():
        if not isinstance(key, str) or not key:
            raise FingerprintError(f"{field} has empty header/meta key")
        parsed[key.lower()] = _parse_pattern_list(val, field=f"{field}.{key}")
    return parsed


def _parse_pattern_list(raw: object, *, field: str) -> tuple[PatternSpec, ...]:
    if not isinstance(raw, list):
        raise FingerprintError(f"{field} must be a list of patterns")
    return tuple(_compile_pattern(item, field=field) for item in raw)


def _compile_pattern(raw: object, *, field: str) -> PatternSpec:
    if not isinstance(raw, str) or len(raw) > MAX_PATTERN_CHARS:
        raise FingerprintError(f"{field} has invalid pattern")
    regex_str, *mods = raw.split("\\;")
    confidence = DEFAULT_CONFIDENCE
    version: str | None = None
    for mod in mods:
        key, sep, val = mod.partition(":")
        if not sep:
            raise FingerprintError(f"{field} has malformed pattern modifier {mod!r}")
        if key == "version":
            version = val
        elif key == "confidence":
            try:
                confidence = int(val)
            except ValueError as exc:
                raise FingerprintError(f"{field} has bad confidence {val!r}") from exc
            if not (MIN_CONFIDENCE <= confidence <= MAX_CONFIDENCE):
                raise FingerprintError(f"{field} confidence out of range: {confidence}")
        else:
            raise FingerprintError(f"{field} has unsupported modifier {mod!r}")

    if not regex_str:
        return PatternSpec(regex=None, version=version, confidence=confidence)
    try:
        compiled = re.compile(regex_str, re.IGNORECASE)
    except re.error as exc:
        raise FingerprintError(f"{field} has invalid regex {regex_str!r}") from exc
    return PatternSpec(regex=compiled, version=version, confidence=confidence)


class _WordPressPageParser(HTMLParser):
    """Collect `<script src>`, `<link href>`, and `<meta name="generator">` from capped HTML."""

    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.asset_urls: list[str] = []
        self.generators: list[str] = []

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        tag_name = tag.lower()
        attr_map = {k.lower(): v for k, v in attrs if v is not None}
        url: str | None = None
        if tag_name == "script":
            url = attr_map.get("src", "").strip()
        elif tag_name == "link":
            url = attr_map.get("href", "").strip()
        elif tag_name == "meta" and attr_map.get("name", "").strip().lower() == "generator":
            content = attr_map.get("content", "").strip()
            if content and len(self.generators) < MAX_META_VALUES_PER_NAME:
                self.generators.append(content[:MAX_HEADER_VALUE_CHARS])
        if url and len(self.asset_urls) < MAX_WP_ASSET_URLS:
            self.asset_urls.append(url[: MAX_HEADER_VALUE_CHARS * 2])


def _parse_wordpress_html(content: bytes, content_type: str) -> _WordPressPageParser | None:
    media_type = content_type.split(";", 1)[0].strip().lower()
    if media_type and media_type not in _HTML_CONTENT_TYPES:
        return None
    html = content[:MAX_HTML_PARSE_BYTES].decode("utf-8", errors="replace").replace("\x00", "")
    if not html:
        return None
    parser = _WordPressPageParser()
    try:
        parser.feed(html)
        parser.close()
    except AssertionError:
        pass
    return parser


def _keep_wp_asset(target: dict[str, str], slug: str, version: str, *, limit: int) -> None:
    if slug in target:
        if len(version.split(".")) > len(target[slug].split(".")):
            target[slug] = version
        return
    if len(target) < limit:
        target[slug] = version


def extract_wordpress_assets(
    content: bytes, content_type: str
) -> tuple[dict[str, str], dict[str, str]]:
    """Extract WordPress plugin and theme `?ver=` versions already embedded in page HTML."""
    parser = _parse_wordpress_html(content, content_type)
    if parser is None:
        return {}, {}
    plugins: dict[str, str] = {}
    themes: dict[str, str] = {}
    for raw_url in parser.asset_urls:
        try:
            parsed = urlsplit(raw_url)
        except ValueError:
            continue
        if ".." in parsed.path.split("/"):
            continue
        path_match = _WP_ASSET_PATH_RE.search(parsed.path)
        if path_match is None:
            continue
        ver_values = parse_qs(parsed.query).get("ver")
        if not ver_values:
            continue
        raw_ver = ver_values[0].strip()
        if not _WP_VERSION_RE.fullmatch(raw_ver):
            continue
        kind = path_match.group(1).lower()
        slug = path_match.group(2).lower()
        if kind == "plugins":
            _keep_wp_asset(plugins, slug, raw_ver, limit=MAX_WP_PLUGINS)
        else:
            _keep_wp_asset(themes, slug, raw_ver, limit=MAX_WP_THEMES)
    return dict(sorted(plugins.items())), dict(sorted(themes.items()))


def extract_wordpress_generator(content: bytes, content_type: str) -> str | None:
    """Return WordPress core version from `<meta name="generator">`, if present in HTML."""
    parser = _parse_wordpress_html(content, content_type)
    if parser is None:
        return None
    for gen in parser.generators:
        match = _WP_GENERATOR_RE.match(gen)
        if match:
            return match.group(1)
    return None
