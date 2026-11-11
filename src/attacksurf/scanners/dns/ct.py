"""Certificate Transparency sources: crt.sh primary, Cert Spotter fallback.

Both services are public data sources declared in the scanner's `ScannerGrant`; every request
still goes through the guarded, pinned HTTP client. Responses are untrusted: names are
normalized, filtered to the scanned root, deduplicated and capped before they become assets.
"""

import json
import re
from collections.abc import Callable, Iterable, Mapping
from dataclasses import dataclass
from urllib.parse import quote, urlencode, urlsplit

from attacksurf.domain.assets import AssetError, normalize_hostname
from attacksurf.domain.net import DnsError, HttpBody, SafeHttpClient
from attacksurf.domain.scope import ScopeError

CRT_SH_HOST = "crt.sh"
CERTSPOTTER_HOST = "api.certspotter.com"
CRT_SH_URL = "https://crt.sh/?q=%25.{root}&output=json"
CERTSPOTTER_URL = "https://api.certspotter.com/v1/issuances"
MAX_RESPONSE_BYTES = 1024 * 1024
MAX_NAMES = 1000
MAX_WILDCARD_CANDIDATES = 20
MAX_CERTSPOTTER_PAGES = 5
HTTP_OK = 200
_NEXT_LINK = re.compile(r'<([^>]+)>\s*;\s*rel="next"')


@dataclass(frozen=True)
class SourceResult:
    """Names under the root and the wildcard zones their certificates mention."""

    names: tuple[str, ...]
    wildcard_zones: tuple[str, ...]
    # False when a page/page cap means the source may have more: such a result is not cached.
    complete: bool = True


def parse_crt_sh(payload: object, root: str) -> SourceResult:
    """SANs from a crt.sh JSON response (`name_value`, newline-separated)."""
    if not isinstance(payload, list):
        raise ValueError("unexpected crt.sh payload")
    raw: list[str] = []
    for entry in payload:
        if not isinstance(entry, dict):
            continue
        for field in ("name_value", "common_name"):
            value = entry.get(field)
            if isinstance(value, str):
                raw.append(value)
    return _collect(raw, root)


def parse_certspotter(payload: object, root: str) -> SourceResult:
    """Names from a Cert Spotter issuance page (`dns_names`)."""
    if not isinstance(payload, list):
        raise ValueError("unexpected Cert Spotter payload")
    raw: list[str] = []
    for entry in payload:
        if not isinstance(entry, dict):
            continue
        names = entry.get("dns_names")
        if isinstance(names, list):
            raw.extend(name for name in names if isinstance(name, str))
    return _collect(raw, root)


def query_sources(http: SafeHttpClient, root: str) -> SourceResult | None:
    """crt.sh first, Cert Spotter when crt.sh fails. None means both sources failed."""
    result = fetch_crt_sh(http, root)
    if result is not None:
        return result
    return fetch_certspotter(http, root)


def fetch_crt_sh(http: SafeHttpClient, root: str) -> SourceResult | None:
    body = _get(http, CRT_SH_URL.format(root=quote(root, safe="")))
    if body is None:
        return None
    return _page(body, root, parse_crt_sh)


def fetch_certspotter(http: SafeHttpClient, root: str) -> SourceResult | None:
    """Paginate the fallback source; a later-page failure returns a partial, uncached result."""
    url: str | None = _certspotter_url(root)
    pages = 0
    names: set[str] = set()
    zones: set[str] = set()
    while url is not None and pages < MAX_CERTSPOTTER_PAGES:
        body = _get(http, url)
        if body is None:
            return None if pages == 0 else _result(names, zones, complete=False)
        page = _page(body, root, parse_certspotter)
        if page is None:
            return None if pages == 0 else _result(names, zones, complete=False)
        names.update(page.names)
        zones.update(page.wildcard_zones)
        pages += 1
        url = _next_link(body.headers)
    # A non-None next URL means the page cap stopped us while the source had more.
    return _result(names, zones, complete=url is None)


def _get(http: SafeHttpClient, url: str) -> HttpBody | None:
    """A complete 200 response, or None for a transport/status/truncation failure."""
    try:
        body = http.get(url, limit=MAX_RESPONSE_BYTES)
    except (DnsError, ScopeError):
        return None
    return None if body.status_code != HTTP_OK or body.truncated else body


def _page[T](body: HttpBody, root: str, parser: Callable[[object, str], T]) -> T | None:
    try:
        return parser(_json(body), root)
    except (ValueError, RecursionError):
        return None


def _collect(raw: Iterable[str], root: str) -> SourceResult:
    names: set[str] = set()
    zones: set[str] = set()
    for value in raw:
        for candidate in value.splitlines():
            name = candidate.strip().removesuffix(".")
            if not name:
                continue
            if name.startswith("*."):
                zone = under_root(name[2:], root)
                if zone is not None:
                    zones.add(zone)
                name = name[2:]
            normalized = under_root(name, root)
            if normalized is not None and normalized != root:
                names.add(normalized)
    return _result(names, zones)


def under_root(raw: str, root: str) -> str | None:
    """A normalized name equal to `root` or under it; None for anything else or invalid."""
    candidate = raw.strip().removesuffix(".")
    if not candidate or "*" in candidate:
        return None
    try:
        name = normalize_hostname(candidate)
    except (AssetError, ValueError, UnicodeError):
        return None
    if name != root and not name.endswith(f".{root}"):
        return None
    return name


def _result(names: Iterable[str], zones: Iterable[str], complete: bool = True) -> SourceResult:
    ordered_names = tuple(sorted(set(names), key=_order)[:MAX_NAMES])
    ordered_zones = tuple(sorted(set(zones), key=_order)[:MAX_WILDCARD_CANDIDATES])
    return SourceResult(ordered_names, ordered_zones, complete)


def _order(name: str) -> tuple[int, str]:
    """Shallow names first, then alphabetical: a deterministic cut when a cap applies."""
    return (name.count("."), name)


def _certspotter_url(root: str) -> str:
    query = urlencode({"domain": root, "include_subdomains": "true", "expand": "dns_names"})
    return f"{CERTSPOTTER_URL}?{query}"


def _next_link(headers: Mapping[str, str]) -> str | None:
    link = _header(headers, "link")
    match = _NEXT_LINK.search(link or "")
    if match is None:
        return None
    url = match.group(1)
    try:
        parts = urlsplit(url)
    except ValueError:
        return None
    if parts.scheme != "https" or parts.hostname != CERTSPOTTER_HOST:
        return None
    return url


def _header(headers: Mapping[str, str], wanted: str) -> str | None:
    for name, value in headers.items():
        if name.lower() == wanted:
            return value
    return None


def _json(body: HttpBody) -> object:
    try:
        return json.loads(body.content.decode("utf-8"))
    except UnicodeDecodeError:
        raise ValueError("response is not UTF-8 JSON") from None
