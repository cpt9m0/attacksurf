"""Vulnerability intelligence domain types, CPE parsing, and version-range matching."""

import re
from dataclasses import dataclass
from datetime import date, datetime

from attacksurf.domain.scanners import ScannerGrant
from attacksurf.domain.scope import HttpPermission

MAX_CVE_DESCRIPTION_CHARS = 2000
MAX_CPE_PART_CHARS = 128
_MIN_CPE23_FIELDS = 6

VULNINTEL_HTTP_HOSTS = frozenset({"services.nvd.nist.gov", "www.cisa.gov", "api.first.org"})
VULNINTEL_GRANT = ScannerGrant(
    http=HttpPermission.SERVICES,
    http_hosts=VULNINTEL_HTTP_HOSTS,
    dns_lookups=10,
)

_CVE_ID_RE = re.compile(r"CVE-\d{4}-\d{4,}")
_PRERELEASE_SEP_RE = re.compile(r"[-~]")
_VER_SPLIT_RE = re.compile(r"[._~\-]+")
_VER_CHUNK_RE = re.compile(r"\d+|[a-z]+")
_CPE_PARTS = frozenset({"a", "o", "h"})
_PRE_RANKS: dict[str, int] = {
    "dev": -5,
    "snapshot": -4,
    "alpha": -3,
    "beta": -2,
    "m": -2,
    "milestone": -2,
    "pre": -1,
    "rc": -1,
}
_POST_WORDS = frozenset({"p", "pl", "patch", "post", "sp", "u", "update", "rev"})


@dataclass(frozen=True)
class CveRecord:
    """Normalized NVD CVE summary metadata."""

    cve_id: str
    description: str = ""
    published_at: datetime | None = None
    last_modified_at: datetime | None = None
    cvss_v3_score: float | None = None
    cvss_v3_vector: str | None = None
    cvss_v4_score: float | None = None
    cvss_v4_vector: str | None = None


@dataclass(frozen=True)
class CpeRange:
    """Affected `(vendor, product)` version constraint linked to one CVE."""

    cve_id: str
    vendor: str
    product: str
    exact_version: str | None = None
    version_start_including: str | None = None
    version_start_excluding: str | None = None
    version_end_including: str | None = None
    version_end_excluding: str | None = None


@dataclass(frozen=True)
class KevEntry:
    """One entry from CISA's Known Exploited Vulnerabilities catalog."""

    cve_id: str
    date_added: date
    short_description: str = ""


@dataclass(frozen=True)
class EpssEntry:
    """One EPSS probability and percentile measurement from FIRST."""

    cve_id: str
    score: float
    percentile: float


@dataclass(frozen=True)
class ProductVulnerability:
    """Matched vulnerability enriched with CVSS, KEV, and EPSS signals."""

    cve_id: str
    description: str
    published_at: datetime | None
    cvss_v3_score: float | None
    cvss_v3_vector: str | None
    cvss_v4_score: float | None
    cvss_v4_vector: str | None
    in_kev: bool
    kev_date_added: date | None
    epss_score: float | None
    epss_percentile: float | None

    @property
    def max_cvss(self) -> float | None:
        scores = [s for s in (self.cvss_v4_score, self.cvss_v3_score) if s is not None]
        return max(scores) if scores else None


@dataclass(frozen=True)
class SyncSummary:
    """Counts and cursors recorded by one `sync_vuln_intel` run."""

    nvd_cves_upserted: int
    nvd_ranges_upserted: int
    kev_updated: int
    epss_updated: int
    nvd_cursor: datetime | None
    kev_catalog_version: str | None
    epss_model_date: str | None


def normalize_cve_id(value: str) -> str | None:
    """Validate and uppercase a CVE identifier."""
    candidate = value.strip().upper()
    return candidate if _CVE_ID_RE.fullmatch(candidate) else None


def normalize_cpe_part(value: str) -> str:
    """Lowercase a CPE attribute (`vendor` or `product`), treating wildcards as empty."""
    cleaned = value.strip().lower()
    return "" if cleaned in {"", "*", "-"} else cleaned


def _split_cpe23(criteria: str) -> list[str]:
    fields: list[str] = []
    current: list[str] = []
    escaped = False
    for ch in criteria:
        if escaped:
            current.append(ch)
            escaped = False
        elif ch == "\\":
            escaped = True
        elif ch == ":":
            fields.append("".join(current))
            current.clear()
        else:
            current.append(ch)
    fields.append("".join(current))
    return fields


def parse_cpe23_uri(criteria: str) -> tuple[str, str, str | None] | None:
    """Extract `(vendor, product, exact_version)` from a CPE 2.3 formatted string."""
    fields = _split_cpe23(criteria.strip())
    if len(fields) < _MIN_CPE23_FIELDS:
        return None
    if fields[0].lower() != "cpe" or fields[1] != "2.3":
        return None
    if fields[2].lower() not in _CPE_PARTS:
        return None
    vendor = normalize_cpe_part(fields[3])
    product = normalize_cpe_part(fields[4])
    if (
        not vendor
        or not product
        or len(vendor) > MAX_CPE_PART_CHARS
        or len(product) > MAX_CPE_PART_CHARS
    ):
        return None
    raw_version = _clean_bound(fields[5])
    if raw_version is not None and not is_valid_version(raw_version):
        raw_version = None
    return vendor, product, raw_version


def is_valid_version(value: str) -> bool:
    """True when `value` carries a concrete version token rather than a wildcard."""
    cleaned = value.strip()
    return bool(cleaned) and cleaned not in {"*", "-"} and any(ch.isdigit() for ch in cleaned)


def _clean_bound(value: str | None) -> str | None:
    if value is None:
        return None
    cleaned = value.strip()
    return None if cleaned in {"", "*", "-"} else cleaned


def _tokenize_version(raw: str) -> tuple[list[int], list[str], bool]:
    cleaned = raw.strip()
    if len(cleaned) > 1 and cleaned[0] in {"v", "V"} and cleaned[1].isdigit():
        cleaned = cleaned[1:]
    cleaned = cleaned.split("+", 1)[0]
    release_part, *rest_parts = _PRERELEASE_SEP_RE.split(cleaned, maxsplit=1)
    release_tokens: list[str] = []
    for segment in _VER_SPLIT_RE.split(release_part):
        if segment:
            release_tokens.extend(_VER_CHUNK_RE.findall(segment.lower()))
    suffix_tokens: list[str] = []
    if rest_parts:
        for segment in _VER_SPLIT_RE.split(rest_parts[0]):
            if segment:
                suffix_tokens.extend(_VER_CHUNK_RE.findall(segment.lower()))
    core: list[int] = []
    idx = 0
    while idx < len(release_tokens) and release_tokens[idx].isdigit():
        core.append(int(release_tokens[idx]))
        idx += 1
    while core and core[-1] == 0:
        core.pop()
    inline_tail = release_tokens[idx:]
    from_separator = not inline_tail and bool(suffix_tokens)
    return core, inline_tail + suffix_tokens, from_separator


def _encode_tokens(tokens: list[str]) -> tuple[tuple[int, int | str], ...]:
    encoded: list[tuple[int, int | str]] = []
    for token in tokens:
        if token.isdigit():
            encoded.append((0, int(token)))
        else:
            encoded.append((1, token))
    return tuple(encoded)


def _qualifier_key(
    tail: list[str], *, from_separator: bool = False
) -> tuple[int, tuple[tuple[int, int | str], ...]]:
    if not tail:
        return (0, ())
    head, rest = tail[0], tail[1:]
    result: tuple[int, tuple[tuple[int, int | str], ...]] = (3, _encode_tokens(tail))
    if head in _PRE_RANKS:
        result = (_PRE_RANKS[head], _encode_tokens(rest))
    elif head in {"a", "b"} and rest and rest[0].isdigit():
        result = (-3 if head == "a" else -2, _encode_tokens(rest))
    elif head == "p" and not rest:
        result = (1, ((0, ord("p")),))
    elif head in _POST_WORDS:
        result = (2, ((1, head), *_encode_tokens(rest)))
    elif len(head) == 1 and head.isalpha():
        result = (1, ((0, ord(head)), *_encode_tokens(rest)))
    elif from_separator:
        rank = -6 if head.isdigit() else -4
        result = (rank, _encode_tokens(tail))
    return result


def compare_versions(left: str, right: str) -> int:
    """Compare two software version strings; returns `-1`, `0`, or `1`."""
    left_core, left_tail, left_sep = _tokenize_version(left)
    right_core, right_tail, right_sep = _tokenize_version(right)
    if left_core != right_core:
        return -1 if left_core < right_core else 1
    left_q = _qualifier_key(left_tail, from_separator=left_sep)
    right_q = _qualifier_key(right_tail, from_separator=right_sep)
    if left_q == right_q:
        return 0
    return -1 if left_q < right_q else 1


def version_matches_range(
    version: str,
    *,
    exact_version: str | None = None,
    version_start_including: str | None = None,
    version_start_excluding: str | None = None,
    version_end_including: str | None = None,
    version_end_excluding: str | None = None,
) -> bool:
    """Check whether `version` falls inside a CPE exact version / boundary interval."""
    if not is_valid_version(version):
        return False
    exact = _clean_bound(exact_version)
    start_inc = _clean_bound(version_start_including)
    start_exc = _clean_bound(version_start_excluding)
    end_inc = _clean_bound(version_end_including)
    end_exc = _clean_bound(version_end_excluding)

    if exact is not None and (not is_valid_version(exact) or compare_versions(version, exact) != 0):
        return False
    bounds = (
        (start_inc, lambda c: c >= 0),
        (start_exc, lambda c: c > 0),
        (end_inc, lambda c: c <= 0),
        (end_exc, lambda c: c < 0),
    )
    for bound, predicate in bounds:
        if bound is None:
            continue
        if not is_valid_version(bound) or not predicate(compare_versions(version, bound)):
            return False
    return True
