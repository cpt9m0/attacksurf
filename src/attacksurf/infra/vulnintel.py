"""External vulnerability intelligence feed clients and parsers (NVD, CISA KEV, FIRST EPSS)."""

import json
import time
from collections.abc import Callable, Mapping, Sequence
from datetime import UTC, date, datetime, timedelta
from typing import Any, Protocol
from urllib.parse import urlencode, urlsplit

from attacksurf.domain.net import HttpBody
from attacksurf.domain.scope import check_addresses, check_public_hostname
from attacksurf.domain.vulnintel import (
    MAX_CPE_PART_CHARS,
    MAX_CVE_DESCRIPTION_CHARS,
    VULNINTEL_HTTP_HOSTS,
    CpeRange,
    CveRecord,
    EpssEntry,
    KevEntry,
    is_valid_version,
    normalize_cve_id,
    parse_cpe23_uri,
)
from attacksurf.infra import public_suffix
from attacksurf.infra.http import AddressResolver, SafeHttpClient

NVD_API_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
CISA_KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
FIRST_EPSS_URL = "https://api.first.org/data/v1/epss"

MAX_VULNINTEL_FEED_BYTES = 16 * 1024 * 1024
NVD_MAX_WINDOW_DAYS = 120
NVD_RESULTS_PER_PAGE = 2000
MAX_NVD_PAGES = 500
NVD_PUBLIC_REQUEST_INTERVAL_SECONDS = 6.0
NVD_API_KEY_REQUEST_INTERVAL_SECONDS = 0.6
NVD_MAX_RETRIES = 3
NVD_RETRY_BASE_SECONDS = 6.0
_MAX_VERSION_BOUND_CHARS = 128
_HTTP_OK = 200
_MAX_CVSS_SCORE = 10.0
_RETRYABLE_NVD_STATUSES = frozenset({403, 429, 503})
_RETRYABLE_HTTP_STATUSES = frozenset({429, 503})


class UpstreamHttpError(ValueError):
    """Non-200 HTTP status returned by an upstream vulnerability feed."""

    def __init__(self, status_code: int) -> None:
        self.status_code = status_code
        super().__init__(f"Upstream feed returned HTTP {status_code}.")


class VulnIntelHttpClient(Protocol):
    """HTTP transport subset needed for vulnerability intelligence feed sync."""

    def get(
        self, url: str, *, limit: int, headers: Mapping[str, str] | None = None
    ) -> HttpBody: ...

    def close(self) -> None: ...


class _PublicAddressResolver:
    """Validate public hostname and resolved IP ranges on every feed lookup (SSRF guard)."""

    def __init__(self, resolver: AddressResolver) -> None:
        self._resolver = resolver

    def resolve_name(self, host: str) -> tuple[str, ...]:
        cleaned = check_public_hostname(host, public_suffix.classify(host))
        return tuple(
            str(address) for address in check_addresses(self._resolver.resolve_name(cleaned))
        )


def _vulnintel_url_allowed(url: str) -> bool:
    try:
        parts = urlsplit(url)
        port = parts.port
    except ValueError:
        return False
    host = (parts.hostname or "").strip().lower().rstrip(".")
    return (
        parts.scheme == "https"
        and host in VULNINTEL_HTTP_HOSTS
        and port in {None, 443}
        and parts.username is None
        and parts.password is None
    )


def build_vulnintel_http_client(
    resolver: AddressResolver, *, user_agent: str | None = None
) -> SafeHttpClient:
    """Return a SafeHttpClient locked down to the approved NVD/CISA/FIRST HTTPS hosts."""
    return SafeHttpClient(
        _PublicAddressResolver(resolver),
        redirect_allowed=_vulnintel_url_allowed,
        max_redirects=2,
        timeout_seconds=30.0,
        max_request_seconds=60.0,
        max_body_bytes=MAX_VULNINTEL_FEED_BYTES,
        user_agent=user_agent,
    )


def _get_json(
    client: VulnIntelHttpClient,
    url: str,
    *,
    limit: int = MAX_VULNINTEL_FEED_BYTES,
    headers: Mapping[str, str] | None = None,
) -> dict[str, Any]:
    body = client.get(url, limit=limit, headers=headers)
    if body.truncated:
        raise ValueError("Upstream response exceeded size cap.")
    if body.status_code != _HTTP_OK:
        raise UpstreamHttpError(body.status_code)
    try:
        parsed = json.loads(body.content)
    except ValueError:
        raise ValueError("Upstream feed returned invalid JSON.") from None
    if not isinstance(parsed, dict):
        raise ValueError("Upstream feed returned a non-object JSON payload.")
    return parsed


def _get_json_with_retry(
    client: VulnIntelHttpClient,
    url: str,
    *,
    limit: int = MAX_VULNINTEL_FEED_BYTES,
    headers: Mapping[str, str] | None = None,
    retry_statuses: frozenset[int] = _RETRYABLE_HTTP_STATUSES,
    max_retries: int = NVD_MAX_RETRIES,
    retry_base_seconds: float = NVD_RETRY_BASE_SECONDS,
    sleep: Callable[[float], None] = time.sleep,
) -> dict[str, Any]:
    for attempt in range(max_retries + 1):
        try:
            return _get_json(client, url, limit=limit, headers=headers)
        except UpstreamHttpError as exc:
            if exc.status_code not in retry_statuses or attempt >= max_retries:
                raise
            sleep(retry_base_seconds * (2**attempt))
    raise AssertionError("unreachable")  # pragma: no cover


def _parse_utc_dt(raw: object) -> datetime | None:
    if not isinstance(raw, str) or not raw.strip():
        return None
    text = raw.strip()
    if text.endswith("Z"):
        text = text[:-1] + "+00:00"
    try:
        dt = datetime.fromisoformat(text)
    except ValueError:
        return None
    return dt.replace(tzinfo=UTC) if dt.tzinfo is None else dt.astimezone(UTC)


def _english_description(descriptions: object) -> str:
    if not isinstance(descriptions, list):
        return ""
    fallback = ""
    for item in descriptions:
        if not isinstance(item, Mapping):
            continue
        value = str(item.get("value", "")).strip()
        if not value:
            continue
        if str(item.get("lang", "")).lower() == "en":
            return value[:MAX_CVE_DESCRIPTION_CHARS]
        if not fallback:
            fallback = value
    return fallback[:MAX_CVE_DESCRIPTION_CHARS]


def _pick_cvss(
    metrics: Mapping[str, Any], keys: tuple[str, ...]
) -> tuple[float | None, str | None]:
    fallback: tuple[float, str | None] | None = None
    for key in keys:
        entries = metrics.get(key)
        if not isinstance(entries, list):
            continue
        for entry in entries:
            if not isinstance(entry, Mapping):
                continue
            cvss_data = entry.get("cvssData")
            if not isinstance(cvss_data, Mapping):
                continue
            raw_score = cvss_data.get("baseScore")
            if not isinstance(raw_score, (int, float)):
                continue
            score = float(raw_score)
            if not 0.0 <= score <= _MAX_CVSS_SCORE:
                continue
            raw_vector = cvss_data.get("vectorString")
            vector = str(raw_vector).strip()[:160] if isinstance(raw_vector, str) else None
            if str(entry.get("type", "")).lower() == "primary":
                return score, vector or None
            if fallback is None:
                fallback = (score, vector or None)
    return fallback if fallback is not None else (None, None)


def _clean_bound_str(raw: object) -> str | None:
    if not isinstance(raw, str):
        return None
    cleaned = raw.strip()
    if not cleaned or len(cleaned) > _MAX_VERSION_BOUND_CHARS or not is_valid_version(cleaned):
        return None
    return cleaned


def _extract_cpe_ranges(cve_id: str, configurations: object) -> list[CpeRange]:
    if not isinstance(configurations, list):
        return []
    collected: list[CpeRange] = []
    for config in configurations:
        if not isinstance(config, Mapping):
            continue
        nodes = config.get("nodes")
        if not isinstance(nodes, list):
            continue
        for node in nodes:
            if not isinstance(node, Mapping):
                continue
            matches = node.get("cpeMatch")
            if not isinstance(matches, list):
                continue
            for match in matches:
                if not isinstance(match, Mapping) or match.get("vulnerable") is not True:
                    continue
                criteria = match.get("criteria")
                if not isinstance(criteria, str):
                    continue
                parsed = parse_cpe23_uri(criteria)
                if parsed is None:
                    continue
                vendor, product, exact_version = parsed
                if len(vendor) > MAX_CPE_PART_CHARS or len(product) > MAX_CPE_PART_CHARS:
                    continue
                collected.append(
                    CpeRange(
                        cve_id=cve_id,
                        vendor=vendor,
                        product=product,
                        exact_version=_clean_bound_str(exact_version),
                        version_start_including=_clean_bound_str(
                            match.get("versionStartIncluding")
                        ),
                        version_start_excluding=_clean_bound_str(
                            match.get("versionStartExcluding")
                        ),
                        version_end_including=_clean_bound_str(match.get("versionEndIncluding")),
                        version_end_excluding=_clean_bound_str(match.get("versionEndExcluding")),
                    )
                )
    return list(dict.fromkeys(collected))


def parse_nvd_page(
    payload: Mapping[str, Any],
) -> tuple[list[CveRecord], dict[str, list[CpeRange]], int, int]:
    """Parse one NVD CVE API 2.0 response page."""
    raw_total = payload.get("totalResults", 0)
    raw_per_page = payload.get("resultsPerPage", NVD_RESULTS_PER_PAGE)
    total_results = int(raw_total) if isinstance(raw_total, int) and raw_total >= 0 else 0
    results_per_page = (
        int(raw_per_page) if isinstance(raw_per_page, int) and raw_per_page > 0 else 0
    )

    records: list[CveRecord] = []
    ranges_by_cve: dict[str, list[CpeRange]] = {}
    vulns = payload.get("vulnerabilities")
    if not isinstance(vulns, list):
        return records, ranges_by_cve, total_results, results_per_page

    for item in vulns:
        if not isinstance(item, Mapping):
            continue
        cve = item.get("cve")
        if not isinstance(cve, Mapping):
            continue
        cve_id = normalize_cve_id(str(cve.get("id", "")))
        if cve_id is None:
            continue
        metrics = cve.get("metrics")
        metrics_map: Mapping[str, Any] = metrics if isinstance(metrics, Mapping) else {}
        v3_score, v3_vector = _pick_cvss(metrics_map, ("cvssMetricV31", "cvssMetricV30"))
        v4_score, v4_vector = _pick_cvss(metrics_map, ("cvssMetricV40",))
        records.append(
            CveRecord(
                cve_id=cve_id,
                description=_english_description(cve.get("descriptions")),
                published_at=_parse_utc_dt(cve.get("published")),
                last_modified_at=_parse_utc_dt(cve.get("lastModified")),
                cvss_v3_score=v3_score,
                cvss_v3_vector=v3_vector[:128] if v3_vector else None,
                cvss_v4_score=v4_score,
                cvss_v4_vector=v4_vector[:160] if v4_vector else None,
            )
        )
        status = str(cve.get("vulnStatus", "")).strip().lower()
        if status == "rejected":
            ranges_by_cve[cve_id] = []
        else:
            ranges_by_cve[cve_id] = _extract_cpe_ranges(cve_id, cve.get("configurations"))

    return records, ranges_by_cve, total_results, results_per_page


def parse_kev_catalog(payload: Mapping[str, Any]) -> tuple[str | None, list[KevEntry]]:
    """Parse CISA's Known Exploited Vulnerabilities JSON catalog."""
    raw_version = payload.get("catalogVersion")
    version = str(raw_version).strip()[:128] if isinstance(raw_version, str) else None
    catalog_version = version or None

    entries_by_cve: dict[str, KevEntry] = {}
    vulns = payload.get("vulnerabilities")
    if not isinstance(vulns, list):
        return catalog_version, []

    for item in vulns:
        if not isinstance(item, Mapping):
            continue
        cve_id = normalize_cve_id(str(item.get("cveID", "")))
        raw_date = item.get("dateAdded")
        if cve_id is None or not isinstance(raw_date, str):
            continue
        try:
            date_added = date.fromisoformat(raw_date.strip())
        except ValueError:
            continue
        short_desc = str(item.get("shortDescription", "")).strip()[:MAX_CVE_DESCRIPTION_CHARS]
        entries_by_cve[cve_id] = KevEntry(
            cve_id=cve_id, date_added=date_added, short_description=short_desc
        )
    return catalog_version, list(entries_by_cve.values())


def parse_epss_response(payload: Mapping[str, Any]) -> tuple[str | None, list[EpssEntry]]:
    """Parse FIRST's EPSS v1 JSON response."""
    rows = payload.get("data")
    if not isinstance(rows, list):
        return None, []

    model_date: str | None = None
    entries_by_cve: dict[str, EpssEntry] = {}
    for row in rows:
        if not isinstance(row, Mapping):
            continue
        cve_id = normalize_cve_id(str(row.get("cve", "")))
        if cve_id is None:
            continue
        try:
            score = float(str(row.get("epss", "")))
            percentile = float(str(row.get("percentile", "")))
        except ValueError:
            continue
        if not (0.0 <= score <= 1.0 and 0.0 <= percentile <= 1.0):
            continue
        raw_date = row.get("date")
        if model_date is None and isinstance(raw_date, str) and raw_date.strip():
            model_date = raw_date.strip()[:128]
        entries_by_cve[cve_id] = EpssEntry(cve_id=cve_id, score=score, percentile=percentile)
    return model_date, list(entries_by_cve.values())


def _format_nvd_ts(dt: datetime) -> str:
    utc_dt = dt.replace(tzinfo=UTC) if dt.tzinfo is None else dt.astimezone(UTC)
    return utc_dt.strftime("%Y-%m-%dT%H:%M:%S.000Z")


def fetch_nvd_modified(
    client: VulnIntelHttpClient,
    *,
    start: datetime,
    end: datetime,
    api_key: str | None = None,
    max_pages: int = MAX_NVD_PAGES,
    request_interval: float | None = None,
    retry_base_seconds: float = NVD_RETRY_BASE_SECONDS,
    max_retries: int = NVD_MAX_RETRIES,
    sleep: Callable[[float], None] = time.sleep,
) -> tuple[list[CveRecord], dict[str, list[CpeRange]]]:
    """Fetch NVD CVEs modified within `[start, end]`, pacing requests for NVD rate limits."""
    if start >= end:
        return [], {}
    headers = {"apiKey": api_key} if api_key else None
    interval = (
        request_interval
        if request_interval is not None
        else (
            NVD_API_KEY_REQUEST_INTERVAL_SECONDS if api_key else NVD_PUBLIC_REQUEST_INTERVAL_SECONDS
        )
    )
    records_by_cve: dict[str, CveRecord] = {}
    ranges_by_cve: dict[str, list[CpeRange]] = {}

    pages_used = 0
    window_start = start
    while window_start < end:
        window_end = min(end, window_start + timedelta(days=NVD_MAX_WINDOW_DAYS))
        start_index = 0
        while pages_used < max_pages:
            if pages_used > 0 and interval > 0:
                sleep(interval)
            query = urlencode(
                {
                    "lastModStartDate": _format_nvd_ts(window_start),
                    "lastModEndDate": _format_nvd_ts(window_end),
                    "resultsPerPage": str(NVD_RESULTS_PER_PAGE),
                    "startIndex": str(start_index),
                }
            )
            payload = _get_json_with_retry(
                client,
                f"{NVD_API_URL}?{query}",
                headers=headers,
                retry_statuses=_RETRYABLE_NVD_STATUSES,
                max_retries=max_retries,
                retry_base_seconds=retry_base_seconds,
                sleep=sleep,
            )
            pages_used += 1
            page_records, page_ranges, total_results, per_page = parse_nvd_page(payload)
            for rec in page_records:
                records_by_cve[rec.cve_id] = rec
            ranges_by_cve.update(page_ranges)
            if not page_records:
                break
            step = max(len(page_records), per_page)
            start_index += step
            if start_index >= total_results:
                break
        window_start = window_end
    return list(records_by_cve.values()), ranges_by_cve


def fetch_kev_catalog(client: VulnIntelHttpClient) -> tuple[str | None, list[KevEntry]]:
    """Download and parse CISA's KEV catalog."""
    payload = _get_json_with_retry(client, CISA_KEV_URL)
    return parse_kev_catalog(payload)


def fetch_epss_scores(
    client: VulnIntelHttpClient, cve_ids: Sequence[str]
) -> tuple[str | None, list[EpssEntry]]:
    """Fetch EPSS scores for one batch of CVE IDs from FIRST."""
    normalized = [cid for raw in cve_ids if (cid := normalize_cve_id(raw)) is not None]
    if not normalized:
        return None, []
    query = urlencode({"cve": ",".join(normalized)})
    payload = _get_json_with_retry(client, f"{FIRST_EPSS_URL}?{query}")
    return parse_epss_response(payload)
