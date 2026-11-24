"""Unit tests for vulnerability intelligence feed parsers and guarded HTTP client."""

from datetime import UTC, date, datetime

import pytest

from attacksurf.domain.net import HttpBody
from attacksurf.domain.scope import ScopeError
from attacksurf.domain.vulnintel import MAX_CVE_DESCRIPTION_CHARS
from attacksurf.infra.vulnintel import (
    CISA_KEV_URL,
    FIRST_EPSS_URL,
    NVD_API_URL,
    build_vulnintel_http_client,
    fetch_nvd_modified,
    parse_epss_response,
    parse_kev_catalog,
    parse_nvd_page,
)


class _StaticResolver:
    def resolve_name(self, host: str) -> tuple[str, ...]:
        return ("93.184.216.34",)


class _StubVulnClient:
    def __init__(self, responses: list[HttpBody]) -> None:
        self._responses = list(responses)
        self.requests: list[tuple[str, dict[str, str] | None]] = []

    def get(self, url: str, *, limit: int, headers: object | None = None) -> HttpBody:
        hdrs = dict(headers) if isinstance(headers, dict) else None
        self.requests.append((url, hdrs))
        assert self._responses, f"No response queued for {url}"
        return self._responses.pop(0)

    def close(self) -> None:
        pass


def test_build_vulnintel_http_client_allows_approved_hosts_and_blocks_others() -> None:
    client = build_vulnintel_http_client(_StaticResolver())
    try:
        assert client._redirect_allowed is not None
        assert client._redirect_allowed(f"{NVD_API_URL}?startIndex=0") is True
        assert client._redirect_allowed(CISA_KEV_URL) is True
        assert client._redirect_allowed(f"{FIRST_EPSS_URL}?cve=CVE-2024-0001") is True

        assert client._redirect_allowed("http://services.nvd.nist.gov/rest/json/cves/2.0") is False
        assert client._redirect_allowed("https://evil.example/cves.json") is False
        assert client._redirect_allowed("https://services.nvd.nist.gov:8443/feed") is False

        with pytest.raises(ScopeError, match="out of scope"):
            client.get("https://evil.example/payload", limit=1024)
    finally:
        client.close()


def test_parse_nvd_page_extracts_primary_metrics_trimmed_desc_and_rejected_clears_ranges() -> None:
    long_desc = "x" * (MAX_CVE_DESCRIPTION_CHARS + 200)
    payload = {
        "totalResults": 2,
        "resultsPerPage": 2,
        "vulnerabilities": [
            {
                "cve": {
                    "id": "CVE-2024-7347",
                    "vulnStatus": "Analyzed",
                    "published": "2024-08-14T16:15:00.000",
                    "lastModified": "2024-08-15T12:00:00.000Z",
                    "descriptions": [
                        {"lang": "es", "value": "Ignorar"},
                        {"lang": "en", "value": long_desc},
                    ],
                    "metrics": {
                        "cvssMetricV30": [
                            {
                                "type": "Primary",
                                "cvssData": {"baseScore": 5.0, "vectorString": "CVSS:3.0/OLD"},
                            }
                        ],
                        "cvssMetricV31": [
                            {
                                "type": "Secondary",
                                "cvssData": {"baseScore": 6.1, "vectorString": "CVSS:3.1/SEC"},
                            },
                            {
                                "type": "Primary",
                                "cvssData": {
                                    "baseScore": 7.5,
                                    "vectorString": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H",
                                },
                            },
                        ],
                        "cvssMetricV40": [
                            {
                                "type": "Primary",
                                "cvssData": {
                                    "baseScore": 8.7,
                                    "vectorString": "CVSS:4.0/AV:N/AC:L/AT:N/PR:N",
                                },
                            }
                        ],
                    },
                    "configurations": [
                        {
                            "nodes": [
                                {
                                    "cpeMatch": [
                                        {
                                            "vulnerable": True,
                                            "criteria": "cpe:2.3:a:f5:nginx:*:*:*:*:*:*:*:*",
                                            "versionStartIncluding": "1.25.0",
                                            "versionEndExcluding": "1.26.2",
                                        },
                                        {
                                            "vulnerable": True,
                                            "criteria": "cpe:2.3:a:f5:nginx:*:*:*:*:*:*:*:*",
                                            "versionStartIncluding": "1.25.0",
                                            "versionEndExcluding": "1.26.2",
                                        },
                                        {
                                            "vulnerable": False,
                                            "criteria": (
                                                "cpe:2.3:o:linux:linux_kernel:*:*:*:*:*:*:*:*"
                                            ),
                                        },
                                    ]
                                }
                            ]
                        }
                    ],
                }
            },
            {
                "cve": {
                    "id": "CVE-2024-9999",
                    "vulnStatus": "Rejected",
                    "descriptions": [{"lang": "en", "value": "Rejected candidate."}],
                    "configurations": [
                        {
                            "nodes": [
                                {
                                    "cpeMatch": [
                                        {
                                            "vulnerable": True,
                                            "criteria": "cpe:2.3:a:acme:app:1.0:*:*:*:*:*:*:*",
                                        }
                                    ]
                                }
                            ]
                        }
                    ],
                }
            },
        ],
    }

    records, ranges_by_cve, total, per_page = parse_nvd_page(payload)

    assert (total, per_page) == (2, 2)
    assert len(records) == 2
    first = records[0]
    assert first.cve_id == "CVE-2024-7347"
    assert len(first.description) == MAX_CVE_DESCRIPTION_CHARS
    assert first.cvss_v3_score == 7.5
    assert first.cvss_v4_score == 8.7
    assert first.published_at == datetime(2024, 8, 14, 16, 15, tzinfo=UTC)
    assert len(ranges_by_cve["CVE-2024-7347"]) == 1
    assert ranges_by_cve["CVE-2024-7347"][0].vendor == "f5"
    assert ranges_by_cve["CVE-2024-7347"][0].product == "nginx"
    assert ranges_by_cve["CVE-2024-9999"] == []


def test_parse_kev_and_epss_responses() -> None:
    kev_version, kev_entries = parse_kev_catalog(
        {
            "catalogVersion": "2026.11.20",
            "vulnerabilities": [
                {
                    "cveID": "cve-2024-7347",
                    "dateAdded": "2024-09-01",
                    "shortDescription": "HTTP/3 crash",
                },
                {"cveID": "BAD", "dateAdded": "2024-09-01"},
            ],
        }
    )
    assert kev_version == "2026.11.20"
    assert len(kev_entries) == 1
    assert kev_entries[0].cve_id == "CVE-2024-7347"
    assert kev_entries[0].date_added == date(2024, 9, 1)

    model_date, epss_entries = parse_epss_response(
        {
            "data": [
                {
                    "cve": "CVE-2024-7347",
                    "epss": "0.421",
                    "percentile": "0.97",
                    "date": "2026-11-23",
                }
            ]
        }
    )
    assert model_date == "2026-11-23"
    assert len(epss_entries) == 1
    assert epss_entries[0].score == pytest.approx(0.421)
    assert epss_entries[0].percentile == pytest.approx(0.97)


def test_fetch_nvd_modified_chunks_windows_paginates_and_rejects_truncated_body() -> None:
    page1 = (
        b'{"totalResults": 2, "resultsPerPage": 1, '
        b'"vulnerabilities": [{"cve": {"id": "CVE-2024-0001"}}]}'
    )
    page2 = (
        b'{"totalResults": 2, "resultsPerPage": 1, '
        b'"vulnerabilities": [{"cve": {"id": "CVE-2024-0002"}}]}'
    )
    page3 = (
        b'{"totalResults": 1, "resultsPerPage": 1, '
        b'"vulnerabilities": [{"cve": {"id": "CVE-2024-0003"}}]}'
    )
    client = _StubVulnClient([HttpBody(200, page1), HttpBody(200, page2), HttpBody(200, page3)])
    records, _ = fetch_nvd_modified(
        client,
        start=datetime(2026, 1, 1, tzinfo=UTC),
        end=datetime(2026, 5, 10, tzinfo=UTC),
        api_key="test-nvd-key",
    )

    assert [r.cve_id for r in records] == ["CVE-2024-0001", "CVE-2024-0002", "CVE-2024-0003"]
    assert all(hdrs == {"apiKey": "test-nvd-key"} for _url, hdrs in client.requests)
    assert "startIndex=1" in client.requests[1][0]

    truncated_client = _StubVulnClient([HttpBody(200, b"{}", truncated=True)])
    with pytest.raises(ValueError, match="size cap"):
        fetch_nvd_modified(
            truncated_client,
            start=datetime(2026, 11, 1, tzinfo=UTC),
            end=datetime(2026, 11, 2, tzinfo=UTC),
        )
