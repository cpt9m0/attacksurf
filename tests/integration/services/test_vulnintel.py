"""Integration tests for vulnerability intelligence sync and `match_product` (#74)."""

import json
from collections.abc import Mapping
from datetime import UTC, date, datetime, timedelta

from sqlalchemy import select
from sqlalchemy.orm import Session

from attacksurf.domain.net import HttpBody
from attacksurf.infra.db.models import VulnCpeRange, VulnCve, VulnSyncState
from attacksurf.infra.vulnintel import CISA_KEV_URL, FIRST_EPSS_URL, NVD_API_URL
from attacksurf.services.vulnintel import match_product, sync_vuln_intel


class FakeVulnIntelClient:
    """Recorded fixture client keyed by feed URL prefix."""

    def __init__(self) -> None:
        self.calls: list[tuple[str, dict[str, str] | None]] = []
        self.nvd_pages: list[dict[str, object]] = []
        self.kev_payload: dict[str, object] = {
            "catalogVersion": "2026.11.23",
            "vulnerabilities": [],
        }
        self.epss_payload: dict[str, object] = {"data": []}

    def head(self, url: str, *, headers: object | None = None) -> HttpBody:
        raise AssertionError("vulnintel sync uses GET only")

    def get(self, url: str, *, limit: int, headers: Mapping[str, str] | None = None) -> HttpBody:
        self.calls.append((url, dict(headers) if headers else None))
        if url.startswith(NVD_API_URL):
            payload = (
                self.nvd_pages.pop(0)
                if self.nvd_pages
                else {"totalResults": 0, "vulnerabilities": []}
            )
            return HttpBody(200, json.dumps(payload).encode())
        if url == CISA_KEV_URL:
            return HttpBody(200, json.dumps(self.kev_payload).encode())
        if url.startswith(FIRST_EPSS_URL):
            return HttpBody(200, json.dumps(self.epss_payload).encode())
        raise AssertionError(f"Unexpected URL: {url}")

    def close(self) -> None:
        pass


def _nvd_fixture_initial() -> dict[str, object]:
    return {
        "totalResults": 3,
        "resultsPerPage": 2000,
        "vulnerabilities": [
            {
                "cve": {
                    "id": "CVE-2024-7347",
                    "vulnStatus": "Analyzed",
                    "published": "2024-08-14T16:15:00Z",
                    "lastModified": "2026-11-22T10:00:00Z",
                    "descriptions": [{"lang": "en", "value": "nginx HTTP/3 worker crash"}],
                    "metrics": {
                        "cvssMetricV31": [
                            {
                                "type": "Primary",
                                "cvssData": {"baseScore": 5.9, "vectorString": "CVSS:3.1/V3"},
                            }
                        ]
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
                                        }
                                    ]
                                }
                            ]
                        }
                    ],
                }
            },
            {
                "cve": {
                    "id": "CVE-2023-44487",
                    "vulnStatus": "Analyzed",
                    "published": "2023-10-10T14:00:00Z",
                    "lastModified": "2026-11-22T11:00:00Z",
                    "descriptions": [{"lang": "en", "value": "HTTP/2 Rapid Reset"}],
                    "metrics": {
                        "cvssMetricV31": [
                            {
                                "type": "Primary",
                                "cvssData": {"baseScore": 7.5, "vectorString": "CVSS:3.1/RR"},
                            }
                        ]
                    },
                    "configurations": [
                        {
                            "nodes": [
                                {
                                    "cpeMatch": [
                                        {
                                            "vulnerable": True,
                                            "criteria": "cpe:2.3:a:f5:nginx:*:*:*:*:*:*:*:*",
                                            "versionEndIncluding": "1.25.2",
                                        },
                                        {
                                            "vulnerable": True,
                                            "criteria": "cpe:2.3:a:f5:nginx:1.25.2:*:*:*:*:*:*:*",
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
                    "id": "CVE-2024-8888",
                    "vulnStatus": "Analyzed",
                    "published": "2024-09-01T00:00:00Z",
                    "lastModified": "2026-11-22T12:00:00Z",
                    "descriptions": [{"lang": "en", "value": "Unrelated nginx issue"}],
                    "metrics": {
                        "cvssMetricV31": [
                            {
                                "type": "Primary",
                                "cvssData": {"baseScore": 9.8, "vectorString": "CVSS:3.1/CRIT"},
                            }
                        ]
                    },
                    "configurations": [
                        {
                            "nodes": [
                                {
                                    "cpeMatch": [
                                        {
                                            "vulnerable": True,
                                            "criteria": "cpe:2.3:a:f5:nginx:*:*:*:*:*:*:*:*",
                                            "versionStartExcluding": "1.25.2",
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


def test_sync_vuln_intel_is_incremental_idempotent_and_preserves_enrichment(
    db_session: Session,
) -> None:
    t0 = datetime(2026, 11, 23, 3, 25, tzinfo=UTC)
    client = FakeVulnIntelClient()
    client.nvd_pages = [_nvd_fixture_initial()]
    client.kev_payload = {
        "catalogVersion": "2026.11.23",
        "vulnerabilities": [
            {
                "cveID": "CVE-2023-44487",
                "dateAdded": "2023-10-10",
                "shortDescription": "Rapid Reset",
            }
        ],
    }
    client.epss_payload = {
        "data": [
            {"cve": "CVE-2024-7347", "epss": "0.12", "percentile": "0.80", "date": "2026-11-23"},
            {"cve": "CVE-2023-44487", "epss": "0.94", "percentile": "0.99", "date": "2026-11-23"},
            {"cve": "CVE-2024-8888", "epss": "0.05", "percentile": "0.40", "date": "2026-11-23"},
        ]
    }

    summary1 = sync_vuln_intel(db_session, client, now=t0, nvd_api_key="my-secret-nvd-key")

    assert summary1.nvd_cves_upserted == 3
    assert summary1.nvd_ranges_upserted == 4
    assert summary1.kev_updated == 1
    assert summary1.epss_updated == 3
    assert summary1.kev_catalog_version == "2026.11.23"
    assert summary1.epss_model_date == "2026-11-23"

    nvd_state = db_session.get(VulnSyncState, "nvd")
    assert nvd_state is not None
    assert nvd_state.cursor_timestamp == t0

    # Immediate re-run with same feeds: NVD passes cursor start date, KEV skips same version,
    # EPSS skips already-scored rows, and DB state remains identical.
    client.calls.clear()
    client.nvd_pages = [_nvd_fixture_initial()]
    summary2 = sync_vuln_intel(
        db_session, client, now=t0 + timedelta(minutes=30), nvd_api_key="my-secret-nvd-key"
    )
    assert summary2.kev_updated == 0
    assert summary2.epss_updated == 0
    assert "lastModStartDate=2026-11-23T03%3A25%3A00.000Z" in client.calls[0][0]
    assert not any(url.startswith(FIRST_EPSS_URL) for url, _ in client.calls)

    # Incremental update on next day: NVD updates CVE-2024-7347 description & rejects
    # CVE-2024-8888, while KEV clears CVE-2023-44487 and EPSS skips when model date matches.
    t1 = t0 + timedelta(days=1)
    client.calls.clear()
    client.nvd_pages = [
        {
            "totalResults": 2,
            "resultsPerPage": 2000,
            "vulnerabilities": [
                {
                    "cve": {
                        "id": "CVE-2024-7347",
                        "vulnStatus": "Modified",
                        "published": "2024-08-14T16:15:00Z",
                        "lastModified": "2026-11-24T01:00:00Z",
                        "descriptions": [{"lang": "en", "value": "Updated description"}],
                        "metrics": {
                            "cvssMetricV31": [
                                {
                                    "type": "Primary",
                                    "cvssData": {"baseScore": 6.5, "vectorString": "CVSS:3.1/UPD"},
                                }
                            ]
                        },
                        "configurations": [],
                    }
                },
                {
                    "cve": {
                        "id": "CVE-2024-8888",
                        "vulnStatus": "Rejected",
                        "descriptions": [{"lang": "en", "value": "Rejected"}],
                    }
                },
            ],
        }
    ]
    client.kev_payload = {"catalogVersion": "2026.11.24", "vulnerabilities": []}
    client.epss_payload = {
        "data": [
            {"cve": "CVE-2023-44487", "epss": "0.94", "percentile": "0.99", "date": "2026-11-23"}
        ]
    }
    sync_vuln_intel(db_session, client, now=t1)

    cve_7347 = db_session.get(VulnCve, "CVE-2024-7347")
    assert cve_7347 is not None
    assert cve_7347.description == "Updated description"
    assert cve_7347.cvss_v3_score == 6.5
    assert cve_7347.epss_score == 0.12  # NVD update preserved EPSS score
    assert (
        db_session.scalars(select(VulnCpeRange).where(VulnCpeRange.cve_id == "CVE-2024-8888")).all()
        == []
    )

    cve_44487 = db_session.get(VulnCve, "CVE-2023-44487")
    assert cve_44487 is not None
    assert cve_44487.in_kev is False
    assert cve_44487.kev_date_added is None


def test_match_product_evaluates_bounds_deduplicates_and_orders_kev_first(
    db_session: Session,
) -> None:
    client = FakeVulnIntelClient()
    client.nvd_pages = [_nvd_fixture_initial()]
    client.kev_payload = {
        "catalogVersion": "2026.11.23",
        "vulnerabilities": [
            {
                "cveID": "CVE-2024-7347",
                "dateAdded": "2024-09-01",
                "shortDescription": "KEV",
            }
        ],
    }
    client.epss_payload = {
        "data": [
            {"cve": "CVE-2024-7347", "epss": "0.20", "percentile": "0.80", "date": "2026-11-23"},
            {"cve": "CVE-2023-44487", "epss": "0.95", "percentile": "0.99", "date": "2026-11-23"},
        ]
    }
    sync_vuln_intel(db_session, client, now=datetime(2026, 11, 23, 3, 25, tzinfo=UTC))

    # nginx 1.25.2 matches: CVE-2024-7347 (in [1.25.0, 1.26.2), KEV=True, CVSS 5.9)
    # and CVE-2023-44487 (<= 1.25.2 and exact 1.25.2 -> deduplicated once, KEV=False, CVSS 7.5).
    # CVE-2024-8888 (> 1.25.2) is excluded.
    hits = match_product(db_session, "F5", "nginx", "1.25.2")

    assert [h.cve_id for h in hits] == ["CVE-2024-7347", "CVE-2023-44487"]
    assert hits[0].in_kev is True
    assert hits[0].kev_date_added == date(2024, 9, 1)
    assert hits[1].max_cvss == 7.5

    # Higher version misses CVE-2023-44487 and CVE-2024-7347, hits CVE-2024-8888 (> 1.25.2)
    hits_newer = match_product(db_session, "f5", "nginx", "1.26.2")
    assert [h.cve_id for h in hits_newer] == ["CVE-2024-8888"]

    assert match_product(db_session, "f5", "nginx", "unknown") == ()
    assert match_product(db_session, "*", "nginx", "1.25.2") == ()
