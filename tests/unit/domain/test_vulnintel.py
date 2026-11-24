"""Unit tests for domain.vulnintel CPE parsing and version-range matching."""

import pytest

from attacksurf.domain.scope import HttpPermission
from attacksurf.domain.vulnintel import (
    VULNINTEL_GRANT,
    compare_versions,
    is_valid_version,
    normalize_cpe_part,
    normalize_cve_id,
    parse_cpe23_uri,
    version_matches_range,
)


def test_vulnintel_grant_allows_only_expected_reference_feeds() -> None:
    assert VULNINTEL_GRANT.http is HttpPermission.SERVICES
    assert VULNINTEL_GRANT.http_hosts == frozenset(
        {"services.nvd.nist.gov", "www.cisa.gov", "api.first.org"}
    )


@pytest.mark.parametrize(
    ("raw", "expected"),
    [
        ("cve-2024-1234", "CVE-2024-1234"),
        ("  CVE-2025-123456 ", "CVE-2025-123456"),
        ("CVE-2024-123", None),
        ("not-a-cve", None),
    ],
)
def test_normalize_cve_id(raw: str, expected: str | None) -> None:
    assert normalize_cve_id(raw) == expected


@pytest.mark.parametrize(
    ("raw", "expected"),
    [
        ("Nginx", "nginx"),
        ("*", ""),
        ("-", ""),
        ("  ", ""),
    ],
)
def test_normalize_cpe_part(raw: str, expected: str) -> None:
    assert normalize_cpe_part(raw) == expected


@pytest.mark.parametrize(
    ("criteria", "expected"),
    [
        ("cpe:2.3:a:f5:nginx:1.24.0:*:*:*:*:*:*:*", ("f5", "nginx", "1.24.0")),
        ("cpe:2.3:a:apache:http_server:*:*:*:*:*:*:*:*", ("apache", "http_server", None)),
        ("cpe:2.3:o:vendor\\:name:my_os:10.1:*:*:*:*:*:*:*", ("vendor:name", "my_os", "10.1")),
        ("cpe:2.3:h:vendor:device:-:*:*:*:*:*:*:*", ("vendor", "device", None)),
        ("cpe:2.3:a:*:product:1.0:*:*:*:*:*:*:*", None),
        ("cpe:2.3:a:vendor:*:1.0:*:*:*:*:*:*:*", None),
        ("cpe:2.2:a:vendor:product:1.0", None),
        ("cpe:2.3:z:vendor:product:1.0:*:*:*:*:*:*:*", None),
        ("invalid", None),
    ],
)
def test_parse_cpe23_uri(criteria: str, expected: tuple[str, str, str | None] | None) -> None:
    assert parse_cpe23_uri(criteria) == expected


@pytest.mark.parametrize(
    ("left", "right", "expected"),
    [
        ("1.24.0", "1.24", 0),
        ("v1.2.3", "1.2.3", 0),
        ("2024.01", "2024.1", 0),
        ("1.2.3+build.9", "1.2.3", 0),
        ("1.10.0", "1.2.0", 1),
        ("1.2.0", "1.10.0", -1),
        ("1.0.0-dev1", "1.0.0-alpha.1", -1),
        ("1.0.0-alpha.1", "1.0.0-beta.1", -1),
        ("1.0.0-beta.1", "1.0.0-rc.1", -1),
        ("1.0.0-rc.1", "1.0.0", -1),
        ("1.0.0-0", "1.0.0", -1),
        ("1.0.0-1", "1.0.0", -1),
        ("1.0.0-0", "1.0.0-1", -1),
        ("1.0.0-1", "1.0.0-alpha", -1),
        ("1.0.0~1", "1.0.0", -1),
        ("1.0.0-p1", "1.0.0", 1),
        ("1.0.0a1", "1.0.0b1", -1),
        ("1.1.1", "1.1.1a", -1),
        ("1.1.1a", "1.1.1w", -1),
        ("1.1.1p", "1.1.1q", -1),
        ("1.1.1w", "1.1.2", -1),
        ("9.6", "9.6p1", -1),
        ("9.6p1", "9.6p2", -1),
    ],
)
def test_compare_versions_handles_semver_prerelease_and_vendor_suffixes(
    left: str, right: str, expected: int
) -> None:
    assert compare_versions(left, right) == expected
    assert compare_versions(right, left) == -expected


@pytest.mark.parametrize(
    ("version", "kwargs", "expected"),
    [
        # Exact version match only
        ("1.24.0", {"exact_version": "1.24.0"}, True),
        ("1.24", {"exact_version": "1.24.0"}, True),
        ("1.24.1", {"exact_version": "1.24.0"}, False),
        # Lower inclusive bound only (open upper)
        ("2.0.0", {"version_start_including": "2.0.0"}, True),
        ("3.1.0", {"version_start_including": "2.0.0"}, True),
        ("1.9.9", {"version_start_including": "2.0.0"}, False),
        # Lower exclusive bound only
        ("2.0.0", {"version_start_excluding": "2.0.0"}, False),
        ("2.0.1", {"version_start_excluding": "2.0.0"}, True),
        # Upper inclusive bound only (open lower)
        ("1.0.0", {"version_end_including": "1.25.3"}, True),
        ("1.25.3", {"version_end_including": "1.25.3"}, True),
        ("1.25.4", {"version_end_including": "1.25.3"}, False),
        # Upper exclusive bound only
        ("1.25.2", {"version_end_excluding": "1.25.3"}, True),
        ("1.25.3", {"version_end_excluding": "1.25.3"}, False),
        ("1.0.0-1", {"version_end_excluding": "1.0.0"}, True),
        ("1.0.0-0", {"version_end_excluding": "1.0.0"}, True),
        # Combined start + end boundaries
        (
            "1.25.0",
            {"version_start_including": "1.25.0", "version_end_excluding": "1.25.4"},
            True,
        ),
        (
            "1.25.4",
            {"version_start_including": "1.25.0", "version_end_excluding": "1.25.4"},
            False,
        ),
        (
            "1.24.9",
            {"version_start_excluding": "1.24.9", "version_end_including": "1.25.3"},
            False,
        ),
        # Unbounded CPE (`*` across all version fields)
        ("1.0.0", {}, True),
        # Invalid / missing target version never matches
        ("*", {}, False),
        ("", {"version_end_excluding": "2.0.0"}, False),
        ("unknown", {"version_end_excluding": "2.0.0"}, False),
    ],
)
def test_version_matches_range_bounds(version: str, kwargs: dict[str, str], expected: bool) -> None:
    assert version_matches_range(version, **kwargs) is expected


def test_is_valid_version_requires_digits() -> None:
    assert is_valid_version("1.0") is True
    assert is_valid_version("unknown") is False
    assert is_valid_version("*") is False
