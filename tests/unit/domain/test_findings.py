import hashlib
from uuid import UUID

import pytest

from attacksurf.domain.findings import FINGERPRINT_LENGTH, finding_fingerprint

ORG = UUID("00000000-0000-7000-8000-000000000001")
ASSET = UUID("00000000-0000-7000-8000-000000000002")
OTHER = UUID("00000000-0000-7000-8000-000000000003")


def test_fingerprint_is_pinned() -> None:
    # Stored fingerprints must keep matching across releases: changing the scheme means a new
    # version prefix (and a data migration), never a silent change to these values.
    assert finding_fingerprint(ORG, ASSET, "dns.email.dmarc_missing") == (
        "b867ff2c03fc3ebb7d3d4857a37faeffa334d837da070382fd6eae3924ab91c1"
    )
    assert finding_fingerprint(ORG, ASSET, "dns.email.dkim_not_found", "selector1") == (
        "4486da5f43ca4d202aae0f0b49305ba3ea1525d11056ef69789a9553fb68f102"
    )


def test_fingerprint_is_sha256_of_versioned_json_array() -> None:
    payload = f'["v1","{ORG}","{ASSET}","dns.caa.missing",""]'

    assert finding_fingerprint(ORG, ASSET, "dns.caa.missing") == (
        hashlib.sha256(payload.encode()).hexdigest()
    )


def test_fingerprint_is_stable_across_calls() -> None:
    first = finding_fingerprint(ORG, ASSET, "dns.email.dmarc_missing")

    assert finding_fingerprint(ORG, ASSET, "dns.email.dmarc_missing") == first
    assert len(first) == FINGERPRINT_LENGTH


@pytest.mark.parametrize(
    "args",
    [
        (OTHER, ASSET, "dns.email.dmarc_missing", ""),
        (ORG, OTHER, "dns.email.dmarc_missing", ""),
        (ORG, ASSET, "dns.email.spf_missing", ""),
        (ORG, ASSET, "dns.email.dmarc_missing", "x"),
    ],
    ids=["org", "asset", "rule", "location"],
)
def test_fingerprint_changes_with_each_component(args: tuple[UUID, UUID, str, str]) -> None:
    base = finding_fingerprint(ORG, ASSET, "dns.email.dmarc_missing", "")

    assert finding_fingerprint(*args) != base


def test_fingerprint_parts_cannot_bleed_into_each_other() -> None:
    a = finding_fingerprint(ORG, ASSET, "dns.a.b", "c|d")
    b = finding_fingerprint(ORG, ASSET, "dns.a.b|c", "d")

    assert a != b


def test_fingerprint_handles_non_ascii_location() -> None:
    assert finding_fingerprint(ORG, ASSET, "dns.a.b", "bücher") != finding_fingerprint(
        ORG, ASSET, "dns.a.b", "bucher"
    )
