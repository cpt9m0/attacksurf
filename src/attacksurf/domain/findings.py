"""Findings: normalized scanner results, identified across scans by a fingerprint (pure Python)."""

import hashlib
import json
from enum import StrEnum
from uuid import UUID

FINGERPRINT_LENGTH = 64  # SHA-256 hex
MAX_LOCATION_LENGTH = 500
_FINGERPRINT_VERSION = "v1"


class Severity(StrEnum):
    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class Confidence(StrEnum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"


class FindingStatus(StrEnum):
    OPEN = "open"
    FIXED = "fixed"
    ACCEPTED_RISK = "accepted_risk"
    FALSE_POSITIVE = "false_positive"


class EvidenceKind(StrEnum):
    DNS_RECORD = "dns_record"
    HTTP_RESPONSE = "http_response"
    RAW = "raw"


def finding_fingerprint(org_id: UUID, asset_id: UUID, rule_id: str, location: str = "") -> str:
    """Identity of "this issue on this asset", the same in every scan that observes it.

    `location` is a canonical string from the scanner that tells apart several issues of one
    rule on one asset (e.g. a DKIM selector); empty for asset-level issues. Never include
    anything that varies between scans (timestamps, TTLs, record order).
    """
    # A JSON array keeps the parts unambiguous ("a", "b|c" vs "a|b", "c"); the version prefix
    # lets the scheme change later without colliding with stored fingerprints.
    payload = json.dumps(
        [_FINGERPRINT_VERSION, str(org_id), str(asset_id), rule_id, location],
        ensure_ascii=False,
        separators=(",", ":"),
    )
    return hashlib.sha256(payload.encode()).hexdigest()
