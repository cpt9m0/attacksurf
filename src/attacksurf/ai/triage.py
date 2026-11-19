"""Triage inputs (ADR 0029): one asset's findings, as a triage call will describe them.

`services/triage.py` builds batches from database rows. A batch holds no database IDs: each
finding gets a batch-local reference (`F1` to `F99`), the only way a reply can point at it.
"""

import hashlib
import json
import re
from collections.abc import Mapping
from dataclasses import dataclass
from typing import Any

from attacksurf.ai.schemas import FINDING_REF_PATTERN, MAX_FINDINGS_PER_BATCH
from attacksurf.domain.assets import AssetType
from attacksurf.domain.findings import Confidence, EvidenceKind, Severity

TRIAGE_PURPOSE = "triage"  # `LLMUsage.purpose` of every triage call
_CACHE_KEY_VERSION = "v1"
_REF = re.compile(FINDING_REF_PATTERN)


@dataclass(frozen=True)
class TriageEvidence:
    kind: EvidenceKind
    data: Mapping[str, Any]


@dataclass(frozen=True)
class TriageFinding:
    """One normalized finding: scanner output only, never anything the AI produced."""

    ref: str
    rule_id: str
    title: str
    description: str
    severity: Severity
    confidence: Confidence
    location: str
    evidence: tuple[TriageEvidence, ...] = ()


@dataclass(frozen=True)
class TriageBatch:
    """One asset's findings for one LLM call."""

    asset_value: str
    asset_type: AssetType
    findings: tuple[TriageFinding, ...]

    def __post_init__(self) -> None:
        # Messages never echo a value: refs and asset names stay out of logs and job errors.
        if not 1 <= len(self.findings) <= MAX_FINDINGS_PER_BATCH:
            raise ValueError(f"a triage batch holds 1 to {MAX_FINDINGS_PER_BATCH} findings")
        refs = [finding.ref for finding in self.findings]
        # A ref the reply schema rejects could never be matched back to its finding.
        if not all(_REF.fullmatch(ref) for ref in refs):
            raise ValueError("finding refs must be F1 to F99")
        if len(set(refs)) != len(refs):
            raise ValueError("finding refs must be unique within a batch")


def triage_cache_key(
    prompt_version: str, model: str, fingerprint: str, evidence_digest: str | None
) -> str:
    """SHA-256 hex naming one judgment: a finding is triaged again only when a part changes.

    Same scheme as `finding_fingerprint`: a JSON array keeps the parts unambiguous, and the
    version prefix lets the scheme change without colliding with stored keys.
    """
    payload = json.dumps(
        [_CACHE_KEY_VERSION, prompt_version, model, fingerprint, evidence_digest],
        ensure_ascii=False,
        separators=(",", ":"),
    )
    return hashlib.sha256(payload.encode()).hexdigest()
