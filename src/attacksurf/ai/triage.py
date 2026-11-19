"""Triage calls (ADR 0029): one asset's findings in, one judgment per finding out.

`services/triage.py` builds batches from database rows. A batch holds no database IDs: each
finding gets a batch-local reference (`F1` to `F99`), the only way a reply can point at it.
Everything about a finding goes to the model inside one `scan_data_block`, as untrusted data.
"""

import hashlib
import json
import re
from collections import Counter
from collections.abc import Mapping
from dataclasses import dataclass
from typing import Any

from attacksurf.ai.prompts import load_prompt
from attacksurf.ai.schemas import (
    FINDING_REF_PATTERN,
    MAX_FINDINGS_PER_BATCH,
    FindingTriage,
    TriageReply,
)
from attacksurf.ai.untrusted import scan_data_block
from attacksurf.domain.assets import AssetType
from attacksurf.domain.findings import Confidence, EvidenceKind, Severity
from attacksurf.domain.llm import LLMProvider, LLMResult, Message

TRIAGE_PURPOSE = "triage"  # `LLMUsage.purpose` of every triage call
TRIAGE_PROMPT_VERSION = "triage/v1"
# A cap, not a spend: room for 20 judgments, and for models whose thinking counts against it.
TRIAGE_MAX_TOKENS = 8192
EVIDENCE_ITEMS_PER_FINDING = 5
EVIDENCE_STRING_LENGTH = 2000
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


def build_triage_messages(batch: TriageBatch) -> list[Message]:
    """The released triage prompt with `batch` as its scan data."""
    payload = {
        "asset": {"name": batch.asset_value, "type": batch.asset_type},
        "findings": [_finding_payload(finding) for finding in batch.findings],
    }
    block = scan_data_block(payload, max_string_length=EVIDENCE_STRING_LENGTH)
    return load_prompt(TRIAGE_PROMPT_VERSION).messages(scan_data=block)


def triage_batch(provider: LLMProvider, batch: TriageBatch) -> LLMResult[TriageReply]:
    """One triage call for `batch`. Provider errors (`LLMError`) pass through unchanged."""
    return provider.complete(
        build_triage_messages(batch), schema=TriageReply, max_tokens=TRIAGE_MAX_TOKENS
    )


def match_results(batch: TriageBatch, reply: TriageReply) -> dict[str, FindingTriage]:
    """The reply's judgments by ref, keeping only refs of `batch` that were judged once.

    A ref outside the batch is a hallucination; a ref judged twice has two conflicting answers
    and neither is trusted. Findings left out of the reply simply stay untriaged.
    """
    counts = Counter(judgment.ref for judgment in reply.findings)
    known = {finding.ref for finding in batch.findings}
    return {
        judgment.ref: judgment
        for judgment in reply.findings
        if judgment.ref in known and counts[judgment.ref] == 1
    }


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


def _finding_payload(finding: TriageFinding) -> dict[str, Any]:
    # Only what the model needs to judge the finding; the order is the order it reads.
    return {
        "ref": finding.ref,
        "rule_id": finding.rule_id,
        "title": finding.title,
        "description": finding.description,
        "scanner_severity": finding.severity,
        "scanner_confidence": finding.confidence,
        "location": finding.location,
        "evidence": [
            {"kind": item.kind, "data": item.data}
            for item in finding.evidence[:EVIDENCE_ITEMS_PER_FINDING]
        ],
    }
