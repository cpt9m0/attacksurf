"""Exposure summary contract and input types (ADR 0030): whole-scan context in, summary out.

`services/summary.py` builds `SummaryInput` from database rows. Database IDs ride on
`SummaryFinding` and `SummaryAsset` only so `validate_summary` can map batch-local references
(`F1`..`F25`, `A1`..`A200`) back to real rows; they never enter the prompt.
"""

import re
from dataclasses import dataclass
from uuid import UUID

from attacksurf.ai.schemas import (
    ASSET_REF_PATTERN,
    FINDING_REF_PATTERN,
    FalsePositiveLikelihood,
    TriagePriority,
)
from attacksurf.domain.assets import AssetType
from attacksurf.domain.findings import Severity

SUMMARY_PURPOSE = "summary"  # `LLMUsage.purpose` of every summary call
SUMMARY_PROMPT_VERSION = "summary/v1"
# A cap, not a spend: room for a full summary, plus thinking tokens on reasoning models.
SUMMARY_MAX_TOKENS = 8192
MAX_SUMMARY_FINDINGS = 25
MAX_SUMMARY_ASSETS = 200
MAX_SUMMARY_RATIONALE_LENGTH = 300
MAX_SUMMARY_DIFF_ASSETS = 25

_FINDING_REF = re.compile(FINDING_REF_PATTERN)
_ASSET_REF = re.compile(ASSET_REF_PATTERN)


@dataclass(frozen=True)
class SummarySeverityCounts:
    total: int
    by_severity: tuple[tuple[str, int], ...] = ()


@dataclass(frozen=True)
class SummaryAssetChanges:
    total: int
    names: tuple[str, ...] = ()


@dataclass(frozen=True)
class SummaryDiff:
    """Change stats for one scan from `services.scan_views.parse_diff` (no database IDs)."""

    new_findings: SummarySeverityCounts
    fixed_findings: SummarySeverityCounts
    regressed_findings: SummarySeverityCounts
    total_findings: SummarySeverityCounts
    new_assets: SummaryAssetChanges
    disappeared_assets: SummaryAssetChanges


@dataclass(frozen=True)
class SummaryFindingTriage:
    """Current (non-stale) AI triage context carried into the summary prompt."""

    priority: TriagePriority
    adjusted_severity: Severity
    false_positive_likelihood: FalsePositiveLikelihood
    rationale: str


@dataclass(frozen=True)
class SummaryFinding:
    """One finding observed by the scan, with no raw evidence."""

    ref: str
    finding_id: UUID
    rule_id: str
    title: str
    severity: Severity
    asset_name: str
    triage: SummaryFindingTriage | None = None


@dataclass(frozen=True)
class SummaryAsset:
    """One active asset under the scan's root."""

    ref: str
    asset_id: UUID
    name: str
    asset_type: AssetType


@dataclass(frozen=True)
class SummaryInput:
    """Everything one exposure summary call may see (ADR 0030)."""

    root_domain: str
    changes: SummaryDiff | None
    findings: tuple[SummaryFinding, ...]
    assets: tuple[SummaryAsset, ...]

    def __post_init__(self) -> None:
        # Messages never echo a value: refs and names stay out of logs and job errors.
        if len(self.findings) > MAX_SUMMARY_FINDINGS:
            raise ValueError(f"a summary input holds at most {MAX_SUMMARY_FINDINGS} findings")
        if len(self.assets) > MAX_SUMMARY_ASSETS:
            raise ValueError(f"a summary input holds at most {MAX_SUMMARY_ASSETS} assets")
        finding_refs = [finding.ref for finding in self.findings]
        if not all(_FINDING_REF.fullmatch(ref) for ref in finding_refs):
            raise ValueError("finding refs must be F1 to F99")
        if len(set(finding_refs)) != len(finding_refs):
            raise ValueError("finding refs must be unique within a summary input")
        asset_refs = [asset.ref for asset in self.assets]
        if not all(_ASSET_REF.fullmatch(ref) for ref in asset_refs):
            raise ValueError("asset refs must be A1 to A999")
        if len(set(asset_refs)) != len(asset_refs):
            raise ValueError("asset refs must be unique within a summary input")
