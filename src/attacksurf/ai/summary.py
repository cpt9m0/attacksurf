"""Exposure summary contract and input types (ADR 0030): whole-scan context in, summary out.

`services/summary.py` builds `SummaryInput` from database rows. Database IDs ride on
`SummaryFinding` and `SummaryAsset` only so `validate_summary` can map batch-local references
(`F1`..`F25`, `A1`..`A200`) back to real rows; they never enter the prompt.
"""

import re
from dataclasses import dataclass
from datetime import datetime
from typing import Any
from uuid import UUID

from attacksurf.ai.prompts import load_prompt
from attacksurf.ai.schemas import (
    ASSET_REF_PATTERN,
    FINDING_REF_PATTERN,
    MIN_CHAIN_FINDINGS,
    ExposureSummary,
    FalsePositiveLikelihood,
    RiskChain,
    StoredKeyRisk,
    StoredNotableAsset,
    StoredRiskChain,
    StoredSummary,
    TriagePriority,
)
from attacksurf.ai.untrusted import cap, scan_data_block
from attacksurf.domain.assets import AssetType
from attacksurf.domain.findings import Severity
from attacksurf.domain.llm import LLMConfig, LLMProvider, LLMResult, Message

SUMMARY_PURPOSE = "summary"  # `LLMUsage.purpose` of every summary call
SUMMARY_PROMPT_VERSION = "summary/v2"
# A cap, not a spend: room for a full summary, plus thinking tokens on reasoning models.
SUMMARY_MAX_TOKENS = 8192
MAX_SUMMARY_FINDINGS = 25
MAX_SUMMARY_ASSETS = 200
MAX_SUMMARY_WEB_URLS = 50
MAX_SUMMARY_URL_TECHNOLOGIES = 10
MAX_SUMMARY_URL_EXPOSURE_RULES = 8
MAX_SUMMARY_URL_TITLE_LENGTH = 120
MAX_SUMMARY_RATIONALE_LENGTH = 300
MAX_SUMMARY_DIFF_ASSETS = 25
SUMMARY_STRING_LENGTH = 500

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
class SummaryUrlContext:
    """Capped web-layer posture and active exposure summary for one active URL asset."""

    status_code: int | None = None
    title: str = ""
    technologies: tuple[str, ...] = ()
    exposure_counts: tuple[tuple[str, int], ...] = ()
    exposure_rules: tuple[str, ...] = ()


@dataclass(frozen=True)
class SummaryAsset:
    """One active asset under the scan's root."""

    ref: str
    asset_id: UUID
    name: str
    asset_type: AssetType
    web: SummaryUrlContext | None = None


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


@dataclass(frozen=True)
class ValidatedSummary:
    """An `ExposureSummary` with refs mapped to real IDs and unknown/duplicate refs dropped."""

    headline: str
    key_risks: tuple[StoredKeyRisk, ...]
    notable_assets: tuple[StoredNotableAsset, ...]
    changes: str
    next_actions: tuple[str, ...]
    web_exposure: str = ""
    risk_chains: tuple[StoredRiskChain, ...] = ()

    def to_stored(
        self,
        *,
        prompt_version: str,
        config: LLMConfig,
        generated_at: datetime,
    ) -> StoredSummary:
        """Build the `StoredSummary` record to persist on `Scan.ai_summary`."""
        return StoredSummary(
            headline=self.headline,
            web_exposure=self.web_exposure,
            key_risks=list(self.key_risks),
            risk_chains=list(self.risk_chains),
            notable_assets=list(self.notable_assets),
            changes=self.changes,
            next_actions=list(self.next_actions),
            prompt_version=prompt_version,
            provider=config.provider,
            model=config.model,
            generated_at=generated_at,
        )


def build_summary_messages(summary_input: SummaryInput) -> list[Message]:
    """The released summary prompt with `summary_input` as its scan data (no IDs, no evidence)."""
    payload = {
        "root_domain": summary_input.root_domain,
        "changes": None if summary_input.changes is None else _diff_payload(summary_input.changes),
        "findings": [_finding_payload(finding) for finding in summary_input.findings],
        "assets": [_asset_payload(asset) for asset in summary_input.assets],
    }
    block = scan_data_block(
        payload, max_string_length=SUMMARY_STRING_LENGTH, max_items=MAX_SUMMARY_ASSETS
    )
    return load_prompt(SUMMARY_PROMPT_VERSION).messages(scan_data=block)


def summarize(provider: LLMProvider, summary_input: SummaryInput) -> LLMResult[ExposureSummary]:
    """One exposure summary call for `summary_input`. Provider errors pass through unchanged."""
    return provider.complete(
        build_summary_messages(summary_input), schema=ExposureSummary, max_tokens=SUMMARY_MAX_TOKENS
    )


def validate_summary(summary_input: SummaryInput, reply: ExposureSummary) -> ValidatedSummary:
    """Map refs to real finding and asset IDs, dropping unknown and duplicate refs.

    Preserves ranked order by keeping the first occurrence of each known ref. Risk chains with
    any unknown finding ref, unknown asset ref, or fewer than `MIN_CHAIN_FINDINGS` distinct
    findings are dropped completely. A stored summary produced through this function can only
    ever reference finding and asset IDs from the input.
    """
    finding_ids = {finding.ref: finding.finding_id for finding in summary_input.findings}
    asset_ids = {asset.ref: asset.asset_id for asset in summary_input.assets}

    key_risks: list[StoredKeyRisk] = []
    seen_findings: set[str] = set()
    for risk in reply.key_risks:
        finding_id = finding_ids.get(risk.finding_ref)
        if finding_id is None or risk.finding_ref in seen_findings:
            continue
        seen_findings.add(risk.finding_ref)
        key_risks.append(StoredKeyRisk(finding_id=finding_id, why=risk.why))

    notable_assets: list[StoredNotableAsset] = []
    seen_assets: set[str] = set()
    for notable in reply.notable_assets:
        asset_id = asset_ids.get(notable.asset_ref)
        if asset_id is None or notable.asset_ref in seen_assets:
            continue
        seen_assets.add(notable.asset_ref)
        notable_assets.append(StoredNotableAsset(asset_id=asset_id, reason=notable.reason))

    risk_chains = _validate_risk_chains(reply.risk_chains, finding_ids, asset_ids)

    return ValidatedSummary(
        headline=reply.headline,
        web_exposure=reply.web_exposure,
        key_risks=tuple(key_risks),
        risk_chains=tuple(risk_chains),
        notable_assets=tuple(notable_assets),
        changes=reply.changes,
        next_actions=tuple(reply.next_actions),
    )


def _validate_risk_chains(
    chains: list[RiskChain],
    finding_ids: dict[str, UUID],
    asset_ids: dict[str, UUID],
) -> list[StoredRiskChain]:
    validated: list[StoredRiskChain] = []
    seen: set[tuple[frozenset[UUID], UUID | None]] = set()
    for chain in chains:
        asset_id: UUID | None = None
        if chain.asset_ref is not None:
            asset_id = asset_ids.get(chain.asset_ref)
            if asset_id is None:
                continue
        mapped_ids: list[UUID] = []
        valid = True
        for ref in chain.finding_refs:
            finding_id = finding_ids.get(ref)
            if finding_id is None:
                valid = False
                break
            if finding_id not in mapped_ids:
                mapped_ids.append(finding_id)
        if not valid or len(mapped_ids) < MIN_CHAIN_FINDINGS:
            continue
        dedupe_key = (frozenset(mapped_ids), asset_id)
        if dedupe_key in seen:
            continue
        seen.add(dedupe_key)
        validated.append(
            StoredRiskChain(
                title=chain.title,
                finding_ids=mapped_ids,
                asset_id=asset_id,
                why=chain.why,
            )
        )
    return validated


def _diff_payload(diff: SummaryDiff) -> dict[str, Any]:
    return {
        "new_findings": _severity_payload(diff.new_findings),
        "fixed_findings": _severity_payload(diff.fixed_findings),
        "regressed_findings": _severity_payload(diff.regressed_findings),
        "total_findings": _severity_payload(diff.total_findings),
        "new_assets": _asset_changes_payload(diff.new_assets),
        "disappeared_assets": _asset_changes_payload(diff.disappeared_assets),
    }


def _severity_payload(bucket: SummarySeverityCounts) -> dict[str, Any]:
    return {
        "total": bucket.total,
        "by_severity": dict(bucket.by_severity),
    }


def _asset_changes_payload(bucket: SummaryAssetChanges) -> dict[str, Any]:
    return {
        "total": bucket.total,
        "names": list(bucket.names[:MAX_SUMMARY_DIFF_ASSETS]),
    }


def _finding_payload(finding: SummaryFinding) -> dict[str, Any]:
    item: dict[str, Any] = {
        "ref": finding.ref,
        "rule_id": finding.rule_id,
        "title": finding.title,
        "scanner_severity": finding.severity,
        "asset": finding.asset_name,
    }
    if finding.triage is not None:
        item["triage"] = {
            "priority": finding.triage.priority,
            "adjusted_severity": finding.triage.adjusted_severity,
            "false_positive_likelihood": finding.triage.false_positive_likelihood,
            "rationale": cap(finding.triage.rationale, MAX_SUMMARY_RATIONALE_LENGTH),
        }
    return item


def _asset_payload(asset: SummaryAsset) -> dict[str, Any]:
    item: dict[str, Any] = {
        "ref": asset.ref,
        "name": asset.name,
        "type": asset.asset_type,
    }
    if asset.web is not None:
        item["web"] = _url_web_payload(asset.web)
    return item


def _url_web_payload(web: SummaryUrlContext) -> dict[str, Any]:
    payload: dict[str, Any] = {}
    if web.status_code is not None:
        payload["status_code"] = web.status_code
    if web.title:
        payload["title"] = cap(web.title, MAX_SUMMARY_URL_TITLE_LENGTH)
    if web.technologies:
        payload["technologies"] = [
            cap(tech, 80) for tech in web.technologies[:MAX_SUMMARY_URL_TECHNOLOGIES]
        ]
    total_exposures = sum(count for _, count in web.exposure_counts)
    payload["exposure_counts"] = {
        "total": total_exposures,
        "by_severity": dict(web.exposure_counts),
    }
    if web.exposure_rules:
        payload["exposure_rules"] = [
            cap(rule_id, 100) for rule_id in web.exposure_rules[:MAX_SUMMARY_URL_EXPOSURE_RULES]
        ]
    return payload
