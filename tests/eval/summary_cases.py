"""The exposure summary eval set (ADR 0030): fixture scans and expectations a good model meets."""

import json
from collections.abc import Mapping
from dataclasses import dataclass
from pathlib import Path
from typing import Any
from uuid import NAMESPACE_URL, uuid5

from attacksurf.ai.schemas import (
    ExposureSummary,
    FalsePositiveLikelihood,
    TriagePriority,
)
from attacksurf.ai.summary import (
    SummaryAsset,
    SummaryAssetChanges,
    SummaryDiff,
    SummaryFinding,
    SummaryFindingTriage,
    SummaryInput,
    SummarySeverityCounts,
    SummaryUrlContext,
)
from attacksurf.domain.assets import AssetType
from attacksurf.domain.findings import Severity

CASES_DIR = Path(__file__).parents[1] / "fixtures" / "ai" / "summary_eval"


@dataclass(frozen=True)
class SummaryExpectation:
    required_key_risks: frozenset[str] = frozenset()
    max_key_risks: int | None = None
    required_notable_assets: frozenset[str] = frozenset()
    forbidden_notable_assets: frozenset[str] = frozenset()
    max_notable_assets: int | None = None
    require_web_exposure: bool = False
    required_risk_chain_findings: tuple[frozenset[str], ...] = ()


@dataclass(frozen=True)
class SummaryEvalCase:
    name: str
    why: str
    summary_input: SummaryInput
    expectation: SummaryExpectation


def load_summary_cases() -> list[SummaryEvalCase]:
    """Every summary eval case, in file-name order."""
    return [_case(path) for path in sorted(CASES_DIR.glob("*.json"))]


def check_summary(case: SummaryEvalCase, reply: ExposureSummary) -> list[str]:
    """Every way `reply` misses the case's expectations; empty when it passes."""
    known_findings = {finding.ref for finding in case.summary_input.findings}
    known_assets = {asset.ref for asset in case.summary_input.assets}
    risk_refs = [risk.finding_ref for risk in reply.key_risks]
    notable_refs = [asset.asset_ref for asset in reply.notable_assets]
    chain_finding_refs = [ref for chain in reply.risk_chains for ref in chain.finding_refs]
    chain_asset_refs = [chain.asset_ref for chain in reply.risk_chains if chain.asset_ref]

    problems: list[str] = []
    unknown_findings = sorted((set(risk_refs) | set(chain_finding_refs)) - known_findings)
    if unknown_findings:
        problems.append(f"unknown finding refs: {', '.join(unknown_findings)}")
    unknown_assets = sorted((set(notable_refs) | set(chain_asset_refs)) - known_assets)
    if unknown_assets:
        problems.append(f"unknown asset refs: {', '.join(unknown_assets)}")

    expect = case.expectation
    if expect.require_web_exposure and not reply.web_exposure.strip():
        problems.append("missing required web_exposure")
    chain_sets = [frozenset(chain.finding_refs) for chain in reply.risk_chains]
    for expected_group in expect.required_risk_chain_findings:
        if not any(expected_group <= group for group in chain_sets):
            problems.append(f"missing risk chain covering: {', '.join(sorted(expected_group))}")
    missing_risks = sorted(expect.required_key_risks - set(risk_refs))
    if missing_risks:
        problems.append(f"missing required key risks: {', '.join(missing_risks)}")
    if expect.max_key_risks is not None and len(risk_refs) > expect.max_key_risks:
        problems.append(f"too many key risks: {len(risk_refs)}, max {expect.max_key_risks}")

    missing_notable = sorted(expect.required_notable_assets - set(notable_refs))
    if missing_notable:
        problems.append(f"missing required notable assets: {', '.join(missing_notable)}")
    forbidden_notable = sorted(expect.forbidden_notable_assets & set(notable_refs))
    if forbidden_notable:
        problems.append(f"unexpected notable assets: {', '.join(forbidden_notable)}")
    if expect.max_notable_assets is not None and len(notable_refs) > expect.max_notable_assets:
        problems.append(
            f"too many notable assets: {len(notable_refs)}, max {expect.max_notable_assets}"
        )
    return problems


def _case(path: Path) -> SummaryEvalCase:
    data = json.loads(path.read_text(encoding="utf-8"))
    summary_input = SummaryInput(
        root_domain=data["root_domain"],
        changes=_diff(data.get("changes")),
        findings=tuple(_finding(path.stem, item) for item in data["findings"]),
        assets=tuple(_asset(path.stem, item) for item in data["assets"]),
    )
    expect_data = data["expect"]
    expectation = SummaryExpectation(
        required_key_risks=frozenset(expect_data.get("required_key_risks", ())),
        max_key_risks=expect_data.get("max_key_risks"),
        required_notable_assets=frozenset(expect_data.get("required_notable_assets", ())),
        forbidden_notable_assets=frozenset(expect_data.get("forbidden_notable_assets", ())),
        max_notable_assets=expect_data.get("max_notable_assets"),
        require_web_exposure=bool(expect_data.get("require_web_exposure", False)),
        required_risk_chain_findings=tuple(
            frozenset(group) for group in expect_data.get("required_risk_chain_findings", ())
        ),
    )
    return SummaryEvalCase(
        name=path.stem,
        why=data["why"],
        summary_input=summary_input,
        expectation=expectation,
    )


def _diff(raw: Mapping[str, Any] | None) -> SummaryDiff | None:
    if raw is None:
        return None
    return SummaryDiff(
        new_findings=_sev(raw["new_findings"]),
        fixed_findings=_sev(raw["fixed_findings"]),
        regressed_findings=_sev(raw["regressed_findings"]),
        total_findings=_sev(raw["total_findings"]),
        new_assets=_asset_changes(raw["new_assets"]),
        disappeared_assets=_asset_changes(raw["disappeared_assets"]),
    )


def _sev(raw: Mapping[str, Any]) -> SummarySeverityCounts:
    return SummarySeverityCounts(
        total=int(raw["total"]),
        by_severity=tuple((k, int(v)) for k, v in raw.get("by_severity", {}).items()),
    )


def _asset_changes(raw: Mapping[str, Any]) -> SummaryAssetChanges:
    return SummaryAssetChanges(total=int(raw["total"]), names=tuple(raw.get("names", ())))


def _finding(case_name: str, item: Mapping[str, Any]) -> SummaryFinding:
    raw_triage = item.get("triage")
    triage = (
        None
        if raw_triage is None
        else SummaryFindingTriage(
            priority=TriagePriority(raw_triage["priority"]),
            adjusted_severity=Severity(raw_triage["adjusted_severity"]),
            false_positive_likelihood=FalsePositiveLikelihood(
                raw_triage["false_positive_likelihood"]
            ),
            rationale=raw_triage["rationale"],
        )
    )
    return SummaryFinding(
        ref=item["ref"],
        finding_id=uuid5(NAMESPACE_URL, f"summary-eval/{case_name}/finding/{item['ref']}"),
        rule_id=item["rule_id"],
        title=item["title"],
        severity=Severity(item["severity"]),
        asset_name=item["asset"],
        triage=triage,
    )


def _asset(case_name: str, item: Mapping[str, Any]) -> SummaryAsset:
    raw_web = item.get("web")
    web = (
        None
        if raw_web is None
        else SummaryUrlContext(
            status_code=raw_web.get("status_code"),
            title=str(raw_web.get("title", "")),
            technologies=tuple(str(t) for t in raw_web.get("technologies", ())),
            exposure_counts=tuple(
                (str(k), int(v)) for k, v in raw_web.get("exposure_counts", {}).items()
            ),
            exposure_rules=tuple(str(r) for r in raw_web.get("exposure_rules", ())),
        )
    )
    return SummaryAsset(
        ref=item["ref"],
        asset_id=uuid5(NAMESPACE_URL, f"summary-eval/{case_name}/asset/{item['ref']}"),
        name=item["name"],
        asset_type=AssetType(item["type"]),
        web=web,
    )
