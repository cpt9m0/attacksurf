"""The triage eval set (ADR 0029): fixture batches, and the judgments a good model must give.

Each case in `tests/fixtures/ai/triage_eval/` is one asset's batch plus, per finding ref, the
priorities, false-positive likelihoods and severity range that count as a pass. Ranges, not
exact answers: models phrase and weigh things differently, but a dangling CNAME is never a P4.
"""

import json
from collections.abc import Mapping
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from attacksurf.ai.schemas import FalsePositiveLikelihood, TriagePriority, TriageReply
from attacksurf.ai.triage import TriageBatch, TriageEvidence, TriageFinding, match_results
from attacksurf.domain.assets import AssetType
from attacksurf.domain.findings import SEVERITY_RANK, Confidence, EvidenceKind, Severity

CASES_DIR = Path(__file__).parents[1] / "fixtures" / "ai" / "triage_eval"


@dataclass(frozen=True)
class Expectation:
    priorities: frozenset[TriagePriority]
    false_positive: frozenset[FalsePositiveLikelihood]
    severity_at_least: Severity = Severity.INFO
    severity_at_most: Severity = Severity.CRITICAL


@dataclass(frozen=True)
class EvalCase:
    name: str
    why: str
    batch: TriageBatch
    expectations: Mapping[str, Expectation]


def load_cases() -> list[EvalCase]:
    """Every case, in file-name order."""
    return [_case(path) for path in sorted(CASES_DIR.glob("*.json"))]


def check(case: EvalCase, reply: TriageReply) -> list[str]:
    """Every way `reply` misses the case's expectations; empty when it passes."""
    judgments = match_results(case.batch, reply)
    problems: list[str] = []
    for ref, expect in case.expectations.items():
        judgment = judgments.get(ref)
        if judgment is None:
            problems.append(f"{ref}: no judgment")
            continue
        if judgment.priority not in expect.priorities:
            problems.append(
                f"{ref}: priority {judgment.priority}, expected {_listed(expect.priorities)}"
            )
        if judgment.false_positive_likelihood not in expect.false_positive:
            problems.append(
                f"{ref}: false positive {judgment.false_positive_likelihood}, "
                f"expected {_listed(expect.false_positive)}"
            )
        rank = SEVERITY_RANK[judgment.adjusted_severity]
        if (
            not SEVERITY_RANK[expect.severity_at_least]
            <= rank
            <= SEVERITY_RANK[expect.severity_at_most]
        ):
            problems.append(
                f"{ref}: severity {judgment.adjusted_severity}, expected "
                f"{expect.severity_at_least} to {expect.severity_at_most}"
            )
    return problems


def _case(path: Path) -> EvalCase:
    data = json.loads(path.read_text(encoding="utf-8"))
    batch = TriageBatch(
        asset_value=data["asset"]["value"],
        asset_type=AssetType(data["asset"]["type"]),
        findings=tuple(_finding(item) for item in data["findings"]),
    )
    return EvalCase(
        name=path.stem,
        why=data["why"],
        batch=batch,
        expectations={ref: _expectation(item) for ref, item in data["expect"].items()},
    )


def _finding(item: Mapping[str, Any]) -> TriageFinding:
    return TriageFinding(
        ref=item["ref"],
        rule_id=item["rule_id"],
        title=item["title"],
        description=item["description"],
        severity=Severity(item["severity"]),
        confidence=Confidence(item["confidence"]),
        location=item["location"],
        evidence=tuple(
            TriageEvidence(EvidenceKind(evidence["kind"]), evidence["data"])
            for evidence in item["evidence"]
        ),
    )


def _expectation(item: Mapping[str, Any]) -> Expectation:
    return Expectation(
        priorities=frozenset(TriagePriority(value) for value in item["priority"]),
        false_positive=frozenset(
            FalsePositiveLikelihood(value) for value in item["false_positive"]
        ),
        severity_at_least=Severity(item.get("severity_at_least", Severity.INFO)),
        severity_at_most=Severity(item.get("severity_at_most", Severity.CRITICAL)),
    )


def _listed(values: frozenset[TriagePriority] | frozenset[FalsePositiveLikelihood]) -> str:
    return " or ".join(sorted(values))
