"""The exposure summary eval harness (CI-safe): cases load and expectations pass/fail right."""

import pytest

from attacksurf.ai.schemas import ExposureSummary
from attacksurf.ai.summary import summarize
from tests.eval.summary_cases import SummaryEvalCase, check_summary, load_summary_cases
from tests.fakes import FakeLLMProvider

CASES = load_summary_cases()


def _case(name: str) -> SummaryEvalCase:
    return next(case for case in CASES if case.name == name)


def _meeting(case: SummaryEvalCase) -> ExposureSummary:
    return ExposureSummary.model_validate(
        {
            "headline": f"Summary for {case.summary_input.root_domain}.",
            "key_risks": [
                {"finding_ref": ref, "why": "Real risk from the scan."}
                for ref in sorted(case.expectation.required_key_risks)
            ],
            "notable_assets": [
                {"asset_ref": ref, "reason": "Sensitive host name."}
                for ref in sorted(case.expectation.required_notable_assets)
            ],
            "changes": "Matches the scan diff.",
            "next_actions": ["Review highlighted items."]
            if case.expectation.required_key_risks
            else [],
        }
    )


def test_every_summary_case_loads_with_valid_expectations() -> None:
    assert [case.name for case in CASES] == ["clean_scan", "risky_scan"]
    for case in CASES:
        finding_refs = {finding.ref for finding in case.summary_input.findings}
        asset_refs = {asset.ref for asset in case.summary_input.assets}
        assert case.why, case.name
        assert case.expectation.required_key_risks <= finding_refs, case.name
        assert case.expectation.required_notable_assets <= asset_refs, case.name
        assert case.expectation.forbidden_notable_assets <= asset_refs, case.name


@pytest.mark.parametrize("case", CASES, ids=lambda case: case.name)
def test_a_reply_meeting_every_expectation_passes(case: SummaryEvalCase) -> None:
    assert check_summary(case, _meeting(case)) == []


def test_risky_scan_fails_when_key_risk_or_notable_asset_is_missed() -> None:
    case = _case("risky_scan")
    empty = ExposureSummary.model_validate(
        {
            "headline": "Nothing to report.",
            "key_risks": [],
            "notable_assets": [],
            "changes": "None.",
            "next_actions": [],
        }
    )

    problems = check_summary(case, empty)

    assert "missing required key risks: F1" in problems
    assert "missing required notable assets: A3, A4" in problems


def test_clean_scan_fails_on_invented_risk_or_hallucinated_ref() -> None:
    case = _case("clean_scan")
    hallucinated = ExposureSummary.model_validate(
        {
            "headline": "Phantom risk.",
            "key_risks": [{"finding_ref": "F1", "why": "Invented."}],
            "notable_assets": [{"asset_ref": "A99", "reason": "Invented."}],
            "changes": "None.",
            "next_actions": [],
        }
    )

    problems = check_summary(case, hallucinated)

    assert "unknown finding refs: F1" in problems
    assert "unknown asset refs: A99" in problems
    assert "too many key risks: 1, max 0" in problems
    assert "too many notable assets: 1, max 0" in problems


@pytest.mark.parametrize("case", CASES, ids=lambda case: case.name)
def test_every_summary_case_runs_through_the_real_call_path(case: SummaryEvalCase) -> None:
    provider = FakeLLMProvider(_meeting(case).model_dump_json())

    result = summarize(provider, case.summary_input)

    assert check_summary(case, result.parsed) == []
