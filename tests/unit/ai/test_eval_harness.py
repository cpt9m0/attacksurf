"""The triage eval harness itself (CI-safe): its cases load, and its checks pass and fail right.

The live run (`make eval`, tests/eval/) needs a real model; this proves the harness without one.
"""

import pytest

from attacksurf.ai.schemas import TriageReply
from attacksurf.ai.triage import build_triage_messages, triage_batch
from attacksurf.domain.findings import SEVERITY_RANK, Severity
from tests.eval.triage_cases import EvalCase, check, load_cases
from tests.fakes import FakeLLMProvider

CASES = load_cases()


def _meeting(case: EvalCase) -> TriageReply:
    """A reply inside every expectation of the case."""
    return TriageReply.model_validate(
        {
            "findings": [
                {
                    "ref": ref,
                    "adjusted_severity": expect.severity_at_least,
                    "confidence": "high",
                    "false_positive_likelihood": min(expect.false_positive),
                    "priority": min(expect.priorities),
                    "rationale": "Matches the evidence.",
                    "exploitability": "",
                    "remediation_steps": [],
                }
                for ref, expect in case.expectations.items()
            ]
        }
    )


def _case(name: str) -> EvalCase:
    return next(case for case in CASES if case.name == name)


def test_every_case_loads_with_expectations_for_its_own_refs() -> None:
    assert [case.name for case in CASES] == [
        "caa_missing",
        "dangling_cname",
        "dkim_selector_guess",
        "injected_txt",
        "spf_permissive",
        "web_env_exposed_prod",
        "web_injected_title",
        "web_kev_behind_admin",
        "web_static_headers",
        "web_x_powered_by",
    ]
    for case in CASES:
        refs = {finding.ref for finding in case.batch.findings}
        assert case.expectations
        assert set(case.expectations) <= refs, case.name
        assert case.why, case.name


def test_every_expected_severity_range_is_possible() -> None:
    for case in CASES:
        for expect in case.expectations.values():
            assert SEVERITY_RANK[expect.severity_at_least] <= SEVERITY_RANK[expect.severity_at_most]


def test_the_acceptance_cases_expect_what_the_issue_asks() -> None:
    takeover = _case("dangling_cname").expectations["F1"]
    benign = _case("dkim_selector_guess").expectations["F1"]
    env_prod = _case("web_env_exposed_prod").expectations["F1"]
    banner = _case("web_x_powered_by").expectations["F1"]
    kev_admin = _case("web_kev_behind_admin").expectations["F1"]
    static_hdr = _case("web_static_headers").expectations["F1"]

    assert takeover.priorities == {"P1", "P2"}  # "gets high priority"
    assert benign.false_positive == {"high"}  # "flagged likely FP"
    assert env_prod.priorities == {"P1", "P2"}
    assert env_prod.severity_at_least is Severity.HIGH
    assert banner.priorities == {"P3", "P4"}
    assert banner.severity_at_most is Severity.LOW
    assert kev_admin.priorities == {"P1", "P2"}
    assert kev_admin.severity_at_least is Severity.HIGH
    assert static_hdr.priorities == {"P3", "P4"}
    assert static_hdr.severity_at_most is Severity.LOW


@pytest.mark.parametrize("case", CASES, ids=lambda case: case.name)
def test_a_reply_inside_every_expectation_passes(case: EvalCase) -> None:
    assert check(case, _meeting(case)) == []


def test_a_wrong_priority_fails() -> None:
    case = _case("dangling_cname")
    reply = _meeting(case).model_copy(deep=True)
    reply.findings[0].priority = "P4"  # type: ignore[assignment]

    assert check(case, reply) == ["F1: priority P4, expected P1 or P2"]


def test_a_missing_or_hallucinated_judgment_fails() -> None:
    case = _case("dangling_cname")
    stray = _meeting(case).model_copy(deep=True)
    stray.findings[0].ref = "F9"

    assert check(case, TriageReply(findings=[])) == ["F1: no judgment"]
    assert check(case, stray) == ["F1: no judgment"]


def test_a_severity_outside_the_range_fails() -> None:
    case = _case("caa_missing")
    reply = _meeting(case).model_copy(deep=True)
    reply.findings[0].adjusted_severity = "critical"  # type: ignore[assignment]

    assert check(case, reply) == ["F1: severity critical, expected info to low"]


@pytest.mark.parametrize("case", CASES, ids=lambda case: case.name)
def test_every_case_runs_through_the_real_call_path(case: EvalCase) -> None:
    provider = FakeLLMProvider(_meeting(case).model_dump_json())

    result = triage_batch(provider, case.batch)

    assert check(case, result.parsed) == []


def test_the_injection_case_stays_inside_the_scan_data_block() -> None:
    user = build_triage_messages(_case("injected_txt").batch)[1].content

    assert user.count("<scan_data>") == 1
    assert user.count("</scan_data>") == 1
    assert "Ignore all previous instructions" in user  # still there, as data


def test_the_web_injection_case_stays_inside_the_scan_data_block() -> None:
    user = build_triage_messages(_case("web_injected_title").batch)[1].content

    assert user.count("<scan_data>") == 1
    assert user.count("</scan_data>") == 1
    assert "Ignore all previous instructions" in user
