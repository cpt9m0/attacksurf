"""The exposure summary eval set against the provider in `.env` (`make eval`; `llm_live`).

Opt-in and never in CI: each case is one real call with the released `summary/v1` prompt on the
developer's key. Record the model and results in the PR of any prompt change.
"""

import pytest

from attacksurf.ai.config import resolve_llm_config
from attacksurf.ai.factory import build_provider
from attacksurf.ai.summary import SUMMARY_PROMPT_VERSION, summarize
from attacksurf.config import Settings
from tests.eval.summary_cases import SummaryEvalCase, check_summary, load_summary_cases

pytestmark = pytest.mark.llm_live


@pytest.mark.parametrize("case", load_summary_cases(), ids=lambda case: case.name)
def test_the_model_summarizes_the_case_as_expected(case: SummaryEvalCase) -> None:
    config = resolve_llm_config(None, Settings())
    assert config is not None

    result = summarize(build_provider(config), case.summary_input)

    problems = check_summary(case, result.parsed)
    outcome = "pass" if not problems else "FAIL: " + "; ".join(problems)
    print(f"\n{case.name} [{config.model}, {SUMMARY_PROMPT_VERSION}]: {outcome}")
    assert not problems, case.why
