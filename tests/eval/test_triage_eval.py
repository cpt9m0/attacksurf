"""The triage eval set against the provider in `.env` (`make eval`; `llm_live`, ADR 0029).

Opt-in and never in CI: each case is one real call with the released prompt, on the developer's
key. A failure prints what the model judged, so prompt versions can be compared case by case.
Record the model and the results in the PR of any prompt change.
"""

import pytest

from attacksurf.ai.config import resolve_llm_config
from attacksurf.ai.factory import build_provider
from attacksurf.ai.triage import TRIAGE_PROMPT_VERSION, triage_batch
from attacksurf.config import Settings
from tests.eval.triage_cases import EvalCase, check, load_cases

pytestmark = pytest.mark.llm_live


@pytest.mark.parametrize("case", load_cases(), ids=lambda case: case.name)
def test_the_model_judges_the_case_as_expected(case: EvalCase) -> None:
    config = resolve_llm_config(None, Settings())  # the real `.env`: that's this test's point
    assert config is not None  # the collection guard skips this test without a key and model

    result = triage_batch(build_provider(config), case.batch)

    problems = check(case, result.parsed)
    outcome = "pass" if not problems else "FAIL: " + "; ".join(problems)
    print(f"\n{case.name} [{config.model}, {TRIAGE_PROMPT_VERSION}]: {outcome}")
    assert not problems, case.why
