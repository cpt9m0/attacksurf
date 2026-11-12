"""One real OpenAI-compatible call with the developer's own key (`llm_live`, ADR 0019).

Runs only with `RUN_LLM_TESTS=1` and never in CI (`tests/conftest.py`). Development uses Meta's
endpoint (`https://api.meta.ai/v1`); run with `.env` configured or override for one run:

    LLM_PROVIDER=openai_compat LLM_BASE_URL=https://api.meta.ai/v1 RUN_LLM_TESTS=1 \
        uv run pytest tests/e2e/test_openai_compat_live.py -m llm_live --no-cov

It sends only the contract's fixture conversation, never scan data.
"""

import pytest

from attacksurf.ai.config import resolve_llm_config
from attacksurf.ai.providers.openai_compat import OpenAICompatProvider
from attacksurf.config import Settings
from attacksurf.domain.llm import ProviderKind
from tests.unit.ai.contract import CONVERSATION, Verdict

pytestmark = pytest.mark.llm_live


def test_openai_compat_format_round_trips_the_contract_schema() -> None:
    config = resolve_llm_config(None, Settings())  # the real `.env`: that's this test's point
    assert config is not None  # the collection guard skips this test without a key and model
    if config.provider is not ProviderKind.OPENAI_COMPAT:
        pytest.skip("needs LLM_PROVIDER=openai_compat (and LLM_BASE_URL for a non-OpenAI host)")

    result = OpenAICompatProvider(config).complete(CONVERSATION, schema=Verdict, max_tokens=1024)

    assert isinstance(result.parsed, Verdict)
    assert result.parsed.reason
    if result.usage.reported:
        assert result.usage.input_tokens > 0
        assert result.usage.output_tokens > 0
