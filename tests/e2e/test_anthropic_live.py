"""One real Anthropic-format call with the developer's own key (`llm_live`, ADR 0019).

Runs only with `RUN_LLM_TESTS=1` and never in CI (`tests/conftest.py`). Development uses Meta's
endpoint, which speaks this format too; switch format for one run without editing `.env`:

    LLM_PROVIDER=anthropic LLM_BASE_URL=https://api.meta.ai RUN_LLM_TESTS=1 \
        uv run pytest tests/e2e/test_anthropic_live.py -m llm_live --no-cov

It sends only the contract's fixture conversation, never scan data.
"""

import pytest

from attacksurf.ai.config import resolve_llm_config
from attacksurf.ai.providers.anthropic import AnthropicProvider
from attacksurf.config import Settings
from attacksurf.domain.llm import ProviderKind
from tests.unit.ai.contract import CONVERSATION, Verdict

pytestmark = pytest.mark.llm_live


def test_anthropic_format_round_trips_the_contract_schema() -> None:
    config = resolve_llm_config(None, Settings())  # the real `.env`: that's this test's point
    assert config is not None  # the collection guard skips this test without a key and model
    if config.provider is not ProviderKind.ANTHROPIC:
        pytest.skip("needs LLM_PROVIDER=anthropic (and LLM_BASE_URL for a non-Anthropic host)")

    result = AnthropicProvider(config).complete(CONVERSATION, schema=Verdict, max_tokens=1024)

    assert isinstance(result.parsed, Verdict)
    assert result.parsed.reason
    if result.usage.reported:
        assert result.usage.input_tokens > 0
        assert result.usage.output_tokens > 0
