"""Turns a resolved `LLMConfig` into the adapter for its API (ADR 0019).

A call site resolves the config first (`ai/config.resolve_llm_config`; None means AI is off, so
skip), then calls `build_provider(config).complete(...)`, then records the outcome with
`services.llm_usage.record_llm_usage`.
"""

from typing import assert_never

from attacksurf.ai.providers.anthropic import AnthropicProvider
from attacksurf.ai.providers.openai_compat import OpenAICompatProvider
from attacksurf.domain.llm import LLMConfig, LLMProvider, ProviderKind


def build_provider(config: LLMConfig) -> LLMProvider:
    """The adapter for `config.provider`, built from that config alone.

    Building only sets up the SDK client; nothing connects until `complete()` is called.
    """
    match config.provider:
        case ProviderKind.ANTHROPIC:
            return AnthropicProvider(config)
        case ProviderKind.OPENAI_COMPAT:
            return OpenAICompatProvider(config)
        case _:
            # pyright flags this line when a new ProviderKind has no case above.
            assert_never(config.provider)
