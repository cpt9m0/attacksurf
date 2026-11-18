"""Building the provider adapter a resolved config names (#23)."""

import socket

import pytest
from pydantic import SecretStr

from attacksurf.ai import factory
from attacksurf.ai.factory import build_provider
from attacksurf.ai.providers.anthropic import AnthropicProvider
from attacksurf.ai.providers.openai_compat import OpenAICompatProvider
from attacksurf.domain.llm import KeySource, LLMConfig, ProviderKind
from tests.unit.ai.contract import API_KEY

# Keyed by every ProviderKind: a new kind without an adapter fails the lookup below.
ADAPTERS: dict[ProviderKind, type] = {
    ProviderKind.ANTHROPIC: AnthropicProvider,
    ProviderKind.OPENAI_COMPAT: OpenAICompatProvider,
}


def _config(provider: ProviderKind) -> LLMConfig:
    return LLMConfig(
        provider=provider,
        model="test-model",
        api_key=SecretStr(API_KEY),
        source=KeySource.INSTANCE,
        base_url=SecretStr("https://llm.example.test/v1"),
    )


class _AdapterSpy:
    """Stands in for an adapter class and records the config each instance was built from."""

    def __init__(self) -> None:
        self.configs: list[LLMConfig] = []

    def __call__(self, config: LLMConfig) -> object:
        self.configs.append(config)
        return object()


@pytest.mark.parametrize("kind", list(ProviderKind))
def test_build_provider_returns_the_adapter_for_each_provider_kind(kind: ProviderKind) -> None:
    provider = build_provider(_config(kind))

    assert type(provider) is ADAPTERS[kind]


@pytest.mark.parametrize("kind", list(ProviderKind))
def test_build_provider_hands_the_adapter_the_whole_config(
    monkeypatch: pytest.MonkeyPatch, kind: ProviderKind
) -> None:
    # Model, key and base URL all come from this one config, so sources never mix (ADR 0019);
    # each adapter's own tests check that it sends them.
    spy = _AdapterSpy()
    monkeypatch.setattr(factory, ADAPTERS[kind].__name__, spy)
    config = _config(kind)

    build_provider(config)

    assert spy.configs == [config]


@pytest.mark.parametrize("kind", list(ProviderKind))
def test_building_a_provider_makes_no_network_call(
    monkeypatch: pytest.MonkeyPatch, kind: ProviderKind
) -> None:
    def refuse(*args: object, **kwargs: object) -> None:
        raise AssertionError("building a provider opened a connection")

    monkeypatch.setattr(socket, "getaddrinfo", refuse)
    monkeypatch.setattr(socket.socket, "connect", refuse)

    build_provider(_config(kind))


@pytest.mark.parametrize("kind", list(ProviderKind))
def test_built_provider_repr_does_not_show_the_key(kind: ProviderKind) -> None:
    provider = build_provider(_config(kind))

    assert API_KEY not in repr(provider)
