from typing import Any

from pydantic import SecretStr

from attacksurf.ai.config import resolve_llm_config
from attacksurf.domain.llm import KeySource, LLMConfig, OrgLLMConfig, ProviderKind
from tests.helpers import make_settings

INSTANCE = {
    "llm_provider": "openai_compat",
    "llm_model": "muse-spark-1.3-contributor",
    "llm_base_url": "https://api.meta.ai/v1",
    "llm_api_key": SecretStr("instance-key"),
}


def org_config(**overrides: Any) -> OrgLLMConfig:
    values: dict[str, Any] = {
        "provider": ProviderKind.ANTHROPIC,
        "model": "org-model",
        "api_key": SecretStr("org-key"),
        "base_url": None,
    }
    return OrgLLMConfig(**(values | overrides))


def test_resolve_llm_config_prefers_the_orgs_own_key() -> None:
    config = resolve_llm_config(org_config(), make_settings(**INSTANCE))

    assert config == LLMConfig(
        provider=ProviderKind.ANTHROPIC,
        model="org-model",
        api_key=SecretStr("org-key"),
        source=KeySource.ORG,
    )


def test_resolve_llm_config_never_mixes_org_and_instance_values() -> None:
    config = resolve_llm_config(org_config(), make_settings(**INSTANCE))

    assert config is not None
    assert config.base_url is None
    assert config.model == "org-model"


def test_resolve_llm_config_falls_back_to_the_instance_key() -> None:
    config = resolve_llm_config(org_config(api_key=None), make_settings(**INSTANCE))

    assert config == LLMConfig(
        provider=ProviderKind.OPENAI_COMPAT,
        model="muse-spark-1.3-contributor",
        api_key=SecretStr("instance-key"),
        source=KeySource.INSTANCE,
        base_url=SecretStr("https://api.meta.ai/v1"),
    )


def test_resolve_llm_config_uses_the_instance_key_without_org_settings() -> None:
    config = resolve_llm_config(None, make_settings(**INSTANCE))

    assert config is not None
    assert config.source is KeySource.INSTANCE


def test_resolve_llm_config_is_off_without_any_key() -> None:
    assert resolve_llm_config(None, make_settings(llm_model="some-model")) is None


def test_resolve_llm_config_is_off_when_the_instance_has_no_model() -> None:
    settings = make_settings(llm_api_key=SecretStr("instance-key"))

    assert resolve_llm_config(None, settings) is None


def test_llm_config_repr_hides_the_api_key() -> None:
    config = resolve_llm_config(None, make_settings(**INSTANCE))

    assert "instance-key" not in repr(config)


def test_instance_endpoint_credentials_are_hidden_after_resolution() -> None:
    endpoint = "https://endpoint-user:endpoint-password@gateway.example/v1"
    settings = make_settings(**(INSTANCE | {"llm_base_url": endpoint}))

    config = resolve_llm_config(None, settings)

    assert config is not None
    for value in (settings, config):
        assert "endpoint-user" not in repr(value)
        assert "endpoint-password" not in str(value)
    assert isinstance(config.base_url, SecretStr)
    assert config.base_url.get_secret_value() == endpoint


def test_org_endpoint_credentials_are_hidden_after_resolution() -> None:
    endpoint = "https://org-user:org-password@gateway.example/v1"
    org = org_config(base_url=SecretStr(endpoint))

    config = resolve_llm_config(org, make_settings(**INSTANCE))

    assert config is not None
    for value in (org, config):
        assert "org-user" not in repr(value)
        assert "org-password" not in str(value)
    assert config.base_url is org.base_url
    assert isinstance(config.base_url, SecretStr)
    assert config.base_url.get_secret_value() == endpoint
