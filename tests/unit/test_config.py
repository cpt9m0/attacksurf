import pytest
from pydantic import SecretStr, ValidationError

from attacksurf.config import get_settings
from tests.helpers import make_settings


def test_settings_defaults_to_dev() -> None:
    settings = make_settings()

    assert settings.env == "dev"
    assert settings.llm_provider == "anthropic"
    assert settings.llm_base_url is None
    assert not settings.is_prod


def test_settings_read_from_environment(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("ENV", "prod")
    monkeypatch.setenv("SECRET_KEY", "from-env")
    monkeypatch.setenv("REDIS_URL", "redis://cache:6379/1")
    monkeypatch.setenv("LLM_PROVIDER", "openai_compat")

    settings = make_settings()

    assert settings.is_prod
    assert settings.secret_key.get_secret_value() == "from-env"
    assert settings.redis_url == "redis://cache:6379/1"
    assert settings.llm_provider == "openai_compat"


def test_empty_env_value_is_treated_as_unset(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("LLM_BASE_URL", "")

    assert make_settings().llm_base_url is None


def test_prod_without_secret_key_fails_fast() -> None:
    with pytest.raises(ValidationError, match="SECRET_KEY must be set"):
        make_settings(env="prod")


def test_dev_without_secret_key_generates_ephemeral_key() -> None:
    first, second = make_settings(), make_settings()

    assert first.secret_key_generated
    assert len(first.secret_key.get_secret_value()) >= 32
    assert first.secret_key.get_secret_value() != second.secret_key.get_secret_value()


def test_explicit_secret_key_is_kept() -> None:
    settings = make_settings(secret_key=SecretStr("given"))

    assert settings.secret_key.get_secret_value() == "given"
    assert not settings.secret_key_generated


def test_secrets_are_not_rendered_in_repr() -> None:
    settings = make_settings(
        secret_key=SecretStr("top-secret"), llm_api_key=SecretStr("sk-live-123")
    )

    assert "top-secret" not in repr(settings)
    assert "sk-live-123" not in repr(settings)


def test_secret_key_generated_cannot_be_set_from_env(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("SECRET_KEY", "given")
    monkeypatch.setenv("SECRET_KEY_GENERATED", "true")

    assert not make_settings().secret_key_generated


def test_get_settings_is_cached() -> None:
    get_settings.cache_clear()

    assert get_settings() is get_settings()
    get_settings.cache_clear()
