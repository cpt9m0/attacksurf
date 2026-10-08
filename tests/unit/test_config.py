import pytest
from pydantic import SecretStr, ValidationError

from attacksurf.config import get_settings
from tests.helpers import PROD_SECRET_KEY, make_settings, settings_from_env


def test_settings_defaults_to_dev() -> None:
    settings = make_settings()

    assert settings.env == "dev"
    assert settings.llm_provider == "anthropic"
    assert settings.llm_base_url is None
    assert not settings.is_prod


def test_settings_read_from_environment(clean_env: pytest.MonkeyPatch) -> None:
    clean_env.setenv("ENV", "prod")
    clean_env.setenv("SECRET_KEY", PROD_SECRET_KEY)
    clean_env.setenv("REDIS_URL", "redis://cache:6379/1")
    clean_env.setenv("LLM_PROVIDER", "openai_compat")

    settings = settings_from_env()

    assert settings.is_prod
    assert settings.secret_key.get_secret_value() == PROD_SECRET_KEY
    assert settings.redis_url.get_secret_value() == "redis://cache:6379/1"
    assert settings.llm_provider == "openai_compat"


def test_empty_env_value_is_treated_as_unset(clean_env: pytest.MonkeyPatch) -> None:
    clean_env.setenv("LLM_BASE_URL", "")

    assert settings_from_env().llm_base_url is None


def test_prod_without_secret_key_fails_fast() -> None:
    with pytest.raises(ValidationError, match="SECRET_KEY must be set"):
        make_settings(env="prod")


@pytest.mark.parametrize("weak", ["x", "change-me", "CHANGE-ME", "a" * 31])
def test_prod_rejects_weak_or_placeholder_secret_key(weak: str) -> None:
    with pytest.raises(ValidationError, match="at least 32 characters"):
        make_settings(env="prod", secret_key=SecretStr(weak))


def test_prod_accepts_strong_secret_key() -> None:
    settings = make_settings(env="prod", secret_key=SecretStr(PROD_SECRET_KEY))

    assert settings.secret_key.get_secret_value() == PROD_SECRET_KEY


def test_helper_settings_ignore_process_environment(clean_env: pytest.MonkeyPatch) -> None:
    clean_env.setenv("ENV", "prod")
    clean_env.setenv("LLM_PROVIDER", "openai_compat")

    settings = make_settings()

    assert settings.env == "dev"
    assert settings.llm_provider == "anthropic"


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


def test_secret_key_generated_cannot_be_set_from_env(clean_env: pytest.MonkeyPatch) -> None:
    clean_env.setenv("SECRET_KEY", "given")
    clean_env.setenv("SECRET_KEY_GENERATED", "true")

    assert not settings_from_env().secret_key_generated


@pytest.mark.usefixtures("clean_env")
def test_get_settings_is_cached() -> None:
    get_settings.cache_clear()

    assert get_settings() is get_settings()
    get_settings.cache_clear()
