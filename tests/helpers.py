from typing import Any

from pydantic_settings import BaseSettings, PydanticBaseSettingsSource

from attacksurf.config import Settings

# Long enough to pass the ENV=prod secret-key policy.
PROD_SECRET_KEY = "test-only-" + "k" * 32


class _InitOnlySettings(Settings):
    """Ignores OS environment variables and .env: only explicit arguments count."""

    @classmethod
    def settings_customise_sources(
        cls,
        settings_cls: type[BaseSettings],
        init_settings: PydanticBaseSettingsSource,
        env_settings: PydanticBaseSettingsSource,
        dotenv_settings: PydanticBaseSettingsSource,
        file_secret_settings: PydanticBaseSettingsSource,
    ) -> tuple[PydanticBaseSettingsSource, ...]:
        return (init_settings,)


def make_settings(**overrides: Any) -> Settings:
    """Hermetic settings for tests: unaffected by the developer's or CI's environment."""
    return _InitOnlySettings(**overrides)


def settings_from_env(**overrides: Any) -> Settings:
    """Settings read from OS environment variables (no .env), for tests of env loading."""
    return Settings(_env_file=None, **overrides)  # pyright: ignore[reportCallIssue]
