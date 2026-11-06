from collections.abc import Callable, Mapping
from typing import Any

from pydantic_settings import BaseSettings, PydanticBaseSettingsSource

from attacksurf.ai.config import resolve_llm_config
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


def llm_live_skip_reason(
    environ: Mapping[str, str], settings: Callable[[], Settings]
) -> str | None:
    """Why `llm_live` tests must not run now, or None when they may (ADR 0019).

    They call a real provider with the developer's own `.env` key, so they run only on request,
    never in CI (GitHub Actions sets `CI`). Settings are only read once live tests are enabled.
    """
    if environ.get("CI"):
        return "llm_live tests never run in CI"
    if environ.get("RUN_LLM_TESTS") != "1":
        return "llm_live tests need RUN_LLM_TESTS=1"
    if resolve_llm_config(None, settings()) is None:
        return "llm_live tests need LLM_API_KEY and LLM_MODEL in .env"
    return None


def settings_from_env(**overrides: Any) -> Settings:
    """Settings read from OS environment variables (no .env), for tests of env loading."""
    return Settings(_env_file=None, **overrides)  # pyright: ignore[reportCallIssue]
