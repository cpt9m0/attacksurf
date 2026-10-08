"""Typed application settings, read from environment variables and `.env`."""

import secrets
from functools import lru_cache
from typing import Literal, Self

from pydantic import PrivateAttr, SecretStr, model_validator
from pydantic_settings import BaseSettings, SettingsConfigDict

MIN_PROD_SECRET_KEY_LENGTH = 32
# Values that appear in docs/examples; using one in prod means a publicly known signing key.
_PLACEHOLDER_SECRET_KEYS = frozenset({"change-me", "changeme", "secret", "dev", "test"})


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_file=".env", env_file_encoding="utf-8", env_ignore_empty=True, extra="ignore"
    )

    env: Literal["dev", "test", "prod"] = "dev"
    secret_key: SecretStr = SecretStr("")
    log_level: str = "INFO"

    # URLs can embed passwords, so they are secrets too; unwrap only where connecting.
    # Defaults match the local Docker Compose services (#3); used from #4 / #10 on.
    database_url: SecretStr = SecretStr(
        "postgresql+psycopg://attacksurf:attacksurf@localhost:5432/attacksurf"
    )
    redis_url: SecretStr = SecretStr("redis://localhost:6379/0")

    llm_provider: Literal["anthropic", "openai_compat"] = "anthropic"
    llm_model: str = "claude-sonnet-5-5"
    llm_base_url: str | None = None
    llm_api_key: SecretStr | None = None

    _secret_key_generated: bool = PrivateAttr(default=False)

    @model_validator(mode="after")
    def _require_secret_key(self) -> Self:
        key = self.secret_key.get_secret_value()
        if self.env == "prod":
            if len(key) < MIN_PROD_SECRET_KEY_LENGTH or key.lower() in _PLACEHOLDER_SECRET_KEYS:
                raise ValueError(
                    f"SECRET_KEY must be set to a random value of at least "
                    f"{MIN_PROD_SECRET_KEY_LENGTH} characters when ENV=prod"
                )
            return self
        if not key:
            # Dev/test only: an ephemeral key means sessions reset on every restart.
            self.secret_key = SecretStr(secrets.token_urlsafe(32))
            self._secret_key_generated = True
        return self

    @property
    def secret_key_generated(self) -> bool:
        """True when no SECRET_KEY was given (dev/test only), so callers can warn about it."""
        return self._secret_key_generated

    @property
    def is_prod(self) -> bool:
        return self.env == "prod"


@lru_cache
def get_settings() -> Settings:
    return Settings()
