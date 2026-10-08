from typing import Any

from attacksurf.config import Settings


def make_settings(**overrides: Any) -> Settings:
    """Settings that ignore any local .env file, so tests are hermetic."""
    return Settings(_env_file=None, **overrides)  # pyright: ignore[reportCallIssue]
