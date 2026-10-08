"""attacksurf: AI-powered attack surface management."""

from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from attacksurf.app import create_app

__all__ = ["create_app"]


def __getattr__(name: str) -> Any:
    # Lazy so importing an inner layer (attacksurf.domain, attacksurf.config, ...) doesn't
    # load Flask and the web blueprints; `flask --app attacksurf` still finds create_app.
    if name == "create_app":
        from attacksurf.app import create_app  # noqa: PLC0415

        return create_app
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")
