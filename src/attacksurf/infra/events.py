"""Best-effort post-commit handlers, not a durable event bus."""

from collections.abc import Callable

import structlog

from attacksurf.domain.events import DomainEvent


class InProcessDispatcher:
    def __init__(self) -> None:
        self.handlers: list[Callable[[DomainEvent], None]] = []

    def publish(self, event: DomainEvent) -> None:
        for handler in tuple(self.handlers):
            try:
                handler(event)
            except Exception as exc:
                structlog.get_logger(__name__).warning(
                    "event handler failed",
                    event_type=type(event).__name__,
                    error=type(exc).__name__,
                )


dispatcher = InProcessDispatcher()
