"""Structured logging (structlog) and per-request IDs."""

import logging
import re
import sys
import time
import uuid
from collections.abc import MutableMapping
from typing import Any

import structlog
from flask import Flask, Response, g, request

from attacksurf.config import Settings

REQUEST_ID_HEADER = "X-Request-ID"
# Client-supplied IDs are echoed into logs and headers; restrict them to prevent log injection.
_VALID_REQUEST_ID = re.compile(r"^[A-Za-z0-9-]{1,64}$")
_SENSITIVE_KEY = re.compile(r"secret|token|password|passwd|api_?key|authorization|cookie", re.I)
REDACTED = "***"

log = structlog.get_logger(__name__)


def redact_secrets(
    _logger: Any, _method: str, event_dict: MutableMapping[str, Any]
) -> MutableMapping[str, Any]:
    for key in event_dict:
        if _SENSITIVE_KEY.search(key):
            event_dict[key] = REDACTED
    return event_dict


def configure_logging(settings: Settings) -> None:
    level = logging.getLevelNamesMapping().get(settings.log_level.upper(), logging.INFO)
    logging.basicConfig(format="%(message)s", stream=sys.stdout, level=level, force=True)

    renderer: structlog.typing.Processor = (
        structlog.processors.JSONRenderer() if settings.is_prod else structlog.dev.ConsoleRenderer()
    )
    structlog.configure(
        processors=[
            structlog.contextvars.merge_contextvars,
            structlog.processors.add_log_level,
            structlog.processors.TimeStamper(fmt="iso", utc=True),
            redact_secrets,
            structlog.processors.format_exc_info,
            renderer,
        ],
        wrapper_class=structlog.make_filtering_bound_logger(level),
        logger_factory=structlog.PrintLoggerFactory(file=sys.stdout),
        cache_logger_on_first_use=False,
    )


def resolve_request_id(incoming: str | None) -> str:
    if incoming and _VALID_REQUEST_ID.fullmatch(incoming):
        return incoming
    return uuid.uuid4().hex


def init_request_logging(app: Flask) -> None:
    @app.before_request
    def _bind_request_id() -> None:
        structlog.contextvars.clear_contextvars()
        g.request_id = resolve_request_id(request.headers.get(REQUEST_ID_HEADER))
        g.request_started = time.perf_counter()
        structlog.contextvars.bind_contextvars(request_id=g.request_id)

    @app.after_request
    def _log_request(response: Response) -> Response:
        response.headers[REQUEST_ID_HEADER] = g.request_id
        log.info(
            "request",
            method=request.method,
            path=request.path,
            status=response.status_code,
            duration_ms=round((time.perf_counter() - g.request_started) * 1000, 2),
        )
        return response

    @app.teardown_request
    def _clear_request_id(_exc: BaseException | None) -> None:
        structlog.contextvars.clear_contextvars()
