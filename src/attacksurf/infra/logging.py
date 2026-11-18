"""Structured logging (structlog) and per-request IDs."""

import logging
import re
import sys
import time
import uuid
from collections.abc import Mapping, MutableMapping
from typing import Any

import structlog
from flask import Flask, Response, g, request

from attacksurf.config import Settings

REQUEST_ID_HEADER = "X-Request-ID"
# Client-supplied IDs are echoed into logs and headers; restrict them to prevent log injection.
_VALID_REQUEST_ID = re.compile(r"^[A-Za-z0-9-]{1,64}$")
_SENSITIVE_KEY = re.compile(
    r"secret|token|password|passwd|api_?key|encryption_?key|private_?key|signing_?key|"
    r"old_keys|key_envelope|ciphertext|authorization|cookie|credential|base_?url",
    re.I,
)
# Redact credentials embedded inside URLs (e.g. https://user:pass@host/v1).
_URL_CREDENTIALS = re.compile(r"([a-z][a-z0-9+.-]*://)([^/\s:@]+(?::[^@\s]*)?)@", re.I)
REDACTED = "***"

log = structlog.get_logger(__name__)


def _scrub_value(value: Any) -> Any:
    if isinstance(value, str):
        return _URL_CREDENTIALS.sub(rf"\1{REDACTED}@", value)
    if isinstance(value, Mapping):
        return {
            key: REDACTED
            if isinstance(key, str) and _SENSITIVE_KEY.search(key)
            else _scrub_value(item)
            for key, item in value.items()
        }
    if isinstance(value, list):
        return [_scrub_value(item) for item in value]
    if isinstance(value, tuple):
        return tuple(_scrub_value(item) for item in value)
    return value


def redact_secrets(
    _logger: Any, _method: str, event_dict: MutableMapping[str, Any]
) -> MutableMapping[str, Any]:
    for key in list(event_dict):
        if _SENSITIVE_KEY.search(key):
            event_dict[key] = REDACTED
        else:
            event_dict[key] = _scrub_value(event_dict[key])
    return event_dict


def configure_logging(settings: Settings) -> None:
    """Route structlog *and* stdlib logging (Flask, Werkzeug, libraries) through one pipeline,
    so every line is JSON in prod and carries the request ID."""
    level = logging.getLevelNamesMapping().get(settings.log_level.upper(), logging.INFO)
    shared: list[structlog.typing.Processor] = [
        structlog.contextvars.merge_contextvars,
        structlog.stdlib.add_logger_name,
        structlog.stdlib.add_log_level,
        structlog.processors.TimeStamper(fmt="iso", utc=True),
        redact_secrets,
    ]
    render: list[structlog.typing.Processor] = (
        [structlog.processors.format_exc_info, structlog.processors.JSONRenderer()]
        if settings.is_prod
        else [structlog.dev.ConsoleRenderer()]
    )

    handler = logging.StreamHandler(sys.stdout)
    handler.setFormatter(
        structlog.stdlib.ProcessorFormatter(
            foreign_pre_chain=shared,
            processors=[structlog.stdlib.ProcessorFormatter.remove_processors_meta, *render],
        )
    )
    root = logging.getLogger()
    root.handlers = [handler]
    root.setLevel(level)

    structlog.configure(
        processors=[
            structlog.stdlib.filter_by_level,
            *shared,
            structlog.stdlib.ProcessorFormatter.wrap_for_formatter,
        ],
        logger_factory=structlog.stdlib.LoggerFactory(),
        wrapper_class=structlog.stdlib.BoundLogger,
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
