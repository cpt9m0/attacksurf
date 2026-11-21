"""Optional, env-gated Sentry error tracking with strict secret/PII scrubbing."""

from __future__ import annotations

import logging
from typing import Any, cast

import sentry_sdk
import structlog
from sentry_sdk.integrations.logging import LoggingIntegration
from sentry_sdk.types import Breadcrumb, BreadcrumbHint, Event, Hint

from attacksurf.config import Settings
from attacksurf.domain.jobs import JobError
from attacksurf.infra.logging import REDACTED, is_sensitive_key, scrub_value

_SAFE_CONTEXT_TAGS = ("request_id", "org_id", "scan_id", "job_id", "task", "task_id")
_SCRUBBED_HEADERS = frozenset(
    {
        "authorization",
        "cookie",
        "proxy-authorization",
        "set-cookie",
        "x-api-key",
        "x-csrf-token",
        "x-csrftoken",
    }
)
_PII_USER_FIELDS = ("email", "ip_address", "username")


def init_sentry(
    settings: Settings,
    *,
    enable_flask: bool = False,
    enable_celery: bool = False,
) -> bool:
    """Initialize Sentry when SENTRY_DSN is set; return whether Sentry is active."""
    if settings.sentry_dsn is None:
        return False

    integrations: list[Any] = [LoggingIntegration(level=logging.INFO, event_level=None)]
    if enable_flask:
        # Lazy import so worker/inner-layer processes never pull Flask into sys.modules.
        from sentry_sdk.integrations.flask import FlaskIntegration  # noqa: PLC0415

        integrations.append(FlaskIntegration())
    if enable_celery:
        from sentry_sdk.integrations.celery import CeleryIntegration  # noqa: PLC0415

        integrations.append(CeleryIntegration(monitor_beat_tasks=False))

    sentry_sdk.init(
        dsn=settings.sentry_dsn.get_secret_value(),
        environment=settings.sentry_environment or settings.env,
        release=settings.sentry_release,
        traces_sample_rate=settings.sentry_traces_sample_rate,
        send_default_pii=False,
        include_local_variables=False,
        max_request_body_size="never",
        max_breadcrumbs=20,
        auto_enabling_integrations=False,
        integrations=integrations,
        before_send=_scrub_event,
        before_send_transaction=_scrub_event,
        before_breadcrumb=_scrub_breadcrumb,
    )
    return True


def capture_exception(error: BaseException) -> None:
    """Report an unexpected exception when Sentry is active, attaching safe context tags."""
    if not sentry_sdk.is_initialized():
        return
    ctx = structlog.contextvars.get_contextvars()
    with sentry_sdk.new_scope() as scope:
        for key in _SAFE_CONTEXT_TAGS:
            value = ctx.get(key)
            if value is not None:
                scope.set_tag(key, str(value))
        sentry_sdk.capture_exception(error)


def _scrub_headers(headers: Any) -> Any:
    if isinstance(headers, dict):
        return {
            key: (
                REDACTED
                if isinstance(key, str)
                and (key.lower() in _SCRUBBED_HEADERS or is_sensitive_key(key))
                else scrub_value(value)
            )
            for key, value in headers.items()
        }
    return scrub_value(headers)


def _scrub_request(req: dict[str, Any]) -> None:
    req.pop("cookies", None)
    req.pop("data", None)
    req.pop("env", None)
    if "headers" in req:
        req["headers"] = _scrub_headers(req["headers"])
    for key in ("url", "query_string"):
        if key in req:
            req[key] = scrub_value(req[key])


def _scrub_exceptions(mutable: dict[str, Any], hint: Hint) -> None:
    """Keep exception messages only for our own `JobError`s; redact third-party messages."""
    exc_section = mutable.get("exception")
    if not isinstance(exc_section, dict):
        return
    values = exc_section.get("values")
    if not isinstance(values, list):
        return
    exc_info = hint.get("exc_info") if isinstance(hint, dict) else None
    raised_exc = exc_info[1] if isinstance(exc_info, tuple) and exc_info[1:] else None
    allow_last_value = isinstance(raised_exc, JobError)
    last_idx = len(values) - 1
    for idx, item in enumerate(values):
        if not isinstance(item, dict):
            continue
        item.pop("mechanism", None)
        if idx == last_idx and allow_last_value and "value" in item:
            item["value"] = scrub_value(item["value"])
        elif "value" in item:
            item["value"] = REDACTED


def _scrub_event(event: Event, hint: Hint) -> Event:
    """Strip PII, request bodies, cookies, headers, and third-party exception messages."""
    mutable = cast(dict[str, Any], event)

    req = mutable.get("request")
    if isinstance(req, dict):
        _scrub_request(req)

    user = mutable.get("user")
    if isinstance(user, dict):
        for field in _PII_USER_FIELDS:
            user.pop(field, None)

    for section in ("extra", "contexts", "tags", "logentry", "breadcrumbs", "spans"):
        if section in mutable:
            mutable[section] = scrub_value(mutable[section])

    _scrub_exceptions(mutable, hint)

    if "message" in mutable:
        mutable["message"] = scrub_value(mutable["message"])

    return event


def _scrub_breadcrumb(crumb: Breadcrumb, _hint: BreadcrumbHint) -> Breadcrumb:
    """Redact credentials and secrets inside Sentry breadcrumbs."""
    mutable = cast(dict[str, Any], crumb)
    for field in ("message", "category", "data"):
        if field in mutable:
            mutable[field] = scrub_value(mutable[field])
    return crumb
