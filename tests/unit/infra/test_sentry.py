import logging
import subprocess
import sys
from typing import Any

import pytest
import sentry_sdk
import structlog
from celery.signals import beat_init, worker_init
from flask import Flask
from pydantic import SecretStr

from attacksurf.app import create_app
from attacksurf.infra.logging import REDACTED
from attacksurf.infra.sentry import (
    _scrub_breadcrumb,
    _scrub_event,
    capture_exception,
    init_sentry,
)
from attacksurf.workers import app as worker_app
from attacksurf.workers import runtime
from tests.helpers import PROD_SECRET_KEY, make_settings

SAMPLE_DSN = "https://publickey@o123.ingest.sentry.io/456"


def test_sentry_stays_disabled_when_dsn_unset(monkeypatch: pytest.MonkeyPatch) -> None:
    calls: list[dict[str, Any]] = []
    monkeypatch.setattr(sentry_sdk, "init", lambda **kwargs: calls.append(kwargs))

    assert init_sentry(make_settings()) is False
    assert calls == []


def test_sentry_initializes_with_safe_defaults(monkeypatch: pytest.MonkeyPatch) -> None:
    captured: list[dict[str, Any]] = []
    monkeypatch.setattr(sentry_sdk, "init", lambda **kwargs: captured.append(kwargs))
    settings = make_settings(
        env="prod",
        secret_key=SecretStr(PROD_SECRET_KEY),
        sentry_dsn=SecretStr(SAMPLE_DSN),
        sentry_environment="production",
        sentry_release="abc123def456",
        sentry_traces_sample_rate=0.05,
    )

    active = init_sentry(settings, enable_flask=True, enable_celery=True)

    assert active is True
    assert len(captured) == 1
    opts = captured[0]
    assert opts["dsn"] == SAMPLE_DSN
    assert opts["environment"] == "production"
    assert opts["release"] == "abc123def456"
    assert opts["traces_sample_rate"] == 0.05
    assert opts["send_default_pii"] is False
    assert opts["include_local_variables"] is False
    assert opts["max_breadcrumbs"] == 20
    assert opts["before_send"] is _scrub_event
    assert opts["before_breadcrumb"] is _scrub_breadcrumb
    integration_names = {type(item).__name__ for item in opts["integrations"]}
    assert integration_names == {"LoggingIntegration", "FlaskIntegration", "CeleryIntegration"}


def test_sentry_scrubs_secrets_headers_cookies_and_url_credentials() -> None:
    event: dict[str, Any] = {
        "message": "failed connecting to https://alice:secret@proxy.internal/v1",
        "request": {
            "url": "https://user:pass@attacksurf.dev/login",
            "query_string": "next=/scans",
            "cookies": {"__Host-session": "raw-cookie"},
            "data": {"password": "hunter2"},
            "env": {"SECRET_KEY": "do-not-send"},
            "headers": {
                "Authorization": "Bearer secret-jwt",
                "Cookie": "__Host-session=abc",
                "Set-Cookie": "id=xyz",
                "X-CSRFToken": "csrf-val",
                "X-Api-Key": "ak-123",
                "Referer": "https://u:pw@attacksurf.dev/scans",
                "Accept": "text/html",
            },
        },
        "user": {
            "id": "org-1",
            "email": "admin@example.com",
            "ip_address": "203.0.113.10",
            "username": "admin",
        },
        "extra": {
            "api_key": "sk-secret",
            "nested": {
                "database_url": "postgresql+psycopg://u:pw@postgres:5432/app",
                "endpoint": "postgresql+psycopg://u:pw@postgres:5432/app",
            },
        },
        "exception": {
            "values": [
                {
                    "type": "RuntimeError",
                    "value": "dial redis://:redispass@redis:6379/0 failed",
                }
            ]
        },
    }

    scrubbed: dict[str, Any] = _scrub_event(event, {})  # type: ignore[arg-type]

    assert scrubbed["message"] == f"failed connecting to https://{REDACTED}@proxy.internal/v1"
    req = scrubbed["request"]
    assert "cookies" not in req
    assert "data" not in req
    assert "env" not in req
    assert req["url"] == f"https://{REDACTED}@attacksurf.dev/login"
    assert req["headers"]["Authorization"] == REDACTED
    assert req["headers"]["Cookie"] == REDACTED
    assert req["headers"]["Set-Cookie"] == REDACTED
    assert req["headers"]["X-CSRFToken"] == REDACTED
    assert req["headers"]["X-Api-Key"] == REDACTED
    assert req["headers"]["Referer"] == f"https://{REDACTED}@attacksurf.dev/scans"
    assert req["headers"]["Accept"] == "text/html"
    assert scrubbed["user"] == {"id": "org-1"}
    assert scrubbed["extra"] == {
        "api_key": REDACTED,
        "nested": {
            "database_url": REDACTED,
            "endpoint": f"postgresql+psycopg://{REDACTED}@postgres:5432/app",
        },
    }
    assert (
        scrubbed["exception"]["values"][0]["value"]
        == f"dial redis://{REDACTED}@redis:6379/0 failed"
    )


def test_sentry_scrubs_breadcrumbs() -> None:
    crumb: dict[str, Any] = {
        "message": "POST https://user:pw@llm.example/v1",
        "data": {"api_key": "sk-123", "url": "https://a:b@example.com/hook"},
    }

    scrubbed: dict[str, Any] = _scrub_breadcrumb(crumb, {})  # type: ignore[arg-type]

    assert scrubbed["message"] == f"POST https://{REDACTED}@llm.example/v1"
    assert scrubbed["data"] == {
        "api_key": REDACTED,
        "url": f"https://{REDACTED}@example.com/hook",
    }


def test_capture_exception_noop_when_uninitialized(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(sentry_sdk, "is_initialized", lambda: False)
    called: list[BaseException] = []
    monkeypatch.setattr(sentry_sdk, "capture_exception", called.append)

    capture_exception(RuntimeError("boom"))

    assert called == []


def test_unhandled_flask_500_is_captured_while_404_is_not(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from attacksurf.web import auth as web_auth  # noqa: PLC0415

    monkeypatch.setattr(sentry_sdk, "init", lambda **_kwargs: None)
    monkeypatch.setattr(web_auth, "PUBLIC_ENDPOINTS", web_auth.PUBLIC_ENDPOINTS | {"_boom"})
    app: Flask = create_app(make_settings(sentry_dsn=SecretStr(SAMPLE_DSN)))

    @app.get("/test-boom")
    def _boom() -> str:
        raise RuntimeError("boom")

    captured: list[tuple[BaseException, dict[str, Any]]] = []

    class _FakeScope:
        def __init__(self) -> None:
            self.tags: dict[str, Any] = {}

        def __enter__(self) -> "_FakeScope":
            return self

        def __exit__(self, *_args: object) -> None:
            return None

        def set_tag(self, key: str, value: str) -> None:
            self.tags[key] = value

    current_scope = _FakeScope()
    monkeypatch.setattr(sentry_sdk, "is_initialized", lambda: True)
    monkeypatch.setattr(sentry_sdk, "new_scope", lambda: current_scope)
    monkeypatch.setattr(
        sentry_sdk,
        "capture_exception",
        lambda exc: captured.append((exc, dict(current_scope.tags))),
    )
    client = app.test_client()

    not_found = client.get("/does-not-exist")
    boom_resp = client.get("/test-boom", headers={"X-Request-ID": "req-sentry-1"})

    assert not_found.status_code == 404
    assert boom_resp.status_code == 500
    assert len(captured) == 1
    assert isinstance(captured[0][0], RuntimeError)
    assert captured[0][1]["request_id"] == "req-sentry-1"
    structlog.contextvars.clear_contextvars()


@pytest.mark.parametrize("signal", [worker_init, beat_init])
def test_worker_signals_initialize_sentry_for_celery(
    monkeypatch: pytest.MonkeyPatch, signal: Any
) -> None:
    calls: list[tuple[bool, bool]] = []
    settings = make_settings(sentry_dsn=SecretStr(SAMPLE_DSN))
    monkeypatch.setattr(runtime, "settings", lambda: settings)
    monkeypatch.setattr(
        worker_app,
        "init_sentry",
        lambda _s, *, enable_flask=False, enable_celery=False: (
            calls.append((enable_flask, enable_celery)) or True
        ),
    )

    signal.send(sender=None)

    assert calls == [(False, True)]


def test_importing_inner_layers_and_worker_sentry_init_stay_isolated() -> None:
    code = (
        "import sys; "
        "import attacksurf.domain, attacksurf.services, attacksurf.config; "
        "assert 'sentry_sdk' not in sys.modules and 'flask' not in sys.modules; "
        "from pydantic import SecretStr; "
        "from attacksurf.config import Settings; "
        "from attacksurf.infra.sentry import init_sentry; "
        "import sentry_sdk; sentry_sdk.init = lambda **kw: None; "
        f"init_sentry(Settings(sentry_dsn=SecretStr({SAMPLE_DSN!r})), enable_celery=True); "
        "sys.exit('sentry_sdk.integrations.flask' in sys.modules)"
    )

    result = subprocess.run([sys.executable, "-c", code], check=False)  # noqa: S603 (fixed argv)

    assert result.returncode == 0
    assert logging.getLogger().handlers is not None
