import json
import logging

import pytest
import structlog
from flask.testing import FlaskClient
from pydantic import SecretStr

from attacksurf.infra.logging import (
    REDACTED,
    REQUEST_ID_HEADER,
    configure_logging,
    redact_secrets,
    resolve_request_id,
)
from tests.helpers import PROD_SECRET_KEY, make_settings


def test_request_id_is_generated_and_echoed(client: FlaskClient) -> None:
    response = client.get("/healthz")

    request_id = response.headers[REQUEST_ID_HEADER]
    assert len(request_id) == 32
    assert request_id.isalnum()


def test_valid_incoming_request_id_is_kept(client: FlaskClient) -> None:
    response = client.get("/healthz", headers={REQUEST_ID_HEADER: "abc-123"})

    assert response.headers[REQUEST_ID_HEADER] == "abc-123"


@pytest.mark.parametrize(
    "incoming",
    ["", "has space", "inject\nfake=log", "x" * 65, "semi;colon", "ünïcode"],
)
def test_malformed_request_id_is_replaced(incoming: str) -> None:
    resolved = resolve_request_id(incoming)

    assert resolved != incoming
    assert len(resolved) == 32


def test_missing_request_id_is_generated() -> None:
    assert len(resolve_request_id(None)) == 32


def test_redact_secrets_masks_sensitive_keys() -> None:
    event = {
        "event": "x",
        "api_key": "sk-1",
        "llm_apikey": "sk-2",
        "Authorization": "Bearer t",
        "password": "p",
        "session_token": "t",
        "path": "/healthz",
    }

    result = redact_secrets(None, "info", event)

    assert result["api_key"] == REDACTED
    assert result["llm_apikey"] == REDACTED
    assert result["Authorization"] == REDACTED
    assert result["password"] == REDACTED
    assert result["session_token"] == REDACTED
    assert result["path"] == "/healthz"


def test_request_is_logged_as_json_in_prod(capsys: pytest.CaptureFixture[str]) -> None:
    configure_logging(make_settings(env="prod", secret_key=SecretStr(PROD_SECRET_KEY)))
    structlog.contextvars.bind_contextvars(request_id="rid-1")

    try:
        structlog.get_logger("t").info("request", path="/healthz", api_key="sk-live")
    finally:
        structlog.contextvars.clear_contextvars()

    line = json.loads(capsys.readouterr().out.strip().splitlines()[-1])
    assert line["event"] == "request"
    assert line["request_id"] == "rid-1"
    assert line["level"] == "info"
    assert line["api_key"] == REDACTED
    assert "timestamp" in line


def test_log_level_filters_lower_levels(capsys: pytest.CaptureFixture[str]) -> None:
    configure_logging(
        make_settings(env="prod", secret_key=SecretStr(PROD_SECRET_KEY), log_level="warning")
    )

    structlog.get_logger("t").info("hidden")
    structlog.get_logger("t").warning("shown")

    out = capsys.readouterr().out
    assert "hidden" not in out
    assert "shown" in out
    assert logging.getLogger().level == logging.WARNING


def test_each_request_is_logged_with_its_fields(
    client: FlaskClient, caplog: pytest.LogCaptureFixture
) -> None:
    with caplog.at_level(logging.INFO):
        client.get("/healthz", headers={REQUEST_ID_HEADER: "req-42"})

    events = [r.msg for r in caplog.records if isinstance(r.msg, dict)]
    request_event = next(e for e in events if e.get("event") == "request")
    assert request_event["request_id"] == "req-42"
    assert request_event["path"] == "/healthz"
    assert request_event["status"] == 200
    assert request_event["method"] == "GET"


def test_stdlib_logs_are_json_with_request_id_in_prod(capsys: pytest.CaptureFixture[str]) -> None:
    configure_logging(make_settings(env="prod", secret_key=SecretStr(PROD_SECRET_KEY)))
    structlog.contextvars.bind_contextvars(request_id="rid-std")

    try:
        logging.getLogger("werkzeug").warning("library message password=%s", "x")
    finally:
        structlog.contextvars.clear_contextvars()

    line = json.loads(capsys.readouterr().out.strip().splitlines()[-1])
    assert line["event"] == "library message password=x"
    assert line["request_id"] == "rid-std"
    assert line["logger"] == "werkzeug"
    assert line["level"] == "warning"


def test_exceptions_are_serialized_in_prod_json(capsys: pytest.CaptureFixture[str]) -> None:
    configure_logging(make_settings(env="prod", secret_key=SecretStr(PROD_SECRET_KEY)))

    try:
        raise ValueError("boom")
    except ValueError:
        structlog.get_logger("t").exception("failed")

    line = json.loads(capsys.readouterr().out.strip().splitlines()[-1])
    assert line["event"] == "failed"
    assert "ValueError: boom" in line["exception"]
