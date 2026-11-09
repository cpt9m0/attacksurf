import os

import pytest
from flask import Flask
from flask.testing import FlaskClient
from pydantic import SecretStr

from attacksurf import create_app
from attacksurf.config import SandboxProxySettings, Settings
from attacksurf.workers import runtime
from tests.helpers import llm_live_skip_reason, make_settings


def pytest_collection_modifyitems(items: list[pytest.Item]) -> None:
    """Skip every `llm_live` test unless live calls are enabled here (never in CI)."""
    live = [item for item in items if item.get_closest_marker("llm_live")]
    if not live:
        return
    reason = llm_live_skip_reason(os.environ, Settings)
    if reason is not None:
        for item in live:
            item.add_marker(pytest.mark.skip(reason=reason))


@pytest.fixture
def clean_env(monkeypatch: pytest.MonkeyPatch) -> pytest.MonkeyPatch:
    """Unset every variable read by application or proxy settings for env-loading tests."""
    for name in Settings.model_fields.keys() | SandboxProxySettings.model_fields.keys():
        monkeypatch.delenv(name.upper(), raising=False)
    return monkeypatch


@pytest.fixture
def settings() -> Settings:
    return make_settings(env="test", secret_key=SecretStr("test-secret-key"))


@pytest.fixture
def app(settings: Settings) -> Flask:
    return create_app(settings)


@pytest.fixture
def client(app: Flask) -> FlaskClient:
    return app.test_client()


def pytest_configure(config: pytest.Config) -> None:
    """Give the worker app test settings, not .env/env, before collection starts.

    Collecting a module-level Celery task finalizes the worker conf, which reads
    `runtime.settings()` once and caches it; a fixture would patch too late (#126).
    """
    worker_settings = make_settings(env="test", secret_key=SecretStr("test-secret-key"))
    mp = pytest.MonkeyPatch()
    mp.setattr(runtime, "settings", lambda: worker_settings)
    config.add_cleanup(mp.undo)
