from collections.abc import Iterator

import pytest
from flask import Flask
from flask.testing import FlaskClient
from pydantic import SecretStr

from attacksurf import create_app
from attacksurf.config import Settings
from attacksurf.workers import runtime
from tests.helpers import make_settings


@pytest.fixture
def clean_env(monkeypatch: pytest.MonkeyPatch) -> pytest.MonkeyPatch:
    """Unset every variable Settings reads, for tests that exercise env loading."""
    for name in Settings.model_fields:
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


@pytest.fixture(autouse=True, scope="session")
def _hermetic_worker_settings() -> Iterator[None]:
    """The worker app reads `runtime.settings()` lazily; give it test settings, not .env/env."""
    worker_settings = make_settings(env="test", secret_key=SecretStr("test-secret-key"))
    with pytest.MonkeyPatch.context() as mp:
        mp.setattr(runtime, "settings", lambda: worker_settings)
        yield
