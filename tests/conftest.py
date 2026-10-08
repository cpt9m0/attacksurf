import pytest
from flask import Flask
from flask.testing import FlaskClient
from pydantic import SecretStr

from attacksurf import create_app
from attacksurf.config import Settings
from tests.helpers import make_settings


@pytest.fixture
def settings() -> Settings:
    return make_settings(env="test", secret_key=SecretStr("test-secret-key"))


@pytest.fixture
def app(settings: Settings) -> Flask:
    return create_app(settings)


@pytest.fixture
def client(app: Flask) -> FlaskClient:
    return app.test_client()
