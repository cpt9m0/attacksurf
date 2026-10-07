import pytest
from flask import Flask
from flask.testing import FlaskClient

from attacksurf import create_app


@pytest.fixture
def app() -> Flask:
    app = create_app()
    app.config.update(TESTING=True)
    return app


@pytest.fixture
def client(app: Flask) -> FlaskClient:
    return app.test_client()
