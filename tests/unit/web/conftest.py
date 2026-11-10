"""Logged-in clients without a database: the identity lookup is faked (see `tests/conftest.py`)."""

import pytest
from flask import Flask
from flask.testing import FlaskClient

from attacksurf.services.auth import SessionUser
from tests.conftest import LoginAs, make_session_user


@pytest.fixture
def session_user() -> SessionUser:
    return make_session_user()


@pytest.fixture
def auth_client(app: Flask, login_as: LoginAs, session_user: SessionUser) -> FlaskClient:
    client = app.test_client()
    login_as(client, session_user)
    return client
