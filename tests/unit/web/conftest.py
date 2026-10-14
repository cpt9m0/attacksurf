"""Logged-in clients without a database: the identity lookup is faked."""

from collections.abc import Callable

import pytest
from flask import Flask
from flask.testing import FlaskClient

from attacksurf.domain.accounts import Role
from attacksurf.domain.ids import uuid7
from attacksurf.services import auth as auth_service
from attacksurf.services.auth import SessionUser

type LoginAs = Callable[[FlaskClient, SessionUser], None]


def make_session_user(role: Role = Role.OWNER, email: str = "alice@example.com") -> SessionUser:
    return SessionUser(user_id=uuid7(), email=email, org_id=uuid7(), org_name="Acme", role=role)


@pytest.fixture
def login_as(monkeypatch: pytest.MonkeyPatch) -> LoginAs:
    users: dict[object, SessionUser] = {}
    monkeypatch.setattr(auth_service, "load_session_user", lambda _session, uid: users.get(uid))

    def _login(client: FlaskClient, user: SessionUser) -> None:
        users[user.user_id] = user
        with client.session_transaction() as sess:
            sess["_user_id"] = str(user.user_id)
            sess["_fresh"] = True

    return _login


@pytest.fixture
def session_user() -> SessionUser:
    return make_session_user()


@pytest.fixture
def auth_client(app: Flask, login_as: LoginAs, session_user: SessionUser) -> FlaskClient:
    client = app.test_client()
    login_as(client, session_user)
    return client
