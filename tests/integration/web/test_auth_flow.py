"""End-to-end auth through the web layer against real Postgres."""

import re

from flask import Flask
from flask.testing import FlaskClient
from sqlalchemy import select
from sqlalchemy.orm import Session

from attacksurf.infra.db.models import AuditLog, User

PASSWORD = "correct horse battery"
_CSRF = re.compile(r'name="csrf_token" value="([^"]+)"')


def _token(client: FlaskClient, path: str) -> str:
    match = _CSRF.search(client.get(path).get_data(as_text=True))
    assert match
    return match.group(1)


def _signup(client: FlaskClient, email: str, org: str = "") -> None:
    response = client.post(
        "/signup",
        data={
            "email": email,
            "password": PASSWORD,
            "org_name": org,
            "csrf_token": _token(client, "/signup"),
        },
    )
    assert response.status_code == 302, response.get_data(as_text=True)


def _login(client: FlaskClient, email: str, password: str = PASSWORD) -> int:
    response = client.post(
        "/login",
        data={"email": email, "password": password, "csrf_token": _token(client, "/login")},
    )
    return response.status_code


def test_signup_logout_login_round_trip(db_app: Flask, db_session: Session) -> None:
    client = db_app.test_client()

    _signup(client, "alice@example.com", "Acme")
    assert "alice@example.com · Acme" in client.get("/").get_data(as_text=True)

    client.post("/logout", data={"csrf_token": _token(client, "/")})
    assert client.get("/").status_code == 302

    assert _login(client, "alice@example.com") == 302
    assert client.get("/findings").status_code == 200
    actions = [e.action for e in db_session.scalars(select(AuditLog).order_by(AuditLog.id))]
    assert actions == ["user.registered", "user.logout", "user.login"]


def test_wrong_password_is_rejected_and_audited(db_app: Flask, db_session: Session) -> None:
    client = db_app.test_client()
    _signup(client, "alice@example.com")
    client.post("/logout", data={"csrf_token": _token(client, "/")})

    assert _login(client, "alice@example.com", "wrong password!") == 422
    assert client.get("/").status_code == 302
    assert db_session.scalar(select(AuditLog).where(AuditLog.action == "user.login_failed"))


def test_deactivated_user_loses_access_on_next_request(db_app: Flask, db_session: Session) -> None:
    client = db_app.test_client()
    _signup(client, "alice@example.com")
    user = db_session.scalars(select(User)).one()

    user.is_active = False
    db_session.commit()

    assert client.get("/").status_code == 302


def test_each_user_sees_only_their_own_org(db_app: Flask) -> None:
    alice, bob = db_app.test_client(), db_app.test_client()
    _signup(alice, "alice@example.com", "Acme")
    _signup(bob, "bob@example.com", "Globex")

    alice_html = alice.get("/").get_data(as_text=True)
    bob_html = bob.get("/").get_data(as_text=True)

    assert "Acme" in alice_html
    assert "Globex" not in alice_html
    assert "Globex" in bob_html
    assert "Acme" not in bob_html
