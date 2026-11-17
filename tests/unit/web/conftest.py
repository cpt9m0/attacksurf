"""Logged-in clients without a database: the identity lookup is faked (see `tests/conftest.py`)."""

import pytest
from flask import Flask
from flask.testing import FlaskClient

from attacksurf.services import asset_views, scan_views
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


@pytest.fixture(autouse=True)
def _no_scans(monkeypatch: pytest.MonkeyPatch) -> None:
    """No database here: the scans page renders an empty org (DB-backed: tests/integration/web).

    Its root filter and start form read `list_root_domains` too.
    """
    no_scans = scan_views.ScanPage(items=(), page=1, pages=1, total=0)
    monkeypatch.setattr(scan_views, "list_scans", lambda *_args, **_kw: no_scans)
    monkeypatch.setattr(scan_views, "active_scan_for_root", lambda *_args, **_kw: None)
    monkeypatch.setattr(asset_views, "list_root_domains", lambda *_args, **_kw: ())
