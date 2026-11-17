"""Fixtures for browser tests of the rendered UI (issue #114)."""

import pytest
from flask import Flask
from flask.testing import FlaskClient

from attacksurf.services import asset_views, scan_views
from tests.conftest import LoginAs, make_session_user

# 40 characters: the email width the issue was reproduced with.
LONG_EMAIL = "ali.ayati.mobile.width.issue@example.com"


@pytest.fixture(autouse=True)
def _no_assets(monkeypatch: pytest.MonkeyPatch) -> None:
    """No database here: the asset pages render an empty org (DB-backed: tests/integration/web)."""
    empty = asset_views.AssetPage(items=(), page=1, pages=1, total=0)
    monkeypatch.setattr(asset_views, "list_assets", lambda *_args, **_kw: empty)
    monkeypatch.setattr(asset_views, "list_root_domains", lambda *_args, **_kw: ())
    no_scans = scan_views.ScanPage(items=(), page=1, pages=1, total=0)
    monkeypatch.setattr(scan_views, "list_scans", lambda *_args, **_kw: no_scans)
    monkeypatch.setattr(scan_views, "active_scan_for_root", lambda *_args, **_kw: None)


@pytest.fixture
def phone_client(app: Flask, login_as: LoginAs) -> FlaskClient:
    """A signed-in client whose email is long enough to overflow a phone-width top bar."""
    client = app.test_client()
    login_as(client, make_session_user(email=LONG_EMAIL))
    return client
