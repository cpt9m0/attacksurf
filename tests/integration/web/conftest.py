"""Fixtures for the upload routes (#87, #101): real Postgres and a real encrypted store."""

import re
import secrets
from pathlib import Path

import pytest
from flask import Flask
from flask.testing import FlaskClient
from pydantic import SecretStr
from sqlalchemy.orm import Session

from attacksurf.app import create_app
from attacksurf.infra.crypto import EnvelopeCipher
from attacksurf.infra.storage import LocalArtifactStore
from attacksurf.web import uploads
from tests.fakes import FakePasswordHasher, FakeQueue
from tests.helpers import make_settings

MAX_BYTES = 3 * 1024 * 1024  # above the default body ceiling, so the raise is exercised
CSRF = re.compile(r'name="csrf_token" value="([^"]+)"')
HTMX = {"HX-Request": "true"}


def signup(app: Flask, email: str) -> FlaskClient:
    client = app.test_client()
    match = CSRF.search(client.get("/signup").get_data(as_text=True))
    assert match
    response = client.post(
        "/signup",
        data={
            "email": email,
            "password": "correct horse battery",
            "org_name": email.split("@", maxsplit=1)[0],
            "csrf_token": match.group(1),
        },
    )
    assert response.status_code == 302
    return client


def stored_files(root: Path) -> list[Path]:
    # Per-artifact `.lock` files live in the store root and are never removed by the
    # store (unlinking would break the flock), so only ciphertext counts here.
    return [path for path in root.rglob("*") if path.is_file() and path.suffix != ".lock"]


@pytest.fixture
def store_root(tmp_path: Path) -> Path:
    return tmp_path / "store"


@pytest.fixture
def upload_app(db_session: Session, store_root: Path, monkeypatch: pytest.MonkeyPatch) -> Flask:
    app = create_app(
        make_settings(
            env="test",
            secret_key=SecretStr("test-secret-key"),
            artifact_max_bytes=MAX_BYTES,
            artifact_store_root=str(store_root),
        )
    )
    app.extensions["db_session_factory"] = lambda: db_session
    app.extensions["password_hasher"] = FakePasswordHasher()
    cipher = EnvelopeCipher(secrets.token_bytes(32), purpose=b"artifact")
    store = LocalArtifactStore(store_root, store_root.parent / "runs", cipher)
    monkeypatch.setattr(uploads, "get_artifact_store", lambda: store)
    monkeypatch.setattr("attacksurf.web.ui.get_task_queue", lambda: FakeQueue(db_session))
    return app
