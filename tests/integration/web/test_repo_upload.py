"""Archive upload through the UI (#87), against real Postgres and a real encrypted store."""

import io
import re
import secrets
from pathlib import Path

import pytest
from flask import Flask
from flask.testing import FlaskClient
from pydantic import SecretStr
from sqlalchemy import select
from sqlalchemy.orm import Session
from werkzeug.test import EnvironBuilder, TestResponse

from attacksurf.app import create_app
from attacksurf.domain.assets import AssetType
from attacksurf.domain.scans import ScanStatus
from attacksurf.infra.crypto import EnvelopeCipher
from attacksurf.infra.db.models import Artifact, Asset, Scan
from attacksurf.infra.storage import LocalArtifactStore
from attacksurf.web import uploads
from tests.fakes import FakePasswordHasher, FakeQueue
from tests.helpers import make_settings

ZIP = (Path(__file__).resolve().parents[2] / "fixtures" / "archives" / "ok.zip").read_bytes()
MAX_BYTES = 3 * 1024 * 1024  # above the default body ceiling, so the raise is exercised
_CSRF = re.compile(r'name="csrf_token" value="([^"]+)"')
HTMX = {"HX-Request": "true"}


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


def _signup(app: Flask, email: str) -> FlaskClient:
    client = app.test_client()
    match = _CSRF.search(client.get("/signup").get_data(as_text=True))
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


def _post(
    client: FlaskClient,
    data: bytes = ZIP,
    filename: str = "My App.zip",
    *,
    csrf: bool = True,
    headers: dict[str, str] | None = None,
) -> TestResponse:
    form: dict[str, object] = {"archive": (io.BytesIO(data), filename)}
    if csrf:
        match = _CSRF.search(client.get("/assets").get_data(as_text=True))
        assert match
        form["csrf_token"] = match.group(1)
    return client.post(
        "/assets/upload", data=form, content_type="multipart/form-data", headers=headers or {}
    )


def _stored_files(root: Path) -> list[Path]:
    # Per-artifact `.lock` files live in the store root and are never removed by the
    # store (unlinking would break the flock), so only ciphertext counts here.
    return [path for path in root.rglob("*") if path.is_file() and path.suffix != ".lock"]


def test_assets_page_offers_a_multipart_upload_form(upload_app: Flask) -> None:
    html = _signup(upload_app, "alice@example.com").get("/assets").get_data(as_text=True)

    form = html[html.index('id="upload-repo"') :]
    assert 'enctype="multipart/form-data"' in form
    assert 'hx-encoding="multipart/form-data"' in form
    assert 'type="file"' in form
    assert 'name="csrf_token"' in form
    assert "3.0 MiB" in form


def test_uploading_a_zip_creates_a_repo_asset_and_a_queued_scan(
    upload_app: Flask, db_session: Session, store_root: Path
) -> None:
    client = _signup(upload_app, "alice@example.com")

    response = _post(client)

    asset = db_session.scalars(select(Asset).where(Asset.type == AssetType.REPO)).one()
    scan = db_session.scalars(select(Scan).where(Scan.root_asset_id == asset.id)).one()
    artifact = db_session.scalars(select(Artifact).where(Artifact.asset_id == asset.id)).one()
    assert response.status_code == 303
    assert response.headers["Location"] == f"/assets/{asset.id}"
    assert asset.value == "upload/my-app"
    assert (scan.profile, scan.status) == ("code", ScanStatus.QUEUED)
    assert scan.stats["revision"] == artifact.sha256
    stored = _stored_files(store_root)
    assert len(stored) == 1
    assert ZIP not in stored[0].read_bytes()  # encrypted at rest
    page = client.get(response.headers["Location"])
    assert page.status_code == 200
    assert "queued until the analysis worker is available" in page.get_data(as_text=True)


def test_upload_larger_than_the_default_ceiling_is_accepted(
    upload_app: Flask, db_session: Session
) -> None:
    """The upload ceiling must be in place before CSRF parses the form, or this is a 413."""
    client = _signup(upload_app, "alice@example.com")
    data = ZIP + b"\0" * (uploads.DEFAULT_MAX_BODY_BYTES + 1)

    response = _post(client, data)

    assert response.status_code == 303
    assert db_session.scalars(select(Artifact.size_bytes)).one() == len(data)


def test_htmx_upload_navigates_with_hx_redirect(upload_app: Flask) -> None:
    response = _post(_signup(upload_app, "alice@example.com"), headers=HTMX)

    assert response.status_code == 200
    assert response.headers["HX-Redirect"].startswith("/assets/")


def test_repo_assets_can_be_filtered_by_type(upload_app: Flask) -> None:
    client = _signup(upload_app, "alice@example.com")
    _post(client)

    html = client.get("/assets?type=repo").get_data(as_text=True)

    assert "Code repository" in html
    assert "upload/my-app" in html


def test_oversize_upload_is_413_and_writes_nothing(
    upload_app: Flask, db_session: Session, store_root: Path
) -> None:
    client = _signup(upload_app, "alice@example.com")

    response = _post(client, ZIP + b"\0" * (MAX_BYTES + uploads.MULTIPART_OVERHEAD_BYTES))

    assert response.status_code == 413
    assert "too large" in response.get_data(as_text=True)
    assert _stored_files(store_root) == []
    assert db_session.scalars(select(Asset)).all() == []


def test_upload_just_over_the_artifact_cap_is_413_from_the_storage_limit(
    upload_app: Flask, db_session: Session, store_root: Path
) -> None:
    client = _signup(upload_app, "alice@example.com")

    # Fits the request ceiling (which allows for multipart framing) but not the artifact cap.
    response = _post(client, ZIP + b"\0" * (MAX_BYTES - len(ZIP) + 1), headers=HTMX)

    assert response.status_code == 413
    assert 'id="upload-repo"' in response.get_data(as_text=True)
    assert _stored_files(store_root) == []
    assert db_session.scalars(select(Artifact)).all() == []


def test_other_routes_keep_the_small_default_body_ceiling(upload_app: Flask) -> None:
    client = _signup(upload_app, "alice@example.com")

    body = {"value": "a" * (uploads.DEFAULT_MAX_BODY_BYTES + 1)}

    assert upload_app.config["MAX_CONTENT_LENGTH"] == uploads.DEFAULT_MAX_BODY_BYTES
    assert client.post("/assets", data=body).status_code == 413
    api = client.post("/api/v1/assets", json=body)
    assert (api.status_code, api.get_json()) == (413, {"error": "Request Entity Too Large"})


def test_upload_that_is_not_an_archive_is_415(
    upload_app: Flask, db_session: Session, store_root: Path
) -> None:
    client = _signup(upload_app, "alice@example.com")

    response = _post(client, b"MZ\x90\x00 definitely not an archive", "tool.zip", headers=HTMX)

    assert response.status_code == 415
    assert "Upload a .zip" in response.get_data(as_text=True)
    assert _stored_files(store_root) == []
    assert db_session.scalars(select(Asset)).all() == []


def test_upload_without_a_file_is_422(upload_app: Flask) -> None:
    client = _signup(upload_app, "alice@example.com")
    match = _CSRF.search(client.get("/assets").get_data(as_text=True))
    assert match

    response = client.post("/assets/upload", data={"csrf_token": match.group(1)})

    assert response.status_code == 422
    assert "Choose an archive" in response.get_data(as_text=True)


def test_upload_requires_csrf_token_and_login(upload_app: Flask, db_session: Session) -> None:
    client = _signup(upload_app, "alice@example.com")

    assert _post(client, csrf=False).status_code == 400
    assert _post(upload_app.test_client(), csrf=False).status_code == 302
    assert db_session.scalars(select(Asset)).all() == []


def test_upload_is_rate_limited_per_user(upload_app: Flask) -> None:
    client = _signup(upload_app, "alice@example.com")
    allowed = int(uploads.UPLOAD_LIMIT.split()[0])

    statuses = [_post(client, b"nope", "x.zip").status_code for _ in range(allowed + 1)]

    assert statuses == [415] * allowed + [429]
    # Another account has its own budget.
    assert _post(_signup(upload_app, "bob@other.example"), b"nope", "x.zip").status_code == 415


def test_uploaded_repo_is_invisible_to_another_org(upload_app: Flask, db_session: Session) -> None:
    _post(_signup(upload_app, "alice@example.com"))
    asset_id = db_session.scalars(select(Asset.id).where(Asset.type == AssetType.REPO)).one()
    bob = _signup(upload_app, "bob@other.example")

    assert bob.get(f"/assets/{asset_id}").status_code == 404
    assert "upload/my-app" not in bob.get("/assets").get_data(as_text=True)
    assert bob.get(f"/api/v1/assets/{asset_id}").status_code == 404


def test_upload_is_refused_when_storage_has_no_encryption_key(
    db_app: Flask, db_session: Session
) -> None:
    client = _signup(db_app, "alice@example.com")

    page = client.get("/assets").get_data(as_text=True)
    response = _post(client, headers=HTMX)

    assert "Uploads are not configured" in page
    assert 'type="file"' not in page
    assert response.status_code == 503
    assert "Uploads are not configured" in response.get_data(as_text=True)
    assert db_session.scalars(select(Asset)).all() == []


def test_file_name_with_a_nul_is_accepted_not_a_server_error(
    upload_app: Flask, db_session: Session
) -> None:
    """Regression: the raw name went into a JSONB column, which rejects NUL (a 500)."""
    response = _post(_signup(upload_app, "alice@example.com"), filename="a\x00b.zip")

    assert response.status_code == 303
    asset = db_session.scalars(select(Asset).where(Asset.type == AssetType.REPO)).one()
    assert asset.details["upload"] == {"filename": "ab.zip"}


def test_htmx_upload_over_the_body_ceiling_keeps_the_form_in_place(
    upload_app: Flask, store_root: Path
) -> None:
    """The 413 is raised while CSRF reads the form, before the view: the generic error page
    would otherwise be swapped over the form."""
    client = _signup(upload_app, "alice@example.com")

    response = _post(
        client, ZIP + b"\0" * (MAX_BYTES + uploads.MULTIPART_OVERHEAD_BYTES), headers=HTMX
    )

    body = response.get_data(as_text=True)
    assert response.status_code == 413
    assert 'id="upload-repo"' in body
    assert "too large to upload" in body
    assert "error-page" not in body
    assert _stored_files(store_root) == []


class _CountingStream(io.BytesIO):
    consumed = 0

    def read(self, size: int | None = -1) -> bytes:
        data = super().read(size)
        self.consumed += len(data)
        return data


def test_rate_limited_upload_is_refused_before_its_body_is_read(upload_app: Flask) -> None:
    client = _signup(upload_app, "alice@example.com")
    for _ in range(int(uploads.UPLOAD_LIMIT.split()[0])):
        _post(client, b"nope", "x.zip")
    match = _CSRF.search(client.get("/assets").get_data(as_text=True))
    assert match
    environ = EnvironBuilder(
        method="POST",
        data={"csrf_token": match.group(1), "archive": (io.BytesIO(ZIP * 50), "big.zip")},
    ).get_environ()
    stream = _CountingStream(environ["wsgi.input"].read())

    response = client.post(
        "/assets/upload",
        input_stream=stream,
        content_type=environ["CONTENT_TYPE"],
        content_length=int(environ["CONTENT_LENGTH"]),
        headers=HTMX,
    )

    body = response.get_data(as_text=True)
    assert response.status_code == 429
    assert stream.consumed == 0
    assert 'id="upload-repo"' in body
    assert "Too many uploads" in body


def test_body_ceiling_is_not_raised_when_storage_has_no_encryption_key(db_app: Flask) -> None:
    client = _signup(db_app, "alice@example.com")

    response = _post(client, ZIP + b"\0" * uploads.DEFAULT_MAX_BODY_BYTES)

    assert response.status_code == 413


def test_upload_whose_scan_cannot_be_queued_is_503_with_the_form(
    upload_app: Flask, db_session: Session, store_root: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    client = _signup(upload_app, "alice@example.com")
    monkeypatch.setattr(
        "attacksurf.web.ui.get_task_queue", lambda: FakeQueue(db_session, fail=True)
    )

    response = _post(client, headers=HTMX)

    body = response.get_data(as_text=True)
    assert response.status_code == 503
    assert 'id="upload-repo"' in body
    assert "could not be queued" in body
    assert db_session.scalars(select(Scan.status)).one() == ScanStatus.FAILED
    assert _stored_files(store_root) == []
