"""Binary upload through the UI (#101), against real Postgres and a real encrypted store."""

import hashlib
import io
from pathlib import Path

import pytest
from flask import Flask
from flask.testing import FlaskClient
from sqlalchemy import select
from sqlalchemy.orm import Session
from werkzeug.test import TestResponse

from attacksurf.domain.assets import AssetType
from attacksurf.domain.scans import ScanStatus
from attacksurf.infra.db.models import Artifact, Asset, AuditLog, Scan
from attacksurf.web import uploads
from tests.binary_fixtures import CORPUS, DETECTED
from tests.integration.web.conftest import CSRF, HTMX, MAX_BYTES, signup, stored_files

ELF = CORPUS["elf64-le"]
VALUE = "sha256:" + hashlib.sha256(ELF).hexdigest()


def _post(
    client: FlaskClient,
    data: bytes = ELF,
    filename: str = "tool",
    *,
    csrf: bool = True,
    headers: dict[str, str] | None = None,
) -> TestResponse:
    form: dict[str, object] = {"binary": (io.BytesIO(data), filename)}
    if csrf:
        match = CSRF.search(client.get("/assets").get_data(as_text=True))
        assert match
        form["csrf_token"] = match.group(1)
    return client.post(
        "/assets/upload-binary",
        data=form,
        content_type="multipart/form-data",
        headers=headers or {},
    )


def test_assets_page_offers_a_binary_upload_form_next_to_the_archive_one(upload_app: Flask) -> None:
    html = signup(upload_app, "alice@example.com").get("/assets").get_data(as_text=True)

    form = html[html.index('id="upload-binary"') :]
    assert html.index('id="upload-repo"') < html.index('id="upload-binary"')
    assert 'action="/assets/upload-binary"' in form
    assert 'enctype="multipart/form-data"' in form
    assert 'hx-encoding="multipart/form-data"' in form
    assert 'name="binary"' in form
    assert 'name="csrf_token"' in form
    assert "never run" in form
    assert "3.0 MiB" in form


@pytest.mark.parametrize("name", sorted(DETECTED))
def test_uploading_each_supported_format_creates_a_binary_asset_and_a_queued_scan(
    upload_app: Flask, db_session: Session, store_root: Path, name: str
) -> None:
    client = signup(upload_app, "alice@example.com")

    response = _post(client, CORPUS[name], name)

    asset = db_session.scalars(select(Asset).where(Asset.type == AssetType.BINARY)).one()
    scan = db_session.scalars(select(Scan).where(Scan.root_asset_id == asset.id)).one()
    artifact = db_session.scalars(select(Artifact).where(Artifact.asset_id == asset.id)).one()
    assert response.status_code == 303
    assert response.headers["Location"] == f"/assets/{asset.id}"
    assert asset.value == "sha256:" + hashlib.sha256(CORPUS[name]).hexdigest()
    assert (scan.profile, scan.status) == ("binary_static", ScanStatus.QUEUED)
    assert asset.value == f"sha256:{artifact.sha256}"
    assert len(stored_files(store_root)) == 1
    assert db_session.scalars(select(AuditLog.action)).all().count("binary.uploaded") == 1


def test_asset_page_shows_the_digest_and_the_escaped_file_name(upload_app: Flask) -> None:
    client = signup(upload_app, "alice@example.com")

    response = _post(client, filename='<img src=x onerror="alert(1)">.exe')
    page = client.get(response.headers["Location"])
    listing = client.get("/assets?type=binary").get_data(as_text=True)

    body = page.get_data(as_text=True)
    assert page.status_code == 200
    assert VALUE in body
    assert "&lt;img src=x onerror=" in body
    assert "<img src=x" not in body
    assert "queued until the analysis worker is available" in body
    assert VALUE in listing
    assert '<option value="binary" selected>Binary</option>' in listing
    for tab in ("findings", "scans"):
        assert client.get(f"{response.headers['Location']}?tab={tab}").status_code == 200


def test_binary_larger_than_the_default_ceiling_is_accepted(
    upload_app: Flask, db_session: Session
) -> None:
    client = signup(upload_app, "alice@example.com")
    big = ELF + bytes(uploads.DEFAULT_MAX_BODY_BYTES)
    assert len(big) < MAX_BYTES

    assert _post(client, big).status_code == 303
    assert db_session.scalars(select(Artifact.size_bytes)).one() == len(big)


def test_text_file_is_rejected_with_a_message_and_nothing_is_stored(
    upload_app: Flask, db_session: Session, store_root: Path
) -> None:
    client = signup(upload_app, "alice@example.com")

    response = _post(client, CORPUS["text.txt"], "notes.exe", headers=HTMX)

    body = response.get_data(as_text=True)
    assert response.status_code == 415
    assert 'id="upload-binary"' in body
    assert "Upload an ELF, PE or Mach-O executable" in body
    assert stored_files(store_root) == []
    assert db_session.scalars(select(Asset)).all() == []
    assert db_session.scalars(select(Scan)).all() == []


def test_rejected_binary_on_a_plain_post_marks_only_the_binary_form(upload_app: Flask) -> None:
    client = signup(upload_app, "alice@example.com")

    body = _post(client, CORPUS["text.txt"]).get_data(as_text=True)

    assert 'id="f-binary-error"' in body
    assert 'id="f-archive-error"' not in body


def test_binary_upload_without_a_file_is_422(upload_app: Flask) -> None:
    client = signup(upload_app, "alice@example.com")
    match = CSRF.search(client.get("/assets").get_data(as_text=True))
    assert match

    response = client.post("/assets/upload-binary", data={"csrf_token": match.group(1)})

    assert response.status_code == 422
    assert "Choose a file" in response.get_data(as_text=True)


def test_binary_upload_requires_csrf_token_and_login(
    upload_app: Flask, db_session: Session
) -> None:
    client = signup(upload_app, "alice@example.com")

    assert _post(client, csrf=False).status_code == 400
    assert _post(upload_app.test_client(), csrf=False).status_code == 302
    assert db_session.scalars(select(Asset)).all() == []


def test_binary_upload_over_the_body_ceiling_is_413_and_keeps_its_own_form(
    upload_app: Flask, db_session: Session, store_root: Path
) -> None:
    client = signup(upload_app, "alice@example.com")

    response = _post(client, ELF + bytes(MAX_BYTES + 128 * 1024), headers=HTMX)

    assert response.status_code == 413
    assert 'id="upload-binary"' in response.get_data(as_text=True)
    assert stored_files(store_root) == []
    assert db_session.scalars(select(Asset)).all() == []


def _post_archive(client: FlaskClient) -> TestResponse:
    match = CSRF.search(client.get("/assets").get_data(as_text=True))
    assert match
    form = {"archive": (io.BytesIO(b"nope"), "a.zip"), "csrf_token": match.group(1)}
    return client.post("/assets/upload", data=form, content_type="multipart/form-data")


def test_binary_upload_is_rate_limited_per_user(upload_app: Flask) -> None:
    client = signup(upload_app, "alice@example.com")
    allowed = int(uploads.UPLOAD_LIMIT.split()[0])

    statuses = [_post(client, b"nope").status_code for _ in range(allowed + 1)]

    assert statuses == [415] * allowed + [429]
    assert _post(signup(upload_app, "bob@other.example"), b"nope").status_code == 415


def test_upload_endpoints_share_one_per_user_allowance(upload_app: Flask) -> None:
    """Regression: each endpoint had its own bucket, so two routes meant twice the uploads."""
    client = signup(upload_app, "alice@example.com")
    allowed = int(uploads.UPLOAD_LIMIT.split()[0])

    binaries = [_post(client, b"nope").status_code for _ in range(allowed // 2)]
    archives = [_post_archive(client).status_code for _ in range(allowed - allowed // 2)]

    assert set(binaries + archives) == {415}
    assert (_post_archive(client).status_code, _post(client, b"nope").status_code) == (429, 429)


def test_uploaded_binary_is_invisible_to_another_org(
    upload_app: Flask, db_session: Session
) -> None:
    _post(signup(upload_app, "alice@example.com"), filename="alice-secret-tool")
    asset_id = db_session.scalars(select(Asset.id).where(Asset.type == AssetType.BINARY)).one()
    bob = signup(upload_app, "bob@other.example")

    assert bob.get(f"/assets/{asset_id}").status_code == 404
    listing = bob.get("/assets?type=binary").get_data(as_text=True)
    assert VALUE not in listing
    assert "alice-secret-tool" not in listing
    assert bob.get(f"/api/v1/assets/{asset_id}").status_code == 404
    # The same bytes uploaded by the other org become that org's own asset.
    assert _post(bob).status_code == 303
    owners = db_session.scalars(select(Asset.org_id).where(Asset.value == VALUE)).all()
    assert len(set(owners)) == 2


def test_binary_upload_is_refused_when_storage_has_no_encryption_key(
    db_app: Flask, db_session: Session
) -> None:
    client = signup(db_app, "alice@example.com")

    response = _post(client, headers=HTMX)

    assert response.status_code == 503
    assert "Uploads are not configured" in response.get_data(as_text=True)
    assert db_session.scalars(select(Asset)).all() == []
