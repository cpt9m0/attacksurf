"""`/api/v1/assets` against real Postgres, signed in through the real signup flow."""

import re
from typing import Any

import pytest
from flask import Flask
from flask.testing import FlaskClient
from sqlalchemy import select
from sqlalchemy.orm import Session

from attacksurf.domain.accounts import Role
from attacksurf.domain.assets import AssetSource, AssetType
from attacksurf.domain.ids import uuid7
from attacksurf.infra.db.models import Asset, Membership, User
from attacksurf.services.assets import record_asset

_CSRF = re.compile(r'name="csrf_token" value="([^"]+)"')


def _csrf(client: FlaskClient, path: str) -> str:
    match = _CSRF.search(client.get(path).get_data(as_text=True))
    assert match
    return match.group(1)


def _signup(app: Flask, email: str) -> FlaskClient:
    client = app.test_client()
    response = client.post(
        "/signup",
        data={
            "email": email,
            "password": "correct horse battery",
            "org_name": email.split("@", maxsplit=1)[0],
            "csrf_token": _csrf(client, "/signup"),
        },
    )
    assert response.status_code == 302, response.get_data(as_text=True)
    return client


def _post(client: FlaskClient, path: str, body: Any = None) -> Any:
    return client.post(path, json=body, headers={"X-CSRFToken": _csrf(client, "/")})


def _add(client: FlaskClient, value: str) -> dict[str, Any]:
    response = _post(client, "/api/v1/assets", {"value": value})
    assert response.status_code == 201, response.get_json()
    return response.get_json()


@pytest.fixture
def alice(db_app: Flask) -> FlaskClient:
    return _signup(db_app, "alice@example.com")


@pytest.fixture
def bob(db_app: Flask) -> FlaskClient:
    return _signup(db_app, "bob@example.com")


def _set_role(session: Session, email: str, role: Role) -> None:
    user = session.scalars(select(User).where(User.email == email)).one()
    membership = session.scalars(select(Membership).where(Membership.user_id == user.id)).one()
    membership.role = role
    session.commit()


def test_anonymous_requests_get_401(db_app: Flask) -> None:
    client = db_app.test_client()

    assert client.get("/api/v1/assets").status_code == 401
    assert client.get(f"/api/v1/assets/{uuid7()}").status_code == 401
    assert client.post("/api/v1/assets", json={"value": "example.com"}).status_code == 401


def test_add_list_and_get_a_root_domain(alice: FlaskClient) -> None:
    created = _add(alice, "Example.COM")

    listed = alice.get("/api/v1/assets").get_json()
    detail = alice.get(f"/api/v1/assets/{created['id']}").get_json()

    assert (created["value"], created["type"], created["source"]) == (
        "example.com",
        "domain",
        "user",
    )
    assert created["open_findings"] == 0
    assert listed["total"] == 1
    assert [item["id"] for item in listed["items"]] == [created["id"]]
    assert (listed["page"], listed["pages"]) == (1, 1)
    assert detail["asset"] == created
    assert (detail["outgoing"], detail["incoming"], detail["discovered"]) == ([], [], 0)


def test_add_returns_location_and_iso_timestamps(alice: FlaskClient) -> None:
    response = _post(alice, "/api/v1/assets", {"value": "example.com"})

    body = response.get_json()
    assert response.headers["Location"] == f"/api/v1/assets/{body['id']}"
    assert re.fullmatch(r"\d{4}-\d\d-\d\dT[\d:.]+\+00:00", body["first_seen"])


@pytest.mark.parametrize("body", [None, {}, {"value": 7}, ["example.com"]])
def test_add_rejects_malformed_bodies(alice: FlaskClient, body: Any) -> None:
    response = _post(alice, "/api/v1/assets", body)

    assert response.status_code == 422
    assert response.get_json()["error"] == "Unprocessable Entity"


def test_add_rejects_unscannable_names_with_a_message(alice: FlaskClient) -> None:
    response = _post(alice, "/api/v1/assets", {"value": "printer.corp"})

    assert response.status_code == 422
    assert response.get_json() == {
        "error": "Unprocessable Entity",
        "message": "Internal-only domain names can't be scanned.",
    }


def test_add_twice_is_a_conflict(alice: FlaskClient) -> None:
    _add(alice, "example.com")

    response = _post(alice, "/api/v1/assets", {"value": "example.com"})

    assert response.status_code == 409
    assert response.get_json()["message"] == "example.com is already in your assets."


def test_add_without_csrf_token_is_rejected(alice: FlaskClient) -> None:
    assert alice.post("/api/v1/assets", json={"value": "example.com"}).status_code == 400


def test_list_applies_filters(alice: FlaskClient, db_session: Session) -> None:
    root = _add(alice, "example.com")
    asset = db_session.get(Asset, root["id"])
    assert asset is not None
    record_asset(
        db_session,
        asset.org_id,
        AssetType.SUBDOMAIN,
        "www.example.com",
        source=AssetSource.DISCOVERED,
        parent_id=asset.id,
    )
    db_session.commit()

    by_type = alice.get("/api/v1/assets?type=subdomain&status=all").get_json()
    by_root = alice.get(f"/api/v1/assets?root={root['id']}&q=www&tag=&page=1").get_json()

    assert [i["value"] for i in by_type["items"]] == ["www.example.com"]
    assert [i["value"] for i in by_root["items"]] == ["www.example.com"]
    assert by_root["items"][0]["root_value"] == "example.com"


@pytest.mark.parametrize(
    "query",
    ["type=server", "root=not-a-uuid", "status=deleted", f"tag={'t' * 51}", f"q={'q' * 254}"],
)
def test_list_rejects_bad_filters(alice: FlaskClient, query: str) -> None:
    response = alice.get(f"/api/v1/assets?{query}")

    assert response.status_code == 400
    assert response.get_json() == {"error": "Bad Request"}


def test_findings_and_scans_of_a_new_root_are_empty(alice: FlaskClient) -> None:
    root = _add(alice, "example.com")

    findings = alice.get(f"/api/v1/assets/{root['id']}/findings")
    scans = alice.get(f"/api/v1/assets/{root['id']}/scans")

    assert (findings.status_code, findings.get_json()) == (200, {"items": []})
    assert (scans.status_code, scans.get_json()) == (200, {"items": []})


def test_owner_can_archive_a_root(alice: FlaskClient) -> None:
    root = _add(alice, "example.com")

    response = _post(alice, f"/api/v1/assets/{root['id']}/archive")

    assert response.status_code == 200
    assert response.get_json()["is_active"] is False
    assert alice.get("/api/v1/assets").get_json()["total"] == 0
    assert alice.get("/api/v1/assets?status=archived").get_json()["total"] == 1


def test_members_cannot_archive(alice: FlaskClient, db_session: Session) -> None:
    root = _add(alice, "example.com")
    _set_role(db_session, "alice@example.com", Role.MEMBER)

    response = _post(alice, f"/api/v1/assets/{root['id']}/archive")

    assert response.status_code == 403
    assert alice.get(f"/api/v1/assets/{root['id']}").get_json()["asset"]["is_active"] is True


def test_admins_can_archive(alice: FlaskClient, db_session: Session) -> None:
    root = _add(alice, "example.com")
    _set_role(db_session, "alice@example.com", Role.ADMIN)

    assert _post(alice, f"/api/v1/assets/{root['id']}/archive").status_code == 200


def test_archiving_a_discovered_asset_is_not_found(alice: FlaskClient, db_session: Session) -> None:
    root = _add(alice, "example.com")
    asset = db_session.get(Asset, root["id"])
    assert asset is not None
    www = record_asset(
        db_session,
        asset.org_id,
        AssetType.SUBDOMAIN,
        "www.example.com",
        source=AssetSource.DISCOVERED,
        parent_id=asset.id,
    )
    db_session.commit()

    assert _post(alice, f"/api/v1/assets/{www.id}/archive").status_code == 404


def test_another_org_cannot_see_or_archive_the_asset(alice: FlaskClient, bob: FlaskClient) -> None:
    root = _add(alice, "example.com")
    asset_url = f"/api/v1/assets/{root['id']}"

    assert bob.get("/api/v1/assets?status=all").get_json()["total"] == 0
    assert bob.get(f"/api/v1/assets?root={root['id']}").get_json()["total"] == 0
    for path in (asset_url, f"{asset_url}/findings", f"{asset_url}/scans"):
        response = bob.get(path)
        assert response.status_code == 404
        assert response.get_json() == {"error": "Not Found", "message": "Asset not found."}
    assert _post(bob, f"{asset_url}/archive").status_code == 404
    assert alice.get(asset_url).get_json()["asset"]["is_active"] is True


def test_another_org_can_add_the_same_domain(alice: FlaskClient, bob: FlaskClient) -> None:
    mine = _add(alice, "example.com")
    theirs = _add(bob, "example.com")

    assert mine["id"] != theirs["id"]
