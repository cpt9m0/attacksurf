"""`/api/v1/scans` against real Postgres, signed in through the real signup flow."""

import re
from typing import Any
from uuid import UUID, uuid4

import pytest
from flask import Flask
from flask.testing import FlaskClient
from sqlalchemy import select
from sqlalchemy.orm import Session

import attacksurf.web.api.v1 as api_module
from attacksurf.domain.scans import ScanStatus
from attacksurf.infra.db.models import Asset, Scan
from attacksurf.infra.db.tenancy import scoped
from tests.fakes import FakeQueue
from tests.helpers import make_settings

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


def _org_id(session: Session, root_id: UUID) -> UUID:
    return session.scalars(select(Asset.org_id).where(Asset.id == root_id)).one()


def _add(client: FlaskClient, value: str) -> dict[str, Any]:
    response = _post(client, "/api/v1/assets", {"value": value})
    assert response.status_code == 201, response.get_json()
    return response.get_json()


@pytest.fixture
def alice(db_app: Flask, monkeypatch: pytest.MonkeyPatch) -> FlaskClient:
    monkeypatch.setattr(
        api_module, "get_task_queue", lambda: FakeQueue(db_app.extensions["db_session_factory"]())
    )
    return _signup(db_app, "alice@example.com")


@pytest.fixture
def bob(db_app: Flask) -> FlaskClient:
    return _signup(db_app, "bob@example.com")


@pytest.fixture
def root_id(alice: FlaskClient) -> UUID:
    return UUID(_add(alice, "example.com")["id"])


def test_anonymous_requests_get_401(db_app: Flask) -> None:
    client = db_app.test_client()
    scan_id = uuid4()

    assert client.get("/api/v1/scans").status_code == 401
    assert client.get(f"/api/v1/scans/{scan_id}").status_code == 401
    assert client.post("/api/v1/scans", json={"root_asset_id": str(scan_id)}).status_code == 401


def test_create_get_and_list_a_scan(alice: FlaskClient, db_session: Session, root_id: UUID) -> None:
    created = _post(alice, "/api/v1/scans", {"root_asset_id": str(root_id)}).get_json()

    assert created["scan"]["root_value"] == "example.com"
    assert created["scan"]["status"] == "queued"
    assert created["jobs_total"] == 1  # the kickoff job
    assert created["diff"] is None
    assert created["can_cancel"] is True

    response = _post(alice, "/api/v1/scans", {"root_asset_id": str(root_id)})
    listed = alice.get("/api/v1/scans").get_json()
    detail = alice.get(f"/api/v1/scans/{created['scan']['id']}").get_json()

    assert response.status_code == 409  # the first scan is still running
    assert response.get_json()["scan_id"] == created["scan"]["id"]
    assert listed["total"] == 1
    assert [item["id"] for item in listed["items"]] == [created["scan"]["id"]]
    assert (listed["page"], listed["pages"]) == (1, 1)
    assert detail == created


def test_create_returns_location_and_defaults_the_profile(
    alice: FlaskClient, root_id: UUID
) -> None:
    response = _post(alice, "/api/v1/scans", {"root_asset_id": str(root_id)})

    body = response.get_json()
    assert response.status_code == 201
    assert response.headers["Location"] == f"/api/v1/scans/{body['scan']['id']}"
    assert body["scan"]["profile"] == "dns_passive"


@pytest.mark.parametrize("body", [None, {}, {"value": "x"}, {"root_asset_id": 7}, []])
def test_create_rejects_malformed_bodies(alice: FlaskClient, body: Any) -> None:
    response = _post(alice, "/api/v1/scans", body)

    assert response.status_code == 422
    assert response.get_json()["error"] == "Unprocessable Entity"


@pytest.mark.parametrize("root_asset_id", ["not-a-uuid", ""])
def test_create_rejects_non_uuid_roots(alice: FlaskClient, root_asset_id: str) -> None:
    response = _post(alice, "/api/v1/scans", {"root_asset_id": root_asset_id})

    assert response.status_code == 422


def test_create_rejects_unknown_profile_and_foreign_root(
    alice: FlaskClient, bob: FlaskClient, root_id: UUID
) -> None:
    # Same value in another org: roots are per-org, so this is a foreign root for alice.
    others = _post(bob, "/api/v1/assets", {"value": "example.com"}).get_json()

    unknown = _post(alice, "/api/v1/scans", {"root_asset_id": str(root_id), "profile": "nope"})
    foreign = _post(alice, "/api/v1/scans", {"root_asset_id": others["id"]})

    assert unknown.status_code == 422
    assert foreign.status_code == 404


def test_rate_limit_returns_429(
    alice: FlaskClient, root_id: UUID, db_session: Session, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(
        api_module, "get_settings", lambda: make_settings(scan_max_starts_per_hour=1)
    )
    _post(alice, "/api/v1/scans", {"root_asset_id": str(root_id)})
    org_id = _org_id(db_session, root_id)
    db_session.scalars(scoped(Scan, org_id)).one().status = ScanStatus.COMPLETED
    db_session.commit()

    limited = _post(alice, "/api/v1/scans", {"root_asset_id": str(root_id)})

    assert limited.status_code == 429
    assert limited.get_json() == {
        "error": "Too Many Requests",
        "message": "Too many scans started recently. Try again later.",
    }


def test_broker_failure_returns_503_without_internals(
    alice: FlaskClient, db_app: Flask, monkeypatch: pytest.MonkeyPatch, root_id: UUID
) -> None:
    session_factory = db_app.extensions["db_session_factory"]
    monkeypatch.setattr(
        api_module, "get_task_queue", lambda: FakeQueue(session_factory(), fail=True)
    )

    response = _post(alice, "/api/v1/scans", {"root_asset_id": str(root_id)})

    assert response.status_code == 503
    body = response.get_json()
    assert body["error"] == "Service Unavailable"
    assert "broker" not in body["message"]
    assert "unreachable" not in body["message"]
    session = session_factory()
    assert (
        session.scalars(scoped(Scan, _org_id(session, root_id))).one().status == ScanStatus.FAILED
    )


def test_get_scan_hides_other_tenants(alice: FlaskClient, bob: FlaskClient, root_id: UUID) -> None:
    created = _post(alice, "/api/v1/scans", {"root_asset_id": str(root_id)}).get_json()
    scan_id = created["scan"]["id"]

    assert bob.get(f"/api/v1/scans/{scan_id}").status_code == 404
    assert bob.get(f"/api/v1/scans/{scan_id}").get_json() == {
        "error": "Not Found",
        "message": "Scan not found.",
    }
    assert alice.get(f"/api/v1/scans/{uuid4()}").status_code == 404
    assert bob.get("/api/v1/scans").get_json()["total"] == 0


def test_list_scans_filters_and_rejects_bad_params(alice: FlaskClient, root_id: UUID) -> None:
    _post(alice, "/api/v1/scans", {"root_asset_id": str(root_id)})

    assert alice.get("/api/v1/scans", query_string={"status": "bogus"}).status_code == 400
    assert alice.get("/api/v1/scans", query_string={"root": "bogus"}).status_code == 400
    assert alice.get("/api/v1/scans", query_string={"root": str(root_id)}).get_json()["total"] == 1
    assert alice.get("/api/v1/scans", query_string={"root": str(uuid4())}).get_json()["total"] == 0
    assert alice.get("/api/v1/scans", query_string={"status": "queued"}).get_json()["total"] == 1
    assert alice.get("/api/v1/scans", query_string={"status": "completed"}).get_json()["total"] == 0
