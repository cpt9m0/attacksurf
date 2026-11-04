"""The ownership card without a database: the services are stubbed (#14)."""

import re
from uuid import uuid4

import pytest
from flask import Flask
from flask.testing import FlaskClient

from attacksurf.domain.accounts import Role
from attacksurf.domain.assets import AssetSource, AssetType
from attacksurf.domain.verification import VerificationMethod, VerificationStatus
from attacksurf.services import asset_views, verifications
from attacksurf.web import ui
from tests.unit.web.conftest import make_session_user


@pytest.fixture
def asset_id() -> object:
    return uuid4()


@pytest.fixture
def stubs(monkeypatch: pytest.MonkeyPatch, asset_id: object) -> dict[str, list[dict[str, object]]]:
    """One root domain with no proof; anything not listed here fails the test if called."""
    row = asset_views.AssetRow(
        id=asset_id,  # type: ignore[arg-type]
        type=AssetType.DOMAIN,
        value="example.com",
        source=AssetSource.USER,
        root_id=None,
        root_value=None,
        tags=(),
        first_seen=None,  # type: ignore[arg-type]
        last_seen=None,  # type: ignore[arg-type]
        is_active=True,
        open_findings=0,
        max_severity=None,
        verification=None,
    )
    calls: dict[str, list[dict[str, object]]] = {"started": [], "checked": []}
    monkeypatch.setattr(asset_views, "get_asset", lambda *_a, **_k: row)
    monkeypatch.setattr(
        asset_views,
        "get_asset_detail",
        lambda *_a, **_k: asset_views.AssetDetail(row, (), (), 0),
    )
    monkeypatch.setattr(verifications, "read_verification", lambda *_a, **_k: None)
    monkeypatch.setattr(verifications, "check_in_flight", lambda *_a, **_k: False)

    def start(*_args: object, **kw: object) -> None:
        calls["started"].append(kw)

    monkeypatch.setattr(verifications, "start_verification", start)

    def queue_check(*_args: object, **kw: object) -> None:
        calls["checked"].append(kw)

    monkeypatch.setattr(verifications, "queue_check", queue_check)
    return calls


@pytest.fixture
def queue(app: Flask) -> object:
    return object()


@pytest.fixture(autouse=True)
def _fake_queue(monkeypatch: pytest.MonkeyPatch, queue: object) -> None:

    monkeypatch.setattr(ui, "get_task_queue", lambda: queue)


def test_the_card_renders_for_a_domain_without_a_proof(
    auth_client: FlaskClient, asset_id: object, stubs: dict[str, list[dict[str, object]]]
) -> None:
    response = auth_client.get(f"/assets/{asset_id}/ownership")

    assert response.status_code == 200
    assert "Start verification" in response.get_data(as_text=True)


def test_a_root_asset_reads_its_own_proof(
    auth_client: FlaskClient,
    asset_id: object,
    stubs: dict[str, list[dict[str, object]]],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    read: list[tuple[object, object]] = []
    monkeypatch.setattr(
        verifications, "read_verification", lambda _session, _org, root_id: read.append(root_id)
    )

    auth_client.get(f"/assets/{asset_id}/ownership")

    assert read == [asset_id]
    assert stubs["started"] == []


def test_members_get_the_card_but_no_actions(
    auth_client: FlaskClient,
    login_as: object,
    asset_id: object,
    stubs: dict[str, list[dict[str, object]]],
) -> None:
    login_as(auth_client, make_session_user(role=Role.MEMBER))  # type: ignore[operator]

    page = auth_client.get(f"/assets/{asset_id}/ownership").get_data(as_text=True)

    assert "Start verification" not in page
    assert "An administrator can prove control" in page


def test_a_start_post_passes_the_org_and_actor_from_the_session(
    auth_client: FlaskClient, asset_id: object, stubs: dict[str, list[dict[str, object]]]
) -> None:
    token = _csrf(auth_client, f"/assets/{asset_id}/ownership")

    response = auth_client.post(
        f"/assets/{asset_id}/verify", data={"action": "start", "csrf_token": token}
    )

    assert response.status_code == 303
    started = stubs["started"]
    assert isinstance(started, list)
    assert len(started) == 1
    # The signed-in user's org and id, never anything taken from the request.
    assert started[0]["org_id"] is not None
    assert started[0]["actor_id"] is not None


def test_a_post_without_csrf_is_rejected(
    auth_client: FlaskClient, asset_id: object, stubs: dict[str, list[dict[str, object]]]
) -> None:
    response = auth_client.post(f"/assets/{asset_id}/verify", data={"action": "start"})

    assert response.status_code == 400
    assert stubs["started"] == []


def test_a_check_queues_without_starting_a_new_proof(
    auth_client: FlaskClient, asset_id: object, stubs: dict[str, list[dict[str, object]]]
) -> None:
    token = _csrf(auth_client, f"/assets/{asset_id}/ownership")

    response = auth_client.post(
        f"/assets/{asset_id}/verify", data={"action": "check", "csrf_token": token}
    )

    assert response.status_code == 303
    assert stubs["started"] == []  # the token the user published must not rotate
    assert len(stubs["checked"]) == 1


def test_a_verified_once_counted_proof_is_shown_with_its_record(
    auth_client: FlaskClient,
    asset_id: object,
    stubs: dict[str, list[dict[str, object]]],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    proof = verifications.VerificationView(
        asset_id=asset_id,  # type: ignore[arg-type]
        status=VerificationStatus.REVOKED,
        method=VerificationMethod.DNS_TXT,
        record_name="_attacksurf-verify.example.com",
        record_value="attacksurf-verification=token",
        verified_at=None,
        last_checked_at=None,
        expires_at=None,
    )
    monkeypatch.setattr(verifications, "read_verification", lambda *_a, **_k: proof)

    page = auth_client.get(f"/assets/{asset_id}/ownership").get_data(as_text=True)

    assert "Revoked" in page
    assert "Rotate token" in page  # a revoked proof can be re-issued


def _csrf(client: FlaskClient, path: str) -> str:
    match = re.search(r'name="csrf_token" value="([^"]+)"', client.get(path).get_data(as_text=True))
    assert match
    return match.group(1)
