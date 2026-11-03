"""Ownership card on the asset pages: who may start a proof, and what it shows (#14)."""

import re
from uuid import UUID

import pytest
from flask import Flask
from flask.testing import FlaskClient
from sqlalchemy import select
from sqlalchemy.orm import Session
from werkzeug.test import TestResponse

from attacksurf.domain.accounts import Role
from attacksurf.domain.assets import AssetSource, AssetType
from attacksurf.domain.verification import record_value
from attacksurf.infra.db.models import Asset, Job, Membership, User, Verification
from attacksurf.services import verifications
from attacksurf.services.assets import record_asset
from attacksurf.web import ui
from tests.fakes import FakeQueue

_CSRF = re.compile(r'name="csrf_token" value="([^"]+)"')
_INLINE = (
    re.compile(r"<script(?![^>]*\ssrc=)[^>]*>"),
    re.compile(r"\son[a-z]+\s*="),
    re.compile(r"\sstyle\s*="),
)


def _csrf(client: FlaskClient, path: str) -> str:
    match = _CSRF.search(client.get(path).get_data(as_text=True))
    assert match
    return match.group(1)


def _signup(app: Flask, email: str, org_name: str | None = None) -> FlaskClient:
    client = app.test_client()
    response = client.post(
        "/signup",
        data={
            "email": email,
            "password": "correct horse battery",
            "org_name": org_name or email.split("@", maxsplit=1)[0],
            "csrf_token": _csrf(client, "/signup"),
        },
    )
    assert response.status_code == 302, response.get_data(as_text=True)
    return client


def _demote(session: Session, email: str) -> None:
    user = session.scalars(select(User).where(User.email == email)).one()
    membership = session.scalars(select(Membership).where(Membership.user_id == user.id)).one()
    membership.role = Role.MEMBER
    session.commit()


def _add(client: FlaskClient, value: str = "example.com") -> UUID:
    response = client.post("/assets", data={"value": value, "csrf_token": _csrf(client, "/assets")})
    assert response.status_code == 303, response.get_data(as_text=True)
    return UUID(str(response.headers["Location"]).rsplit("/", 1)[-1])


def _html(client: FlaskClient, path: str) -> str:
    response = client.get(path)
    assert response.status_code == 200, response.status_code
    return response.get_data(as_text=True)


def _start(client: FlaskClient, asset_id: UUID, *, htmx: bool = False) -> TestResponse:
    headers = {"HX-Request": "true"} if htmx else {}
    return client.post(
        f"/assets/{asset_id}/verify",
        data={"action": "start", "csrf_token": _csrf(client, f"/assets/{asset_id}")},
        headers=headers,
    )


class RecordingQueue:
    """Stands in for the app's Celery queue: the real one would dial Redis (not in tests)."""

    def __init__(self) -> None:
        self.sent: list[str] = []

    def enqueue(self, task_name: str, *, org_id: UUID, job_id: UUID) -> str:
        self.sent.append(task_name)
        return f"task-{len(self.sent)}"


@pytest.fixture
def queue(monkeypatch: pytest.MonkeyPatch) -> RecordingQueue:
    recorder = RecordingQueue()
    monkeypatch.setattr(ui, "get_task_queue", lambda: recorder)
    return recorder


@pytest.fixture
def alice(db_app: Flask, queue: RecordingQueue) -> FlaskClient:
    return _signup(db_app, "alice@example.com")


@pytest.fixture
def root(db_session: Session, alice: FlaskClient) -> UUID:
    return _add(alice)


def test_an_unverified_root_offers_to_start_verification(alice: FlaskClient, root: UUID) -> None:
    page = _html(alice, f"/assets/{root}")

    assert "Start verification" in page
    assert "_attacksurf-verify.example.com" not in page


def test_starting_a_proof_shows_the_record_to_publish(
    alice: FlaskClient, db_session: Session, root: UUID
) -> None:
    response = _start(alice, root)

    assert response.status_code == 303
    page = _html(alice, f"/assets/{root}")
    token = db_session.scalars(select(Verification.token)).one()
    assert f'_attacksurf-verify.example.com TXT "attacksurf-verification={token}"' in page
    assert "Verify now" in page
    assert "Pending" in page


def test_starting_a_proof_queues_the_check_without_a_scan(
    alice: FlaskClient, db_session: Session, root: UUID, queue: RecordingQueue
) -> None:
    _start(alice, root)

    job = db_session.scalars(select(Job)).one()
    assert (job.stage, job.scan_id, job.asset_id) == ("verify", None, root)
    assert queue.sent == ["passive.verify_ownership"]


def test_htmx_start_swaps_only_the_ownership_card(
    alice: FlaskClient, db_session: Session, root: UUID
) -> None:
    response = _start(alice, root, htmx=True)

    page = response.get_data(as_text=True)
    assert response.status_code == 200
    assert page.lstrip().startswith('<section class="card card-body ownership"')
    assert "_attacksurf-verify.example.com" in page
    assert "Verify now" in page


def test_check_requires_a_token_first(alice: FlaskClient, root: UUID) -> None:
    response = alice.post(
        f"/assets/{root}/verify",
        data={"action": "check", "csrf_token": _csrf(alice, f"/assets/{root}")},
    )

    assert response.status_code == 404


def test_a_verified_root_shows_its_badge_everywhere(
    alice: FlaskClient, db_session: Session, root: UUID
) -> None:
    proof = verifications.start_verification(
        db_session, FakeQueue(db_session), org_id=_org_id(db_session, root), asset_id=root,
        actor_id=None,
    )  # fmt: skip
    verifications.record_check(db_session, proof, (record_value(proof.token),))
    db_session.commit()

    details = _html(alice, f"/assets/{root}")
    row = _list_row(_html(alice, "/assets"), root)

    assert details.count("Verified") >= 2  # header badge and the ownership card
    assert "Verified" in row


def test_a_subdomain_shows_its_roots_proof_read_only(
    alice: FlaskClient, db_session: Session, root: UUID
) -> None:
    org_id = _org_id(db_session, root)
    verifications.start_verification(
        db_session, FakeQueue(db_session), org_id=org_id, asset_id=root, actor_id=None
    )
    child = record_asset(
        db_session,
        org_id,
        AssetType.SUBDOMAIN,
        "www.example.com",
        source=AssetSource.DISCOVERED,
        parent_id=root,
    ).id
    db_session.commit()

    page = _html(alice, f"/assets/{child}")

    assert "_attacksurf-verify.example.com" in page  # the root's record
    assert "Verify now" not in page
    assert "/verify" not in page


def test_members_see_no_start_action_and_cannot_verify(
    alice: FlaskClient, db_session: Session, root: UUID
) -> None:
    _demote(db_session, "alice@example.com")

    page = _html(alice, f"/assets/{root}")
    response = _start(alice, root)

    assert "Start verification" not in page
    assert "An administrator can prove control" in page
    assert response.status_code == 403


def test_another_org_cannot_see_or_start_a_proof(
    db_app: Flask, db_session: Session, root: UUID
) -> None:
    other = _signup(db_app, "mallory@example.com", "mallory")
    other.post("/assets", data={"value": "mallory.example", "csrf_token": _csrf(other, "/assets")})

    detail = other.get(f"/assets/{root}")
    # A valid CSRF token of their own, so only the tenant scoping can stop the request.
    response = other.post(
        f"/assets/{root}/verify",
        data={"action": "start", "csrf_token": _csrf(other, "/assets")},
    )

    assert detail.status_code == 404
    assert response.status_code == 404
    assert not db_session.scalars(select(Verification)).all()


def test_ownership_card_has_no_inline_script_style_or_handlers(
    alice: FlaskClient, db_session: Session, root: UUID
) -> None:
    _start(alice, root)
    db_session.commit()

    page = _html(alice, f"/assets/{root}")

    for pattern in _INLINE:
        assert not pattern.search(page), pattern.pattern


def test_the_card_route_serves_the_fragment_alone(
    alice: FlaskClient, db_session: Session, root: UUID
) -> None:
    _start(alice, root)
    db_session.commit()

    page = _html(alice, f"/assets/{root}/ownership")

    assert page.lstrip().startswith('<section class="card card-body ownership"')
    assert "<html" not in page


def test_an_unknown_asset_has_no_card(alice: FlaskClient) -> None:
    response = alice.get("/assets/00000000-0000-0000-0000-000000000000/ownership")

    assert response.status_code == 404


def test_a_pending_proof_cannot_be_rotated_yet(
    alice: FlaskClient, db_session: Session, root: UUID
) -> None:
    _start(alice, root)
    db_session.commit()

    assert "Rotate token" not in _html(alice, f"/assets/{root}")


def _org_id(session: Session, asset_id: UUID) -> UUID:
    asset = session.get(Asset, asset_id)
    assert asset is not None
    return asset.org_id


def _list_row(page: str, asset_id: UUID) -> str:
    start = page.index(f'<tr><td><a class="mono" href="/assets/{asset_id}"')
    return page[start : page.index("</tr>", start)]
