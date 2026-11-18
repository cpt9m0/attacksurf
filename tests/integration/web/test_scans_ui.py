"""Scan pages against real Postgres, signed in through the real signup flow.

Starting and cancelling scans is open to every org member (only archiving and
verification need an admin), so the main client here is demoted to MEMBER.
"""

import re
from datetime import UTC, datetime
from uuid import UUID, uuid4

import pytest
from flask import Flask
from flask.testing import FlaskClient
from sqlalchemy import select, update
from sqlalchemy.orm import Session

import attacksurf.web.ui as ui_module
from attacksurf.domain.accounts import Role
from attacksurf.domain.assets import AssetSource, AssetType
from attacksurf.domain.scans import ScanStatus
from attacksurf.infra.db.models import Asset, Job, Membership, Scan, User
from attacksurf.infra.db.tenancy import scoped
from attacksurf.services import scan_views
from attacksurf.services.assets import record_asset
from attacksurf.services.scan_views import ScanFilter
from tests.fakes import FakeQueue
from tests.helpers import make_settings

_CSRF = re.compile(r'name="csrf_token" value="([^"]+)"')
HTMX = {"HX-Request": "true"}
_STATS = {
    "findings": {
        "new": {
            "total": 1,
            "by_severity": {"critical": 1, "high": 0, "medium": 0, "low": 0, "info": 0},
        },
        "fixed": {
            "total": 0,
            "by_severity": {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0},
        },
        "regressed": {
            "total": 0,
            "by_severity": {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0},
        },
        "total": {
            "total": 2,
            "by_severity": {"critical": 1, "high": 1, "medium": 0, "low": 0, "info": 0},
        },
    },
    "assets": {
        "new": {
            "total": 1,
            "assets": [
                {
                    "id": "11111111-1111-1111-1111-111111111111",
                    "type": "subdomain",
                    "value": "new.example.com",
                }
            ],
        },
        "disappeared": {"total": 0, "assets": []},
    },
}


def _csrf(client: FlaskClient, path: str = "/scans") -> str:
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


def _org_id(session: Session, root_id: UUID) -> UUID:
    return session.scalars(select(Asset.org_id).where(Asset.id == root_id)).one()


def _demote(session: Session, email: str) -> None:
    user = session.scalars(select(User).where(User.email == email)).one()
    membership = session.scalars(select(Membership).where(Membership.user_id == user.id)).one()
    membership.role = Role.MEMBER
    session.commit()


def _add_domain(client: FlaskClient, value: str) -> UUID:
    response = client.post("/assets", data={"value": value, "csrf_token": _csrf(client, "/assets")})
    assert response.status_code == 303, response.get_data(as_text=True)
    return UUID(response.headers["Location"].rsplit("/", 1)[1])


def _start(client: FlaskClient, root_id: UUID) -> str:
    response = client.post(
        "/scans",
        data={
            "root_asset_id": str(root_id),
            "profile": "dns_passive",
            "csrf_token": _csrf(client),
        },
    )
    assert response.status_code == 303, response.get_data(as_text=True)
    return response.headers["Location"]


def _html(client: FlaskClient, path: str, headers: dict[str, str] | None = None) -> str:
    response = client.get(path, headers=headers or {})
    assert response.status_code == 200, (path, response.status_code)
    return response.get_data(as_text=True)


@pytest.fixture
def alice(db_app: Flask, monkeypatch: pytest.MonkeyPatch) -> FlaskClient:
    monkeypatch.setattr(
        ui_module, "get_task_queue", lambda: FakeQueue(db_app.extensions["db_session_factory"]())
    )
    return _signup(db_app, "alice@example.com")


@pytest.fixture
def member(alice: FlaskClient, db_session: Session) -> FlaskClient:
    _demote(db_session, "alice@example.com")
    return alice


def test_member_starts_a_scan_from_the_scans_page(member: FlaskClient, db_session: Session) -> None:
    root_id = _add_domain(member, "example.com")

    location = _start(member, root_id)

    scan_id = UUID(location.rsplit("/", 1)[1])
    scan = db_session.get(Scan, scan_id)
    assert scan is not None
    assert (scan.status, scan.profile) == (ScanStatus.QUEUED, "dns_passive")
    detail = _html(member, location)
    assert "Scan of" in detail
    assert "example.com" in detail
    assert 'hx-trigger="every 2s"' in detail  # progress polls while the scan runs
    assert "Scan started for example.com." in detail  # the flash survives the redirect


def test_scan_now_on_the_asset_detail_page(member: FlaskClient) -> None:
    root_id = _add_domain(member, "example.com")

    detail = _html(member, f"/assets/{root_id}")

    assert 'action="/scans"' in detail
    assert f'name="root_asset_id" value="{root_id}"' in detail
    assert "Scan now" in detail


def test_asset_page_shows_running_scan_instead_of_a_second_button(
    member: FlaskClient,
) -> None:
    root_id = _add_domain(member, "example.com")
    location = _start(member, root_id)

    detail = _html(member, f"/assets/{root_id}")

    assert "Scan now" not in detail
    assert f'href="{location}"' in detail
    assert "View running scan" in detail


def test_scan_now_only_on_active_root_domains(member: FlaskClient, db_session: Session) -> None:
    root_id = _add_domain(member, "example.com")
    org_id = _org_id(db_session, root_id)
    child_id = record_asset(
        db_session,
        org_id,
        AssetType.SUBDOMAIN,
        "sub.example.com",
        source=AssetSource.DISCOVERED,
        parent_id=root_id,
    ).id
    db_session.commit()

    assert "Scan now" not in _html(member, "/assets")  # the list never starts scans
    assert "Scan now" not in _html(member, f"/assets/{child_id}")  # nor subdomains


def test_duplicate_start_lands_on_the_running_scan(member: FlaskClient) -> None:
    root_id = _add_domain(member, "example.com")
    location = _start(member, root_id)

    response = member.post(
        "/scans",
        data={
            "root_asset_id": str(root_id),
            "profile": "dns_passive",
            "csrf_token": _csrf(member),
        },
    )

    assert response.status_code == 303
    assert response.headers["Location"] == location
    assert "already running" in _html(member, location)


def test_quota_refuses_with_a_flash_and_no_new_scan(
    member: FlaskClient, db_session: Session, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(
        ui_module, "get_settings", lambda: make_settings(scan_max_starts_per_hour=2)
    )
    root_id = _add_domain(member, "example.com")
    org_id = _org_id(db_session, root_id)
    _start(member, root_id)
    db_session.execute(update(Scan).values(status=ScanStatus.COMPLETED))
    db_session.commit()
    _start(member, root_id)
    db_session.execute(update(Scan).values(status=ScanStatus.COMPLETED))
    db_session.commit()

    response = member.post(
        "/scans",
        data={
            "root_asset_id": str(root_id),
            "profile": "dns_passive",
            "csrf_token": _csrf(member),
        },
    )

    assert response.status_code == 303
    assert response.headers["Location"] == f"/assets/{root_id}"
    assert "Too many scans" in _html(member, f"/assets/{root_id}")
    assert db_session.scalars(scoped(Scan, org_id)).all().__len__() == 2


def test_progress_stops_polling_and_shows_the_diff_once_finished(
    member: FlaskClient, db_session: Session
) -> None:
    root_id = _add_domain(member, "example.com")
    location = _start(member, root_id)
    scan_id = UUID(location.rsplit("/", 1)[1])

    detail = _html(member, location)
    assert detail.index('id="scan-actions"') < detail.index(
        'id="scan-progress"'
    )  # the dialog lives outside the polled subtree
    assert detail.count('id="scan-progress"') == 1
    for target in ("scan-status", "scan-meta", "scan-actions"):
        assert detail.count(f'id="{target}"') == 1  # OOB targets exist exactly once
    assert "hx-swap-oob" not in detail  # first paint carries no out-of-band swaps
    assert "/cancel" in detail  # the action is on the page, not in the fragment
    assert ">queued<" in detail

    running = _html(member, f"{location}/progress", headers=HTMX)
    assert 'hx-trigger="every 2s"' in running
    # Every replacement carries its target's id: the swap removes the old element, so a
    # later poll must still find its target.
    assert running.count('hx-swap-oob="true"') == 2
    assert '<span id="scan-status" hx-swap-oob="true">' in running
    assert '<div id="scan-meta" hx-swap-oob="true">' in running
    assert "scan-actions" not in running  # the action is untouched while active
    assert "/cancel" not in running

    db_session.execute(
        update(Scan)
        .where(Scan.id == scan_id)
        .values(status=ScanStatus.RUNNING, started_at=datetime.now(UTC))
    )
    db_session.commit()
    mid = _html(member, f"{location}/progress", headers=HTMX)
    assert ">running<" in mid  # status and timestamps refresh without a reload
    assert '<div id="scan-actions" hx-swap-oob="true">' not in mid

    db_session.execute(
        update(Scan).where(Scan.id == scan_id).values(status=ScanStatus.COMPLETED, stats=_STATS)
    )
    db_session.execute(update(Job).values(status=ScanStatus.COMPLETED))
    db_session.commit()

    finished = _html(member, f"{location}/progress", headers=HTMX)
    assert "every 2s" not in finished
    assert ">completed<" in finished
    assert finished.count('hx-swap-oob="true"') == 3
    assert '<div id="scan-actions" hx-swap-oob="true"></div>' in finished
    assert "Changes since the last scan" in finished
    assert "new.example.com" in finished

    final = _html(member, location)
    assert "Cancel scan" not in final
    assert ">completed<" in final
    assert "1 of 1 job finished" in final


def test_diff_shows_disappeared_truncation_notice(member: FlaskClient, db_session: Session) -> None:
    root_id = _add_domain(member, "example.com")
    location = _start(member, root_id)
    scan_id = UUID(location.rsplit("/", 1)[1])
    stats = {
        "findings": {},
        "assets": {
            "new": {"total": 0, "assets": []},
            "disappeared": {
                "total": scan_views.MAX_DIFF_ASSETS + 1,
                "assets": [
                    {
                        "id": str(uuid4()),
                        "type": "subdomain",
                        "value": f"gone-{index}.example.com",
                    }
                    for index in range(scan_views.MAX_DIFF_ASSETS + 1)
                ],
            },
        },
    }
    db_session.execute(
        update(Scan).where(Scan.id == scan_id).values(status=ScanStatus.COMPLETED, stats=stats)
    )
    db_session.commit()

    finished = _html(member, f"{location}/progress", headers=HTMX)

    assert f"of {scan_views.MAX_DIFF_ASSETS + 1} disappeared assets." in finished
    assert "new assets." not in finished  # only the disappeared half truncates


def test_cancel_scan_cancels_scan_and_jobs(member: FlaskClient, db_session: Session) -> None:
    root_id = _add_domain(member, "example.com")
    location = _start(member, root_id)
    org_id = _org_id(db_session, root_id)

    response = member.post(f"{location}/cancel", data={"csrf_token": _csrf(member, location)})

    assert response.status_code == 303
    assert response.headers["Location"] == location
    assert "Scan cancelled." in _html(member, location)
    assert db_session.scalars(scoped(Scan, org_id)).one().status == ScanStatus.CANCELLED
    assert {job.status for job in db_session.scalars(scoped(Job, org_id))} == {ScanStatus.CANCELLED}

    again = member.post(f"{location}/cancel", data={"csrf_token": _csrf(member, location)})
    assert again.status_code == 303  # idempotent


def test_other_tenants_scans_are_invisible(
    alice: FlaskClient, db_app: Flask, db_session: Session
) -> None:
    root_id = _add_domain(alice, "example.com")
    location = _start(alice, root_id)
    org_id = _org_id(db_session, root_id)
    bob = _signup(db_app, "bob@example.com")

    assert bob.get(location).status_code == 404
    assert bob.get(f"{location}/progress").status_code == 404
    assert (
        bob.post(f"{location}/cancel", data={"csrf_token": _csrf(bob, "/assets")}).status_code
        == 404
    )
    other_org = _html(bob, "/scans")
    assert "/scans/" not in other_org  # no links to scan detail pages
    assert f"/assets/{root_id}" not in other_org  # nor to alice's root
    assert scan_views.list_scans(db_session, org_id, ScanFilter()).total == 1


def test_broker_failure_marks_the_scan_failed(
    alice: FlaskClient, db_app: Flask, monkeypatch: pytest.MonkeyPatch
) -> None:
    session_factory = db_app.extensions["db_session_factory"]
    monkeypatch.setattr(
        ui_module, "get_task_queue", lambda: FakeQueue(session_factory(), fail=True)
    )
    root_id = _add_domain(alice, "example.com")

    response = alice.post(
        "/scans",
        data={
            "root_asset_id": str(root_id),
            "profile": "dns_passive",
            "csrf_token": _csrf(alice),
        },
    )

    assert response.status_code == 303
    assert "could not be queued" in _html(alice, response.headers["Location"])
    session = session_factory()
    assert (
        session.scalars(scoped(Scan, _org_id(session, root_id))).one().status == ScanStatus.FAILED
    )
