"""`/api/v1/findings` endpoints against real Postgres, signed in through the real signup flow."""

import re
from typing import Any
from uuid import UUID

import pytest
from flask import Flask
from flask.testing import FlaskClient
from sqlalchemy import select
from sqlalchemy.orm import Session

from attacksurf.domain.assets import AssetSource, AssetType
from attacksurf.domain.findings import EvidenceKind, FindingStatus, Severity
from attacksurf.infra.db.models import Asset, Evidence, Finding, Membership, User
from attacksurf.services.assets import record_asset
from tests.integration.factories import T0, make_finding

_CSRF = re.compile(r'name="csrf_token" value="([^"]+)"')


def _csrf(client: FlaskClient, path: str = "/") -> str:
    match = _CSRF.search(client.get(path).get_data(as_text=True))
    assert match, path
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


def _org_id(session: Session, email: str) -> UUID:
    user = session.scalars(select(User).where(User.email == email)).one()
    return session.scalars(select(Membership).where(Membership.user_id == user.id)).one().org_id


def _asset(session: Session, org_id: UUID, value: str = "example.com") -> Asset:
    asset = record_asset(session, org_id, AssetType.DOMAIN, value, source=AssetSource.USER)
    session.commit()
    return asset


def _finding(
    session: Session,
    org_id: UUID,
    asset_id: UUID,
    *,
    title: str = "No DMARC record",
    severity: Severity = Severity.HIGH,
    status: FindingStatus = FindingStatus.OPEN,
    location: str = "",
) -> Finding:
    finding = make_finding(
        session,
        org_id,
        asset_id,
        title=title,
        severity=severity,
        status=status,
        location=location,
        evidence=(),
        first_seen=T0,
        last_seen=T0,
    )
    session.commit()
    return finding


def _post(client: FlaskClient, path: str, body: Any) -> Any:
    return client.post(path, json=body, headers={"X-CSRFToken": _csrf(client)})


@pytest.fixture
def alice(db_app: Flask) -> FlaskClient:
    return _signup(db_app, "alice@example.com")


@pytest.fixture
def alice_org(db_session: Session, alice: FlaskClient) -> UUID:
    return _org_id(db_session, "alice@example.com")


def test_findings_require_a_session(db_app: Flask) -> None:
    client = db_app.test_client()

    assert client.get("/api/v1/findings").status_code == 401
    assert client.get(f"/api/v1/findings/{UUID(int=1)}").status_code == 401


def test_list_findings_shape_and_filters(
    alice: FlaskClient, db_session: Session, alice_org: UUID
) -> None:
    root = _asset(db_session, alice_org)
    _finding(db_session, alice_org, root.id, title="critical one", severity=Severity.CRITICAL)
    _finding(db_session, alice_org, root.id, title="low one", severity=Severity.LOW, location="a")

    everything = alice.get("/api/v1/findings").get_json()
    critical = alice.get("/api/v1/findings?severity=critical").get_json()

    assert everything["total"] == 2
    assert everything["page"] == 1
    assert everything["pages"] == 1
    assert [item["title"] for item in everything["items"]] == ["critical one", "low one"]
    assert everything["items"][0]["first_seen"].endswith("+00:00")
    assert [item["title"] for item in critical["items"]] == ["critical one"]


def test_get_finding_includes_evidence_and_refuses_other_orgs(
    db_app: Flask, alice: FlaskClient, db_session: Session, alice_org: UUID
) -> None:
    root = _asset(db_session, alice_org)
    finding = _finding(db_session, alice_org, root.id)
    finding_id = finding.id
    db_session.add(
        Evidence(
            org_id=alice_org,
            finding_id=finding_id,
            kind=EvidenceKind.DNS_RECORD,
            data={"record": "TXT", "name": "example.com", "values": ["v=spf1"]},
            captured_at=T0,
        )
    )
    db_session.commit()

    body = alice.get(f"/api/v1/findings/{finding_id}").get_json()
    bob = _signup(db_app, "bob@example.com")
    foreign = bob.get(f"/api/v1/findings/{finding_id}")

    assert body["finding"]["title"] == "No DMARC record"
    assert body["evidence"][0]["kind"] == "dns_record"
    assert body["evidence"][0]["body"] == "v=spf1"
    assert foreign.status_code == 404


def test_status_change_requires_comment_and_csrf(
    alice: FlaskClient, db_session: Session, alice_org: UUID
) -> None:
    root = _asset(db_session, alice_org)
    finding = _finding(db_session, alice_org, root.id)
    path = f"/api/v1/findings/{finding.id}/status"
    # `finding` is detached once the first request closes the shared session; the id is not.

    no_csrf = alice.post(path, json={"status": "accepted_risk", "comment": "why"})
    missing = _post(alice, path, {"status": "accepted_risk"})
    unknown = _post(alice, path, {"status": "not-a-status"})

    assert no_csrf.status_code == 400
    assert missing.status_code == 422
    assert unknown.status_code == 422


def test_status_change_updates_and_audits(
    alice: FlaskClient, db_session: Session, alice_org: UUID
) -> None:
    root = _asset(db_session, alice_org)
    finding = _finding(db_session, alice_org, root.id)
    finding_id = finding.id

    response = _post(
        alice,
        f"/api/v1/findings/{finding_id}/status",
        {"status": "false_positive", "comment": "test fixture"},
    )

    assert response.status_code == 200
    assert response.get_json() == {"id": str(finding_id), "status": "false_positive"}
    assert db_session.scalar(select(Finding.status).where(Finding.id == finding_id)) is (
        FindingStatus.FALSE_POSITIVE
    )


def test_invalid_transitions_are_conflicts(
    alice: FlaskClient, db_session: Session, alice_org: UUID
) -> None:
    root = _asset(db_session, alice_org)
    finding = _finding(db_session, alice_org, root.id, status=FindingStatus.FIXED)
    finding_id = finding.id

    response = _post(
        alice,
        f"/api/v1/findings/{finding_id}/status",
        {"status": "accepted_risk", "comment": "nope"},
    )

    assert response.status_code == 409


def test_bulk_status_is_all_or_nothing(
    alice: FlaskClient, db_session: Session, alice_org: UUID
) -> None:
    root = _asset(db_session, alice_org)
    first = _finding(db_session, alice_org, root.id, location="a")
    second = _finding(db_session, alice_org, root.id, location="b")
    first_id, second_id = first.id, second.id

    mixed = _post(
        alice,
        "/api/v1/findings/bulk-status",
        {
            "finding_ids": [str(first_id), str(UUID(int=1))],
            "status": "accepted_risk",
            "comment": "batch",
        },
    )
    ok = _post(
        alice,
        "/api/v1/findings/bulk-status",
        {
            "finding_ids": [str(first_id), str(second_id)],
            "status": "false_positive",
            "comment": "batch",
        },
    )

    assert mixed.status_code == 404
    assert ok.status_code == 200
    assert ok.get_json() == {"updated": 2}


def test_bulk_payload_validation(alice: FlaskClient, db_session: Session, alice_org: UUID) -> None:
    root = _asset(db_session, alice_org)
    _finding(db_session, alice_org, root.id)

    too_many = _post(
        alice,
        "/api/v1/findings/bulk-status",
        {
            "finding_ids": [str(UUID(int=index + 1)) for index in range(51)],
            "status": "false_positive",
            "comment": "batch",
        },
    )
    malformed = _post(
        alice, "/api/v1/findings/bulk-status", {"finding_ids": "nope", "status": "open"}
    )

    assert too_many.status_code == 422
    assert malformed.status_code == 422


def test_listing_never_shows_another_orgs_findings(
    db_app: Flask, alice: FlaskClient, db_session: Session, alice_org: UUID
) -> None:
    root = _asset(db_session, alice_org)
    _finding(db_session, alice_org, root.id, title="secret finding")
    bob = _signup(db_app, "bob@example.com")

    body = bob.get("/api/v1/findings").get_json()

    assert body["total"] == 0
    assert body["items"] == []


@pytest.mark.parametrize(
    "evidence_case",
    [
        ("A", "10.0.0.7", [], "10.0.0.7"),
        (
            "AAAA",
            "fd00::7",
            ["www.example.com", "edge.example.com", "origin.example.com"],
            "fd00::7\nCNAME chain: www.example.com → edge.example.com → origin.example.com",
        ),
    ],
)
def test_get_finding_keeps_dns_resolver_evidence(
    alice: FlaskClient,
    db_session: Session,
    alice_org: UUID,
    evidence_case: tuple[str, str, list[str], str],
) -> None:
    record, address, chain, expected_body = evidence_case
    root = _asset(db_session, alice_org)
    finding = make_finding(
        db_session,
        alice_org,
        root.id,
        rule_id="dns.records.private_ip_exposed",
        evidence=(
            (EvidenceKind.DNS_RECORD, {"record": record, "value": address, "cname_chain": chain}),
        ),
    )
    finding_id = finding.id
    db_session.commit()

    response = alice.get(f"/api/v1/findings/{finding_id}")

    assert response.status_code == 200
    [evidence] = response.get_json()["evidence"]
    assert evidence["kind"] == "dns_record"
    assert evidence["title"] == f"{record} record"
    assert evidence["body"] == expected_body
    assert evidence["truncated"] is False
