"""Findings pages: list, filters, detail evidence, status workflow, exports and dashboard."""

import csv
import io
import json
import re
from typing import Any
from uuid import UUID

import pytest
from flask import Flask
from flask.testing import FlaskClient
from sqlalchemy import select
from sqlalchemy.orm import Session

from attacksurf.domain.assets import AssetSource, AssetType
from attacksurf.domain.findings import (
    EvidenceKind,
    FindingStatus,
    Severity,
)
from attacksurf.infra.db.models import Asset, AuditLog, Finding, Membership, User
from attacksurf.services.assets import record_asset
from tests.integration.factories import T0, make_finding

_CSRF = re.compile(r'name="csrf_token" value="([^"]+)"')
HTMX = {"HX-Request": "true"}


def _csrf(client: FlaskClient, path: str) -> str:
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
    description: str = "The domain publishes no DMARC policy.",
    evidence: tuple[tuple[EvidenceKind, dict[str, Any]], ...] = (),
) -> Finding:
    finding = make_finding(
        session,
        org_id,
        asset_id,
        title=title,
        severity=severity,
        status=status,
        location=location,
        description=description,
        evidence=evidence,
        first_seen=T0,
        last_seen=T0,
    )
    session.commit()
    return finding


def _status(session: Session, finding_id: UUID) -> FindingStatus | None:
    """Re-read after a request: request teardown closes the shared test session."""
    return session.scalar(select(Finding.status).where(Finding.id == finding_id))


@pytest.fixture
def alice(db_app: Flask) -> FlaskClient:
    return _signup(db_app, "alice@example.com")


@pytest.fixture
def alice_org(db_session: Session, alice: FlaskClient) -> UUID:
    return _org_id(db_session, "alice@example.com")


def test_findings_page_lists_and_filters(
    alice: FlaskClient, db_session: Session, alice_org: UUID
) -> None:
    root = _asset(db_session, alice_org)
    _finding(db_session, alice_org, root.id, title="critical one", severity=Severity.CRITICAL)
    _finding(db_session, alice_org, root.id, title="low one", severity=Severity.LOW, location="low")

    everything = alice.get("/findings").get_data(as_text=True)
    critical = alice.get("/findings?severity=critical").get_data(as_text=True)

    assert "critical one" in everything
    assert "low one" in everything
    assert "critical one" in critical
    assert "low one" not in critical
    assert "2 findings" in everything


def test_findings_page_has_an_empty_state(alice: FlaskClient) -> None:
    body = alice.get("/findings").get_data(as_text=True)

    assert "No findings yet" in body
    assert "0 findings" in body


def test_findings_page_returns_only_the_fragment_for_htmx(
    alice: FlaskClient, db_session: Session, alice_org: UUID
) -> None:
    root = _asset(db_session, alice_org)
    _finding(db_session, alice_org, root.id, title="critical one", severity=Severity.CRITICAL)

    body = alice.get("/findings", headers=HTMX).get_data(as_text=True)

    assert 'id="finding-results"' in body
    assert "<html" not in body


def test_finding_detail_shows_rule_guidance_and_escapes_evidence(
    alice: FlaskClient, db_session: Session, alice_org: UUID
) -> None:
    root = _asset(db_session, alice_org)
    payload = '"><img src=x onerror=alert(1)>'
    finding = _finding(
        db_session,
        alice_org,
        root.id,
        title="TXT payload",
        description="<script>alert('description')</script>",
        evidence=(
            (
                EvidenceKind.DNS_RECORD,
                {"record": "TXT", "name": "example.com", "values": [payload]},
            ),
        ),
    )

    body = alice.get(f"/findings/{finding.id}").get_data(as_text=True)

    assert "TXT record" in body
    assert "&lt;script&gt;alert(&#39;description&#39;)&lt;/script&gt;" in body
    assert "<script>alert" not in body
    assert "&lt;img" in body
    assert "<img" not in body


def test_finding_detail_has_an_ai_placeholder(
    alice: FlaskClient, db_session: Session, alice_org: UUID
) -> None:
    root = _asset(db_session, alice_org)
    finding = _finding(db_session, alice_org, root.id)

    body = alice.get(f"/findings/{finding.id}").get_data(as_text=True)

    assert "AI triage" in body
    assert "hasn&#39;t run" in body or "hasn't run" in body


def test_status_change_needs_csrf_and_a_comment(
    alice: FlaskClient, db_session: Session, alice_org: UUID
) -> None:
    root = _asset(db_session, alice_org)
    finding = _finding(db_session, alice_org, root.id)
    path = f"/findings/{finding.id}/status"

    without_csrf = alice.post(path, data={"status": "accepted_risk"})
    missing_comment = alice.post(
        path,
        data={"status": "accepted_risk", "csrf_token": _csrf(alice, f"/findings/{finding.id}")},
        follow_redirects=True,
    )

    assert without_csrf.status_code == 400
    assert _status(db_session, finding.id) is FindingStatus.OPEN
    assert "Add a comment" in missing_comment.get_data(as_text=True)


def test_status_change_accepts_risk_and_shows_the_audit_trail(
    alice: FlaskClient, db_session: Session, alice_org: UUID
) -> None:
    root = _asset(db_session, alice_org)
    finding = _finding(db_session, alice_org, root.id)
    path = f"/findings/{finding.id}/status"

    response = alice.post(
        path,
        data={
            "status": "accepted_risk",
            "comment": "Risk owner signed off",
            "csrf_token": _csrf(alice, f"/findings/{finding.id}"),
        },
        follow_redirects=True,
    )

    assert response.status_code == 200
    assert _status(db_session, finding.id) is FindingStatus.ACCEPTED_RISK
    body = response.get_data(as_text=True)
    assert "Risk owner signed off" in body
    assert "Accepted risk" in body
    [entry] = db_session.scalars(
        select(AuditLog).where(AuditLog.target_id == str(finding.id))
    ).all()
    assert entry.action == "finding.accepted_risk"
    assert entry.details["comment"] == "Risk owner signed off"


def test_reopen_returns_a_fixed_finding_to_open(
    alice: FlaskClient, db_session: Session, alice_org: UUID
) -> None:
    root = _asset(db_session, alice_org)
    finding = _finding(db_session, alice_org, root.id, status=FindingStatus.FIXED)

    alice.post(
        f"/findings/{finding.id}/status",
        data={"status": "open", "csrf_token": _csrf(alice, f"/findings/{finding.id}")},
    )

    assert _status(db_session, finding.id) is FindingStatus.OPEN
    assert db_session.scalar(select(Finding.fixed_at).where(Finding.id == finding.id)) is None


def test_bulk_action_updates_the_selection(
    alice: FlaskClient, db_session: Session, alice_org: UUID
) -> None:
    root = _asset(db_session, alice_org)
    first = _finding(db_session, alice_org, root.id, location="a")
    second = _finding(db_session, alice_org, root.id, location="b")
    token = _csrf(alice, "/findings")

    response = alice.post(
        "/findings/bulk-status",
        data={
            "finding_ids": [str(first.id), str(second.id)],
            "status": "false_positive",
            "comment": "scanner bug",
            "csrf_token": token,
        },
        follow_redirects=True,
    )

    assert response.status_code == 200
    assert _status(db_session, first.id) is FindingStatus.FALSE_POSITIVE
    assert _status(db_session, second.id) is FindingStatus.FALSE_POSITIVE
    assert "Updated 2 findings" in response.get_data(as_text=True)


def test_bulk_action_rejects_more_than_the_limit(
    alice: FlaskClient, db_session: Session, alice_org: UUID
) -> None:
    root = _asset(db_session, alice_org)
    finding = _finding(db_session, alice_org, root.id)
    token = _csrf(alice, "/findings")
    ids = [str(finding.id), *(str(UUID(int=index + 1)) for index in range(50))]

    response = alice.post(
        "/findings/bulk-status",
        data={
            "finding_ids": ids,
            "status": "false_positive",
            "comment": "too many",
            "csrf_token": token,
        },
        follow_redirects=True,
    )

    assert response.status_code == 200
    assert _status(db_session, finding.id) is FindingStatus.OPEN
    assert "at most 50" in response.get_data(as_text=True)


def test_export_csv_is_an_attachment_with_formula_safe_cells(
    alice: FlaskClient, db_session: Session, alice_org: UUID
) -> None:
    root = _asset(db_session, alice_org)
    _finding(db_session, alice_org, root.id, title="=cmd|' /C calc'!A0")

    response = alice.get("/findings/export.csv")

    assert response.status_code == 200
    assert response.mimetype == "text/csv"
    assert response.headers["Content-Disposition"] == 'attachment; filename="findings.csv"'
    rows = list(csv.reader(io.StringIO(response.get_data(as_text=True))))
    assert rows[0][:4] == ["ID", "Severity", "Status", "Title"]
    assert rows[1][3] == "'=cmd|' /C calc'!A0"


def test_export_json_is_an_attachment(
    alice: FlaskClient, db_session: Session, alice_org: UUID
) -> None:
    root = _asset(db_session, alice_org)
    finding = _finding(db_session, alice_org, root.id)

    response = alice.get("/findings/export.json")

    assert response.mimetype == "application/json"
    payload = json.loads(response.get_data(as_text=True))
    assert payload["count"] == 1
    assert payload["truncated"] is False
    assert payload["findings"][0]["id"] == str(finding.id)


def test_dashboard_shows_findings_and_assets(
    alice: FlaskClient, db_session: Session, alice_org: UUID
) -> None:
    root = _asset(db_session, alice_org)
    _finding(db_session, alice_org, root.id, severity=Severity.CRITICAL)

    body = alice.get("/").get_data(as_text=True)

    assert "Open findings" in body
    assert "Critical" in body
    assert "example.com" in body
    assert "Never scanned" in body


def test_other_orgs_finding_is_not_found(
    db_app: Flask, alice: FlaskClient, db_session: Session, alice_org: UUID
) -> None:
    root = _asset(db_session, alice_org)
    finding = _finding(db_session, alice_org, root.id, title="secret finding")
    finding_id = finding.id
    bob = _signup(db_app, "bob@example.com")

    detail = bob.get(f"/findings/{finding_id}")
    listing = bob.get("/findings").get_data(as_text=True)

    assert detail.status_code == 404
    assert "secret finding" not in listing


def test_finding_detail_shows_dns_resolver_address_and_chain(
    alice: FlaskClient, db_session: Session, alice_org: UUID
) -> None:
    root = _asset(db_session, alice_org)
    finding = make_finding(
        db_session,
        alice_org,
        root.id,
        rule_id="dns.records.private_ip_exposed",
        evidence=(
            (
                EvidenceKind.DNS_RECORD,
                {
                    "record": "A",
                    "value": "10.0.0.7",
                    "cname_chain": ["www.example.com", "origin.example.com"],
                },
            ),
        ),
    )
    finding_id = finding.id
    db_session.commit()

    response = alice.get(f"/findings/{finding_id}")

    expected = "10.0.0.7\nCNAME chain: www.example.com → origin.example.com"
    assert response.status_code == 200
    assert f'<pre class="evidence-body">{expected}</pre>' in response.get_data(as_text=True)
