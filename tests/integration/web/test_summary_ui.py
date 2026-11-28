"""AI exposure summary in the UI (ADR 0030): scan page card and dashboard cards."""

from datetime import UTC, datetime
from uuid import UUID

import pytest
from flask import Flask
from flask.testing import FlaskClient
from sqlalchemy.orm import Session

from attacksurf.ai.schemas import StoredSummary
from attacksurf.domain.assets import AssetSource, AssetType
from attacksurf.domain.llm import ProviderKind
from attacksurf.domain.scans import JobStatus, ScanStatus, ScanTrigger
from attacksurf.infra.db.models import Asset, Job, Scan
from attacksurf.services import jobs
from attacksurf.services.assets import record_asset
from tests.integration.web.test_findings_ui import _asset, _finding, _org_id, _signup

HTMX = {"HX-Request": "true"}
XSS = "<script>alert('summary-xss')</script>"
NOW = datetime(2026, 11, 20, 12, 0, tzinfo=UTC)


@pytest.fixture
def alice(db_app: Flask) -> FlaskClient:
    return _signup(db_app, "alice@example.com")


@pytest.fixture
def org_id(alice: FlaskClient, db_session: Session) -> UUID:
    return _org_id(db_session, "alice@example.com")


def _completed_scan(session: Session, org_id: UUID, root_id: UUID) -> Scan:
    scan = Scan(
        org_id=org_id,
        root_asset_id=root_id,
        profile="dns_passive",
        status=ScanStatus.COMPLETED,
        triggered_by=ScanTrigger.USER,
        started_at=datetime(2026, 11, 20, 11, 50, tzinfo=UTC),
        finished_at=datetime(2026, 11, 20, 11, 55, tzinfo=UTC),
    )
    session.add(scan)
    session.commit()
    return scan


def _attach_summary(
    session: Session,
    scan_id: UUID,
    *,
    finding_ids: list[UUID] | None = None,
    asset_ids: list[UUID] | None = None,
    headline: str = "Subdomain takeover risk on assets.acme.example.",
    web_exposure: str = "",
    risk_chains: list[dict[str, object]] | None = None,
    why: str = "Dangling CNAME points to an unclaimed cloud bucket.",
    reason: str = "Exposed CI server.",
    changes: str = "1 new high finding since the last scan.",
    next_actions: list[str] | None = None,
) -> None:
    scan = session.get(Scan, scan_id)
    assert scan is not None
    stored = StoredSummary(
        headline=headline,
        web_exposure=web_exposure,
        key_risks=[
            {"finding_id": fid, "why": why}  # type: ignore[misc]
            for fid in (finding_ids or [])
        ],
        risk_chains=risk_chains or [],  # type: ignore[arg-type]
        notable_assets=[
            {"asset_id": aid, "reason": reason}  # type: ignore[misc]
            for aid in (asset_ids or [])
        ],
        changes=changes,
        next_actions=next_actions if next_actions is not None else ["Remove the dangling CNAME."],
        prompt_version="summary/v2" if (web_exposure or risk_chains) else "summary/v1",
        provider=ProviderKind.ANTHROPIC,
        model="muse-spark-1.3",
        generated_at=NOW,
    )
    scan.ai_summary = stored.model_dump(mode="json")
    session.commit()


def _job(session: Session, scan_id: UUID, org_id: UUID, stage: str, status: JobStatus) -> UUID:
    job = jobs.record_job(session, org_id=org_id, scan_id=scan_id, stage=stage)
    job.status = status
    session.commit()
    return job.id


def _body(client: FlaskClient, path: str, headers: dict[str, str] | None = None) -> str:
    response = client.get(path, headers=headers or {})
    assert response.status_code == 200, (path, response.status_code)
    return response.get_data(as_text=True)


def _subdomain(session: Session, org_id: UUID, root_id: UUID, label: str) -> Asset:
    asset = record_asset(
        session,
        org_id,
        AssetType.SUBDOMAIN,
        f"{label}.acme.example",
        source=AssetSource.DISCOVERED,
        parent_id=root_id,
    )
    session.commit()
    return asset


# --- Scan page card ------------------------------------------------------------------------


def test_scan_page_shows_summary_with_real_finding_and_asset_links(
    alice: FlaskClient, db_session: Session, org_id: UUID
) -> None:
    root = _asset(db_session, org_id)
    jenkins = _subdomain(db_session, org_id, root.id, "jenkins")
    finding = _finding(db_session, org_id, jenkins.id, title="Dangling CNAME")
    finding_id, jenkins_id = finding.id, jenkins.id
    scan = _completed_scan(db_session, org_id, root.id)
    scan_id = scan.id
    _attach_summary(db_session, scan_id, finding_ids=[finding_id], asset_ids=[jenkins_id])

    body = _body(alice, f"/scans/{scan_id}")

    assert body.count('id="scan-summary"') == 1
    assert "AI-generated" in body
    assert "muse-spark-1.3" in body
    assert "summary/v1" in body
    assert "Subdomain takeover risk on assets.acme.example." in body
    assert f'href="/findings/{finding_id}"' in body
    assert f'href="/assets/{jenkins_id}"' in body
    assert "jenkins.acme.example" in body
    assert "1 new high finding since the last scan." in body
    assert "Remove the dangling CNAME." in body
    assert f'hx-get="/scans/{scan_id}/summary"' not in body


def test_summary_section_polls_while_active_and_stops_when_done(
    alice: FlaskClient, db_session: Session, org_id: UUID
) -> None:
    root = _asset(db_session, org_id)
    scan = _completed_scan(db_session, org_id, root.id)
    scan_id = scan.id
    job_id = _job(db_session, scan_id, org_id, "summary", JobStatus.QUEUED)

    pending = _body(alice, f"/scans/{scan_id}/summary", headers=HTMX)
    assert 'hx-trigger="every 2s"' in pending
    assert f'hx-get="/scans/{scan_id}/summary"' in pending

    job = db_session.get(Job, job_id)
    assert job is not None
    job.status = JobStatus.COMPLETED
    db_session.commit()
    _attach_summary(db_session, scan_id)

    done = _body(alice, f"/scans/{scan_id}/summary", headers=HTMX)
    assert 'hx-trigger="every 2s"' not in done
    assert "Subdomain takeover risk" in done


def test_page_opened_mid_scan_polls_for_summary(
    alice: FlaskClient, db_session: Session, org_id: UUID
) -> None:
    root = _asset(db_session, org_id)
    scan = _completed_scan(db_session, org_id, root.id)
    scan.status = ScanStatus.RUNNING
    scan.finished_at = None
    db_session.commit()
    scan_id = scan.id

    body = _body(alice, f"/scans/{scan_id}")

    assert f'hx-get="/scans/{scan_id}/summary"' in body
    assert "AI exposure summary starts once triage completes." in body


def test_xss_in_ai_summary_is_escaped_on_scan_page_and_dashboard(
    alice: FlaskClient, db_session: Session, org_id: UUID
) -> None:
    root = _asset(db_session, org_id)
    finding = _finding(db_session, org_id, root.id, title="Dangling CNAME", location="f1")
    finding2 = _finding(db_session, org_id, root.id, title="Exposed Admin", location="f2")
    finding_id, finding2_id, root_id = finding.id, finding2.id, root.id
    scan = _completed_scan(db_session, org_id, root_id)
    scan_id = scan.id
    _attach_summary(
        db_session,
        scan_id,
        finding_ids=[finding_id],
        asset_ids=[root_id],
        headline=XSS,
        web_exposure=XSS,
        risk_chains=[
            {
                "title": XSS,
                "finding_ids": [finding_id, finding2_id],
                "asset_id": root_id,
                "why": XSS,
            }
        ],
        why=XSS,
        reason=XSS,
        changes=XSS,
        next_actions=[XSS],
    )

    for path in (f"/scans/{scan_id}/summary", "/"):
        body = _body(alice, path)
        assert "&lt;script&gt;alert(&#39;summary-xss&#39;)&lt;/script&gt;" in body
        assert XSS not in body


def test_scan_page_renders_web_exposure_and_risk_chains_sections(
    alice: FlaskClient, db_session: Session, org_id: UUID
) -> None:
    root = _asset(db_session, org_id)
    ci_url = record_asset(
        db_session,
        org_id,
        AssetType.URL,
        "https://ci.acme.example/",
        source=AssetSource.DISCOVERED,
        parent_id=root.id,
    )
    f1 = _finding(db_session, org_id, ci_url.id, title="Outdated Jenkins", location="f1")
    f2 = _finding(db_session, org_id, ci_url.id, title="Exposed Login", location="f2")
    f1_id, f2_id, url_id = f1.id, f2.id, ci_url.id
    scan_id = _completed_scan(db_session, org_id, root.id).id
    _attach_summary(
        db_session,
        scan_id,
        finding_ids=[f1_id],
        asset_ids=[url_id],
        web_exposure="ci.acme.example runs Jenkins 2.346 with an open login form.",
        risk_chains=[
            {
                "title": "Jenkins + Public Login",
                "finding_ids": [f1_id, f2_id],
                "asset_id": url_id,
                "why": "Vulnerable Jenkins instance is directly exposed without VPN.",
            }
        ],
    )

    body = _body(alice, f"/scans/{scan_id}/summary", headers=HTMX)

    assert "Web exposure" in body
    assert "ci.acme.example runs Jenkins 2.346 with an open login form." in body
    assert "Risk chains" in body
    assert "Jenkins + Public Login" in body
    assert f'href="/findings/{f1_id}"' in body
    assert f'href="/findings/{f2_id}"' in body
    assert f'href="/assets/{url_id}"' in body


# --- Dashboard card ------------------------------------------------------------------------


def test_dashboard_shows_latest_ai_summary_with_top_3_risks_and_scan_link(
    alice: FlaskClient, db_session: Session, org_id: UUID
) -> None:
    root = _asset(db_session, org_id)
    findings = [
        _finding(db_session, org_id, root.id, title=f"Risk {index}", location=f"loc-{index}")
        for index in range(4)
    ]
    finding_ids = [f.id for f in findings]
    scan = _completed_scan(db_session, org_id, root.id)
    scan_id = scan.id
    _attach_summary(db_session, scan_id, finding_ids=finding_ids)

    body = _body(alice, "/")
    card_start = body.index("ai-summary-card")
    card_end = body.index("</article>", card_start)
    card_html = body[card_start:card_end]

    assert "Latest AI summary" in body
    assert "Subdomain takeover risk on assets.acme.example." in card_html
    assert f'href="/scans/{scan_id}"' in card_html
    for fid in finding_ids[:3]:
        assert f'href="/findings/{fid}"' in card_html
    assert f'href="/findings/{finding_ids[3]}"' not in card_html


# --- Tenant isolation ----------------------------------------------------------------------


def test_another_org_gets_404_for_summary_fragment(
    alice: FlaskClient, db_app: Flask, db_session: Session, org_id: UUID
) -> None:
    root = _asset(db_session, org_id)
    scan_id = _completed_scan(db_session, org_id, root.id).id
    _attach_summary(db_session, scan_id, headline="Alice confidential summary")
    bob = _signup(db_app, "bob@example.com")

    assert bob.get(f"/scans/{scan_id}/summary", headers=HTMX).status_code == 404
    assert "Alice confidential summary" not in _body(bob, "/")
