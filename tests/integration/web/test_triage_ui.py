"""AI triage in the UI (ADR 0029): the finding page's panel and the scan page's section."""

from datetime import UTC, datetime
from uuid import UUID

import pytest
from flask import Flask
from flask.testing import FlaskClient
from pydantic import SecretStr
from sqlalchemy.orm import Session

from attacksurf.ai.schemas import FindingTriage, StoredTriage
from attacksurf.ai.triage import TRIAGE_PROMPT_VERSION
from attacksurf.domain.findings import Severity
from attacksurf.domain.llm import KeySource, LLMConfig, ProviderKind
from attacksurf.domain.scans import JobStatus, ScanStatus, ScanTrigger
from attacksurf.infra.db.models import Finding, FindingObservation, Job, Scan
from attacksurf.services import jobs
from attacksurf.services.triage import finding_cache_key
from tests.integration.web.test_findings_ui import _asset, _finding, _org_id, _signup

HTMX = {"HX-Request": "true"}
XSS = "<script>alert('ai')</script>"
MARKER = 'class="ai-stale-tag"'  # the "Outdated" marker itself, not the legend that explains it
_CONFIG = LLMConfig(
    provider=ProviderKind.ANTHROPIC,
    model="muse-spark-1.3",
    api_key=SecretStr("instance-key"),
    source=KeySource.INSTANCE,
)


@pytest.fixture
def alice(db_app: Flask) -> FlaskClient:
    return _signup(db_app, "alice@example.com")


@pytest.fixture
def org_id(alice: FlaskClient, db_session: Session) -> UUID:
    return _org_id(db_session, "alice@example.com")


def _judge(
    session: Session, finding_id: UUID, *, rationale: str = "The record points nowhere."
) -> None:
    finding = session.get(Finding, finding_id)
    assert finding is not None
    judgment = FindingTriage.model_validate(
        {
            "ref": "F1",
            "adjusted_severity": "critical",
            "confidence": "high",
            "false_positive_likelihood": "low",
            "priority": "P1",
            "rationale": rationale,
            "exploitability": "Anyone can claim the target.",
            "remediation_steps": ["Remove the record.", rationale],
        }
    )
    finding.ai_triage = StoredTriage.from_judgment(
        judgment,
        prompt_version=TRIAGE_PROMPT_VERSION,
        config=_CONFIG,
        cache_key=finding_cache_key(finding, _CONFIG.model),  # current for the finding as is
        triaged_at=datetime(2026, 11, 19, tzinfo=UTC),
    ).model_dump(mode="json")
    session.commit()


def _raise_severity(session: Session, finding_id: UUID) -> None:
    """What a later scan does when the rule's severity changes: the judgment goes stale."""
    finding = session.get(Finding, finding_id)
    assert finding is not None
    finding.severity = Severity.CRITICAL
    session.commit()


def _completed_scan(session: Session, org_id: UUID, root_id: UUID) -> Scan:
    scan = Scan(
        org_id=org_id,
        root_asset_id=root_id,
        profile="dns_passive",
        status=ScanStatus.COMPLETED,
        triggered_by=ScanTrigger.USER,
        started_at=datetime(2026, 11, 19, tzinfo=UTC),
        finished_at=datetime(2026, 11, 19, 0, 5, tzinfo=UTC),
    )
    session.add(scan)
    session.commit()
    return scan


def _observe(session: Session, scan: Scan, finding: Finding) -> None:
    session.add(
        FindingObservation(
            org_id=scan.org_id, scan_id=scan.id, finding_id=finding.id, severity=finding.severity
        )
    )
    session.commit()


def _coordinator(session: Session, scan: Scan, status: JobStatus, error: str | None = None) -> UUID:
    job = jobs.record_job(session, org_id=scan.org_id, scan_id=scan.id, stage="triage")
    job.status = status
    job.error = error
    session.commit()
    return job.id


def _body(client: FlaskClient, path: str, headers: dict[str, str] | None = None) -> str:
    response = client.get(path, headers=headers or {})
    assert response.status_code == 200, (path, response.status_code)
    return response.get_data(as_text=True)


# --- The finding page ----------------------------------------------------------------------


def test_the_finding_page_shows_the_ai_judgment(
    alice: FlaskClient, db_session: Session, org_id: UUID
) -> None:
    root = _asset(db_session, org_id)
    finding = _finding(db_session, org_id, root.id)
    _judge(db_session, finding.id)

    body = _body(alice, f"/findings/{finding.id}")

    assert "AI-generated" in body
    assert "muse-spark-1.3" in body
    assert "triage/v1" in body
    assert "P1" in body
    assert "Remove the record." in body
    assert "Anyone can claim the target." in body
    assert "hasn't run" not in body
    assert "hasn&#39;t run" not in body


def test_the_finding_page_marks_a_judgment_whose_finding_changed(
    alice: FlaskClient, db_session: Session, org_id: UUID
) -> None:
    # Regression: the old judgment was shown as current until a new run replaced it.
    root = _asset(db_session, org_id)
    finding = _finding(db_session, org_id, root.id)
    finding_id = finding.id
    _judge(db_session, finding_id)
    assert MARKER not in _body(alice, f"/findings/{finding_id}")

    _raise_severity(db_session, finding_id)

    body = _body(alice, f"/findings/{finding_id}")
    assert MARKER in body
    assert "Remove the record." in body  # still shown, but marked


def test_ai_text_on_the_finding_page_is_escaped(
    alice: FlaskClient, db_session: Session, org_id: UUID
) -> None:
    root = _asset(db_session, org_id)
    finding = _finding(db_session, org_id, root.id)
    _judge(db_session, finding.id, rationale=XSS)

    body = _body(alice, f"/findings/{finding.id}")

    assert "&lt;script&gt;alert(&#39;ai&#39;)&lt;/script&gt;" in body
    assert XSS not in body


# --- The scan page -------------------------------------------------------------------------


def test_the_scan_page_lists_the_scans_judgments(
    alice: FlaskClient, db_session: Session, org_id: UUID
) -> None:
    root = _asset(db_session, org_id)
    finding = _finding(db_session, org_id, root.id, title="Dangling CNAME")
    _judge(db_session, finding.id)
    scan = _completed_scan(db_session, org_id, root.id)
    _observe(db_session, scan, finding)
    _coordinator(db_session, scan, JobStatus.COMPLETED)

    body = _body(alice, f"/scans/{scan.id}")

    assert body.count('id="scan-triage"') == 1
    assert f'href="/findings/{finding.id}"' in body
    assert "Dangling CNAME" in body
    assert "AI-generated" in body
    assert 'hx-trigger="every 2s"' not in body  # a finished run is not polled


def test_a_page_opened_mid_scan_polls_for_the_triage_to_come(
    alice: FlaskClient, db_session: Session, org_id: UUID
) -> None:
    # Regression: only the progress section polled, so this one stayed on its first paint.
    root = _asset(db_session, org_id)
    scan = _completed_scan(db_session, org_id, root.id)
    scan.status = ScanStatus.RUNNING
    scan.finished_at = None
    db_session.commit()
    scan_id = scan.id  # requests close the test session

    body = _body(alice, f"/scans/{scan_id}")

    assert f'hx-get="/scans/{scan_id}/triage"' in body
    assert "AI triage starts once the scan completes." in body


def test_the_triage_section_polls_only_while_the_run_is_active(
    alice: FlaskClient, db_session: Session, org_id: UUID
) -> None:
    root = _asset(db_session, org_id)
    scan = _completed_scan(db_session, org_id, root.id)
    coordinator = _coordinator(db_session, scan, JobStatus.QUEUED)

    pending = _body(alice, f"/scans/{scan.id}/triage", headers=HTMX)
    assert 'hx-trigger="every 2s"' in pending
    assert f'hx-get="/scans/{scan.id}/triage"' in pending

    job = db_session.get(Job, coordinator)
    assert job is not None
    job.status = JobStatus.COMPLETED
    db_session.commit()

    done = _body(alice, f"/scans/{scan.id}/triage", headers=HTMX)
    assert 'hx-trigger="every 2s"' not in done


def test_a_skipped_run_says_why(alice: FlaskClient, db_session: Session, org_id: UUID) -> None:
    root = _asset(db_session, org_id)
    scan = _completed_scan(db_session, org_id, root.id)
    _coordinator(db_session, scan, JobStatus.SKIPPED, "AI is disabled or not configured.")

    body = _body(alice, f"/scans/{scan.id}/triage", headers=HTMX)

    assert "AI is disabled or not configured." in body


def test_the_scan_page_marks_a_judgment_whose_finding_changed(
    alice: FlaskClient, db_session: Session, org_id: UUID
) -> None:
    root = _asset(db_session, org_id)
    finding = _finding(db_session, org_id, root.id, title="Dangling CNAME")
    finding_id = finding.id
    _judge(db_session, finding_id)
    scan = _completed_scan(db_session, org_id, root.id)
    _observe(db_session, scan, finding)
    _coordinator(db_session, scan, JobStatus.COMPLETED)
    scan_id = scan.id
    assert MARKER not in _body(alice, f"/scans/{scan_id}/triage", headers=HTMX)

    _raise_severity(db_session, finding_id)

    assert MARKER in _body(alice, f"/scans/{scan_id}/triage", headers=HTMX)


def test_ai_text_on_the_scan_page_is_escaped(
    alice: FlaskClient, db_session: Session, org_id: UUID
) -> None:
    root = _asset(db_session, org_id)
    finding = _finding(db_session, org_id, root.id, title=XSS)
    _judge(db_session, finding.id, rationale=XSS)
    scan = _completed_scan(db_session, org_id, root.id)
    _observe(db_session, scan, finding)
    _coordinator(db_session, scan, JobStatus.COMPLETED)

    body = _body(alice, f"/scans/{scan.id}/triage", headers=HTMX)

    assert "&lt;script&gt;" in body
    assert XSS not in body


def test_another_orgs_triage_section_is_not_found(
    alice: FlaskClient, db_app: Flask, db_session: Session, org_id: UUID
) -> None:
    root = _asset(db_session, org_id)
    scan_id = _completed_scan(db_session, org_id, root.id).id  # requests close the test session
    bob = _signup(db_app, "bob@example.com")

    assert bob.get(f"/scans/{scan_id}/triage", headers=HTMX).status_code == 404
    assert bob.get(f"/scans/{scan_id}", headers=HTMX).status_code == 404
