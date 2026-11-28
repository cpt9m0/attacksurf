"""What the UI shows about a scan's AI exposure summary (ADR 0030)."""

from datetime import UTC, datetime, timedelta
from uuid import UUID

import pytest
from sqlalchemy.orm import Session

from attacksurf.ai.schemas import StoredSummary
from attacksurf.domain.assets import AssetSource, AssetType
from attacksurf.domain.llm import ProviderKind
from attacksurf.domain.scans import JobStatus, ScanNotFound, ScanStatus, ScanTrigger
from attacksurf.infra.db.models import Asset, Job, Scan
from attacksurf.services import jobs
from attacksurf.services.assets import record_asset
from attacksurf.services.summary_views import (
    SummaryState,
    get_scan_summary,
    list_latest_root_summaries,
)
from tests.integration.factories import make_finding, make_scan

NOW = datetime(2026, 11, 20, 12, 0, tzinfo=UTC)


def _scan(session: Session, name: str = "acme") -> Scan:
    scan = make_scan(session, name)
    scan.status = ScanStatus.COMPLETED
    session.flush()
    return scan


def _job(
    session: Session,
    scan: Scan,
    stage: str,
    status: JobStatus = JobStatus.QUEUED,
    *,
    error: str | None = None,
    finished_at: datetime | None = None,
) -> Job:
    job = jobs.record_job(session, org_id=scan.org_id, scan_id=scan.id, stage=stage)
    job.status = status
    job.error = error
    job.finished_at = finished_at
    session.flush()
    return job


def _store_summary(
    session: Session,
    scan: Scan,
    *,
    finding_ids: list[UUID] | None = None,
    asset_ids: list[UUID] | None = None,
    headline: str = "One high-risk finding needs attention.",
) -> StoredSummary:
    stored = StoredSummary(
        headline=headline,
        key_risks=[
            {"finding_id": fid, "why": f"Risk {idx}"}  # type: ignore[misc]
            for idx, fid in enumerate(finding_ids or [], start=1)
        ],
        notable_assets=[
            {"asset_id": aid, "reason": f"Sensitive host {idx}"}  # type: ignore[misc]
            for idx, aid in enumerate(asset_ids or [], start=1)
        ],
        changes="1 new high finding since the last scan.",
        next_actions=["Fix the dangling CNAME."],
        prompt_version="summary/v1",
        provider=ProviderKind.ANTHROPIC,
        model="muse-spark-1.3",
        generated_at=NOW,
    )
    scan.ai_summary = stored.model_dump(mode="json")
    session.flush()
    return stored


# --- Polling state machine -----------------------------------------------------------------


@pytest.mark.parametrize("status", [ScanStatus.QUEUED, ScanStatus.RUNNING])
def test_active_scan_awaits_summary_and_polls(db_session: Session, status: ScanStatus) -> None:
    scan = _scan(db_session)
    scan.status = status
    db_session.flush()

    view = get_scan_summary(db_session, scan.org_id, scan.id, now=NOW)

    assert view.state is SummaryState.AWAITING_SCAN
    assert view.active


def test_just_completed_scan_keeps_polling_during_grace_period(db_session: Session) -> None:
    scan = _scan(db_session)
    scan.finished_at = NOW - timedelta(seconds=10)
    db_session.flush()

    view = get_scan_summary(db_session, scan.org_id, scan.id, now=NOW)

    assert view.state is SummaryState.AWAITING_SCAN
    assert view.active


@pytest.mark.parametrize(
    ("status", "finished_ago"),
    [
        (ScanStatus.COMPLETED, timedelta(minutes=5)),
        (ScanStatus.FAILED, timedelta(seconds=5)),
        (ScanStatus.CANCELLED, timedelta(seconds=5)),
    ],
)
def test_ended_scan_without_jobs_stops_polling(
    db_session: Session, status: ScanStatus, finished_ago: timedelta
) -> None:
    scan = _scan(db_session)
    scan.status = status
    scan.finished_at = NOW - finished_ago
    db_session.flush()

    view = get_scan_summary(db_session, scan.org_id, scan.id, now=NOW)

    assert view.state is SummaryState.NOT_STARTED
    assert not view.active


def test_running_triage_keeps_summary_pending_and_polled(db_session: Session) -> None:
    scan = _scan(db_session)
    scan.finished_at = NOW - timedelta(minutes=5)
    _job(db_session, scan, "triage", JobStatus.COMPLETED)
    _job(db_session, scan, "triage_batch", JobStatus.RUNNING)
    _job(db_session, scan, "triage_done", JobStatus.QUEUED)

    view = get_scan_summary(db_session, scan.org_id, scan.id, now=NOW)

    assert view.state is SummaryState.PENDING
    assert view.active


def test_skipped_triage_propagates_notice_and_stops_polling(db_session: Session) -> None:
    scan = _scan(db_session)
    _job(db_session, scan, "triage", JobStatus.SKIPPED, error="AI is disabled or not configured.")

    view = get_scan_summary(db_session, scan.org_id, scan.id, now=NOW)

    assert view.state is SummaryState.SKIPPED
    assert view.notice == "AI is disabled or not configured."
    assert not view.active


@pytest.mark.parametrize(
    ("status", "expected_state", "expected_active"),
    [
        (JobStatus.QUEUED, SummaryState.PENDING, True),
        (JobStatus.RUNNING, SummaryState.RUNNING, True),
        (JobStatus.SKIPPED, SummaryState.SKIPPED, False),
        (JobStatus.FAILED, SummaryState.FAILED, False),
    ],
)
def test_summary_job_statuses_map_cleanly(
    db_session: Session,
    status: JobStatus,
    expected_state: SummaryState,
    expected_active: bool,
) -> None:
    scan = _scan(db_session)
    _job(
        db_session,
        scan,
        "summary",
        status,
        error="Budget spent." if status is JobStatus.SKIPPED else "RuntimeError",
    )

    view = get_scan_summary(db_session, scan.org_id, scan.id, now=NOW)

    assert view.state is expected_state
    assert view.active is expected_active
    if status is JobStatus.FAILED:
        assert view.notice == "AI exposure summary could not run."
    if status is JobStatus.SKIPPED:
        assert view.notice == "Budget spent."


def test_stored_summary_resolves_real_findings_and_assets(db_session: Session) -> None:
    scan = _scan(db_session)
    jenkins = record_asset(
        db_session,
        scan.org_id,
        AssetType.SUBDOMAIN,
        "jenkins.acme.example",
        source=AssetSource.DISCOVERED,
        parent_id=scan.root_asset_id,
    )
    finding = make_finding(db_session, scan.org_id, jenkins.id, title="Dangling CNAME")
    _store_summary(db_session, scan, finding_ids=[finding.id], asset_ids=[jenkins.id])

    view = get_scan_summary(db_session, scan.org_id, scan.id, now=NOW)

    assert view.state is SummaryState.DONE
    assert not view.active
    assert view.summary is not None
    assert len(view.key_risks) == 1
    assert (view.key_risks[0].finding_id, view.key_risks[0].title) == (finding.id, "Dangling CNAME")
    assert len(view.notable_assets) == 1
    assert (view.notable_assets[0].asset_id, view.notable_assets[0].value) == (
        jenkins.id,
        "jenkins.acme.example",
    )


def test_another_orgs_scan_summary_is_not_found(db_session: Session) -> None:
    scan = _scan(db_session, "acme")
    other = _scan(db_session, "globex")

    with pytest.raises(ScanNotFound):
        get_scan_summary(db_session, other.org_id, scan.id, now=NOW)


# --- Dashboard latest summaries per root ---------------------------------------------------


def test_dashboard_returns_latest_summary_per_active_root_with_top_3_risks(
    db_session: Session,
) -> None:
    older = _scan(db_session, "acme")
    older.created_at = NOW - timedelta(days=1)
    _store_summary(db_session, older, headline="Older summary")

    newer = Scan(
        org_id=older.org_id,
        root_asset_id=older.root_asset_id,
        profile="dns_passive",
        status=ScanStatus.COMPLETED,
        triggered_by=ScanTrigger.USER,
        created_at=NOW,
    )
    db_session.add(newer)
    db_session.flush()
    findings = [
        make_finding(db_session, older.org_id, older.root_asset_id, location=f"r{i}")
        for i in range(4)
    ]
    _store_summary(
        db_session,
        newer,
        finding_ids=[f.id for f in findings],
        headline="Latest summary",
    )

    # Another org's summarized scan must never appear.
    other = _scan(db_session, "globex")
    _store_summary(db_session, other, headline="Globex secret")

    cards = list_latest_root_summaries(db_session, older.org_id)

    assert len(cards) == 1
    assert cards[0].scan_id == newer.id
    assert cards[0].summary.headline == "Latest summary"
    assert [r.finding_id for r in cards[0].top_risks] == [f.id for f in findings[:3]]

    # Archiving the root hides its dashboard summary card.
    root = db_session.get(Asset, older.root_asset_id)
    assert root is not None
    root.is_active = False
    root.deactivated_at = NOW
    db_session.flush()
    assert list_latest_root_summaries(db_session, older.org_id) == ()


def test_get_scan_summary_resolves_valid_risk_chains_and_drops_foreign_ones(
    db_session: Session,
) -> None:
    scan = _scan(db_session, "acme")
    url = record_asset(
        db_session,
        scan.org_id,
        AssetType.URL,
        "https://ci.acme.example/",
        source=AssetSource.DISCOVERED,
        parent_id=scan.root_asset_id,
    )
    f1 = make_finding(db_session, scan.org_id, url.id, title="Outdated Jenkins", location="f1")
    f2 = make_finding(db_session, scan.org_id, url.id, title="Exposed Login", location="f2")
    other = _scan(db_session, "globex")
    foreign_finding = make_finding(
        db_session, other.org_id, other.root_asset_id, title="Globex secret"
    )
    stored = StoredSummary(
        headline="Web chain summary.",
        web_exposure="CI URL exposes outdated Jenkins.",
        key_risks=[],
        risk_chains=[
            {
                "title": "Valid CI chain",
                "finding_ids": [f1.id, f2.id],
                "asset_id": url.id,
                "why": "Compounds risk.",
            },  # type: ignore[list-item]
            {
                "title": "Cross-org chain dropped",
                "finding_ids": [f1.id, foreign_finding.id],
                "asset_id": other.root_asset_id,
                "why": "Cannot resolve foreign finding.",
            },  # type: ignore[list-item]
        ],
        notable_assets=[],
        changes="No change.",
        next_actions=[],
        prompt_version="summary/v2",
        provider=ProviderKind.ANTHROPIC,
        model="muse-spark-1.3",
        generated_at=NOW,
    )
    scan.ai_summary = stored.model_dump(mode="json")
    db_session.flush()

    view = get_scan_summary(db_session, scan.org_id, scan.id, now=NOW)

    assert view.summary is not None
    assert view.summary.web_exposure == "CI URL exposes outdated Jenkins."
    assert len(view.risk_chains) == 1
    assert view.risk_chains[0].title == "Valid CI chain"
    assert view.risk_chains[0].asset_id == url.id
    assert view.risk_chains[0].asset_value == "https://ci.acme.example/"
    assert [item.finding_id for item in view.risk_chains[0].findings] == [f1.id, f2.id]
