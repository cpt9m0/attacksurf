"""What the UI shows about a scan's AI triage (ADR 0029)."""

from datetime import UTC, datetime, timedelta

import pytest
from pydantic import SecretStr
from sqlalchemy.orm import Session

from attacksurf.ai.schemas import FindingTriage, StoredTriage
from attacksurf.ai.triage import TRIAGE_PROMPT_VERSION
from attacksurf.domain.findings import Severity
from attacksurf.domain.llm import KeySource, LLMConfig, ProviderKind
from attacksurf.domain.scans import JobStatus, ScanNotFound, ScanStatus
from attacksurf.infra.db.models import Finding, FindingObservation, Job, Scan
from attacksurf.services import jobs, scan_views
from attacksurf.services.triage import finding_cache_key
from attacksurf.services.triage_views import (
    TRIAGE_ROW_LIMIT,
    TriageState,
    get_scan_triage,
)
from tests.integration.factories import make_finding, make_scan

NOW = datetime(2026, 11, 19, 12, 0, tzinfo=UTC)
_CONFIG = LLMConfig(
    provider=ProviderKind.ANTHROPIC,
    model="muse-spark-1.3",
    api_key=SecretStr("instance-key"),
    source=KeySource.INSTANCE,
)


def _scan(session: Session) -> Scan:
    scan = make_scan(session)
    scan.status = ScanStatus.COMPLETED
    session.flush()
    return scan


def _job(
    session: Session,
    scan: Scan,
    stage: str,
    status: JobStatus = JobStatus.QUEUED,
    error: str | None = None,
) -> Job:
    job = jobs.record_job(session, org_id=scan.org_id, scan_id=scan.id, stage=stage)
    job.status = status
    job.error = error
    session.flush()
    return job


def _judged(
    session: Session,
    scan: Scan,
    *,
    location: str,
    priority: str = "P2",
    adjusted: str = "high",
    observed: bool = True,
) -> Finding:
    finding = make_finding(session, scan.org_id, scan.root_asset_id, location=location)
    if observed:
        session.add(
            FindingObservation(
                org_id=scan.org_id,
                scan_id=scan.id,
                finding_id=finding.id,
                severity=finding.severity,
            )
        )
    judgment = FindingTriage.model_validate(
        {
            "ref": "F1",
            "adjusted_severity": adjusted,
            "confidence": "high",
            "false_positive_likelihood": "low",
            "priority": priority,
            "rationale": "Confirmed by the evidence.",
            "exploitability": "",
            "remediation_steps": ["Fix the record."],
        }
    )
    finding.ai_triage = StoredTriage.from_judgment(
        judgment,
        prompt_version=TRIAGE_PROMPT_VERSION,
        config=_CONFIG,
        cache_key=finding_cache_key(finding, _CONFIG.model),  # current for the finding as is
        triaged_at=datetime(2026, 11, 19, tzinfo=UTC),
    ).model_dump(mode="json")
    session.flush()
    return finding


# --- The run's state -----------------------------------------------------------------------


def test_a_scan_without_a_triage_job_has_not_started(db_session: Session) -> None:
    scan = _scan(db_session)

    view = get_scan_triage(db_session, scan.org_id, scan.id)

    assert view.state is TriageState.NOT_STARTED
    assert not view.active


@pytest.mark.parametrize("status", [ScanStatus.QUEUED, ScanStatus.RUNNING])
def test_an_active_scan_awaits_its_triage_and_is_polled(
    db_session: Session, status: ScanStatus
) -> None:
    # Regression: a page opened mid-scan never polled, so triage never showed without a reload.
    scan = _scan(db_session)
    scan.status = status
    db_session.flush()

    view = get_scan_triage(db_session, scan.org_id, scan.id, now=NOW)

    assert view.state is TriageState.AWAITING_SCAN
    assert view.active


def test_a_just_completed_scan_keeps_polling_until_its_triage_job_appears(
    db_session: Session,
) -> None:
    # `finalize_scan` commits the scan before it creates the triage job.
    scan = _scan(db_session)
    scan.finished_at = NOW - timedelta(seconds=5)
    db_session.flush()

    view = get_scan_triage(db_session, scan.org_id, scan.id, now=NOW)

    assert view.state is TriageState.AWAITING_SCAN
    assert view.active


@pytest.mark.parametrize(
    ("status", "finished_ago"),
    [
        (ScanStatus.COMPLETED, timedelta(minutes=10)),  # triage was never queued
        (ScanStatus.FAILED, timedelta(seconds=5)),
        (ScanStatus.CANCELLED, timedelta(seconds=5)),
    ],
)
def test_a_scan_that_ended_without_triage_stops_polling(
    db_session: Session, status: ScanStatus, finished_ago: timedelta
) -> None:
    scan = _scan(db_session)
    scan.status = status
    scan.finished_at = NOW - finished_ago
    db_session.flush()

    view = get_scan_triage(db_session, scan.org_id, scan.id, now=NOW)

    assert view.state is TriageState.NOT_STARTED
    assert not view.active


def test_a_queued_coordinator_is_pending_and_polled(db_session: Session) -> None:
    scan = _scan(db_session)
    _job(db_session, scan, "triage")

    view = get_scan_triage(db_session, scan.org_id, scan.id)

    assert view.state is TriageState.PENDING
    assert view.active


def test_a_skipped_coordinator_shows_why(db_session: Session) -> None:
    scan = _scan(db_session)
    _job(
        db_session, scan, "triage", JobStatus.SKIPPED, "Monthly instance AI token budget exceeded."
    )

    view = get_scan_triage(db_session, scan.org_id, scan.id)

    assert view.state is TriageState.SKIPPED
    assert view.notice == "Monthly instance AI token budget exceeded."
    assert not view.active


def test_a_failed_coordinator_is_failed(db_session: Session) -> None:
    scan = _scan(db_session)
    _job(db_session, scan, "triage", JobStatus.FAILED, "RuntimeError")

    view = get_scan_triage(db_session, scan.org_id, scan.id)

    assert view.state is TriageState.FAILED
    assert view.notice == "AI triage could not run."  # never a raw error class


def test_running_batches_report_progress(db_session: Session) -> None:
    scan = _scan(db_session)
    _job(db_session, scan, "triage", JobStatus.COMPLETED)
    _job(db_session, scan, "triage_batch", JobStatus.COMPLETED)
    _job(db_session, scan, "triage_batch", JobStatus.RUNNING)
    _job(db_session, scan, "triage_batch")
    _job(db_session, scan, "triage_done")

    view = get_scan_triage(db_session, scan.org_id, scan.id)

    assert view.state is TriageState.RUNNING
    assert (view.batches_done, view.batches_total) == (1, 3)
    assert view.active


def test_a_finished_run_counts_its_failed_and_skipped_batches(db_session: Session) -> None:
    scan = _scan(db_session)
    _job(db_session, scan, "triage", JobStatus.COMPLETED)
    _job(db_session, scan, "triage_batch", JobStatus.COMPLETED)
    _job(db_session, scan, "triage_batch", JobStatus.FAILED, "LLMOutputError: bad reply")
    _job(db_session, scan, "triage_batch", JobStatus.SKIPPED, "Monthly AI token budget exceeded.")
    _job(db_session, scan, "triage_done", JobStatus.COMPLETED)

    view = get_scan_triage(db_session, scan.org_id, scan.id)

    assert view.state is TriageState.DONE
    assert view.notice == "2 of 3 assets were not triaged this time."
    assert not view.active


def test_a_run_with_nothing_new_is_done(db_session: Session) -> None:
    scan = _scan(db_session)
    _job(db_session, scan, "triage", JobStatus.COMPLETED)

    view = get_scan_triage(db_session, scan.org_id, scan.id)

    assert view.state is TriageState.DONE
    assert view.notice is None


def test_a_run_closed_by_its_error_callback_is_failed(db_session: Session) -> None:
    scan = _scan(db_session)
    _job(db_session, scan, "triage", JobStatus.COMPLETED)
    _job(db_session, scan, "triage_batch", JobStatus.FAILED, "JobError: RuntimeError")
    _job(
        db_session,
        scan,
        "triage_done",
        JobStatus.FAILED,
        "AI triage stopped after an unexpected error.",
    )

    view = get_scan_triage(db_session, scan.org_id, scan.id)

    assert view.state is TriageState.FAILED
    assert view.notice == "AI triage stopped after an unexpected error."


def test_the_newest_coordinator_wins_over_a_legacy_stage(db_session: Session) -> None:
    # Scans queued before ADR 0029 also have a completed `triage` stage from the old chain.
    scan = _scan(db_session)
    _job(db_session, scan, "triage", JobStatus.COMPLETED)
    _job(db_session, scan, "triage")

    assert get_scan_triage(db_session, scan.org_id, scan.id).state is TriageState.PENDING


# --- The judgments -------------------------------------------------------------------------


def test_judgments_are_listed_by_priority_then_ai_severity(db_session: Session) -> None:
    scan = _scan(db_session)
    _judged(db_session, scan, location="p3", priority="P3", adjusted="critical")
    _judged(db_session, scan, location="p1-low", priority="P1", adjusted="low")
    _judged(db_session, scan, location="p1-critical", priority="P1", adjusted="critical")

    view = get_scan_triage(db_session, scan.org_id, scan.id)

    assert [row.location for row in view.rows] == ["p1-critical", "p1-low", "p3"]
    assert view.rows[0].asset_value == "acme.example"
    assert view.rows[0].severity is Severity.HIGH  # the scanner's, shown beside the AI's


def test_a_judgment_whose_finding_changed_is_marked_stale(db_session: Session) -> None:
    # Regression: the scan page listed the old judgment as current after the finding changed.
    scan = _scan(db_session)
    _judged(db_session, scan, location="current")
    changed = _judged(db_session, scan, location="changed")
    changed.severity = Severity.CRITICAL  # a later scan raised it
    db_session.flush()

    view = get_scan_triage(db_session, scan.org_id, scan.id)

    assert {row.location: row.stale for row in view.rows} == {"current": False, "changed": True}


def test_only_this_scans_judged_findings_are_listed(db_session: Session) -> None:
    scan = _scan(db_session)
    _judged(db_session, scan, location="listed")
    _judged(db_session, scan, location="other-scan", observed=False)
    unjudged = make_finding(db_session, scan.org_id, scan.root_asset_id, location="unjudged")
    db_session.add(
        FindingObservation(
            org_id=scan.org_id, scan_id=scan.id, finding_id=unjudged.id, severity=unjudged.severity
        )
    )
    db_session.flush()

    view = get_scan_triage(db_session, scan.org_id, scan.id)

    assert [row.location for row in view.rows] == ["listed"]


def test_at_most_a_hundred_judgments_are_listed(db_session: Session) -> None:
    scan = _scan(db_session)
    for index in range(TRIAGE_ROW_LIMIT + 5):
        _judged(db_session, scan, location=f"loc{index:03d}")

    view = get_scan_triage(db_session, scan.org_id, scan.id)

    assert len(view.rows) == TRIAGE_ROW_LIMIT == 100
    assert view.total == 105


def test_another_orgs_scan_is_not_found(db_session: Session) -> None:
    scan = _scan(db_session)
    other = make_scan(db_session, "other")

    with pytest.raises(ScanNotFound):
        get_scan_triage(db_session, other.org_id, scan.id)


# --- The scan's own progress ---------------------------------------------------------------


def test_the_scans_job_count_leaves_ai_jobs_out(db_session: Session) -> None:
    scan = _scan(db_session)
    _job(db_session, scan, "check", JobStatus.COMPLETED)
    for stage in ("triage", "triage_batch", "triage_done", "triage_failure"):
        _job(db_session, scan, stage)

    detail = scan_views.get_scan_detail(db_session, scan.org_id, scan.id)

    assert (detail.jobs_finished, detail.jobs_total) == (1, 1)
    assert [job.stage for job in detail.jobs] == ["check"]
