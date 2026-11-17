"""`services.scans` guards: one active scan per root, the hourly quota, cancellation."""

from datetime import UTC, datetime, timedelta
from uuid import uuid4

import pytest
from sqlalchemy.orm import Session

from attacksurf.domain.scans import (
    JobStatus,
    ScanAlreadyActive,
    ScanError,
    ScanNotFound,
    ScanRateLimited,
    ScanStatus,
)
from attacksurf.infra.db.models import AuditLog, Job, Scan
from attacksurf.infra.db.tenancy import scoped
from attacksurf.scanners.registry import ScannerRegistry
from attacksurf.services import jobs, scans
from tests.fakes import FakeQueue
from tests.integration.factories import make_scan
from tests.scanner_fixtures import PROFILES, capped_registry, fixture_registry


def _start(
    session: Session,
    root: Scan,
    queue: FakeQueue | None = None,
    profile: str = "fixture",
    registry: ScannerRegistry | None = None,
    **kwargs: object,
) -> Scan:
    return scans.start_scan(
        session,
        queue or FakeQueue(session),
        org_id=root.org_id,
        root_asset_id=root.root_asset_id,
        profile=profile,
        registry=fixture_registry() if registry is None else registry,
        profiles=PROFILES,
        **kwargs,  # type: ignore[arg-type]
    )


def _finish(session: Session, scan: Scan, status: ScanStatus = ScanStatus.COMPLETED) -> None:
    scan.status = status
    session.flush()


def test_second_start_rejected_while_first_is_running(db_session: Session) -> None:
    root = make_scan(db_session)
    before = db_session.scalars(scoped(Scan, root.org_id)).all()

    with pytest.raises(ScanAlreadyActive) as exc_info:
        _start(db_session, root)

    assert exc_info.value.scan_id == root.id
    assert "already" in str(exc_info.value).lower()
    assert db_session.scalars(scoped(Scan, root.org_id)).all() == before


def test_second_start_rejected_while_first_is_queued(db_session: Session) -> None:
    root = make_scan(db_session)
    root.status = ScanStatus.QUEUED

    with pytest.raises(ScanAlreadyActive):
        _start(db_session, root)


@pytest.mark.parametrize("status", [ScanStatus.COMPLETED, ScanStatus.FAILED, ScanStatus.CANCELLED])
def test_start_allowed_once_previous_scan_is_terminal(
    db_session: Session, status: ScanStatus
) -> None:
    root = make_scan(db_session)
    _finish(db_session, root, status)

    scan = _start(db_session, root)

    assert scan.status == ScanStatus.QUEUED
    assert scan.root_asset_id == root.root_asset_id


def test_unknown_profile_rejected_without_creating_a_scan(db_session: Session) -> None:
    root = make_scan(db_session)
    root.status = ScanStatus.COMPLETED

    with pytest.raises(ScanError, match="Unknown scan profile"):
        scans.start_scan(
            db_session,
            FakeQueue(db_session),
            org_id=root.org_id,
            root_asset_id=root.root_asset_id,
            profile="nope",
            registry=fixture_registry(),
            profiles=PROFILES,
        )

    assert db_session.scalars(scoped(Scan, root.org_id).where(Scan.id != root.id)).all() == []


def test_quota_blocks_the_start_over_the_cap(db_session: Session) -> None:
    root = make_scan(db_session)
    root.status = ScanStatus.COMPLETED

    first = _start(db_session, root, max_starts_per_hour=2)
    _finish(db_session, first)
    second = _start(db_session, root, max_starts_per_hour=2)
    _finish(db_session, second)

    with pytest.raises(ScanRateLimited):
        _start(db_session, root, max_starts_per_hour=2)


def test_quota_ignores_old_scans_other_profiles_and_orgs(db_session: Session) -> None:
    root = make_scan(db_session)
    root.status = ScanStatus.COMPLETED
    other = make_scan(db_session, "other")
    other.status = ScanStatus.COMPLETED

    stale = _start(db_session, root, max_starts_per_hour=1)
    stale.created_at = datetime.now(UTC) - timedelta(hours=2)
    _finish(db_session, stale)
    capped = _start(
        db_session,
        root,
        profile="capped",
        registry=capped_registry(),
        max_starts_per_hour=1,
    )
    assert capped.profile == "capped"
    _finish(db_session, capped)
    foreign = _start(db_session, other, max_starts_per_hour=1)
    _finish(db_session, foreign)

    # None of the above counts toward the "fixture" quota: one more start is allowed.
    assert _start(db_session, root, max_starts_per_hour=1).profile == "fixture"
    assert foreign.org_id != root.org_id


def test_failed_starts_consume_the_quota(db_session: Session) -> None:
    root = make_scan(db_session)
    root.status = ScanStatus.COMPLETED

    with pytest.raises(ConnectionError):
        _start(db_session, root, FakeQueue(db_session, fail=True), max_starts_per_hour=1)
    failed = db_session.scalars(scoped(Scan, root.org_id).where(Scan.id != root.id)).one()
    assert failed.status == ScanStatus.FAILED

    with pytest.raises(ScanRateLimited):
        _start(db_session, root, max_starts_per_hour=1)


def test_cancel_scan_cancels_scan_and_unfinished_jobs(db_session: Session) -> None:
    root = make_scan(db_session)
    root.status = ScanStatus.COMPLETED
    scan = _start(db_session, root)
    queue = FakeQueue(db_session)
    running = jobs.create_job(
        db_session,
        queue,
        org_id=scan.org_id,
        scan_id=scan.id,
        stage="check",
        task_name="passive.scan",
    )
    done = jobs.create_job(
        db_session,
        queue,
        org_id=scan.org_id,
        scan_id=scan.id,
        stage="check",
        task_name="passive.scan",
    )
    jobs.mark_job_running(db_session, scan.org_id, running.id, "celery-1", max_attempts=3)
    jobs.mark_job_completed(db_session, scan.org_id, done.id)

    cancelled = scans.cancel_scan(db_session, scan.org_id, scan.id, actor_id=None)

    assert cancelled.status == ScanStatus.CANCELLED
    assert cancelled.finished_at is not None
    assert cancelled.started_at is not None
    assert cancelled.finished_at >= cancelled.started_at
    states = {
        job.id: (job.status, job.error)
        for job in db_session.scalars(scoped(Job, scan.org_id).where(Job.scan_id == scan.id))
    }
    assert len(states) == 3  # kickoff plus the two check jobs
    assert states[running.id] == (JobStatus.CANCELLED, "Scan cancelled.")
    assert states[done.id] == (JobStatus.COMPLETED, None)
    assert (JobStatus.CANCELLED, "Scan cancelled.") in set(states.values())
    entry = db_session.scalars(
        scoped(AuditLog, scan.org_id).where(AuditLog.action == "scan.cancelled")
    ).one()
    assert entry.details == {"reason": "user_requested"}


def test_cancel_scan_is_idempotent_on_a_terminal_scan(db_session: Session) -> None:
    root = make_scan(db_session)
    scans.cancel_scan(db_session, root.org_id, root.id)

    again = scans.cancel_scan(db_session, root.org_id, root.id)

    assert again.status == ScanStatus.CANCELLED
    assert (
        len(
            db_session.scalars(
                scoped(AuditLog, root.org_id).where(AuditLog.action == "scan.cancelled")
            ).all()
        )
        == 1
    )


@pytest.mark.parametrize("missing", ["gone", "other-tenant"])
def test_cancel_scan_rejects_missing_and_other_tenant_scans(
    db_session: Session, missing: str
) -> None:
    root = make_scan(db_session)
    target = uuid4() if missing == "gone" else root.id
    org_id = root.org_id if missing == "gone" else uuid4()

    with pytest.raises(ScanNotFound):
        scans.cancel_scan(db_session, org_id, target)
