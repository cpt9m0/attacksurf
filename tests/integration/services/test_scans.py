"""`services.scans` guards: one active scan per root, the hourly quota, cancellation."""

import threading
import time
from datetime import UTC, datetime, timedelta
from typing import Any
from uuid import UUID, uuid4

import pytest
from sqlalchemy import Engine, delete, func, select
from sqlalchemy.orm import Session, sessionmaker

from attacksurf.domain.assets import AssetSource, AssetType
from attacksurf.domain.scans import (
    JobStatus,
    ScanAlreadyActive,
    ScanError,
    ScanNotFound,
    ScanRateLimited,
    ScanStatus,
    ScanTrigger,
)
from attacksurf.infra.db.models import AuditLog, Job, Org, Scan
from attacksurf.infra.db.tenancy import scoped
from attacksurf.scanners.registry import ScannerRegistry
from attacksurf.services import jobs, scans
from attacksurf.services.assets import record_asset
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


def test_quota_serialises_concurrent_starts_for_different_roots(
    db_engine: Engine, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Two roots, one org: the second start blocks on the org lock, then sees the first scan.

    Each request locks a different asset row, so without the org lock both could read the
    same below-limit count and both insert. T1 pauses inside its queue call (after the quota
    check, before the commit) while holding the org row; T2 must then refuse once T1
    commits. The outcome is the same if T2 only reaches the lock after the commit: it reads
    the new count directly. Setup and teardown use their own connections; nothing here uses
    the rolled-back `db_session`, and the org delete cascades every row this test commits.
    """
    entered = threading.Event()
    release = threading.Event()
    real_create_job = jobs.create_job

    def pausing_create_job(session: Session, queue: FakeQueue, **kwargs: Any) -> Job:
        entered.set()
        assert release.wait(15), "the test never released the queue"
        return real_create_job(session, queue, **kwargs)

    monkeypatch.setattr(jobs, "create_job", pausing_create_job)
    factory = sessionmaker(bind=db_engine)
    org_id, root_a_id, root_b_id = _race_org(factory)
    try:
        errors: list[Exception] = []
        outcomes: dict[str, str] = {}
        t1 = threading.Thread(
            target=_threaded_start,
            args=(factory, org_id, root_a_id, "a"),
            kwargs={"outcomes": outcomes, "errors": errors},
        )
        t1.start()
        assert entered.wait(15), f"T1 never reached the queue: {errors}"
        t2 = threading.Thread(
            target=_threaded_start,
            args=(factory, org_id, root_b_id, "b"),
            kwargs={"outcomes": outcomes, "errors": errors},
        )
        t2.start()
        time.sleep(0.5)  # let T2 reach the org lock; the outcome is the same if it does not
        release.set()
        t1.join(15)
        t2.join(15)
        assert not t1.is_alive(), "the first start deadlocked"
        assert not t2.is_alive(), "the second start deadlocked"
        assert not errors, errors
        assert outcomes.get("b") == "limited", outcomes
        assert _scan_count(factory, org_id) == 2  # the fixture scan plus T1's
    finally:
        _delete_org(factory, org_id)


def _race_org(factory: sessionmaker[Session]) -> tuple[UUID, UUID, UUID]:
    """An org with two roots and one completed scan, committed for real connections."""
    setup = factory()
    try:
        token = uuid4().hex[:12]
        org = Org(name=f"race-{token}", slug=f"race-{token}")
        setup.add(org)
        setup.flush()
        root_a = record_asset(
            setup, org.id, AssetType.DOMAIN, f"a-{token}.example", source=AssetSource.USER
        )
        root_b = record_asset(
            setup, org.id, AssetType.DOMAIN, f"b-{token}.example", source=AssetSource.USER
        )
        setup.add(
            Scan(
                org_id=org.id,
                root_asset_id=root_a.id,
                profile="fixture",
                status=ScanStatus.COMPLETED,
                triggered_by=ScanTrigger.USER,
            )
        )
        setup.commit()
        return org.id, root_a.id, root_b.id
    finally:
        setup.close()


def _threaded_start(
    factory: sessionmaker[Session],
    org_id: UUID,
    root_id: UUID,
    name: str,
    *,
    outcomes: dict[str, str],
    errors: list[Exception],
) -> None:
    session = factory()
    try:
        scans.start_scan(
            session,
            FakeQueue(session),
            org_id=org_id,
            root_asset_id=root_id,
            profile="fixture",
            registry=fixture_registry(),
            profiles=PROFILES,
            max_starts_per_hour=2,
        )
    except ScanRateLimited:
        outcomes[name] = "limited"
    except Exception as exc:
        errors.append(exc)
        outcomes[name] = f"unexpected: {exc!r}"
    else:
        outcomes[name] = "started"
    finally:
        session.close()


def _scan_count(factory: sessionmaker[Session], org_id: UUID) -> int:
    check = factory()
    try:
        return (
            check.scalar(
                select(func.count())
                .select_from(Scan)
                .where(Scan.org_id == org_id, Scan.profile == "fixture")
            )
            or 0
        )
    finally:
        check.close()


def _delete_org(factory: sessionmaker[Session], org_id: UUID) -> None:
    cleanup = factory()
    try:
        cleanup.execute(delete(Org).where(Org.id == org_id))
        cleanup.commit()
    finally:
        cleanup.close()


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
