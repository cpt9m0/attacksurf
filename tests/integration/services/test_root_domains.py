"""Use cases: adding and archiving root domains."""

import threading

import pytest
from sqlalchemy import Engine, delete, select, text
from sqlalchemy.orm import Session

from attacksurf.domain.assets import (
    AssetNotFound,
    AssetSource,
    AssetType,
    DomainAlreadyAdded,
    InvalidAssetValue,
)
from attacksurf.domain.ids import uuid7
from attacksurf.domain.scans import JobStatus, ScanStatus, ScanTrigger
from attacksurf.infra.db.models import Asset, AuditLog, Job, Org, Scan, User
from attacksurf.services.assets import add_root_domain, archive_root_domain, record_asset


@pytest.fixture
def org(db_session: Session) -> Org:
    org = Org(name="acme", slug="acme")
    db_session.add(org)
    db_session.flush()
    return org


@pytest.fixture
def user(db_session: Session) -> User:
    user = User(email="alice@example.com", password_hash="not-a-real-hash")
    db_session.add(user)
    db_session.flush()
    return user


def _audit(session: Session, org: Org) -> list[tuple[str, str | None, dict[str, object]]]:
    entries = session.scalars(
        select(AuditLog).where(AuditLog.org_id == org.id).order_by(AuditLog.id)
    )
    return [(e.action, e.target_id, e.details) for e in entries]


def _child(session: Session, org: Org, root: Asset, value: str) -> Asset:
    return record_asset(
        session,
        org.id,
        AssetType.SUBDOMAIN,
        value,
        source=AssetSource.DISCOVERED,
        parent_id=root.id,
    )


def _scan(session: Session, root: Asset, status: ScanStatus) -> Scan:
    scan = Scan(
        org_id=root.org_id,
        root_asset_id=root.id,
        profile="dns_passive",
        status=status,
        triggered_by=ScanTrigger.USER,
    )
    session.add(scan)
    session.flush()
    return scan


def _job(session: Session, scan: Scan, status: JobStatus) -> Job:
    job = Job(org_id=scan.org_id, scan_id=scan.id, stage="check", status=status, scanner="fixture")
    session.add(job)
    session.flush()
    return job


def test_add_root_domain_stores_normalized_user_root(db_session: Session, org: Org) -> None:
    asset = add_root_domain(db_session, org.id, " ExAmple.COM. ", actor_id=None)

    assert (asset.type, asset.value, asset.source) == ("domain", "example.com", "user")
    assert (asset.parent_id, asset.is_active) == (None, True)
    assert _audit(db_session, org) == [
        ("asset.root_added", str(asset.id), {"value": "example.com"})
    ]


def test_root_domain_use_cases_record_the_actor(db_session: Session, org: Org, user: User) -> None:
    asset = add_root_domain(db_session, org.id, "example.com", actor_id=user.id)
    archive_root_domain(db_session, org.id, asset.id, actor_id=user.id)

    entries = db_session.scalars(select(AuditLog).where(AuditLog.org_id == org.id)).all()
    assert [e.actor_user_id for e in entries] == [user.id, user.id]


def test_add_root_domain_accepts_a_subdomain_the_org_controls(
    db_session: Session, org: Org
) -> None:
    asset = add_root_domain(db_session, org.id, "eng.example.co.uk", actor_id=None)

    assert (asset.type, asset.value, asset.parent_id) == ("domain", "eng.example.co.uk", None)


@pytest.mark.parametrize(
    ("raw", "message"),
    [
        ("", "Enter a domain name."),
        ("192.0.2.1", "is an IP address"),
        ("localhost", "is not a valid domain name"),
        ("printer.corp", "Internal-only domain names"),
        ("app.internal", "Internal-only domain names"),
        ("co.uk", "known public suffix"),
        ("example.notatld", "known public suffix"),
        ("exa mple.com", "is not a valid domain name"),
    ],
)
def test_add_root_domain_rejects_names_that_cannot_be_scanned(
    db_session: Session, org: Org, raw: str, message: str
) -> None:
    with pytest.raises(InvalidAssetValue, match=message):
        add_root_domain(db_session, org.id, raw, actor_id=None)

    assert db_session.scalars(select(Asset)).all() == []


def test_adding_an_active_root_twice_is_rejected(db_session: Session, org: Org) -> None:
    add_root_domain(db_session, org.id, "example.com", actor_id=None)

    with pytest.raises(DomainAlreadyAdded, match=r"example\.com is already in your assets"):
        add_root_domain(db_session, org.id, "EXAMPLE.com", actor_id=None)


def test_same_domain_in_another_org_is_independent(db_session: Session, org: Org) -> None:
    other = Org(name="globex", slug="globex")
    db_session.add(other)
    db_session.flush()
    add_root_domain(db_session, org.id, "example.com", actor_id=None)

    asset = add_root_domain(db_session, other.id, "example.com", actor_id=None)

    assert asset.org_id == other.id


def test_archive_deactivates_root_and_its_discovered_assets_only(
    db_session: Session, org: Org
) -> None:
    root = add_root_domain(db_session, org.id, "example.com", actor_id=None)
    www = _child(db_session, org, root, "www.example.com")
    other_root = add_root_domain(db_session, org.id, "example.org", actor_id=None)
    other_child = _child(db_session, org, other_root, "www.example.org")

    archived = archive_root_domain(db_session, org.id, root.id, actor_id=None)

    assert archived.id == root.id
    for asset in (root, www):
        db_session.refresh(asset)
        assert not asset.is_active
        assert asset.deactivated_at is not None
    for asset in (other_root, other_child):
        db_session.refresh(asset)
        assert asset.is_active
    assert _audit(db_session, org)[-1] == (
        "asset.root_archived",
        str(root.id),
        {"value": "example.com", "children": 1, "scans_cancelled": 0},
    )


def test_archive_keeps_already_inactive_children_deactivation_time(
    db_session: Session, org: Org
) -> None:
    root = add_root_domain(db_session, org.id, "example.com", actor_id=None)
    gone = _child(db_session, org, root, "old.example.com")
    gone.is_active, gone.deactivated_at = False, gone.last_seen
    db_session.flush()

    archive_root_domain(db_session, org.id, root.id, actor_id=None)

    db_session.refresh(gone)
    assert gone.deactivated_at == gone.last_seen
    assert _audit(db_session, org)[-1][2] == {
        "value": "example.com",
        "children": 0,
        "scans_cancelled": 0,
    }


def test_archiving_an_archived_root_changes_nothing(db_session: Session, org: Org) -> None:
    root = add_root_domain(db_session, org.id, "example.com", actor_id=None)
    archive_root_domain(db_session, org.id, root.id, actor_id=None)
    db_session.refresh(root)
    deactivated_at = root.deactivated_at

    archive_root_domain(db_session, org.id, root.id, actor_id=None)

    db_session.refresh(root)
    assert root.deactivated_at == deactivated_at
    assert [a for a, *_ in _audit(db_session, org)].count("asset.root_archived") == 1


def test_readding_an_archived_root_restores_it_but_not_its_children(
    db_session: Session, org: Org
) -> None:
    root = add_root_domain(db_session, org.id, "example.com", actor_id=None)
    www = _child(db_session, org, root, "www.example.com")
    archive_root_domain(db_session, org.id, root.id, actor_id=None)

    restored = add_root_domain(db_session, org.id, "example.com", actor_id=None)

    db_session.refresh(www)
    assert restored.id == root.id
    assert (restored.is_active, restored.deactivated_at) == (True, None)
    assert not www.is_active  # comes back when a scan sees it again
    assert _audit(db_session, org)[-1][0] == "asset.root_restored"


def test_archive_rejects_discovered_assets(db_session: Session, org: Org) -> None:
    root = add_root_domain(db_session, org.id, "example.com", actor_id=None)
    www = _child(db_session, org, root, "www.example.com")

    with pytest.raises(AssetNotFound):
        archive_root_domain(db_session, org.id, www.id, actor_id=None)


def test_archive_rejects_another_orgs_root(db_session: Session, org: Org) -> None:
    other = Org(name="globex", slug="globex")
    db_session.add(other)
    db_session.flush()
    theirs = add_root_domain(db_session, other.id, "globex.com", actor_id=None)

    with pytest.raises(AssetNotFound):
        archive_root_domain(db_session, org.id, theirs.id, actor_id=None)

    db_session.refresh(theirs)
    assert theirs.is_active


def test_archive_rejects_unknown_ids(db_session: Session, org: Org) -> None:
    with pytest.raises(AssetNotFound):
        archive_root_domain(db_session, org.id, uuid7(), actor_id=None)


@pytest.mark.parametrize("status", [ScanStatus.QUEUED, ScanStatus.RUNNING])
def test_archive_cancels_the_roots_queued_and_running_scans(
    db_session: Session, org: Org, status: ScanStatus
) -> None:
    root = add_root_domain(db_session, org.id, "example.com", actor_id=None)
    scan = _scan(db_session, root, status)
    other_root = add_root_domain(db_session, org.id, "example.org", actor_id=None)
    other = _scan(db_session, other_root, ScanStatus.RUNNING)

    archive_root_domain(db_session, org.id, root.id, actor_id=None)

    db_session.expire_all()
    assert scan.status is ScanStatus.CANCELLED
    assert scan.finished_at is not None
    assert scan.finished_at >= (scan.started_at or scan.created_at)
    assert other.status is ScanStatus.RUNNING


def test_archive_leaves_completed_scans_untouched(db_session: Session, org: Org) -> None:
    root = add_root_domain(db_session, org.id, "example.com", actor_id=None)
    done = _scan(db_session, root, ScanStatus.COMPLETED)

    archive_root_domain(db_session, org.id, root.id, actor_id=None)

    db_session.refresh(done)
    assert done.status is ScanStatus.COMPLETED


def test_archive_cancels_the_unfinished_jobs_of_cancelled_scans(
    db_session: Session, org: Org
) -> None:
    root = add_root_domain(db_session, org.id, "example.com", actor_id=None)
    scan = _scan(db_session, root, ScanStatus.RUNNING)
    queued = _job(db_session, scan, JobStatus.QUEUED)
    running = _job(db_session, scan, JobStatus.RUNNING)
    finished = _job(db_session, scan, JobStatus.COMPLETED)

    archive_root_domain(db_session, org.id, root.id, actor_id=None)

    for job in (queued, running):
        db_session.refresh(job)
        assert job.status is JobStatus.CANCELLED
        assert job.error == "Root domain was archived."
        assert job.finished_at is not None
    db_session.refresh(finished)
    assert finished.status is JobStatus.COMPLETED


def test_archive_audits_each_cancelled_scan(db_session: Session, org: Org) -> None:
    root = add_root_domain(db_session, org.id, "example.com", actor_id=None)
    scan = _scan(db_session, root, ScanStatus.RUNNING)

    archive_root_domain(db_session, org.id, root.id, actor_id=None)

    # Both entries land in one transaction; FKs order them arbitrarily, so compare unordered.
    assert sorted(map(repr, _audit(db_session, org)[-2:])) == sorted(
        map(
            repr,
            [
                (
                    "asset.root_archived",
                    str(root.id),
                    {"value": "example.com", "children": 0, "scans_cancelled": 1},
                ),
                ("scan.cancelled", str(scan.id), {"reason": "root_archived"}),
            ],
        )
    )


def test_archive_without_scans_writes_no_cancellation(db_session: Session, org: Org) -> None:
    root = add_root_domain(db_session, org.id, "example.com", actor_id=None)

    archive_root_domain(db_session, org.id, root.id, actor_id=None)

    assert [action for action, *_ in _audit(db_session, org)] == [
        "asset.root_added",
        "asset.root_archived",
    ]


def test_cancelling_never_sets_finished_before_a_worker_start_time(
    db_engine: Engine,
) -> None:
    """Regression: `now()` is the transaction's start, so a worker that committed `started_at`
    after the archive request began could push `finished_at` before it and roll back the archive.
    """
    with Session(db_engine) as setup:
        org = Org(name="clock", slug="clock")
        setup.add(org)
        setup.flush()
        root = add_root_domain(setup, org.id, "clock.example.com", actor_id=None)
        scan = _scan(setup, root, ScanStatus.QUEUED)
        job = _job(setup, scan, JobStatus.QUEUED)
        setup.commit()
        org_id, root_id, scan_id, job_id = org.id, root.id, scan.id, job.id

    archive = Session(db_engine)
    worker = Session(db_engine)
    try:
        archive.get(Asset, root_id)  # the request's transaction begins now, before the worker
        worker_scan = worker.get(Scan, scan_id)
        worker_job = worker.get(Job, job_id)
        assert worker_scan is not None
        assert worker_job is not None
        # The worker starts the scan and its job later than the archive request began.
        started = worker.execute(text("SELECT clock_timestamp()")).scalar_one()
        worker_scan.status = ScanStatus.RUNNING
        worker_scan.started_at = started
        worker_job.status = JobStatus.RUNNING
        worker_job.started_at = started
        worker.commit()

        archive_root_domain(archive, org_id, root_id, actor_id=None)  # must not violate the check

        archive.expire_all()
        assert archive.get(Scan, scan_id).status == ScanStatus.CANCELLED  # type: ignore[union-attr]
        assert archive.get(Job, job_id).status == JobStatus.CANCELLED  # type: ignore[union-attr]
        rows = archive.execute(
            text(
                "SELECT finished_at >= started_at FROM scans WHERE id = :s"
                " UNION ALL SELECT finished_at >= started_at FROM jobs WHERE id = :j"
            ),
            {"s": scan_id, "j": job_id},
        ).scalars()
        assert all(rows)
    finally:
        archive.rollback()
        worker.rollback()
        archive.close()
        worker.close()
        with Session(db_engine) as cleanup:
            cleanup.execute(delete(AuditLog).where(AuditLog.org_id == org_id))
            cleanup.execute(delete(Job).where(Job.org_id == org_id))
            cleanup.execute(delete(Scan).where(Scan.org_id == org_id))
            cleanup.execute(delete(Asset).where(Asset.org_id == org_id))
            cleanup.execute(delete(Org).where(Org.id == org_id))
            cleanup.commit()


def test_concurrent_archives_of_one_root_do_not_deadlock(db_engine: Engine) -> None:
    """Regression: both archives held the root key-share, then deadlocked upgrading to write.

    Two admins archiving the same root at once must see one archive run and the other find it
    already archived, never a deadlock (the root has no scans here, so nothing else is involved).
    """
    with Session(db_engine) as setup:
        org = Org(name="twice", slug="twice")
        setup.add(org)
        setup.flush()
        root = add_root_domain(setup, org.id, "twice.example.com", actor_id=None)
        setup.commit()
        org_id, root_id = org.id, root.id

    ready = threading.Barrier(2)  # both archive requests are in flight together
    errors: list[BaseException] = []

    def archive() -> None:
        session = Session(db_engine)
        try:
            session.get(Org, org_id)  # the request transaction opens before the archive
            ready.wait(timeout=10)
            archive_root_domain(session, org_id, root_id, actor_id=None)
        except BaseException as exc:
            errors.append(exc)
            session.rollback()
        finally:
            session.close()

    try:
        threads = [threading.Thread(target=archive, daemon=True) for _ in range(2)]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join(timeout=20)
            assert not thread.is_alive()
        assert errors == [], f"deadlock or failure: {errors}"

        with Session(db_engine) as check:
            archived = check.scalars(
                select(AuditLog).where(AuditLog.action == "asset.root_archived")
            ).all()
            assert len(archived) == 1  # the second archive changed nothing
            assert check.get(Asset, root_id).is_active is False  # type: ignore[union-attr]
    finally:
        with Session(db_engine) as cleanup:
            cleanup.execute(delete(AuditLog).where(AuditLog.org_id == org_id))
            cleanup.execute(delete(Job).where(Job.org_id == org_id))
            cleanup.execute(delete(Scan).where(Scan.org_id == org_id))
            cleanup.execute(delete(Asset).where(Asset.org_id == org_id))
            cleanup.execute(delete(Org).where(Org.id == org_id))
            cleanup.commit()
