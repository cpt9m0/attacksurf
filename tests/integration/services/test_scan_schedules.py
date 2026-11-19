"""Scan schedule preferences: tenant scoping, no-op saves, and locked dispatch."""

from datetime import UTC, datetime, timedelta
from uuid import UUID

import pytest
from sqlalchemy import select
from sqlalchemy.orm import Session

from attacksurf.domain.assets import AssetNotFound
from attacksurf.domain.scans import ScanStatus, ScanTrigger, ScheduleFrequency
from attacksurf.infra.db.models import Org, Scan
from attacksurf.scanners.registry import registry
from attacksurf.services import scan_schedules
from attacksurf.services.assets import add_root_domain
from attacksurf.workers.app import app as _worker_app  # noqa: F401 - registers production plugins
from tests.fakes import FakeQueue

NOW = datetime(2026, 11, 19, 18, tzinfo=UTC)


def _root(session: Session, slug: str = "acme") -> tuple[UUID, UUID]:
    org = Org(name=slug, slug=slug)
    session.add(org)
    session.flush()
    root = add_root_domain(session, org.id, f"{slug}.example.com", actor_id=None)
    return org.id, root.id


def test_saving_same_preferences_does_not_reset_due_date(db_session: Session) -> None:
    org_id, root_id = _root(db_session)

    def save(now: datetime) -> None:
        scan_schedules.save_schedule(
            db_session,
            org_id=org_id,
            root_asset_id=root_id,
            actor_id=None,
            frequency=ScheduleFrequency.DAILY,
            enabled=True,
            now=now,
        )

    save(NOW)
    row = scan_schedules.get_schedule(db_session, org_id, root_id)
    assert row is not None
    due = row.next_run_at
    assert due is not None
    assert NOW + timedelta(days=1) <= due < NOW + timedelta(days=1, minutes=10)

    save(NOW + timedelta(hours=5))

    assert row.next_run_at == due


def test_foreign_org_cannot_read_or_save_schedule(db_session: Session) -> None:
    _, root_id = _root(db_session)
    foreign_org_id, _ = _root(db_session, "foreign")

    assert scan_schedules.get_schedule(db_session, foreign_org_id, root_id) is None
    with pytest.raises(AssetNotFound):
        scan_schedules.save_schedule(
            db_session,
            org_id=foreign_org_id,
            root_asset_id=root_id,
            actor_id=None,
            frequency=ScheduleFrequency.DAILY,
            enabled=False,
            now=NOW,
        )


def _due(db_session: Session, org_id: UUID, root_id: UUID, when: datetime = NOW) -> None:
    schedule = scan_schedules.get_schedule(db_session, org_id, root_id)
    assert schedule is not None
    schedule.next_run_at = when
    db_session.commit()


def _tick(session: Session, queue: FakeQueue, now: datetime = NOW) -> int:
    return scan_schedules.enqueue_due_scans(
        session, queue, now=now, registry=registry, max_starts_per_hour=10
    )


def test_one_due_occurrence_queues_once_at_frozen_time(db_session: Session) -> None:
    org_id, root_id = _root(db_session)
    _due(db_session, org_id, root_id)
    queue = FakeQueue(db_session)

    assert _tick(db_session, queue, NOW - timedelta(seconds=1)) == 0
    assert _tick(db_session, queue) == 1

    row = db_session.scalars(select(Scan).where(Scan.root_asset_id == root_id)).one()
    assert (row.org_id, row.profile, row.triggered_by) == (
        org_id,
        "dns_scheduled",
        ScanTrigger.SCHEDULE,
    )
    # Even a scan that ended before the duplicate delivery must not start twice.
    row.status = ScanStatus.COMPLETED
    db_session.commit()
    assert _tick(db_session, queue) == 0
    [(task, sent_org, _, already_committed)] = queue.sent
    assert (task, sent_org, already_committed) == ("passive.discover", org_id, True)
    scheduled = scan_schedules.get_schedule(db_session, org_id, root_id)
    assert scheduled is not None
    assert scheduled.next_run_at is not None
    assert NOW + timedelta(days=7) <= scheduled.next_run_at < NOW + timedelta(days=7, minutes=10)


@pytest.mark.parametrize("status", [ScanStatus.QUEUED, ScanStatus.RUNNING])
def test_due_root_with_active_scan_is_skipped(db_session: Session, status: ScanStatus) -> None:
    org_id, root_id = _root(db_session)
    _due(db_session, org_id, root_id)
    db_session.add(
        Scan(
            org_id=org_id,
            root_asset_id=root_id,
            status=status,
            profile="dns_passive",
            triggered_by=ScanTrigger.USER,
        )
    )
    db_session.commit()
    queue = FakeQueue(db_session)

    assert _tick(db_session, queue) == 0

    assert queue.sent == []
    assert len(db_session.scalars(select(Scan)).all()) == 1
    schedule = scan_schedules.get_schedule(db_session, org_id, root_id)
    assert schedule is not None
    assert schedule.next_run_at is not None
    assert schedule.next_run_at > NOW
