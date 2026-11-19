"""Scan schedule preferences: tenant scoping, no-op saves, and locked dispatch."""

from datetime import UTC, datetime, timedelta
from uuid import UUID

import pytest
from sqlalchemy.orm import Session

from attacksurf.domain.assets import AssetNotFound
from attacksurf.domain.scans import ScheduleFrequency
from attacksurf.infra.db.models import Org
from attacksurf.services import scan_schedules
from attacksurf.services.assets import add_root_domain

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
