"""Database guarantees of scan schedules: one row per root, valid due times, indexable."""

from datetime import UTC, datetime

import pytest
from sqlalchemy import inspect
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from attacksurf.infra.db.models import Org, ScanSchedule
from tests.integration.factories import make_scan


def _insert_schedule(session: Session, **fields: object) -> None:
    session.add(ScanSchedule(**fields))  # type: ignore[arg-type]
    session.flush()


def test_scan_schedule_has_due_index(db_session: Session) -> None:
    indexes = inspect(db_session.connection()).get_indexes("scan_schedules")

    assert any(index["name"] == "ix_scan_schedules_due" for index in indexes)


@pytest.mark.parametrize("bad", ["foreign", "duplicate", "missing_due"])
def test_scan_schedule_rejects_invalid_rows(db_session: Session, bad: str) -> None:
    root_scan = make_scan(db_session)
    other = Org(name="other", slug="other")
    db_session.add(other)
    db_session.flush()
    fields: dict[str, object] = {
        "org_id": root_scan.org_id,
        "root_asset_id": root_scan.root_asset_id,
        "profile": "dns_scheduled",
        "frequency": "weekly",
        "next_run_at": datetime(2026, 11, 19, tzinfo=UTC),
        "enabled": True,
    }
    if bad == "foreign":
        fields["org_id"] = other.id
    elif bad == "missing_due":
        fields["next_run_at"] = None
    else:
        db_session.add(ScanSchedule(**fields))
        db_session.flush()

    with db_session.begin_nested(), pytest.raises(IntegrityError):
        _insert_schedule(db_session, **fields)
