"""The scheduler tick end to end: real task, real queue adapter, frozen clock."""

from datetime import UTC, datetime, tzinfo
from typing import Any

import pytest
from sqlalchemy import select
from sqlalchemy.orm import Session, sessionmaker

from attacksurf.domain.scans import ScanStatus, ScanTrigger
from attacksurf.infra.db.models import Org, Scan
from attacksurf.services import scan_schedules
from attacksurf.services.assets import add_root_domain
from attacksurf.workers import runtime
from attacksurf.workers.tasks import system

NOW = datetime(2026, 11, 19, 18, tzinfo=UTC)


class FrozenDateTime(datetime):
    @classmethod
    def now(cls, tz: tzinfo | None = None) -> datetime:
        assert tz is UTC
        return NOW


def test_beat_task_queues_exactly_one_due_scan_on_duplicate_delivery(
    db_session: Session, monkeypatch: pytest.MonkeyPatch
) -> None:
    org = Org(name="beat", slug="beat")
    db_session.add(org)
    db_session.flush()
    root = add_root_domain(db_session, org.id, "beat.example.com", actor_id=None)
    root_id = root.id
    row = scan_schedules.get_schedule(db_session, root.org_id, root_id)
    assert row is not None
    row.next_run_at = NOW
    db_session.commit()
    factory = sessionmaker(bind=db_session.connection(), join_transaction_mode="create_savepoint")
    sent: list[tuple[str, str]] = []

    def record(task: str, **options: Any) -> Any:
        assert options["queue"] == "passive"
        sent.append((task, options["kwargs"]["org_id"]))
        return type("Result", (), {"id": "fake-message"})()

    org_id = str(root.org_id)
    monkeypatch.setattr(runtime, "session_factory", lambda: factory)
    monkeypatch.setattr(system, "datetime", FrozenDateTime)
    monkeypatch.setattr(system.app, "send_task", record)

    system.enqueue_due_scans()
    scan = db_session.scalars(select(Scan).where(Scan.root_asset_id == root_id)).one()
    assert scan.triggered_by == ScanTrigger.SCHEDULE
    scan.status = ScanStatus.COMPLETED
    db_session.commit()
    system.enqueue_due_scans()

    assert sent == [("passive.discover", org_id)]
    assert len(db_session.scalars(select(Scan).where(Scan.root_asset_id == root_id)).all()) == 1
