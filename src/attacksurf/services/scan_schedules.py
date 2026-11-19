"""Recurring scan schedules: creation defaults and time calculations.

`seed_schedule` is a building block for root registration (no commit); the preference and
dispatch use cases live here too and commit once each.
"""

from datetime import datetime, timedelta
from uuid import UUID

from sqlalchemy.dialects.postgresql import insert
from sqlalchemy.orm import Session

from attacksurf.domain.scans import ScanScheduleDefault, ScheduleFrequency
from attacksurf.infra.db.models import ScanSchedule
from attacksurf.scanners.profiles import SCHEDULED_DNS_PROFILE

JITTER_SECONDS = 600  # spread a fleet of same-day roots across ten minutes


def _next_run(now: datetime, root_asset_id: UUID, frequency: ScheduleFrequency) -> datetime:
    """The next due time, plus a stable per-root jitter so runs don't stampede."""
    days = 1 if frequency is ScheduleFrequency.DAILY else 7
    jitter = int.from_bytes(root_asset_id.bytes[-2:], "big") % JITTER_SECONDS
    return now + timedelta(days=days, seconds=jitter)


def seed_schedule(
    session: Session,
    *,
    org_id: UUID,
    root_asset_id: UUID,
    default: ScanScheduleDefault,
    now: datetime,
) -> None:
    """Seed a newly registered root; a restored root keeps its saved preference.

    Doesn't commit: the registration use case commits once.
    """
    enabled = default != "off"
    frequency = ScheduleFrequency(default) if enabled else ScheduleFrequency.WEEKLY
    session.execute(
        insert(ScanSchedule)
        .values(
            org_id=org_id,
            root_asset_id=root_asset_id,
            profile=SCHEDULED_DNS_PROFILE,
            frequency=frequency,
            enabled=enabled,
            next_run_at=_next_run(now, root_asset_id, frequency) if enabled else None,
        )
        .on_conflict_do_nothing(index_elements=[ScanSchedule.org_id, ScanSchedule.root_asset_id])
    )
