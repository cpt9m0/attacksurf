"""Recurring scan schedules: creation defaults and time calculations.

`seed_schedule` is a building block for root registration (no commit); the preference and
dispatch use cases live here too and commit once each.
"""

from datetime import datetime, timedelta
from uuid import UUID

from sqlalchemy.dialects.postgresql import insert
from sqlalchemy.orm import Session

from attacksurf.domain.assets import AssetNotFound, AssetSource, AssetType
from attacksurf.domain.scans import ScanScheduleDefault, ScheduleFrequency
from attacksurf.infra.db.models import Asset, ScanSchedule
from attacksurf.infra.db.tenancy import scoped
from attacksurf.scanners.profiles import SCHEDULED_DNS_PROFILE
from attacksurf.services.audit import audit

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


def _lock_root(
    session: Session, org_id: UUID, root_asset_id: UUID, *, skip_locked: bool
) -> Asset | None:
    """Lock an active user root, the same row and filters `start_scan` and archiving use."""
    return session.scalars(
        scoped(Asset, org_id)
        .where(
            Asset.id == root_asset_id,
            Asset.type == AssetType.DOMAIN,
            Asset.source == AssetSource.USER,
            Asset.parent_id.is_(None),
            Asset.is_active.is_(True),
        )
        .with_for_update(skip_locked=skip_locked),
        execution_options={"populate_existing": True},
    ).one_or_none()


def get_schedule(session: Session, org_id: UUID, root_asset_id: UUID) -> ScanSchedule | None:
    """The org's saved schedule for a root, refreshed past any identity-map copy."""
    return session.scalars(
        scoped(ScanSchedule, org_id).where(ScanSchedule.root_asset_id == root_asset_id),
        execution_options={"populate_existing": True},
    ).one_or_none()


def save_schedule(
    session: Session,
    *,
    org_id: UUID,
    root_asset_id: UUID,
    actor_id: UUID | None,
    frequency: ScheduleFrequency,
    enabled: bool,
    now: datetime,
) -> None:
    """Save a root's preference and commit; re-saving it unchanged keeps the due time.

    The root lock serialises this with `start_scan` and archiving, so a change can't race a
    dispatch that is already claiming this root. Raises `AssetNotFound` for another org's root.
    """
    if _lock_root(session, org_id, root_asset_id, skip_locked=False) is None:
        raise AssetNotFound("Root asset not found.")
    schedule = get_schedule(session, org_id, root_asset_id)
    if schedule is not None and (schedule.enabled, schedule.frequency) == (enabled, frequency):
        session.commit()
        return
    if schedule is None:
        schedule = ScanSchedule(org_id=org_id, root_asset_id=root_asset_id)
        session.add(schedule)
    schedule.profile = SCHEDULED_DNS_PROFILE
    schedule.enabled = enabled
    schedule.frequency = frequency
    schedule.next_run_at = _next_run(now, root_asset_id, frequency) if enabled else None
    audit(
        session,
        org_id,
        "scan.schedule_updated",
        actor_id=actor_id,
        target_type="asset",
        target_id=str(root_asset_id),
        details={"enabled": enabled, "frequency": frequency.value},
    )
    session.commit()
