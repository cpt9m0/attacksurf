"""Recording assets and their relations (used by the scan pipeline and asset management)."""

from datetime import UTC, datetime
from uuid import UUID

from sqlalchemy import case, func
from sqlalchemy.dialects.postgresql import insert
from sqlalchemy.orm import Session

from attacksurf.domain.assets import (
    AssetSource,
    AssetType,
    InvalidAssetValue,
    RelationKind,
    normalize_asset_value,
)
from attacksurf.domain.ids import uuid7
from attacksurf.infra.db.models import Asset, AssetRelation


def record_asset(
    session: Session,
    org_id: UUID,
    asset_type: AssetType,
    value: str,
    *,
    source: AssetSource,
    parent_id: UUID | None = None,
    seen_at: datetime | None = None,
) -> Asset:
    """Insert the asset or, if the org already has it, mark it seen again. Doesn't commit.

    One atomic `INSERT ... ON CONFLICT`, so concurrent scans can't create duplicates.
    Re-seeing an asset never downgrades `source=user` and keeps its first parent.
    Raises `InvalidAssetValue` / `UnsupportedAssetType` for values that can't be normalized.
    """
    seen = seen_at or datetime.now(UTC)
    stmt = insert(Asset).values(
        id=uuid7(),
        org_id=org_id,
        type=asset_type,
        value=normalize_asset_value(asset_type, value),
        source=source,
        parent_id=parent_id,
        first_seen=seen,
        last_seen=seen,
    )
    new = stmt.excluded
    stmt = stmt.on_conflict_do_update(
        index_elements=[Asset.org_id, Asset.type, Asset.value],
        set_={
            # greatest/least: results processed out of order never move the window backwards.
            "last_seen": func.greatest(Asset.last_seen, new.last_seen),
            "first_seen": func.least(Asset.first_seen, new.first_seen),
            # A stale sighting (older than what's stored) must not resurrect an asset that
            # newer results marked inactive.
            "is_active": case((new.last_seen >= Asset.last_seen, True), else_=Asset.is_active),
            "source": case((Asset.source == AssetSource.USER, Asset.source), else_=new.source),
            "parent_id": func.coalesce(Asset.parent_id, new.parent_id),
            "updated_at": func.now(),
        },
    )
    return session.scalars(
        stmt.returning(Asset), execution_options={"populate_existing": True}
    ).one()


def record_relation(
    session: Session,
    org_id: UUID,
    from_asset_id: UUID,
    to_asset_id: UUID,
    kind: RelationKind,
    *,
    seen_at: datetime | None = None,
) -> AssetRelation:
    """Insert the edge or mark it seen again. Doesn't commit. Both assets must be the org's."""
    if from_asset_id == to_asset_id:
        raise InvalidAssetValue("An asset can't be related to itself.")
    seen = seen_at or datetime.now(UTC)
    stmt = insert(AssetRelation).values(
        id=uuid7(),
        org_id=org_id,
        from_asset_id=from_asset_id,
        to_asset_id=to_asset_id,
        kind=kind,
        first_seen=seen,
        last_seen=seen,
    )
    new = stmt.excluded
    stmt = stmt.on_conflict_do_update(
        index_elements=[
            AssetRelation.org_id,
            AssetRelation.from_asset_id,
            AssetRelation.to_asset_id,
            AssetRelation.kind,
        ],
        set_={
            "last_seen": func.greatest(AssetRelation.last_seen, new.last_seen),
            "first_seen": func.least(AssetRelation.first_seen, new.first_seen),
        },
    )
    return session.scalars(
        stmt.returning(AssetRelation), execution_options={"populate_existing": True}
    ).one()
