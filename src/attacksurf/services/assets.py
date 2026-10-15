"""Recording assets and their relations (used by the scan pipeline and asset management).

These are building blocks: they don't commit; the use case that calls them commits once.
"""

from collections.abc import Collection
from datetime import UTC, datetime
from uuid import UUID

from sqlalchemy import case, func, null
from sqlalchemy.dialects.postgresql import insert
from sqlalchemy.orm import Session

from attacksurf.domain.assets import (
    AssetNotFound,
    AssetSource,
    AssetType,
    InvalidAssetValue,
    RelationKind,
    normalize_asset_value,
)
from attacksurf.domain.ids import uuid7
from attacksurf.infra.db.models import Asset, AssetRelation
from attacksurf.infra.db.tenancy import scoped


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
    Re-seeing an asset never downgrades `source=user` and keeps its first parent; a user
    adding a discovered asset detaches it, since user-added assets are roots.
    Raises `InvalidAssetValue` / `UnsupportedAssetType` for values that can't be normalized
    and `AssetNotFound` if `parent_id` isn't one of the org's assets.
    """
    if parent_id is not None:
        if source == AssetSource.USER:
            raise InvalidAssetValue(
                "User-added assets are roots; only discovered assets have a parent."
            )
        _lock_existing_assets(session, org_id, {parent_id})
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
    # Only a sighting after the scan that found it gone reactivates it; delayed older results don't.
    reactivate = Asset.deactivated_at.is_(None) | (new.last_seen > Asset.deactivated_at)
    stmt = stmt.on_conflict_do_update(
        index_elements=[Asset.org_id, Asset.type, Asset.value],
        set_={
            # greatest/least: results processed out of order never move the window backwards.
            "last_seen": func.greatest(Asset.last_seen, new.last_seen),
            "first_seen": func.least(Asset.first_seen, new.first_seen),
            "is_active": reactivate,
            "deactivated_at": case((reactivate, null()), else_=Asset.deactivated_at),
            "source": case((Asset.source == AssetSource.USER, Asset.source), else_=new.source),
            # Never re-parented after insert, so the parent graph stays acyclic.
            "parent_id": case((new.source == AssetSource.USER, null()), else_=Asset.parent_id),
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
    """Insert the edge or mark it seen again. Doesn't commit.

    Raises `AssetNotFound` unless both endpoints are the org's assets.
    """
    if from_asset_id == to_asset_id:
        raise InvalidAssetValue("An asset can't be related to itself.")
    _lock_existing_assets(session, org_id, {from_asset_id, to_asset_id})
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


def _lock_existing_assets(session: Session, org_id: UUID, ids: Collection[UUID]) -> None:
    """Raise `AssetNotFound` unless all `ids` are the org's assets.

    FOR KEY SHARE (needs `read=True` too, else it's FOR NO KEY UPDATE) keeps them from being
    deleted until the transaction ends, so the insert that references them can't fail on its
    foreign key (and abort the caller's transaction) instead. Key-share locks don't conflict
    with each other, so concurrent scans touching the same assets don't serialize.
    """
    found = session.scalars(
        scoped(Asset, org_id).where(Asset.id.in_(ids)).with_for_update(read=True, key_share=True)
    ).all()
    if len(found) != len(ids):
        raise AssetNotFound("Asset not found.")
