"""Assets and their relations: root-domain use cases and the pipeline's building blocks.

`add_root_domain` / `archive_root_domain` are use cases and commit once. `record_asset` /
`record_relation` are building blocks: they don't commit; the use case that calls them does.
"""

from collections.abc import Collection
from datetime import UTC, datetime
from uuid import UUID

from sqlalchemy import case, func, null, update
from sqlalchemy.dialects.postgresql import insert
from sqlalchemy.orm import Session

from attacksurf.domain.assets import (
    AssetNotFound,
    AssetSource,
    AssetType,
    DomainAlreadyAdded,
    InvalidAssetValue,
    RelationKind,
    normalize_asset_value,
    normalize_hostname,
)
from attacksurf.domain.ids import uuid7
from attacksurf.domain.scope import ScopeError, check_public_hostname
from attacksurf.infra import public_suffix
from attacksurf.infra.db.models import Asset, AssetRelation
from attacksurf.infra.db.tenancy import scoped
from attacksurf.services.audit import audit


def add_root_domain(session: Session, org_id: UUID, raw: str, *, actor_id: UUID | None) -> Asset:
    """Register a domain the org owns as a scan root, and commit.

    Accepts any name ScopeGuard would scan: registrable (`example.com`) or a subdomain the org
    controls (`eng.example.com`). Re-adding an archived root restores it; what was discovered
    under it stays inactive until a scan sees it again.
    Raises `InvalidAssetValue` for names that can't be scanned and `DomainAlreadyAdded`.
    """
    name = _scannable_hostname(raw)
    existing = session.scalars(
        scoped(Asset, org_id).where(Asset.type == AssetType.DOMAIN, Asset.value == name)
    ).one_or_none()
    if existing is not None and existing.is_active and existing.source == AssetSource.USER:
        raise DomainAlreadyAdded(f"{name} is already in your assets.")
    restored = existing is not None and not existing.is_active
    asset = record_asset(session, org_id, AssetType.DOMAIN, name, source=AssetSource.USER)
    audit(
        session,
        org_id,
        "asset.root_restored" if restored else "asset.root_added",
        actor_id=actor_id,
        target_type="asset",
        target_id=str(asset.id),
        details={"value": name},
    )
    session.commit()
    return asset


def archive_root_domain(
    session: Session, org_id: UUID, asset_id: UUID, *, actor_id: UUID | None
) -> Asset:
    """Mark a root domain and everything discovered under it inactive, and commit.

    Findings and scan history are kept; `start_scan` refuses inactive roots. Archiving an
    archived root changes nothing. Raises `AssetNotFound` unless `asset_id` is one of the
    org's root domains.
    """
    root = session.scalars(
        scoped(Asset, org_id).where(Asset.id == asset_id).with_for_update()
    ).one_or_none()
    if root is None or root.type != AssetType.DOMAIN or root.parent_id is not None:
        raise AssetNotFound("Asset not found.")
    if not root.is_active:
        return root
    # Discovered assets are always direct children: the pipeline parents them to the scan root.
    archived = session.scalars(
        update(Asset)
        .where(
            Asset.org_id == org_id,
            (Asset.id == root.id) | (Asset.parent_id == root.id),
            Asset.is_active.is_(True),
        )
        .values(is_active=False, deactivated_at=datetime.now(UTC), updated_at=func.now())
        .returning(Asset.id),
        execution_options={"synchronize_session": "fetch"},
    ).all()
    audit(
        session,
        org_id,
        "asset.root_archived",
        actor_id=actor_id,
        target_type="asset",
        target_id=str(root.id),
        details={"value": root.value, "children": len(archived) - 1},
    )
    session.commit()
    return root


def _scannable_hostname(raw: str) -> str:
    name = normalize_hostname(raw)  # raises InvalidAssetValue with a specific message
    try:
        return check_public_hostname(name, public_suffix.classify(name))
    except ScopeError as exc:
        raise InvalidAssetValue(str(exc)) from None


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
