"""Assets and their relations: root-domain use cases and the pipeline's building blocks.

`add_root_domain` / `archive_root_domain` are use cases and commit once. `record_asset` /
`record_relation` are building blocks: they don't commit; the use case that calls them does.
"""

from collections.abc import Collection, Sequence
from datetime import UTC, datetime
from typing import Any
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
from attacksurf.domain.scans import ScanScheduleDefault
from attacksurf.domain.scope import ScopeError, check_public_hostname
from attacksurf.infra import public_suffix
from attacksurf.infra.db.models import Asset, AssetRelation
from attacksurf.infra.db.tenancy import scoped
from attacksurf.services.audit import audit
from attacksurf.services.scan_schedules import seed_schedule
from attacksurf.services.scans import cancel_root_scans


def add_root_domain(
    session: Session,
    org_id: UUID,
    raw: str,
    *,
    actor_id: UUID | None,
    scan_default_frequency: ScanScheduleDefault = "weekly",
) -> Asset:
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
    seed_schedule(
        session,
        org_id=org_id,
        root_asset_id=asset.id,
        default=scan_default_frequency,
        now=datetime.now(UTC),
    )
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

    Findings and scan history are kept; `start_scan` refuses inactive roots. Scans of the root
    that are queued or running are cancelled in the same transaction, so they show as
    `cancelled` in their history, and so do their unfinished jobs. Nothing is revoked in Celery:
    worker tasks that are already queued or running see the cancelled scan or the inactive root
    and drop their output instead of writing it (ADR 0021). Archiving an archived root changes
    nothing. Raises `AssetNotFound` unless `asset_id` is one of the org's root domains.
    """
    # A plain read: any lock here would later be upgraded by `_lock_root`, and two archives
    # holding it key-share would deadlock upgrading (same rule as persistence, ADR 0021).
    current = session.scalars(scoped(Asset, org_id).where(Asset.id == asset_id)).one_or_none()
    if current is None or current.type != AssetType.DOMAIN or current.parent_id is not None:
        raise AssetNotFound("Asset not found.")
    if not current.is_active:
        return current
    # Scan rows before the root, the order `run_check` uses (`load_job_scan`, then persistence):
    # the other order deadlocks against a worker persisting at the same moment (ADR 0021).
    cancelled = _cancel_scans(session, org_id, current.id)
    root = _lock_root(session, org_id, current.id)
    if not root.is_active:  # archived while we waited: that archive did all of this
        session.rollback()
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
        details={
            "value": root.value,
            "children": len(archived) - 1,
            "scans_cancelled": len(cancelled),
        },
    )
    for scan_id in cancelled:
        audit(
            session,
            org_id,
            "scan.cancelled",
            actor_id=actor_id,
            target_type="scan",
            target_id=str(scan_id),
            details={"reason": "root_archived"},
        )
    session.commit()
    return root


def _lock_root(session: Session, org_id: UUID, root_id: UUID) -> Asset:
    """Lock the root for `archive_root_domain`, after it has locked the root's scan rows.

    Re-reads the row: another archive may have committed while we waited for a scan row.
    Archiving an archived root changes nothing, so the caller must stop when it is inactive.
    """
    return session.scalars(
        scoped(Asset, org_id).where(Asset.id == root_id).with_for_update(),
        execution_options={"populate_existing": True},
    ).one()


def _cancel_scans(session: Session, org_id: UUID, root_id: UUID) -> Sequence[UUID]:
    """Cancel the root's queued/running scans and their unfinished jobs, without committing.

    Returned IDs are the scans cancelled by this call. Shares its statement with user
    cancellation (`services.scans.cancel_root_scans`); the lock order stays scan-then-job
    and the root lock is taken once, afterwards (ADR 0021).
    """
    return cancel_root_scans(session, org_id, root_id, job_error="Root domain was archived.")


def _scannable_hostname(raw: str) -> str:
    name = normalize_hostname(raw)  # raises InvalidAssetValue with a specific message
    try:
        return check_public_hostname(name, public_suffix.classify(name))
    except ScopeError as exc:
        raise InvalidAssetValue(str(exc)) from None


_UPSERT_CHUNK_SIZE = 500


def record_asset(
    session: Session,
    org_id: UUID,
    asset_type: AssetType,
    value: str,
    *,
    source: AssetSource,
    parent_id: UUID | None = None,
    seen_at: datetime | None = None,
    scan_id: UUID | None = None,
) -> Asset:
    """Insert the asset or, if the org already has it, mark it seen again. Doesn't commit.

    `scan_id` records which scan discovered it, so a later diff can attribute the discovery to
    that scan even when scans overlap (ADR 0027); user-added roots pass none.
    One atomic `INSERT ... ON CONFLICT`, so concurrent scans can't create duplicates.
    Re-seeing an asset never downgrades `source=user` and keeps its first parent; a user
    adding a discovered asset detaches it, since user-added assets are roots.
    Raises `InvalidAssetValue` for values that can't be normalized
    and `AssetNotFound` if `parent_id` isn't one of the org's assets.
    """
    return record_assets(
        session,
        org_id,
        ((asset_type, value),),
        source=source,
        parent_id=parent_id,
        seen_at=seen_at,
        scan_id=scan_id,
    )[0]


def record_assets(
    session: Session,
    org_id: UUID,
    assets: Sequence[tuple[AssetType, str]],
    *,
    source: AssetSource,
    parent_id: UUID | None = None,
    seen_at: datetime | None = None,
    scan_id: UUID | None = None,
) -> list[Asset]:
    """Batch version of `record_asset` sharing one parent lock check and chunked upserts."""
    if parent_id is not None and source == AssetSource.USER:
        raise InvalidAssetValue(
            "User-added assets are roots; only discovered assets have a parent."
        )
    if not assets:
        return []
    deduped: list[tuple[AssetType, str]] = []
    seen_keys: set[tuple[AssetType, str]] = set()
    for asset_type, value in assets:
        normalized = normalize_asset_value(asset_type, value)
        key = (asset_type, normalized)
        if key not in seen_keys:
            seen_keys.add(key)
            deduped.append(key)
    if parent_id is not None:
        _lock_existing_assets(session, org_id, {parent_id})
    seen = seen_at or datetime.now(UTC)
    rows_out: list[Asset] = []
    for start in range(0, len(deduped), _UPSERT_CHUNK_SIZE):
        chunk = deduped[start : start + _UPSERT_CHUNK_SIZE]
        values = [
            {
                "id": uuid7(),
                "org_id": org_id,
                "type": asset_type,
                "value": normalized,
                "source": source,
                "parent_id": parent_id,
                "first_seen": seen,
                "last_seen": seen,
                "first_seen_scan_id": scan_id,
            }
            for asset_type, normalized in chunk
        ]
        rows_out.extend(
            session.scalars(
                _asset_upsert_stmt(values), execution_options={"populate_existing": True}
            ).all()
        )
    return rows_out


def _asset_upsert_stmt(values: list[dict[str, Any]]) -> Any:
    stmt = insert(Asset).values(values)
    new = stmt.excluded
    # Only a sighting after the scan that found it gone reactivates it; delayed older results don't.
    reactivate = Asset.deactivated_at.is_(None) | (new.last_seen > Asset.deactivated_at)
    return stmt.on_conflict_do_update(
        index_elements=[Asset.org_id, Asset.type, Asset.value],
        set_={
            # greatest/least: results processed out of order never move the window backwards.
            "last_seen": func.greatest(Asset.last_seen, new.last_seen),
            "first_seen": func.least(Asset.first_seen, new.first_seen),
            "first_seen_scan_id": case(
                (new.first_seen < Asset.first_seen, new.first_seen_scan_id),
                else_=Asset.first_seen_scan_id,
            ),
            "is_active": reactivate,
            "deactivated_at": case((reactivate, null()), else_=Asset.deactivated_at),
            "source": case((Asset.source == AssetSource.USER, Asset.source), else_=new.source),
            # Never re-parented after insert, so the parent graph stays acyclic.
            "parent_id": case((new.source == AssetSource.USER, null()), else_=Asset.parent_id),
            "updated_at": func.now(),
        },
    ).returning(Asset)


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
    return record_relations(
        session, org_id, ((from_asset_id, to_asset_id, kind),), seen_at=seen_at
    )[0]


def record_relations(
    session: Session,
    org_id: UUID,
    edges: Sequence[tuple[UUID, UUID, RelationKind]],
    *,
    seen_at: datetime | None = None,
) -> list[AssetRelation]:
    """Batch version of `record_relation` sharing one endpoint lock and chunked upserts."""
    if not edges:
        return []
    deduped: list[tuple[UUID, UUID, RelationKind]] = []
    seen_keys: set[tuple[UUID, UUID, RelationKind]] = set()
    endpoints: set[UUID] = set()
    for from_asset_id, to_asset_id, kind in edges:
        if from_asset_id == to_asset_id:
            raise InvalidAssetValue("An asset can't be related to itself.")
        key = (from_asset_id, to_asset_id, kind)
        if key not in seen_keys:
            seen_keys.add(key)
            deduped.append(key)
            endpoints.add(from_asset_id)
            endpoints.add(to_asset_id)
    _lock_existing_assets(session, org_id, endpoints)
    seen = seen_at or datetime.now(UTC)
    rows_out: list[AssetRelation] = []
    for start in range(0, len(deduped), _UPSERT_CHUNK_SIZE):
        chunk = deduped[start : start + _UPSERT_CHUNK_SIZE]
        stmt = insert(AssetRelation).values(
            [
                {
                    "id": uuid7(),
                    "org_id": org_id,
                    "from_asset_id": from_asset_id,
                    "to_asset_id": to_asset_id,
                    "kind": kind,
                    "first_seen": seen,
                    "last_seen": seen,
                }
                for from_asset_id, to_asset_id, kind in chunk
            ]
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
        rows_out.extend(
            session.scalars(
                stmt.returning(AssetRelation), execution_options={"populate_existing": True}
            ).all()
        )
    return rows_out


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
