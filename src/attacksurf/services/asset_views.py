"""Read side of asset management: the asset list and detail views (no writes).

Results are frozen dataclasses, so `web/` renders and serializes them without touching ORM rows.
"""

import math
from dataclasses import dataclass
from datetime import datetime
from enum import StrEnum
from typing import Any
from uuid import UUID

from sqlalchemy import ColumnElement, Select, case, func, or_
from sqlalchemy.orm import Session, aliased

from attacksurf.domain.assets import AssetNotFound, AssetSource, AssetType, RelationKind
from attacksurf.domain.findings import (
    SEVERITY_RANK,
    Confidence,
    FindingStatus,
    Severity,
    severity_from_rank,
)
from attacksurf.domain.scans import ScanStatus, ScanTrigger
from attacksurf.infra.db.models import Asset, AssetRelation, Finding, Scan
from attacksurf.infra.db.tenancy import scoped

PAGE_SIZE = 25
MAX_FINDINGS = 200
MAX_SCANS = 50


class AssetStatus(StrEnum):
    ACTIVE = "active"
    ARCHIVED = "archived"
    ALL = "all"


@dataclass(frozen=True)
class AssetFilter:
    type: AssetType | None = None
    root_id: UUID | None = None  # the root itself and everything discovered under it
    tag: str | None = None
    q: str | None = None  # substring of the stored (punycode) value, case-insensitive
    status: AssetStatus = AssetStatus.ACTIVE


@dataclass(frozen=True)
class AssetRow:
    id: UUID
    type: AssetType
    value: str
    source: AssetSource
    root_id: UUID | None
    root_value: str | None
    tags: tuple[str, ...]
    first_seen: datetime
    last_seen: datetime
    is_active: bool
    open_findings: int
    max_severity: Severity | None  # worst open finding


@dataclass(frozen=True)
class AssetPage:
    items: tuple[AssetRow, ...]
    page: int
    pages: int
    total: int


@dataclass(frozen=True)
class RelationRow:
    kind: RelationKind
    peer_id: UUID
    peer_type: AssetType
    peer_value: str
    first_seen: datetime
    last_seen: datetime


@dataclass(frozen=True)
class AssetDetail:
    asset: AssetRow
    outgoing: tuple[RelationRow, ...]  # this asset --kind--> peer
    incoming: tuple[RelationRow, ...]  # peer --kind--> this asset
    discovered: int  # assets found under it (roots only)


@dataclass(frozen=True)
class FindingRow:
    id: UUID
    rule_id: str
    title: str
    severity: Severity
    confidence: Confidence
    status: FindingStatus
    location: str
    first_seen: datetime
    last_seen: datetime


@dataclass(frozen=True)
class ScanRow:
    id: UUID
    profile: str
    status: ScanStatus
    triggered_by: ScanTrigger
    created_at: datetime
    started_at: datetime | None
    finished_at: datetime | None


@dataclass(frozen=True)
class RootOption:
    id: UUID
    value: str
    is_active: bool


def list_assets(session: Session, org_id: UUID, flt: AssetFilter, page: int = 1) -> AssetPage:
    """One page of the org's assets, each root followed by what was discovered under it."""
    conditions = _filter_conditions(flt)
    total = session.scalar(scoped(Asset, org_id).where(*conditions).with_only_columns(func.count()))
    total = total or 0
    pages = max(1, math.ceil(total / PAGE_SIZE))
    page = min(max(page, 1), pages)
    stmt, root = _asset_rows(org_id)
    rows = session.execute(
        stmt.where(*conditions)
        .order_by(
            func.coalesce(root.value, Asset.value),
            Asset.parent_id.is_not(None),  # the root first, then its children
            Asset.value,
            Asset.type,
        )
        .limit(PAGE_SIZE)
        .offset((page - 1) * PAGE_SIZE)
    ).all()
    return AssetPage(
        items=tuple(_asset_row(*row) for row in rows), page=page, pages=pages, total=total
    )


def get_asset(session: Session, org_id: UUID, asset_id: UUID) -> AssetRow:
    """Raises `AssetNotFound` if the asset doesn't exist or belongs to another org."""
    stmt, _root = _asset_rows(org_id)
    row = session.execute(stmt.where(Asset.id == asset_id)).one_or_none()
    if row is None:
        raise AssetNotFound("Asset not found.")
    return _asset_row(*row)


def get_asset_detail(session: Session, org_id: UUID, asset_id: UUID) -> AssetDetail:
    """The asset with its relation edges in both directions. Raises `AssetNotFound`."""
    asset = get_asset(session, org_id, asset_id)
    discovered = 0
    if asset.root_id is None:
        discovered = (
            session.scalar(
                scoped(Asset, org_id)
                .where(Asset.parent_id == asset_id)
                .with_only_columns(func.count())
            )
            or 0
        )
    return AssetDetail(
        asset=asset,
        outgoing=_relations(session, org_id, asset_id, outgoing=True),
        incoming=_relations(session, org_id, asset_id, outgoing=False),
        discovered=discovered,
    )


def list_asset_findings(
    session: Session, org_id: UUID, asset_id: UUID, limit: int = MAX_FINDINGS
) -> tuple[FindingRow, ...]:
    """The asset's findings: open ones first, worst first. Raises `AssetNotFound`."""
    get_asset(session, org_id, asset_id)
    findings = session.scalars(
        scoped(Finding, org_id)
        .where(Finding.asset_id == asset_id)
        .order_by(
            Finding.status != FindingStatus.OPEN,
            _severity_rank().desc(),
            Finding.last_seen.desc(),
            Finding.id,
        )
        .limit(limit)
    ).all()
    return tuple(
        FindingRow(
            id=f.id,
            rule_id=f.rule_id,
            title=f.title,
            severity=f.severity,
            confidence=f.confidence,
            status=f.status,
            location=f.location,
            first_seen=f.first_seen,
            last_seen=f.last_seen,
        )
        for f in findings
    )


def list_asset_scans(
    session: Session, org_id: UUID, asset_id: UUID, limit: int = MAX_SCANS
) -> tuple[ScanRow, ...]:
    """Scans of the asset's root (scans always run on a root), newest first.

    Raises `AssetNotFound`.
    """
    asset = get_asset(session, org_id, asset_id)
    scans = session.scalars(
        scoped(Scan, org_id)
        .where(Scan.root_asset_id == (asset.root_id or asset.id))
        .order_by(Scan.created_at.desc(), Scan.id.desc())
        .limit(limit)
    ).all()
    return tuple(
        ScanRow(
            id=s.id,
            profile=s.profile,
            status=s.status,
            triggered_by=s.triggered_by,
            created_at=s.created_at,
            started_at=s.started_at,
            finished_at=s.finished_at,
        )
        for s in scans
    )


def list_root_domains(session: Session, org_id: UUID) -> tuple[RootOption, ...]:
    """The org's root domains (active and archived), for the list's root filter."""
    roots = session.scalars(
        scoped(Asset, org_id)
        .where(Asset.type == AssetType.DOMAIN, Asset.parent_id.is_(None))
        .order_by(Asset.value)
    ).all()
    return tuple(RootOption(id=r.id, value=r.value, is_active=r.is_active) for r in roots)


def _asset_rows(org_id: UUID) -> tuple[Select[Any], Any]:
    """Assets with their root's value and open-finding stats; returns the root alias too."""
    stats = (
        scoped(Finding, org_id)
        .where(Finding.status == FindingStatus.OPEN)
        .with_only_columns(
            Finding.asset_id,
            func.count().label("open_findings"),
            func.max(_severity_rank()).label("max_rank"),
        )
        .group_by(Finding.asset_id)
        .subquery()
    )
    root = aliased(Asset)
    stmt = (
        scoped(Asset, org_id)
        .add_columns(root.value, stats.c.open_findings, stats.c.max_rank)
        .outerjoin(root, (root.id == Asset.parent_id) & (root.org_id == org_id))
        .outerjoin(stats, stats.c.asset_id == Asset.id)
    )
    return stmt, root


def _asset_row(
    asset: Asset, root_value: str | None, open_findings: int | None, max_rank: int | None
) -> AssetRow:
    return AssetRow(
        id=asset.id,
        type=asset.type,
        value=asset.value,
        source=asset.source,
        root_id=asset.parent_id,
        root_value=root_value,
        tags=tuple(asset.tags),
        first_seen=asset.first_seen,
        last_seen=asset.last_seen,
        is_active=asset.is_active,
        open_findings=open_findings or 0,
        max_severity=severity_from_rank(max_rank),
    )


def _filter_conditions(flt: AssetFilter) -> list[ColumnElement[bool]]:
    conditions: list[ColumnElement[bool]] = []
    if flt.type is not None:
        conditions.append(Asset.type == flt.type)
    if flt.root_id is not None:
        conditions.append(or_(Asset.id == flt.root_id, Asset.parent_id == flt.root_id))
    if flt.tag:
        conditions.append(Asset.tags.contains([flt.tag]))
    if flt.q:
        conditions.append(Asset.value.ilike(f"%{_escape_like(flt.q.lower())}%", escape="\\"))
    if flt.status is AssetStatus.ACTIVE:
        conditions.append(Asset.is_active.is_(True))
    elif flt.status is AssetStatus.ARCHIVED:
        conditions.append(Asset.is_active.is_(False))
    return conditions


def _relations(
    session: Session, org_id: UUID, asset_id: UUID, *, outgoing: bool
) -> tuple[RelationRow, ...]:
    peer = aliased(Asset)
    this_end, peer_end = (
        (AssetRelation.from_asset_id, AssetRelation.to_asset_id)
        if outgoing
        else (AssetRelation.to_asset_id, AssetRelation.from_asset_id)
    )
    rows = session.execute(
        scoped(AssetRelation, org_id)
        .add_columns(peer)
        .join(peer, (peer.id == peer_end) & (peer.org_id == org_id))
        .where(this_end == asset_id)
        .order_by(AssetRelation.kind, peer.value)
    ).all()
    return tuple(
        RelationRow(
            kind=rel.kind,
            peer_id=other.id,
            peer_type=other.type,
            peer_value=other.value,
            first_seen=rel.first_seen,
            last_seen=rel.last_seen,
        )
        for rel, other in rows
    )


def _severity_rank() -> ColumnElement[int]:
    return case(SEVERITY_RANK, value=Finding.severity)


def _escape_like(text: str) -> str:
    """Make `%`, `_` and the escape character match literally in LIKE."""
    return text.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_")
