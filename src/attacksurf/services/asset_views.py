"""Read side of asset management: the asset list and detail views (no writes).

Results are frozen dataclasses, so `web/` renders and serializes them without touching ORM rows.
"""

import math
from dataclasses import dataclass
from datetime import UTC, datetime
from enum import StrEnum
from typing import Any
from urllib.parse import urlsplit
from uuid import UUID

import idna
from sqlalchemy import ColumnElement, Select, case, exists, func, or_, select
from sqlalchemy.orm import Session, aliased

from attacksurf.domain.assets import AssetNotFound, AssetSource, AssetType, RelationKind
from attacksurf.domain.findings import (
    ACTIVE_STATUSES,
    SEVERITY_RANK,
    Confidence,
    FindingStatus,
    Severity,
    severity_from_rank,
)
from attacksurf.domain.scans import ScanStatus, ScanTrigger
from attacksurf.domain.verification import OwnershipState, VerificationStatus, ownership_state
from attacksurf.infra.db.models import Asset, AssetRelation, Finding, Scan, Verification
from attacksurf.infra.db.tenancy import scoped

PAGE_SIZE = 25
MAX_FINDINGS = 200
MAX_SCANS = 50
MAX_DETAIL_RECORDS = 20
MAX_DETAIL_LENGTH = 512
_SECURITY_HEADER_CHECKS = (
    ("hsts", "HSTS"),
    ("csp", "Content-Security-Policy"),
    ("clickjacking_protected", "Clickjacking protection"),
    ("nosniff", "X-Content-Type-Options"),
    ("redirects_to_https", "HTTPS redirect"),
)
_DNS_FIELDS = (
    ("a", "A"),
    ("aaaa", "AAAA"),
    ("cname", "CNAME"),
    ("mx", "MX"),
    ("ns", "NS"),
    ("txt", "TXT"),
    ("caa", "CAA"),
    ("soa", "SOA"),
)


class AssetStatus(StrEnum):
    ACTIVE = "active"
    ARCHIVED = "archived"
    ALL = "all"


@dataclass(frozen=True)
class AssetFilter:
    type: AssetType | None = None
    root_id: UUID | None = None  # the root itself and everything discovered under it
    tag: str | None = None
    tech: str | None = None
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
    verification: OwnershipState  # expired while the row still says verified is shown as such


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
class DnsRecordRow:
    type: str
    values: tuple[str, ...]


@dataclass(frozen=True)
class DnsDetails:
    chain: tuple[str, ...]  # asset -> CNAME hops -> A/AAAA, for display
    records: tuple[DnsRecordRow, ...]
    private_ips: tuple[str, ...]


@dataclass(frozen=True)
class IpDetails:
    ptr: str | None
    asn: int | None
    org: str | None
    country: str | None


@dataclass(frozen=True)
class RedirectHop:
    url: str
    status: int


@dataclass(frozen=True)
class WebDetails:
    status_code: int | None
    title: str | None
    final_url: str | None
    content_type: str | None
    redirect_chain: tuple[RedirectHop, ...]
    redirect_stopped_out_of_scope: bool


@dataclass(frozen=True)
class TechnologyView:
    name: str
    version: str | None
    categories: tuple[str, ...]
    confidence: int | None


@dataclass(frozen=True)
class TlsDetails:
    protocol: str | None
    cipher: str | None
    issuer: str | None
    subject: str | None
    not_before: str | None
    not_after: str | None
    trusted_chain: bool | None
    hostname_matches: bool | None
    error_code: str | None
    key_type: str | None
    key_size: int | None
    legacy_protocols_accepted: tuple[str, ...]


@dataclass(frozen=True)
class HeaderCheckRow:
    key: str
    label: str
    passed: bool | None


@dataclass(frozen=True)
class AssetDetail:
    asset: AssetRow
    outgoing: tuple[RelationRow, ...]  # this asset --kind--> peer
    incoming: tuple[RelationRow, ...]  # peer --kind--> this asset
    discovered: int  # assets found under it (roots only)
    dns: DnsDetails | None = None
    ip: IpDetails | None = None
    uploaded_as: str | None = None  # the uploader's file name: display only, always escaped
    web: WebDetails | None = None
    technologies: tuple[TechnologyView, ...] = ()
    tls: TlsDetails | None = None
    security_headers: tuple[HeaderCheckRow, ...] = ()


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
        items=tuple(_asset_row(row) for row in rows),
        page=page,
        pages=pages,
        total=total,
    )


def get_asset(session: Session, org_id: UUID, asset_id: UUID) -> AssetRow:
    """Raises `AssetNotFound` if the asset doesn't exist or belongs to another org."""
    stmt, _root = _asset_rows(org_id)
    row = session.execute(stmt.where(Asset.id == asset_id)).one_or_none()
    if row is None:
        raise AssetNotFound("Asset not found.")
    return _asset_row(row)


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
    details = session.scalar(
        scoped(Asset, org_id).where(Asset.id == asset_id).with_only_columns(Asset.details)
    )
    if details is None:
        raise AssetNotFound("Asset not found.")
    return AssetDetail(
        asset=asset,
        outgoing=_relations(session, org_id, asset_id, outgoing=True),
        incoming=_relations(session, org_id, asset_id, outgoing=False),
        discovered=discovered,
        dns=_dns_details(details, asset.value),
        ip=_ip_details(details),
        uploaded_as=_uploaded_as(details),
        web=_web_details(details),
        technologies=_technologies(details),
        tls=_tls_details(details),
        security_headers=_security_header_rows(details),
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
            Finding.status.not_in(tuple(ACTIVE_STATUSES)),
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


def list_technologies(session: Session, org_id: UUID) -> tuple[str, ...]:
    """Distinct fingerprinted technology names across the org's assets, sorted cleanly."""
    names: set[str] = set()
    rows = session.scalars(
        scoped(Asset, org_id)
        .where(func.jsonb_typeof(Asset.details["technologies"]) == "array")
        .with_only_columns(Asset.details["technologies"])
    ).all()
    for raw_list in rows:
        if not isinstance(raw_list, list):
            continue
        for item in raw_list:
            if isinstance(item, dict):
                raw_name = item.get("name")
                if isinstance(raw_name, str) and raw_name.strip():
                    names.add(raw_name.strip()[:MAX_DETAIL_LENGTH])
    return tuple(sorted(names, key=str.casefold))


def _asset_rows(org_id: UUID) -> tuple[Select[Any], Any]:
    """Assets with their root's value and open-finding stats; returns the root alias too."""
    proofs = (
        scoped(Verification, org_id)
        .with_only_columns(Verification.asset_id, Verification.status, Verification.expires_at)
        .subquery()
    )
    parent_proofs = (
        scoped(Verification, org_id)
        .with_only_columns(Verification.asset_id, Verification.status, Verification.expires_at)
        .subquery()
    )
    stats = (
        scoped(Finding, org_id)
        .where(Finding.status.in_(tuple(ACTIVE_STATUSES)))
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
        .add_columns(
            root.value,
            stats.c.open_findings,
            stats.c.max_rank,
            proofs.c.status,
            proofs.c.expires_at,
            root.type,
            root.is_active,
            parent_proofs.c.status,
            parent_proofs.c.expires_at,
        )
        .outerjoin(root, (root.id == Asset.parent_id) & (root.org_id == org_id))
        .outerjoin(stats, stats.c.asset_id == Asset.id)
        .outerjoin(proofs, proofs.c.asset_id == Asset.id)
        .outerjoin(parent_proofs, parent_proofs.c.asset_id == Asset.parent_id)
    )
    return stmt, root


def _url_host_matches_root(url: str, root_value: str | None) -> bool:
    if not root_value:
        return False
    raw_host = urlsplit(url).hostname
    if not raw_host:
        return False
    try:
        host = idna.encode(raw_host.removesuffix("."), uts46=True).decode("ascii").lower()
    except idna.IDNAError:
        return False
    return host == root_value or host.endswith(f".{root_value}")


def _asset_verification(
    asset: Asset,
    *,
    now: datetime,
    verification: VerificationStatus | None,
    expires_at: datetime | None,
    root_value: str | None,
    root_type: AssetType | None,
    root_active: bool | None,
    parent_verification: VerificationStatus | None,
    parent_expires_at: datetime | None,
) -> OwnershipState:
    if asset.type is AssetType.URL:
        if (
            asset.is_active
            and asset.parent_id is not None
            and root_type == AssetType.DOMAIN
            and root_active is True
            and _url_host_matches_root(asset.value, root_value)
        ):
            return ownership_state(parent_verification, parent_expires_at, now)
        return OwnershipState.NONE
    return ownership_state(verification, expires_at, now)


def _asset_row(row: Any) -> AssetRow:
    (
        asset,
        root_value,
        open_findings,
        max_rank,
        verification,
        expires_at,
        root_type,
        root_active,
        parent_verification,
        parent_expires_at,
    ) = row
    now = datetime.now(UTC)
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
        verification=_asset_verification(
            asset,
            now=now,
            verification=verification,
            expires_at=expires_at,
            root_value=root_value,
            root_type=root_type,
            root_active=root_active,
            parent_verification=parent_verification,
            parent_expires_at=parent_expires_at,
        ),
    )


def _filter_conditions(flt: AssetFilter) -> list[ColumnElement[bool]]:
    conditions: list[ColumnElement[bool]] = []
    if flt.type is not None:
        conditions.append(Asset.type == flt.type)
    if flt.root_id is not None:
        conditions.append(or_(Asset.id == flt.root_id, Asset.parent_id == flt.root_id))
    if flt.tag:
        conditions.append(Asset.tags.contains([flt.tag]))
    if flt.tech:
        tech_el = (
            func.jsonb_array_elements(Asset.details["technologies"])
            .table_valued("value")
            .alias("tech_el")
        )
        conditions.append(
            (func.jsonb_typeof(Asset.details["technologies"]) == "array")
            & exists(
                select(1)
                .select_from(tech_el)
                .where(func.lower(tech_el.c.value.op("->>")("name")) == flt.tech.lower())
            )
        )
    if flt.q:
        conditions.append(Asset.value.ilike(f"%{_escape_like(flt.q.lower())}%", escape="\\"))
    if flt.status is AssetStatus.ACTIVE:
        conditions.append(Asset.is_active.is_(True))
    elif flt.status is AssetStatus.ARCHIVED:
        conditions.append(Asset.is_active.is_(False))
    return conditions


def _dns_details(details: Any, asset_value: str) -> DnsDetails | None:
    raw = details.get("dns") if isinstance(details, dict) else None
    if not isinstance(raw, dict):
        return None
    records: list[DnsRecordRow] = []
    by_key: dict[str, tuple[str, ...]] = {}
    for key, label in _DNS_FIELDS:
        values = _detail_values(raw.get(key))
        if values:
            by_key[key] = values
            records.append(DnsRecordRow(type=label, values=values))
    chain = _detail_values(raw.get("cname_chain"))
    addresses = (*by_key.get("a", ()), *by_key.get("aaaa", ()))
    private = _detail_values(raw.get("private_ips"))
    if not records and not chain and not addresses and not private:
        return None
    if not chain or chain[0] != asset_value:
        chain = (asset_value, *chain)
    display = tuple(dict.fromkeys((*chain, *addresses)))
    return DnsDetails(chain=display, records=tuple(records), private_ips=private)


def _uploaded_as(details: Any) -> str | None:
    """The file name a repo archive or binary was last uploaded under (#87, #101)."""
    upload = details.get("upload") if isinstance(details, dict) else None
    name = upload.get("filename") if isinstance(upload, dict) else None
    return name if isinstance(name, str) and name else None


def _ip_details(details: Any) -> IpDetails | None:
    raw = details.get("ip") if isinstance(details, dict) else None
    if not isinstance(raw, dict):
        return None
    ptr = _detail_text(raw.get("ptr"))
    org = _detail_text(raw.get("org"))
    country = _detail_text(raw.get("country"))
    asn = raw.get("asn")
    number = asn if isinstance(asn, int) and not isinstance(asn, bool) else None
    if ptr is None and org is None and country is None and number is None:
        return None
    return IpDetails(ptr=ptr, asn=number, org=org, country=country)


def _detail_int(value: Any) -> int | None:
    return value if isinstance(value, int) and not isinstance(value, bool) else None


def _detail_bool(value: Any) -> bool | None:
    return value if isinstance(value, bool) else None


def _web_details(details: Any) -> WebDetails | None:
    raw = details.get("web") if isinstance(details, dict) else None
    if not isinstance(raw, dict):
        return None
    status_code = _detail_int(raw.get("status_code"))
    title = _detail_text(raw.get("title"))
    final_url = _detail_text(raw.get("final_url"))
    content_type = _detail_text(raw.get("content_type"))
    stopped_oos = raw.get("redirect_stopped_out_of_scope") is True
    chain_items: list[RedirectHop] = []
    raw_chain = raw.get("redirect_chain")
    if isinstance(raw_chain, list):
        for hop in raw_chain[:MAX_DETAIL_RECORDS]:
            if isinstance(hop, dict):
                hop_url = _detail_text(hop.get("url"))
                hop_status = _detail_int(hop.get("status"))
                if hop_url is not None and hop_status is not None:
                    chain_items.append(RedirectHop(url=hop_url, status=hop_status))
    if (
        status_code is None
        and title is None
        and final_url is None
        and content_type is None
        and not chain_items
        and not stopped_oos
    ):
        return None
    return WebDetails(
        status_code=status_code,
        title=title,
        final_url=final_url,
        content_type=content_type,
        redirect_chain=tuple(chain_items),
        redirect_stopped_out_of_scope=stopped_oos,
    )


def _technologies(details: Any) -> tuple[TechnologyView, ...]:
    raw = details.get("technologies") if isinstance(details, dict) else None
    if not isinstance(raw, list):
        return ()
    techs: list[TechnologyView] = []
    for item in raw:
        if not isinstance(item, dict):
            continue
        name = _detail_text(item.get("name"))
        if name is None:
            continue
        techs.append(
            TechnologyView(
                name=name,
                version=_detail_text(item.get("version")),
                categories=_detail_values(item.get("categories")),
                confidence=_detail_int(item.get("confidence")),
            )
        )
    return tuple(techs)


def _tls_details(details: Any) -> TlsDetails | None:
    raw = details.get("tls") if isinstance(details, dict) else None
    if not isinstance(raw, dict):
        return None
    protocol = _detail_text(raw.get("protocol"))
    cipher = _detail_text(raw.get("cipher"))
    issuer = _detail_text(raw.get("issuer"))
    subject = _detail_text(raw.get("subject"))
    not_before = _detail_text(raw.get("not_before"))
    not_after = _detail_text(raw.get("not_after"))
    trusted_chain = _detail_bool(raw.get("trusted_chain"))
    hostname_matches = _detail_bool(raw.get("hostname_matches"))
    error_code = _detail_text(raw.get("error_code"))
    key_type = _detail_text(raw.get("key_type"))
    key_size = _detail_int(raw.get("key_size"))
    legacy = _detail_values(raw.get("legacy_protocols_accepted"))
    if (
        protocol is None
        and cipher is None
        and issuer is None
        and subject is None
        and not_after is None
        and trusted_chain is None
        and hostname_matches is None
        and error_code is None
        and not legacy
    ):
        return None
    return TlsDetails(
        protocol=protocol,
        cipher=cipher,
        issuer=issuer,
        subject=subject,
        not_before=not_before,
        not_after=not_after,
        trusted_chain=trusted_chain,
        hostname_matches=hostname_matches,
        error_code=error_code,
        key_type=key_type,
        key_size=key_size,
        legacy_protocols_accepted=legacy,
    )


def _security_header_rows(details: Any) -> tuple[HeaderCheckRow, ...]:
    raw = details.get("security_headers") if isinstance(details, dict) else None
    if not isinstance(raw, dict):
        return ()
    rows = [
        HeaderCheckRow(key=key, label=label, passed=_detail_bool(raw.get(key)))
        for key, label in _SECURITY_HEADER_CHECKS
    ]
    if all(row.passed is None for row in rows):
        return ()
    return tuple(rows)


def _detail_values(value: Any) -> tuple[str, ...]:
    if not isinstance(value, list):
        return ()
    result: list[str] = []
    for item in value:
        text = _detail_text(item)
        if text is not None:
            result.append(text)
        if len(result) >= MAX_DETAIL_RECORDS:
            break
    return tuple(result)


def _detail_text(value: Any) -> str | None:
    if not isinstance(value, str):
        return None
    text = value.strip()
    return text[:MAX_DETAIL_LENGTH] or None


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
