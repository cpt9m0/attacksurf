"""Read side of findings: the list, one finding's detail, exports and the dashboard (no writes).

Results are frozen dataclasses, so `web/` renders and serializes them without touching ORM rows.
Evidence is untrusted scanner data: this module only shapes it, the templates always escape it.
"""

import json
import math
from dataclasses import dataclass
from datetime import datetime
from enum import StrEnum
from typing import Any
from uuid import UUID

from sqlalchemy import ColumnElement, case, func, or_
from sqlalchemy.orm import Session, aliased

from attacksurf.ai.schemas import StoredTriage
from attacksurf.domain.assets import AssetType
from attacksurf.domain.findings import (
    ACTIVE_STATUSES,
    MAX_STATUS_COMMENT,
    SEVERITY_RANK,
    Confidence,
    EvidenceKind,
    FindingNotFound,
    FindingStatus,
    Severity,
)
from attacksurf.domain.rules import RULES
from attacksurf.domain.scans import ScanStatus
from attacksurf.infra.db.models import (
    Asset,
    AuditLog,
    Evidence,
    Finding,
    FindingObservation,
    Scan,
    User,
)
from attacksurf.infra.db.tenancy import scoped
from attacksurf.services import asset_views
from attacksurf.services.asset_views import RootOption
from attacksurf.services.triage import stored_triage, triage_is_stale

PAGE_SIZE = 25
EXPORT_LIMIT = 5_000
MAX_EVIDENCE = 20
MAX_EVIDENCE_TEXT = 4_096
MAX_EVIDENCE_VALUES = 100
MAX_FIELD_TEXT = 512
MAX_EVENTS = 50
MAX_DASHBOARD_FINDINGS = 5
MAX_DASHBOARD_ROOTS = 8

_SEVERITY_ORDER = (
    Severity.CRITICAL,
    Severity.HIGH,
    Severity.MEDIUM,
    Severity.LOW,
    Severity.INFO,
)

_ACTION_LABELS = {
    "finding.accepted_risk": "Accepted risk",
    "finding.false_positive": "Marked false positive",
    "finding.reopened": "Reopened",
}


class FindingStatusFilter(StrEnum):
    """The list's status filter: the two live states, one exact status, or everything."""

    ACTIVE = "active"
    OPEN = "open"
    FIXED = "fixed"
    REGRESSED = "regressed"
    ACCEPTED_RISK = "accepted_risk"
    FALSE_POSITIVE = "false_positive"
    ALL = "all"


class FindingSort(StrEnum):
    SEVERITY = "severity"  # worst first
    LAST_SEEN = "last_seen"  # most recently observed first


@dataclass(frozen=True)
class FindingFilter:
    severity: Severity | None = None
    status: FindingStatusFilter = FindingStatusFilter.ACTIVE
    rule_id: str | None = None
    asset: str | None = None  # substring of the asset's stored value
    root_id: UUID | None = None  # the root itself and everything discovered under it
    new_since_last_scan: bool = False
    sort: FindingSort = FindingSort.SEVERITY


@dataclass(frozen=True)
class FindingRow:
    id: UUID
    rule_id: str
    title: str
    severity: Severity
    confidence: Confidence
    status: FindingStatus
    location: str
    asset_id: UUID
    asset_type: AssetType
    asset_value: str
    root_id: UUID | None  # None when the asset is a root itself
    root_value: str
    first_seen: datetime
    last_seen: datetime
    fixed_at: datetime | None
    scanner: str | None


@dataclass(frozen=True)
class FindingPage:
    items: tuple[FindingRow, ...]
    page: int
    pages: int
    total: int
    # What "new since last scan" compared against, so the UI can name the scan.
    latest_scan_id: UUID | None = None
    latest_scan_at: datetime | None = None


@dataclass(frozen=True)
class RuleOption:
    id: str
    title: str


@dataclass(frozen=True)
class FindingFilterOptions:
    roots: tuple[RootOption, ...]
    rules: tuple[RuleOption, ...]


@dataclass(frozen=True)
class EvidenceField:
    label: str
    value: str


@dataclass(frozen=True)
class EvidenceRow:
    id: UUID
    kind: EvidenceKind
    title: str
    fields: tuple[EvidenceField, ...]
    body: str | None
    truncated: bool
    captured_at: datetime


@dataclass(frozen=True)
class FindingEvent:
    action: str  # human label, not the audit action name
    actor: str | None  # email, when the user still exists
    at: datetime
    comment: str | None


@dataclass(frozen=True)
class FindingDetail:
    finding: FindingRow
    description: str
    remediation: str
    references: tuple[str, ...]
    ai_triage: StoredTriage | None  # None when untriaged or written by an older version
    ai_triage_stale: bool  # the finding changed since the judgment: shown, marked outdated
    evidence: tuple[EvidenceRow, ...]
    evidence_total: int
    events: tuple[FindingEvent, ...]
    observations: int


@dataclass(frozen=True)
class FindingExport:
    items: tuple[FindingRow, ...]
    truncated: bool  # more matched than `EXPORT_LIMIT`; `items` holds the first page


@dataclass(frozen=True)
class SeverityCount:
    severity: Severity
    count: int


@dataclass(frozen=True)
class RootScanRow:
    root_id: UUID
    root_value: str
    scan_id: UUID | None
    scan_status: ScanStatus | None
    scan_at: datetime | None
    scan_finished: datetime | None


@dataclass(frozen=True)
class DashboardData:
    open_findings: int
    by_severity: tuple[SeverityCount, ...]
    newest: tuple[FindingRow, ...]
    active_assets: int
    roots: tuple[RootScanRow, ...]


def list_findings(session: Session, org_id: UUID, flt: FindingFilter, page: int = 1) -> FindingPage:
    """One page of findings, worst first or newest observation first. Filters combine."""
    asset, root, conditions = _conditions(org_id, flt)
    latest_scan_id, latest_scan_at = (
        _latest_scan(session, org_id, flt.root_id) if flt.new_since_last_scan else (None, None)
    )
    if flt.new_since_last_scan:
        if latest_scan_id is None:
            # No completed scan to be "new since": an honest empty result, not an error.
            return FindingPage((), 1, 1, 0)
        conditions = [*conditions, Finding.first_seen_scan_id == latest_scan_id]
    total = (
        session.scalar(
            _query(org_id, asset, root).where(*conditions).with_only_columns(func.count(Finding.id))
        )
        or 0
    )
    pages = max(1, math.ceil(total / PAGE_SIZE))
    page = min(max(page, 1), pages)
    rows = session.execute(
        _query(org_id, asset, root)
        .where(*conditions)
        .order_by(*_order(flt.sort))
        .limit(PAGE_SIZE)
        .offset((page - 1) * PAGE_SIZE)
    ).all()
    return FindingPage(
        items=tuple(_finding_row(row) for row in rows),
        page=page,
        pages=pages,
        total=total,
        latest_scan_id=latest_scan_id,
        latest_scan_at=latest_scan_at,
    )


def list_filter_options(session: Session, org_id: UUID) -> FindingFilterOptions:
    """Root domains and the rule catalog for the filter selects (rules are code-defined)."""
    return FindingFilterOptions(
        roots=asset_views.list_root_domains(session, org_id),
        rules=tuple(
            RuleOption(id=rule.id, title=rule.title)
            for rule in sorted(RULES.values(), key=lambda item: item.id)
        ),
    )


def get_finding_detail(session: Session, org_id: UUID, finding_id: UUID) -> FindingDetail:
    """One finding with bounded evidence and its status decisions. Raises `FindingNotFound`."""
    asset, root, _ = _conditions(org_id, FindingFilter(status=FindingStatusFilter.ALL))
    row = session.execute(_query(org_id, asset, root).where(Finding.id == finding_id)).one_or_none()
    if row is None:
        raise FindingNotFound("Finding not found.")
    finding = row[0]
    evidence = session.scalars(
        scoped(Evidence, org_id)
        .where(Evidence.finding_id == finding_id)
        .order_by(Evidence.captured_at.desc(), Evidence.id.desc())
        .limit(MAX_EVIDENCE)
    ).all()
    evidence_total = (
        session.scalar(
            scoped(Evidence, org_id)
            .where(Evidence.finding_id == finding_id)
            .with_only_columns(func.count(Evidence.id))
        )
        or 0
    )
    observations = (
        session.scalar(
            scoped(FindingObservation, org_id)
            .where(FindingObservation.finding_id == finding_id)
            .with_only_columns(func.count(FindingObservation.id))
        )
        or 0
    )
    events = session.execute(
        scoped(AuditLog, org_id)
        .add_columns(User.email)
        .outerjoin(User, User.id == AuditLog.actor_user_id)
        .where(AuditLog.target_type == "finding", AuditLog.target_id == str(finding_id))
        # Newest first, so a long history keeps the recent decisions; the timeline reverses it.
        .order_by(AuditLog.created_at.desc(), AuditLog.id.desc())
        .limit(MAX_EVENTS)
    ).all()
    triage = stored_triage(finding)
    return FindingDetail(
        finding=_finding_row(row),
        description=finding.description,
        remediation=finding.remediation,
        references=tuple(finding.references),
        ai_triage=triage,
        ai_triage_stale=triage is not None and triage_is_stale(finding, triage),
        evidence=tuple(_evidence_row(item) for item in evidence),
        evidence_total=evidence_total,
        events=tuple(
            FindingEvent(
                action=_ACTION_LABELS.get(entry.action or "", entry.action or "Status change"),
                actor=email,
                at=entry.created_at,
                comment=_comment(entry.details),
            )
            for entry, email in reversed(events)
        ),
        observations=observations,
    )


def export_findings(session: Session, org_id: UUID, flt: FindingFilter) -> FindingExport:
    """Every matching finding up to the export cap, worst first, for a file download."""
    asset, root, conditions = _conditions(org_id, flt)
    if flt.new_since_last_scan:
        latest_scan_id, _ = _latest_scan(session, org_id, flt.root_id)
        if latest_scan_id is None:
            return FindingExport((), False)
        conditions = [*conditions, Finding.first_seen_scan_id == latest_scan_id]
    rows = session.execute(
        _query(org_id, asset, root)
        .where(*conditions)
        .order_by(*_order(FindingSort.SEVERITY), Finding.id)
        .limit(EXPORT_LIMIT + 1)
    ).all()
    truncated = len(rows) > EXPORT_LIMIT
    return FindingExport(
        items=tuple(_finding_row(row) for row in rows[:EXPORT_LIMIT]), truncated=truncated
    )


def get_dashboard(session: Session, org_id: UUID) -> DashboardData:
    """Open findings by severity, the newest ones, the asset count and each root's last scan."""
    counts = dict(
        session.execute(
            scoped(Finding, org_id)
            .where(Finding.status.in_(tuple(ACTIVE_STATUSES)))
            .with_only_columns(Finding.severity, func.count())
            .group_by(Finding.severity)
        ).all()
    )
    by_severity = tuple(
        SeverityCount(severity=severity, count=counts.get(severity, 0))
        for severity in _SEVERITY_ORDER
    )
    active_assets = (
        session.scalar(
            scoped(Asset, org_id)
            .where(Asset.is_active.is_(True))
            .with_only_columns(func.count(Asset.id))
        )
        or 0
    )
    asset, root, _ = _conditions(org_id, FindingFilter(status=FindingStatusFilter.ALL))
    newest_rows = session.execute(
        _query(org_id, asset, root)
        .where(Finding.status.in_(tuple(ACTIVE_STATUSES)))
        .order_by(
            Finding.first_seen.desc(),
            case(SEVERITY_RANK, value=Finding.severity).desc(),
            Finding.id.desc(),
        )
        .limit(MAX_DASHBOARD_FINDINGS)
    ).all()
    latest = (
        scoped(Scan, org_id)
        .with_only_columns(
            Scan.root_asset_id,
            Scan.id.label("scan_id"),
            Scan.status.label("scan_status"),
            Scan.created_at.label("scan_at"),
            Scan.finished_at.label("scan_finished"),
            func.row_number()
            .over(
                partition_by=Scan.root_asset_id,
                order_by=(Scan.created_at.desc(), Scan.id.desc()),
            )
            .label("rank"),
        )
        .subquery()
    )
    root_rows = session.execute(
        scoped(Asset, org_id)
        .add_columns(
            latest.c.scan_id, latest.c.scan_status, latest.c.scan_at, latest.c.scan_finished
        )
        .outerjoin(latest, (latest.c.root_asset_id == Asset.id) & (latest.c.rank == 1))
        .where(
            Asset.type == AssetType.DOMAIN,
            Asset.parent_id.is_(None),
            Asset.is_active.is_(True),
        )
        .order_by(latest.c.scan_at.desc().nulls_last(), Asset.value)
        .limit(MAX_DASHBOARD_ROOTS)
    ).all()
    return DashboardData(
        open_findings=sum(item.count for item in by_severity),
        by_severity=by_severity,
        newest=tuple(_finding_row(row) for row in newest_rows),
        active_assets=active_assets,
        roots=tuple(
            RootScanRow(
                root_id=asset_row.id,
                root_value=asset_row.value,
                scan_id=scan_id,
                scan_status=scan_status,
                scan_at=scan_at,
                scan_finished=scan_finished,
            )
            for asset_row, scan_id, scan_status, scan_at, scan_finished in root_rows
        ),
    )


def _conditions(org_id: UUID, flt: FindingFilter) -> tuple[Any, Any, list[ColumnElement[bool]]]:
    """The asset/root aliases plus the filter predicates that need them."""
    asset = aliased(Asset)
    root = aliased(Asset)
    conditions: list[ColumnElement[bool]] = []
    if flt.severity is not None:
        conditions.append(Finding.severity == flt.severity)
    if flt.status is FindingStatusFilter.ACTIVE:
        conditions.append(Finding.status.in_(tuple(ACTIVE_STATUSES)))
    elif flt.status is not FindingStatusFilter.ALL:
        conditions.append(Finding.status == FindingStatus(flt.status.value))
    if flt.rule_id:
        conditions.append(Finding.rule_id == flt.rule_id)
    if flt.asset:
        conditions.append(asset.value.ilike(f"%{_escape_like(flt.asset)}%", escape="\\"))
    if flt.root_id is not None:
        # Discovery attaches new assets to the scan root (ADR 0025), so two cases cover it.
        conditions.append(or_(asset.id == flt.root_id, asset.parent_id == flt.root_id))
    return asset, root, conditions


def _query(org_id: UUID, asset: Any, root: Any) -> Any:
    """Findings joined to their asset and root; both joins are org-scoped too."""
    return (
        scoped(Finding, org_id)
        .add_columns(asset.value, asset.type, asset.parent_id, root.value)
        .join(asset, (asset.id == Finding.asset_id) & (asset.org_id == org_id))
        .outerjoin(root, (root.id == asset.parent_id) & (root.org_id == org_id))
    )


def _finding_row(row: Any) -> FindingRow:
    finding, asset_value, asset_type, parent_id, root_value = row
    return FindingRow(
        id=finding.id,
        rule_id=finding.rule_id,
        title=finding.title,
        severity=finding.severity,
        confidence=finding.confidence,
        status=finding.status,
        location=finding.location,
        asset_id=finding.asset_id,
        asset_type=asset_type,
        asset_value=asset_value,
        root_id=parent_id,
        root_value=root_value or asset_value,
        first_seen=finding.first_seen,
        last_seen=finding.last_seen,
        fixed_at=finding.fixed_at,
        scanner=finding.scanner,
    )


def _order(sort: FindingSort) -> tuple[Any, ...]:
    severity = case(SEVERITY_RANK, value=Finding.severity).desc()
    if sort is FindingSort.SEVERITY:
        return (severity, Finding.last_seen.desc(), Finding.id)
    return (Finding.last_seen.desc(), severity, Finding.id)


def _latest_scan(
    session: Session, org_id: UUID, root_id: UUID | None
) -> tuple[UUID | None, datetime | None]:
    """The root's (or the org's) latest completed scan, the yardstick for "new"."""
    conditions = [Scan.status == ScanStatus.COMPLETED]
    if root_id is not None:
        conditions.append(Scan.root_asset_id == root_id)
    row = session.execute(
        scoped(Scan, org_id)
        .add_columns(Scan.id, Scan.finished_at, Scan.created_at)
        .where(*conditions)
        .order_by(Scan.finished_at.desc().nulls_last(), Scan.created_at.desc(), Scan.id.desc())
        .limit(1)
    ).one_or_none()
    if row is None:
        return None, None
    _, scan_id, finished_at, created_at = row
    return scan_id, finished_at or created_at


def _evidence_row(evidence: Evidence) -> EvidenceRow:
    """Normalize one JSONB evidence blob into escaped-template-friendly fields."""
    data = evidence.data if isinstance(evidence.data, dict) else {}
    kind = evidence.kind
    if kind is EvidenceKind.DNS_RECORD:
        record = _text(data.get("record"), 64)
        name = _text(data.get("name"), MAX_FIELD_TEXT)
        status = _text(data.get("status"), 64)
        records = _text_list(data.get("records"))
        values = _text_list(data.get("values"))
        fields = ([] if not name else [EvidenceField("Name", name)]) + (
            [] if not status else [EvidenceField("Status", status)]
        )
        lines = records or values
        if not lines:
            address = _text(data.get("value"), MAX_FIELD_TEXT)
            if address:
                lines = [address]
        chain = _text_list(data.get("cname_chain"))
        if chain:
            lines.append(f"CNAME chain: {' → '.join(chain)}")
        body = "\n".join(lines)
        title = f"{record} record" if record else "DNS record"
    elif kind is EvidenceKind.HTTP_RESPONSE:
        url = _text(data.get("url"), MAX_FIELD_TEXT)
        status_code = _text(data.get("status_code"), 32)
        fields = []
        if url:
            fields.append(EvidenceField("URL", url))
        if status_code:
            fields.append(EvidenceField("Status", status_code))
        raw_headers = data.get("headers")
        header_lines = (
            [f"{k}: {_text(v, MAX_FIELD_TEXT)}" for k, v in raw_headers.items()]
            if isinstance(raw_headers, dict)
            else []
        )
        snippet = _text(data.get("body_snippet"), MAX_EVIDENCE_TEXT)
        body = "\n".join([*header_lines, "", snippet]).strip() if header_lines else snippet
        title = "HTTP response"
    else:
        fields = []
        body = json.dumps(data, indent=2, sort_keys=True, ensure_ascii=False, default=str)
        title = "Raw evidence"
    body, truncated = _truncate(body, MAX_EVIDENCE_TEXT)
    return EvidenceRow(
        id=evidence.id,
        kind=kind,
        title=title,
        fields=tuple(fields),
        body=body or None,
        truncated=truncated,
        captured_at=evidence.captured_at,
    )


def _text(value: object, limit: int) -> str:
    text = value if isinstance(value, str) else ("" if value is None else str(value))
    return _truncate(text, limit)[0]


def _text_list(value: object) -> list[str]:
    if not isinstance(value, list):
        return []
    return [_text(item, MAX_FIELD_TEXT) for item in value[:MAX_EVIDENCE_VALUES]]


def _truncate(text: str, limit: int) -> tuple[str, bool]:
    return (text, False) if len(text) <= limit else (text[:limit], True)


def _comment(details: object) -> str | None:
    if not isinstance(details, dict):
        return None
    comment = details.get("comment")
    if not isinstance(comment, str) or not comment.strip():
        return None
    return _text(comment, MAX_STATUS_COMMENT)


def _escape_like(text: str) -> str:
    """Make `%`, `_` and the escape character match literally in LIKE."""
    return text.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_")
