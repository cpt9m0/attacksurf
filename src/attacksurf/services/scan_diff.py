"""Finding lifecycle diff and scan stats: fixed, regressed, new assets (ADR 0027).

Runs after every scanner result is committed (`persist` barrier) and before `finalize`. A
finding is never fixed just because it is missing from this scan: its own scanner must have
completed for its asset here, so a failed, skipped or unplanned check proves nothing (ADR 0011).
"""

from collections.abc import Iterable, Sequence
from datetime import datetime
from uuid import UUID

from sqlalchemy import Row, func, select, update
from sqlalchemy.orm import InstrumentedAttribute, Session

from attacksurf.domain.assets import AssetType
from attacksurf.domain.events import EventDispatcher, FindingFixed, FindingRegressed
from attacksurf.domain.findings import ACTIVE_STATUSES, FindingStatus, Severity
from attacksurf.domain.scans import JobStatus, ScanStatus
from attacksurf.infra.db.models import Asset, Finding, Job, Scan
from attacksurf.infra.db.tenancy import scoped
from attacksurf.services.audit import audit
from attacksurf.services.scans import TERMINAL, load_job_scan, root_is_active

# Caps the asset list stored per bucket; `total` always holds the real count.
MAX_STATS_ASSETS = 1000
_SCANNER_STAGES = ("discovery", "check")


def diff_scan(session: Session, org_id: UUID, job_id: UUID, events: EventDispatcher) -> None:
    """Record this scan's finding/asset changes in `Scan.stats`, commit, then publish events.

    A finding observed again that was `fixed` comes back as `regressed`. An `open`/`regressed`
    finding is fixed only when its scanner completed for its asset in this scan. Suppressed
    findings are never auto-fixed. Replay-safe: once the stats hold a diff, a redelivery
    changes nothing (the job row may not have been marked completed before a crash).
    """
    _, scan = load_job_scan(session, org_id, job_id)
    if scan.status in TERMINAL or not root_is_active(session, org_id, scan):
        session.rollback()
        return
    if _already_diffed(scan):
        session.rollback()
        return
    seen = scan.started_at or scan.created_at
    fixed = _fix(session, org_id, scan, seen)
    regressed = _regress(session, org_id, scan)
    assets = _asset_changes(session, org_id, scan, seen)
    first_seen = _observed_severities(session, org_id, Finding.first_seen_scan_id, scan.id)
    last_seen = _observed_severities(session, org_id, Finding.last_seen_scan_id, scan.id)
    findings = {
        "new": _severity_bucket(first_seen),
        "fixed": _severity_bucket(severity for _, severity in fixed),
        "regressed": _severity_bucket(severity for _, severity in regressed),
        "total": _severity_bucket(last_seen),
    }
    stats = {"findings": findings, "assets": assets}
    scan.stats = {**(scan.stats or {}), **stats}
    audit(
        session,
        org_id,
        "scan.diffed",
        target_type="scan",
        target_id=str(scan.id),
        details={
            "new_findings": findings["new"]["total"],
            "fixed_findings": findings["fixed"]["total"],
            "regressed_findings": findings["regressed"]["total"],
            "new_assets": assets["new"]["total"],
            "disappeared_assets": assets["disappeared"]["total"],
        },
    )
    session.commit()
    for finding_id, _ in fixed:
        events.publish(FindingFixed(org_id, scan.id, finding_id))
    for finding_id, _ in regressed:
        events.publish(FindingRegressed(org_id, scan.id, finding_id))


def _already_diffed(scan: Scan) -> bool:
    stats = scan.stats or {}
    return "findings" in stats and "assets" in stats


def _fix(session: Session, org_id: UUID, scan: Scan, seen: datetime) -> list[tuple[UUID, Severity]]:
    """Fix active findings whose scanner completed for their asset in this scan, once.

    `last_seen <= seen` keeps a delayed older scan from fixing what a newer scan just observed.
    The `EXISTS` ties coverage to the finding's own scanner and asset, so a successful check of
    a different scanner on the same asset never hides a finding.
    """
    covered = (
        select(Job.id)
        .where(
            Job.org_id == Finding.org_id,
            Job.scan_id == scan.id,
            Job.stage.in_(_SCANNER_STAGES),
            Job.status == JobStatus.COMPLETED,
            Job.scanner == Finding.scanner,
            Job.asset_id == Finding.asset_id,
        )
        .exists()
    )
    rows = session.execute(
        update(Finding)
        .where(
            Finding.org_id == org_id,
            Finding.status.in_(ACTIVE_STATUSES),
            Finding.scanner.is_not(None),
            Finding.last_seen_scan_id.is_distinct_from(scan.id),
            Finding.last_seen <= seen,
            covered,
        )
        .values(status=FindingStatus.FIXED, fixed_at=func.now(), updated_at=func.now())
        .returning(Finding.id, Finding.severity),
        execution_options={"synchronize_session": "fetch"},
    ).all()
    return [(row.id, row.severity) for row in rows]


def _regress(session: Session, org_id: UUID, scan: Scan) -> list[tuple[UUID, Severity]]:
    """A fixed finding observed again in this scan comes back as `regressed`."""
    rows = session.execute(
        update(Finding)
        .where(
            Finding.org_id == org_id,
            Finding.last_seen_scan_id == scan.id,
            Finding.status == FindingStatus.FIXED,
        )
        .values(status=FindingStatus.REGRESSED, fixed_at=None, updated_at=func.now())
        .returning(Finding.id, Finding.severity),
        execution_options={"synchronize_session": "fetch"},
    ).all()
    return [(row.id, row.severity) for row in rows]


def _observed_severities(
    session: Session, org_id: UUID, pointer: InstrumentedAttribute[UUID | None], scan_id: UUID
) -> list[Severity]:
    """Severities of the findings this scan first saw (`first_seen_scan_id`) or last saw."""
    return list(
        session.scalars(
            scoped(Finding, org_id).where(pointer == scan_id).with_only_columns(Finding.severity)
        )
    )


def _severity_bucket(severities: Iterable[Severity]) -> dict[str, object]:
    """`{"total": n, "by_severity": {...}}` with every severity present, zero-filled."""
    counts = dict.fromkeys(Severity, 0)
    total = 0
    for severity in severities:
        counts[severity] += 1
        total += 1
    return {
        "total": total,
        "by_severity": {severity.value: counts[severity] for severity in Severity},
    }


def _asset_changes(
    session: Session, org_id: UUID, scan: Scan, seen: datetime
) -> dict[str, dict[str, object]]:
    """Discovered assets new since this scan started, and ones the previous scan still saw.

    "Disappeared" needs a completed discovery job for this scan and an earlier completed scan:
    without both, a missing name only means we did not look (ADR 0011).
    """
    children = scoped(Asset, org_id).where(Asset.parent_id == scan.root_asset_id)
    columns = (Asset.id, Asset.type, Asset.value)
    new = session.execute(
        children.where(Asset.first_seen >= seen)
        .with_only_columns(*columns)
        .order_by(Asset.type, Asset.value)
    ).all()
    disappeared: Sequence[Row[UUID, AssetType, str]] = ()
    previous = (
        _previous_scan(session, org_id, scan, seen)
        if _discovery_ran(session, org_id, scan)
        else None
    )
    if previous is not None and previous.started_at is not None:
        disappeared = session.execute(
            children.where(
                Asset.first_seen < seen,
                Asset.last_seen < seen,
                Asset.last_seen >= previous.started_at,
            )
            .with_only_columns(*columns)
            .order_by(Asset.type, Asset.value)
        ).all()
    return {"new": _asset_bucket(new), "disappeared": _asset_bucket(disappeared)}


def _asset_bucket(rows: Sequence[Row[UUID, AssetType, str]]) -> dict[str, object]:
    return {
        "total": len(rows),
        "assets": [
            {"id": str(row.id), "type": row.type.value, "value": row.value}
            for row in rows[:MAX_STATS_ASSETS]
        ],
    }


def _previous_scan(session: Session, org_id: UUID, scan: Scan, seen: datetime) -> Scan | None:
    """The latest completed scan of the same root that ran before this one."""
    return session.scalars(
        scoped(Scan, org_id)
        .where(
            Scan.root_asset_id == scan.root_asset_id,
            Scan.id != scan.id,
            Scan.status == ScanStatus.COMPLETED,
            Scan.started_at.is_not(None),
            Scan.started_at < seen,
        )
        .order_by(Scan.started_at.desc(), Scan.id.desc())
        .limit(1)
    ).one_or_none()


def _discovery_ran(session: Session, org_id: UUID, scan: Scan) -> bool:
    return (
        session.scalar(
            scoped(Job, org_id)
            .where(
                Job.scan_id == scan.id,
                Job.stage == "discovery",
                Job.status == JobStatus.COMPLETED,
            )
            .with_only_columns(func.count())
        )
        or 0
    ) > 0
