"""Finding lifecycle diff and scan stats: fixed, regressed, new assets (ADR 0027).

Runs after every scanner result is committed (`persist` barrier) and before `finalize`. A
finding is never fixed just because it is missing from this scan: its own scanner must have
completed for its asset here, so a failed, skipped or unplanned check proves nothing (ADR 0011).
"Seen by this scan" always means a `finding_observations` row for this scan, never the mutable
`Finding.last_seen_scan_id` pointer that overlapping scans can move.
"""

from collections.abc import Iterable, Sequence
from datetime import datetime
from uuid import UUID

from sqlalchemy import Row, func, select, update
from sqlalchemy.orm import Session
from sqlalchemy.sql.elements import ColumnElement

from attacksurf.domain.assets import AssetType
from attacksurf.domain.events import EventDispatcher, FindingFixed, FindingRegressed
from attacksurf.domain.findings import ACTIVE_STATUSES, FindingStatus, Severity
from attacksurf.domain.scans import JobStatus
from attacksurf.infra.db.models import Asset, Finding, FindingObservation, Job, Scan
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
    regressed = _regress(session, org_id, scan, seen)
    assets = _asset_changes(session, org_id, scan, seen)
    findings = {
        "new": _severity_bucket(_new_severities(session, org_id, scan.id)),
        "fixed": _severity_bucket(severity for _, severity in fixed),
        "regressed": _severity_bucket(severity for _, severity in regressed),
        "total": _severity_bucket(_observed_severities(session, org_id, scan.id)),
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


def _observed_here(scan_id: UUID) -> ColumnElement[bool]:
    """`EXISTS` a `finding_observations` row linking this finding to the scan."""
    return (
        select(FindingObservation.id)
        .where(
            FindingObservation.org_id == Finding.org_id,
            FindingObservation.scan_id == scan_id,
            FindingObservation.finding_id == Finding.id,
        )
        .exists()
    )


def _fix(session: Session, org_id: UUID, scan: Scan, seen: datetime) -> list[tuple[UUID, Severity]]:
    """Fix active findings whose scanner completed for their asset in this scan, once.

    Findings this scan observed are excluded through its own observation rows, so an overlapping
    scan moving `last_seen_scan_id` cannot make them look unseen. `last_seen <= seen` keeps a
    delayed older scan from fixing what a newer scan just observed. `fixed_at` is this scan's
    start (not wall-clock time), so `_regress` can compare it with a later scan's start and an
    older delayed observation cannot undo a newer fix. The coverage `EXISTS` ties the job to the
    finding's own scanner and asset, so a successful check of a different scanner on the same
    asset never hides a finding.
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
            ~_observed_here(scan.id),
            Finding.last_seen <= seen,
            covered,
        )
        .values(status=FindingStatus.FIXED, fixed_at=seen, updated_at=func.now())
        .returning(Finding.id, Finding.severity),
        execution_options={"synchronize_session": "fetch"},
    ).all()
    return [(row.id, row.severity) for row in rows]


def _regress(
    session: Session, org_id: UUID, scan: Scan, seen: datetime
) -> list[tuple[UUID, Severity]]:
    """A fixed finding this scan observed again comes back as `regressed`.

    Only a fix established before this scan started regresses: a delayed positive result from
    an older scan can be persisted after a newer scan already fixed the finding, and that must
    not undo the newer decision. The observation row, not `last_seen_scan_id`, proves the
    observation belongs to this scan.
    """
    rows = session.execute(
        update(Finding)
        .where(
            Finding.org_id == org_id,
            _observed_here(scan.id),
            Finding.status == FindingStatus.FIXED,
            Finding.fixed_at < seen,
        )
        .values(status=FindingStatus.REGRESSED, fixed_at=None, updated_at=func.now())
        .returning(Finding.id, Finding.severity),
        execution_options={"synchronize_session": "fetch"},
    ).all()
    return [(row.id, row.severity) for row in rows]


def _observed_severities(session: Session, org_id: UUID, scan_id: UUID) -> list[Severity]:
    """Severities of every finding this scan observed, from its own observation rows."""
    return list(
        session.scalars(
            scoped(FindingObservation, org_id)
            .where(FindingObservation.scan_id == scan_id)
            .with_only_columns(FindingObservation.severity)
        )
    )


def _new_severities(session: Session, org_id: UUID, scan_id: UUID) -> list[Severity]:
    """Severities of the findings this scan was the first to observe."""
    return list(
        session.scalars(
            scoped(FindingObservation, org_id)
            .join(
                Finding,
                (Finding.id == FindingObservation.finding_id) & (Finding.org_id == org_id),
            )
            .where(
                FindingObservation.scan_id == scan_id,
                Finding.first_seen_scan_id == scan_id,
            )
            .with_only_columns(FindingObservation.severity)
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
    """Discovered assets new since this scan started, and subdomains it found gone.

    "Disappeared" is a resolution verdict, not an absence: the asset was deactivated during this
    scan because a scanner resolved it to nothing (ADR 0025), so it never depends on how
    complete the discovery sources were. IPs are excluded until per-hostname resolution coverage
    exists; a failed resolve leaves their `last_seen` stale without deactivating them.
    """
    children = scoped(Asset, org_id).where(Asset.parent_id == scan.root_asset_id)
    columns = (Asset.id, Asset.type, Asset.value)
    new = session.execute(
        children.where(Asset.first_seen >= seen)
        .with_only_columns(*columns)
        .order_by(Asset.type, Asset.value)
    ).all()
    disappeared = session.execute(
        children.where(
            Asset.type != AssetType.IP,
            Asset.is_active.is_(False),
            Asset.deactivated_at >= seen,
            Asset.first_seen < seen,
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
