"""Read side of scans: the scan list, one scan's progress, and its diff (no writes).

Results are frozen dataclasses, so `web/` renders and serializes them without touching
ORM rows. `Scan.stats` is untrusted-shaped JSONB (upload scans store a revision there,
cancelled scans never get a diff), so the diff summary parses defensively: anything
unexpected means "no diff yet", never an exception.
"""

import math
from dataclasses import dataclass
from datetime import datetime
from typing import Any
from uuid import UUID

from sqlalchemy import func
from sqlalchemy.orm import Session, aliased

from attacksurf.domain.findings import Severity
from attacksurf.domain.scans import JobStatus, ScanNotFound, ScanStatus, ScanTrigger
from attacksurf.infra.db.models import Asset, Job, Scan
from attacksurf.infra.db.tenancy import scoped
from attacksurf.services import jobs as job_lifecycle
from attacksurf.services.scans import TERMINAL

PAGE_SIZE = 25
# Diff asset lists shown on the scan page; `total` always holds the real count.
MAX_DIFF_ASSETS = 100
_SEVERITIES = (
    Severity.CRITICAL,
    Severity.HIGH,
    Severity.MEDIUM,
    Severity.LOW,
    Severity.INFO,
)


@dataclass(frozen=True)
class ScanFilter:
    root_id: UUID | None = None  # scans of one root domain
    status: ScanStatus | None = None


@dataclass(frozen=True)
class ScanRow:
    id: UUID
    root_asset_id: UUID
    root_value: str
    profile: str
    status: ScanStatus
    triggered_by: ScanTrigger
    created_at: datetime
    started_at: datetime | None
    finished_at: datetime | None
    jobs_finished: int
    jobs_total: int


@dataclass(frozen=True)
class ScanPage:
    items: tuple[ScanRow, ...]
    page: int
    pages: int
    total: int


@dataclass(frozen=True)
class JobRow:
    id: UUID
    stage: str
    scanner: str | None
    asset_id: UUID | None
    asset_value: str | None  # None when the asset was deleted after the job ran
    status: JobStatus
    attempts: int
    error: str | None
    started_at: datetime | None
    finished_at: datetime | None


@dataclass(frozen=True)
class SeverityBucket:
    total: int
    by_severity: tuple[tuple[str, int], ...]  # canonical worst-first order


@dataclass(frozen=True)
class DiffAsset:
    id: str
    type: str
    value: str


@dataclass(frozen=True)
class DiffAssetBucket:
    total: int
    assets: tuple[DiffAsset, ...]
    truncated: bool


@dataclass(frozen=True)
class DiffSummary:
    new_findings: SeverityBucket
    fixed_findings: SeverityBucket
    regressed_findings: SeverityBucket
    total_findings: SeverityBucket
    new_assets: DiffAssetBucket
    disappeared_assets: DiffAssetBucket


@dataclass(frozen=True)
class ScanDetail:
    scan: ScanRow
    jobs: tuple[JobRow, ...]
    jobs_finished: int
    jobs_total: int
    by_status: tuple[tuple[str, int], ...]
    can_cancel: bool
    diff: DiffSummary | None


def list_scans(session: Session, org_id: UUID, flt: ScanFilter, page: int = 1) -> ScanPage:
    """Newest first, with per-scan progress counts. Filters are optional and combined."""
    conditions = []
    if flt.root_id is not None:
        conditions.append(Scan.root_asset_id == flt.root_id)
    if flt.status is not None:
        conditions.append(Scan.status == flt.status)
    total = (
        session.scalar(scoped(Scan, org_id).where(*conditions).with_only_columns(func.count())) or 0
    )
    pages = max(1, math.ceil(total / PAGE_SIZE))
    page = min(max(page, 1), pages)
    root = aliased(Asset)
    # Whole-org aggregates joined by scan id (the asset_views findings-stats pattern):
    # correct for every filter without correlating a subquery.
    finished = (
        scoped(Job, org_id)
        .where(Job.status.in_(tuple(job_lifecycle.FINISHED)))
        .with_only_columns(Job.scan_id, func.count().label("done"))
        .group_by(Job.scan_id)
        .subquery()
    )
    totals = (
        scoped(Job, org_id)
        .with_only_columns(Job.scan_id, func.count().label("total"))
        .group_by(Job.scan_id)
        .subquery()
    )
    rows = session.execute(
        scoped(Scan, org_id)
        .add_columns(
            root.value,
            func.coalesce(finished.c.done, 0),
            func.coalesce(totals.c.total, 0),
        )
        .outerjoin(root, (root.id == Scan.root_asset_id) & (root.org_id == org_id))
        .outerjoin(finished, finished.c.scan_id == Scan.id)
        .outerjoin(totals, totals.c.scan_id == Scan.id)
        .where(*conditions)
        .order_by(Scan.created_at.desc(), Scan.id.desc())
        .limit(PAGE_SIZE)
        .offset((page - 1) * PAGE_SIZE)
    ).all()
    return ScanPage(
        items=tuple(
            _scan_row(scan, root_value or "", done, total_jobs)
            for scan, root_value, done, total_jobs in rows
        ),
        page=page,
        pages=pages,
        total=total,
    )


def active_scan_for_root(session: Session, org_id: UUID, root_asset_id: UUID) -> ScanRow | None:
    """The root's queued/running scan, if any. Raises nothing for other tenants' roots."""
    root = aliased(Asset)
    row = session.execute(
        scoped(Scan, org_id)
        .add_columns(root.value)
        .outerjoin(root, (root.id == Scan.root_asset_id) & (root.org_id == org_id))
        .where(
            Scan.root_asset_id == root_asset_id,
            Scan.status.in_((ScanStatus.QUEUED, ScanStatus.RUNNING)),
        )
        .order_by(Scan.created_at.desc(), Scan.id.desc())
        .limit(1)
    ).one_or_none()
    if row is None:
        return None
    scan, root_value = row
    return _scan_row(scan, root_value or "", 0, 0)


def get_scan_detail(session: Session, org_id: UUID, scan_id: UUID) -> ScanDetail:
    """One scan with its jobs and diff summary. Raises `ScanNotFound`."""
    root = aliased(Asset)
    row = session.execute(
        scoped(Scan, org_id)
        .add_columns(root.value)
        .outerjoin(root, (root.id == Scan.root_asset_id) & (root.org_id == org_id))
        .where(Scan.id == scan_id)
    ).one_or_none()
    if row is None:
        raise ScanNotFound(str(scan_id))
    scan, root_value = row
    asset = aliased(Asset)
    job_rows = session.execute(
        scoped(Job, org_id)
        .add_columns(asset.value)
        .outerjoin(asset, (asset.id == Job.asset_id) & (asset.org_id == org_id))
        .where(Job.scan_id == scan_id)
        .order_by(Job.created_at, Job.id)
    ).all()
    jobs = tuple(
        JobRow(
            id=job.id,
            stage=job.stage,
            scanner=job.scanner,
            asset_id=job.asset_id,
            asset_value=asset_value,
            status=job.status,
            attempts=job.attempts,
            error=job.error,
            started_at=job.started_at,
            finished_at=job.finished_at,
        )
        for job, asset_value in job_rows
    )
    counts: dict[JobStatus, int] = {}
    for job in jobs:
        counts[job.status] = counts.get(job.status, 0) + 1
    finished = sum(counts.get(status, 0) for status in job_lifecycle.FINISHED)
    return ScanDetail(
        scan=_scan_row(scan, root_value or "", finished, len(jobs)),
        jobs=jobs,
        jobs_finished=finished,
        jobs_total=len(jobs),
        by_status=tuple((status.value, counts.get(status, 0)) for status in JobStatus),
        can_cancel=scan.status not in TERMINAL,
        diff=parse_diff(scan.stats),
    )


def parse_diff(stats: Any) -> DiffSummary | None:
    """This scan's finding/asset changes, or None when there is no diff to show.

    Anything that isn't the `diff_scan` shape (upload revisions, queued scans, a diff
    that never ran because the scan was cancelled) parses to None. Counts are coerced
    to ints; unknown severity names are ignored so a newer writer never breaks this read.
    """
    if not isinstance(stats, dict):
        return None
    findings = stats.get("findings")
    assets = stats.get("assets")
    if not isinstance(findings, dict) or not isinstance(assets, dict):
        return None
    try:
        return DiffSummary(
            new_findings=_severity_bucket(findings.get("new")),
            fixed_findings=_severity_bucket(findings.get("fixed")),
            regressed_findings=_severity_bucket(findings.get("regressed")),
            total_findings=_severity_bucket(findings.get("total")),
            new_assets=_asset_bucket(assets.get("new")),
            disappeared_assets=_asset_bucket(assets.get("disappeared")),
        )
    except (TypeError, ValueError, AttributeError):
        return None


def _scan_row(scan: Scan, root_value: str, done: int, total_jobs: int) -> ScanRow:
    return ScanRow(
        id=scan.id,
        root_asset_id=scan.root_asset_id,
        root_value=root_value,
        profile=scan.profile,
        status=scan.status,
        triggered_by=scan.triggered_by,
        created_at=scan.created_at,
        started_at=scan.started_at,
        finished_at=scan.finished_at,
        jobs_finished=done,
        jobs_total=total_jobs,
    )


def _severity_bucket(value: Any) -> SeverityBucket:
    raw = value.get("by_severity") if isinstance(value, dict) else None
    raw = raw if isinstance(raw, dict) else {}
    counts = {severity.value: _as_int(raw.get(severity.value)) for severity in _SEVERITIES}
    total = _as_int(value.get("total")) if isinstance(value, dict) else 0
    total = max(total, sum(counts.values()))
    return SeverityBucket(
        total=total,
        by_severity=tuple((severity.value, counts[severity.value]) for severity in _SEVERITIES),
    )


def _asset_bucket(value: Any) -> DiffAssetBucket:
    """Display-capped entries with the writer's true total. Bad entries are skipped, so a
    newer writer shape degrades to fewer rows instead of hiding the whole diff."""
    raw = value.get("assets") if isinstance(value, dict) else None
    entries: list[DiffAsset] = []
    if isinstance(raw, list):
        for entry in raw[:MAX_DIFF_ASSETS]:
            if not isinstance(entry, dict):
                continue
            asset_id = entry.get("id")
            asset_type = entry.get("type")
            asset_value = entry.get("value")
            if (
                not isinstance(asset_id, str)
                or not isinstance(asset_type, str)
                or not isinstance(asset_value, str)
                or not (asset_id and asset_type and asset_value)
            ):
                continue
            entries.append(DiffAsset(id=asset_id, type=asset_type, value=asset_value))
    total = _as_int(value.get("total")) if isinstance(value, dict) else 0
    truncated = isinstance(raw, list) and len(raw) > MAX_DIFF_ASSETS
    return DiffAssetBucket(
        total=max(total, len(entries)), assets=tuple(entries), truncated=truncated
    )


def _as_int(value: Any) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value < 0:
        return 0
    return value
