"""One scanner attempt: no database transaction is held during plugin execution."""

from collections.abc import Mapping
from dataclasses import replace
from uuid import UUID

import structlog
from sqlalchemy import func, select
from sqlalchemy.orm import Session, aliased

from attacksurf.domain.assets import AssetError
from attacksurf.domain.events import EventDispatcher
from attacksurf.domain.jobs import JobNotFound, TransientJobError
from attacksurf.domain.rules import RULES, Rule
from attacksurf.domain.scanners import (
    AssetRef,
    ScanContext,
    ScannerError,
    ScannerGate,
    ScanProfile,
)
from attacksurf.domain.scans import JobStatus
from attacksurf.domain.scope import ScopeError, ScopePolicyError
from attacksurf.infra.db.models import Asset, Job, Scan
from attacksurf.infra.db.tenancy import scoped
from attacksurf.infra.scanner_runner import run_scanner
from attacksurf.scanners.registry import ScannerRegistry
from attacksurf.services import jobs
from attacksurf.services.scan_results import persist_scan_output
from attacksurf.services.scans import TERMINAL, load_job_scan


def run_check(
    session: Session,
    org_id: UUID,
    job_id: UUID,
    *,
    registry: ScannerRegistry,
    gate: ScannerGate,
    events: EventDispatcher,
    retry_allowed: bool,
    catalog: Mapping[str, Rule] = RULES,
    profiles: Mapping[str, ScanProfile] | None = None,
) -> None:
    target_alias = aliased(Asset)
    root_alias = aliased(Asset)
    loaded = session.execute(
        select(Job, Scan, target_alias, root_alias)
        .outerjoin(Scan, (Scan.id == Job.scan_id) & (Scan.org_id == Job.org_id))
        .outerjoin(
            target_alias,
            (target_alias.id == Job.asset_id) & (target_alias.org_id == Job.org_id),
        )
        .outerjoin(
            root_alias,
            (root_alias.id == Scan.root_asset_id) & (root_alias.org_id == Scan.org_id),
        )
        .where(Job.org_id == org_id, Job.id == job_id)
    ).one_or_none()
    if loaded is None:
        raise JobNotFound(str(job_id))
    job, scan, asset, root = loaded
    if scan is None or scan.status in TERMINAL:
        jobs.mark_job_skipped(session, org_id, job_id, "Scan is no longer running.")
        return
    if asset is None or root is None:
        jobs.mark_job_skipped(session, org_id, job_id, "Asset no longer exists.")
        return
    scanner = registry.get(job.scanner or "")
    asset_id = asset.id
    profile = profiles.get(scan.profile) if profiles else None
    target = AssetRef(type=asset.type, value=asset.value)
    ctx = ScanContext(
        org_id,
        scan.id,
        AssetRef(type=root.type, value=root.value),
        scan.profile,
        max_discovered_assets=profile.max_discovered_assets if profile else None,
        target_is_wildcard=bool((asset.details or {}).get("wildcard")),
    )
    session.rollback()  # release connection/transaction before untrusted or slow I/O
    try:
        runtime = gate.check(ctx, target, scanner)
    except (ScopeError, ScopePolicyError) as exc:
        _gate_denied(session, org_id, job_id, exc)
        return
    ctx = replace(ctx, runtime=runtime)
    try:
        output = run_scanner(scanner, ctx, target)
    except TransientJobError:
        if retry_allowed:
            raise
        _failed(session, org_id, job_id, ScannerError("Scanner exhausted its retries."))
        return
    except Exception as exc:
        _failed(session, org_id, job_id, exc)
        return
    finally:
        # Closed only after the thread's budget elapsed: a timed-out thread may still use it,
        # and the client refuses new requests on a closed pool.
        runtime.close()
    # Lock in ADR 0021 order (scan, then job): cancellation/redelivery may win while scanning.
    job, scan = load_job_scan(session, org_id, job_id)
    job = session.scalars(
        scoped(Job, org_id).where(Job.id == job_id).with_for_update(),
        execution_options={"populate_existing": True},
    ).one()
    if job.status in jobs.FINISHED or scan.status in TERMINAL:
        jobs.mark_job_skipped(session, org_id, job_id, "Scan is no longer running.")
        return
    try:
        produced = persist_scan_output(
            session,
            scan,
            asset_id=asset_id,
            output=output,
            catalog=catalog,
            discovered_limit=profile.max_discovered_assets if profile else None,
            scanner=job.scanner,
        )
    except (AssetError, ValueError, LookupError) as exc:
        session.rollback()
        _failed(session, org_id, job_id, exc)
    else:
        job.status = JobStatus.COMPLETED
        job.error = None
        job.finished_at = func.now()
        session.commit()  # data + terminal job state are atomic on redelivery
        for event in produced:
            events.publish(event)


def _gate_denied(session: Session, org_id: UUID, job_id: UUID, exc: Exception) -> None:
    """Record the gate's verdict: a policy bug fails its job, a denial only skips it (ADR 0013)."""
    if isinstance(exc, ScopePolicyError):
        _failed(session, org_id, job_id, exc)
    else:
        jobs.mark_job_skipped(session, org_id, job_id, jobs.describe_error(exc))


def _failed(session: Session, org_id: UUID, job_id: UUID, exc: BaseException) -> None:
    jobs.mark_job_failed(session, org_id, job_id, exc)
    structlog.get_logger(__name__).warning(
        "scanner failed", org_id=str(org_id), job_id=str(job_id), error=jobs.describe_error(exc)
    )
