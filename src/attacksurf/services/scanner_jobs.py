"""One scanner attempt: no database transaction is held during plugin execution."""

from collections.abc import Mapping
from dataclasses import replace
from uuid import UUID

import structlog
from sqlalchemy import func
from sqlalchemy.orm import Session

from attacksurf.domain.assets import AssetError
from attacksurf.domain.events import EventDispatcher
from attacksurf.domain.jobs import TransientJobError
from attacksurf.domain.rules import RULES, Rule
from attacksurf.domain.scanners import (
    AssetRef,
    ScanContext,
    ScannerError,
    ScannerGate,
    ScanProfile,
)
from attacksurf.domain.scans import JobStatus
from attacksurf.domain.scope import ScopeError
from attacksurf.infra.db.models import Asset, Job
from attacksurf.infra.db.tenancy import get_scoped, scoped
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
    job, scan = load_job_scan(session, org_id, job_id)
    if scan.status in TERMINAL:
        jobs.mark_job_skipped(session, org_id, job_id, "Scan is no longer running.")
        return
    asset = get_scoped(session, Asset, job.asset_id, org_id) if job.asset_id else None
    root = get_scoped(session, Asset, scan.root_asset_id, org_id)
    if asset is None or root is None:
        jobs.mark_job_skipped(session, org_id, job_id, "Asset no longer exists.")
        return
    scanner = registry.get(job.scanner or "")
    asset_id = asset.id
    profile = profiles.get(scan.profile) if profiles else None
    target = AssetRef(type=asset.type, value=asset.value)
    ctx = ScanContext(org_id, scan.id, AssetRef(type=root.type, value=root.value), scan.profile)
    session.rollback()  # release locks/connection before untrusted or slow I/O
    try:
        runtime = gate.check(ctx, target, scanner)
    except ScopeError as exc:
        # A denial is a recorded outcome (skipped job), not a failure of the scan.
        jobs.mark_job_skipped(session, org_id, job_id, jobs.describe_error(exc))
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
    # Lock again: cancellation or another delivery may have won while the scanner ran.
    job, scan = load_job_scan(session, org_id, job_id)
    job = session.scalars(
        scoped(Job, org_id).where(Job.id == job_id).with_for_update(),
        execution_options={"populate_existing": True},
    ).one()
    if job.status in jobs.FINISHED or scan.status in TERMINAL:
        jobs.mark_job_skipped(session, org_id, job_id, "Scan is no longer running.")
        return
    try:
        created = persist_scan_output(
            session,
            scan,
            asset_id=asset_id,
            output=output,
            catalog=catalog,
            discovered_limit=profile.max_discovered_assets if profile else None,
        )
    except (AssetError, ValueError, LookupError) as exc:
        session.rollback()
        _failed(session, org_id, job_id, exc)
    else:
        job.status = JobStatus.COMPLETED
        job.error = None
        job.finished_at = func.now()
        session.commit()  # data + terminal job state are atomic on redelivery
        for event in created:
            events.publish(event)


def _failed(session: Session, org_id: UUID, job_id: UUID, exc: BaseException) -> None:
    jobs.mark_job_failed(session, org_id, job_id, exc)
    structlog.get_logger(__name__).warning(
        "scanner failed", org_id=str(org_id), job_id=str(job_id), error=jobs.describe_error(exc)
    )
