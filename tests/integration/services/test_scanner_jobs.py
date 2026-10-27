"""`run_check`: how a gate's verdict maps onto the job and the scan (ADR 0013)."""

from uuid import uuid4

import pytest
from sqlalchemy.orm import Session

from attacksurf.domain.events import DomainEvent
from attacksurf.domain.scanners import AssetRef, ScanContext, Scanner
from attacksurf.domain.scans import JobStatus, ScanStatus
from attacksurf.domain.scope import ScopeError, ScopePolicyError
from attacksurf.infra.db.models import Job, Scan
from attacksurf.services.scanner_jobs import run_check
from tests.integration.factories import make_scan
from tests.scanner_fixtures import fixture_registry


class _NoEvents:
    def publish(self, event: DomainEvent) -> None:
        raise AssertionError("no events expected")


class RaisingGate:
    """A gate that denies or errors exactly as `ScopeGuard` does."""

    def __init__(self, error: Exception) -> None:
        self._error = error

    def check(self, ctx: ScanContext, asset: AssetRef, scanner: Scanner) -> object:
        raise self._error


def add_job(session: Session, scan: Scan, *, scanner: str = "fixture.check") -> Job:
    job = Job(
        org_id=scan.org_id,
        scan_id=scan.id,
        asset_id=scan.root_asset_id,
        stage="check",
        scanner=scanner,
        status=JobStatus.RUNNING,
    )
    session.add(job)
    # Committed: `run_check` rolls back to release locks before doing I/O.
    session.commit()
    return job


def run(session: Session, scan: Scan, job: Job, gate: RaisingGate) -> None:
    job_id, org_id = job.id, scan.org_id
    run_check(
        session,
        org_id,
        job_id,
        registry=fixture_registry(),
        gate=gate,  # type: ignore[arg-type]
        events=_NoEvents(),  # type: ignore[arg-type]
        retry_allowed=False,
    )
    # `run_check` rolls back (releasing locks) before doing I/O: drop stale copies.
    session.refresh(job)
    session.refresh(scan)


def test_policy_error_fails_only_its_job_and_leaves_the_scan_running(db_session: Session) -> None:
    """A bad grant is a plugin bug: it must not fail the scan or cancel its other jobs."""
    scan = make_scan(db_session)
    failing = add_job(db_session, scan, scanner="fixture.check")
    other = add_job(db_session, scan, scanner="fixture.check")

    run(db_session, scan, failing, RaisingGate(ScopePolicyError("A scanner is misconfigured.")))

    db_session.refresh(other)
    assert failing.status is JobStatus.FAILED
    assert "misconfigured" in (failing.error or "")
    assert other.status is JobStatus.RUNNING
    assert scan.status is ScanStatus.RUNNING


def test_scope_denial_skips_the_job_without_failing_it(db_session: Session) -> None:
    scan = make_scan(db_session)
    job = add_job(db_session, scan)

    run(db_session, scan, job, RaisingGate(ScopeError("Out of scope.")))

    assert job.status is JobStatus.SKIPPED
    assert scan.status is ScanStatus.RUNNING


def test_missing_asset_skips_the_job(db_session: Session) -> None:
    scan = make_scan(db_session)
    job = add_job(db_session, scan)
    job.asset_id = None
    db_session.flush()

    run(db_session, scan, job, RaisingGate(ScopeError("Out of scope.")))

    assert job.status is JobStatus.SKIPPED
    assert "no longer exists" in (job.error or "")


def test_unknown_tenant_cannot_run_another_orgs_job(db_session: Session) -> None:
    scan = make_scan(db_session)
    job = add_job(db_session, scan)

    with pytest.raises(LookupError):
        run_check(
            db_session,
            uuid4(),  # a different tenant
            job.id,
            registry=fixture_registry(),
            gate=RaisingGate(ScopeError("Out of scope.")),  # type: ignore[arg-type]
            events=_NoEvents(),  # type: ignore[arg-type]
            retry_allowed=False,
        )

    assert job.status is JobStatus.RUNNING
