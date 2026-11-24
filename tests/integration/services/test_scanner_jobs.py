"""`run_check`: how a gate's verdict maps onto the job and the scan (ADR 0013)."""

from datetime import UTC, datetime, timedelta
from uuid import uuid4

import pytest
from sqlalchemy.orm import Session, sessionmaker

from attacksurf.domain.assets import AssetType
from attacksurf.domain.events import DomainEvent
from attacksurf.domain.jobs import JobTask
from attacksurf.domain.scanners import (
    AssetRef,
    ScanContext,
    Scanner,
    ScannerGrant,
    ScanOutput,
    ScanProfile,
)
from attacksurf.domain.scans import JobStatus, ScanStatus
from attacksurf.domain.scope import HttpPermission, PublicSuffix, ScopeError, ScopePolicyError
from attacksurf.domain.verification import VerificationMethod, VerificationStatus
from attacksurf.infra.db.models import Job, Scan, Verification
from attacksurf.infra.http import SafeHttpClient
from attacksurf.infra.scope_guard import ScopeGuard
from attacksurf.scanners.registry import ScannerRegistry
from attacksurf.services import scans
from attacksurf.services.ownership import DbOwnershipChecker
from attacksurf.services.scanner_jobs import run_check
from tests.dns_fakes import MutableDnsZone
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


class _ActiveTargetScanner:
    name = "fixture.active_target"
    asset_types = frozenset({AssetType.DOMAIN})
    queue = "active"
    requires_verification = True
    timeout_seconds = 5.0
    grant = ScannerGrant(http=HttpPermission.TARGET, dns_lookups=1)

    def run(self, ctx: ScanContext, asset: AssetRef) -> ScanOutput:
        return ScanOutput()


def _active_registry() -> ScannerRegistry:
    reg = ScannerRegistry()
    reg.register(_ActiveTargetScanner)
    return reg


def _mark_root_verified(session: Session, scan: Scan) -> None:
    now = datetime.now(UTC)
    session.add(
        Verification(
            org_id=scan.org_id,
            asset_id=scan.root_asset_id,
            method=VerificationMethod.DNS_TXT,
            token="verify-token",
            status=VerificationStatus.VERIFIED,
            verified_at=now,
            last_checked_at=now,
            recheck_at=now + timedelta(hours=20),
            expires_at=now + timedelta(hours=24),
        )
    )
    session.commit()


class _RecordingPipelineQueue:
    def __init__(self) -> None:
        self.workflows: list[tuple[tuple[JobTask, ...], tuple[JobTask, ...], JobTask]] = []

    def enqueue_workflow(
        self, header: tuple[JobTask, ...], tail: tuple[JobTask, ...], error: JobTask
    ) -> None:
        self.workflows.append((header, tail, error))


def test_dispatch_stage_routes_active_scanners_to_active_queue(db_session: Session) -> None:
    scan = make_scan(db_session)
    scan.profile = "active_fixture"
    kickoff = Job(
        org_id=scan.org_id,
        scan_id=scan.id,
        stage="checks",
        status=JobStatus.QUEUED,
    )
    db_session.add(kickoff)
    db_session.flush()
    queue = _RecordingPipelineQueue()
    reg = _active_registry()
    profiles = {
        "active_fixture": ScanProfile(name="active_fixture", checks=("fixture.active_target",))
    }

    scans.dispatch_stage(
        db_session,
        queue,
        scan.org_id,
        kickoff.id,
        registry=reg,
        profiles=profiles,
    )

    assert len(queue.workflows) == 1
    header, _tail, _error = queue.workflows[0]
    assert [task.task_name for task in header] == ["active.scan"]


@pytest.mark.parametrize(
    ("enabled", "verified", "expected_status", "expected_error"),
    [
        (False, True, JobStatus.SKIPPED, "disabled"),
        (True, False, JobStatus.SKIPPED, "verified"),
        (True, True, JobStatus.COMPLETED, None),
    ],
)
def test_active_job_runs_only_when_enabled_and_verified(
    db_session: Session,
    enabled: bool,
    verified: bool,
    expected_status: JobStatus,
    expected_error: str | None,
) -> None:
    scan = make_scan(db_session)
    if verified:
        _mark_root_verified(db_session, scan)
    job = add_job(db_session, scan, scanner="fixture.active_target")
    factory = sessionmaker(
        bind=db_session.connection(),
        join_transaction_mode="create_savepoint",
        expire_on_commit=False,
    )

    gate = ScopeGuard(
        dns=MutableDnsZone(),
        http=SafeHttpClient(MutableDnsZone()),
        ownership=DbOwnershipChecker(factory),
        classify=lambda _host: PublicSuffix.ROOT,
        active_scans_enabled=enabled,
    )

    run_check(
        db_session,
        scan.org_id,
        job.id,
        registry=_active_registry(),
        gate=gate,
        events=_NoEvents(),  # type: ignore[arg-type]
        retry_allowed=False,
    )

    db_session.refresh(job)
    assert job.status is expected_status
    if expected_error is None:
        assert job.error is None
    else:
        assert expected_error in (job.error or "")
