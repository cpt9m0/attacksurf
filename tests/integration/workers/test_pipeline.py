from datetime import UTC, datetime, timedelta
from threading import Event
from uuid import UUID, uuid4

import pytest
from celery.backends.cache import CacheBackend
from sqlalchemy import update
from sqlalchemy.orm import Session, sessionmaker

from attacksurf.domain.assets import AssetNotFound
from attacksurf.domain.events import FindingCreated, FindingFixed, ScanCompleted
from attacksurf.domain.findings import FindingStatus
from attacksurf.domain.jobs import JobNotFound, JobTask, TransientJobError
from attacksurf.domain.scanners import (
    AssetRef,
    ClosedGate,
    RawFinding,
    ScanContext,
    ScanOutput,
    ScanProfile,
)
from attacksurf.domain.scans import JobStatus, ScanStatus, ScanTrigger
from attacksurf.infra.db.models import Asset, AssetRelation, Evidence, Finding, Job, Scan
from attacksurf.infra.db.tenancy import scoped
from attacksurf.infra.events import InProcessDispatcher
from attacksurf.services import assets as assets_service
from attacksurf.services import jobs, scanner_jobs, scans
from attacksurf.services.scan_results import persist_scan_output
from attacksurf.workers import runtime
from attacksurf.workers.app import app
from attacksurf.workers.tasks import pipeline
from tests.fakes import FakeQueue
from tests.integration.factories import make_scan
from tests.scanner_fixtures import PROFILES, RULE, FakeCheck, FixtureGate, fixture_registry


@pytest.fixture
def pipeline_env(db_session: Session, monkeypatch: pytest.MonkeyPatch) -> InProcessDispatcher:
    factory = sessionmaker(
        bind=db_session.connection(),
        join_transaction_mode="create_savepoint",
        expire_on_commit=False,
    )
    monkeypatch.setattr(runtime, "session_factory", lambda: factory)
    monkeypatch.setattr(runtime, "scanner_gate", FixtureGate)
    monkeypatch.setattr(pipeline, "registry", fixture_registry())
    monkeypatch.setattr(pipeline, "PROFILES", PROFILES)
    monkeypatch.setattr(pipeline, "RULES", {RULE.id: RULE})
    events = InProcessDispatcher()
    monkeypatch.setattr(pipeline, "dispatcher", events)
    monkeypatch.setitem(app.conf, "task_always_eager", True)
    monkeypatch.setitem(app.conf, "task_eager_propagates", False)
    # Celery's _backend property setter cannot restore None; patch its thread-local cache.
    monkeypatch.setattr(
        app.__dict__["_local"], "backend", CacheBackend(app=app, backend="memory"), raising=False
    )
    return events


def test_fake_scanner_pipeline_completes_with_assets_findings_and_isolated_errors(
    db_session: Session,
    pipeline_env: InProcessDispatcher,
) -> None:
    root_scan = make_scan(db_session)
    scan = scans.start_scan(
        db_session,
        FakeQueue(db_session),
        org_id=root_scan.org_id,
        root_asset_id=root_scan.root_asset_id,
        profile="fixture",
        registry=fixture_registry(),
        profiles=PROFILES,
    )
    received = []
    pipeline_env.handlers.append(received.append)
    kickoff = db_session.scalars(scoped(Job, scan.org_id).where(Job.scan_id == scan.id)).one()

    pipeline.discover.apply(kwargs={"org_id": str(scan.org_id), "job_id": str(kickoff.id)})

    db_session.expire_all()
    assert scan.status == ScanStatus.COMPLETED
    assert scan.started_at is not None
    assert scan.finished_at is not None
    assert scan.started_at <= scan.finished_at
    assert len(db_session.scalars(scoped(Asset, scan.org_id)).all()) == 2
    assert len(db_session.scalars(scoped(AssetRelation, scan.org_id)).all()) == 1
    assert len(db_session.scalars(scoped(Finding, scan.org_id)).all()) == 2
    assert len(db_session.scalars(scoped(Evidence, scan.org_id)).all()) == 2
    failed = db_session.scalars(
        scoped(Job, scan.org_id).where(Job.status == JobStatus.FAILED)
    ).all()
    assert len(failed) == 2
    assert all(job.error == "RuntimeError" for job in failed)
    assert sum(isinstance(event, FindingCreated) for event in received) == 2
    assert sum(isinstance(event, ScanCompleted) for event in received) == 1

    pipeline.discover.apply(kwargs={"org_id": str(scan.org_id), "job_id": str(kickoff.id)})
    assert len(db_session.scalars(scoped(Evidence, scan.org_id)).all()) == 2
    assert len(received) == 3


def test_diff_task_fixes_a_finding_its_scanner_completed_for(
    db_session: Session, pipeline_env: InProcessDispatcher
) -> None:
    tenant = make_scan(db_session)
    base = datetime(2026, 11, 1, tzinfo=UTC)
    first = Scan(
        org_id=tenant.org_id,
        root_asset_id=tenant.root_asset_id,
        profile="dns_passive",
        status=ScanStatus.RUNNING,
        triggered_by=ScanTrigger.USER,
        started_at=base,
    )
    db_session.add(first)
    db_session.flush()
    persist_scan_output(
        db_session,
        first,
        first.root_asset_id,
        ScanOutput(findings=(RawFinding(rule_id=RULE.id),)),
        catalog={RULE.id: RULE},
        scanner=FakeCheck.name,
    )
    first.status = ScanStatus.COMPLETED
    first.finished_at = first.started_at
    second = Scan(
        org_id=tenant.org_id,
        root_asset_id=tenant.root_asset_id,
        profile="dns_passive",
        status=ScanStatus.RUNNING,
        triggered_by=ScanTrigger.USER,
        started_at=base + timedelta(hours=1),
    )
    db_session.add(second)
    db_session.flush()
    db_session.add(
        Job(
            org_id=tenant.org_id,
            scan_id=second.id,
            stage="check",
            scanner=FakeCheck.name,
            asset_id=second.root_asset_id,
            status=JobStatus.COMPLETED,
        )
    )
    diff_job = jobs.create_job(
        db_session,
        FakeQueue(db_session),
        org_id=tenant.org_id,
        scan_id=second.id,
        stage="diff",
        task_name="passive.diff",
    )
    received: list[object] = []
    pipeline_env.handlers.append(received.append)

    pipeline.diff.apply(kwargs={"org_id": str(second.org_id), "job_id": str(diff_job.id)})

    db_session.expire_all()
    finding = db_session.scalars(scoped(Finding, tenant.org_id)).one()
    assert finding.status is FindingStatus.FIXED
    assert diff_job.status is JobStatus.COMPLETED
    assert second.stats["findings"]["fixed"]["total"] == 1
    assert [type(event) for event in received] == [FindingFixed]


def test_start_scan_rejects_another_tenants_root(db_session: Session) -> None:
    scan = make_scan(db_session)
    with pytest.raises(AssetNotFound):
        scans.start_scan(
            db_session,
            FakeQueue(db_session),
            org_id=uuid4(),
            root_asset_id=scan.root_asset_id,
            profile="fixture",
            registry=fixture_registry(),
            profiles=PROFILES,
        )


def _check_job(session: Session, name: str = FakeCheck.name) -> Job:
    scan = make_scan(session)
    return jobs.create_job(
        session,
        FakeQueue(session),
        org_id=scan.org_id,
        scan_id=scan.id,
        stage="check",
        task_name="passive.scan",
        scanner=name,
        asset_id=scan.root_asset_id,
    )


def test_default_gate_skips_a_scanner_without_running_it(
    db_session: Session,
    pipeline_env: InProcessDispatcher,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(runtime, "scanner_gate", ClosedGate)
    job = _check_job(db_session)
    pipeline.scan.apply(kwargs={"org_id": str(job.org_id), "job_id": str(job.id)})
    db_session.expire_all()
    assert job.status == JobStatus.SKIPPED
    assert db_session.scalars(scoped(Finding, job.org_id)).all() == []


@pytest.mark.parametrize("failures", [2, 99])
def test_transient_scanner_failure_retries_then_isolates_exhaustion(
    db_session: Session,
    pipeline_env: InProcessDispatcher,
    failures: int,
) -> None:
    calls = []

    class RetryingCheck(FakeCheck):
        name = "fixture.retry"

        def run(self, ctx: ScanContext, asset: AssetRef) -> ScanOutput:
            calls.append(1)
            if len(calls) <= failures:
                raise TransientJobError("Fixture timeout.")
            return super().run(ctx, asset)

    pipeline.registry.register(RetryingCheck)
    job = _check_job(db_session, RetryingCheck.name)
    result = pipeline.scan.apply(kwargs={"org_id": str(job.org_id), "job_id": str(job.id)})
    db_session.expire_all()
    assert result.successful()  # even exhausted checks release the chord
    assert job.attempts == min(failures + 1, 4)
    assert job.status == (JobStatus.COMPLETED if failures == 2 else JobStatus.FAILED)
    if job.status == JobStatus.COMPLETED:
        assert job.error is None


def test_cancelled_scan_does_not_persist_late_output(
    db_session: Session,
    pipeline_env: InProcessDispatcher,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    job = _check_job(db_session)
    real = pipeline.registry.get(FakeCheck.name).run

    def cancel_then_return(scanner: object, ctx: ScanContext, asset: AssetRef) -> ScanOutput:
        # Simulate cancellation in the execution window, without accessing DB from a thread.
        parent = db_session.get(Scan, job.scan_id)
        assert parent is not None
        parent.status = ScanStatus.CANCELLED
        db_session.commit()
        return real(ctx, asset)

    monkeypatch.setattr("attacksurf.services.scanner_jobs.run_scanner", cancel_then_return)
    pipeline.scan.apply(kwargs={"org_id": str(job.org_id), "job_id": str(job.id)})
    db_session.expire_all()
    assert job.status == JobStatus.SKIPPED
    assert db_session.scalars(scoped(Finding, job.org_id)).all() == []


def test_pipeline_task_rejects_other_tenants_job(
    db_session: Session,
    pipeline_env: InProcessDispatcher,
) -> None:
    job = _check_job(db_session)
    with pytest.raises(JobNotFound):
        scans.load_job_scan(db_session, uuid4(), job.id)
    assert job.status == JobStatus.QUEUED


def test_empty_profile_is_rejected_without_creating_a_scan(db_session: Session) -> None:
    parent = make_scan(db_session)
    with pytest.raises(ValueError, match="no scanners"):
        scans.start_scan(
            db_session,
            FakeQueue(db_session),
            org_id=parent.org_id,
            root_asset_id=parent.root_asset_id,
            profile="empty",
            registry=fixture_registry(),
            profiles={"empty": ScanProfile("empty")},
        )


def test_broker_failure_fails_the_scan_and_its_kickoff_job(db_session: Session) -> None:
    parent = make_scan(db_session)
    with pytest.raises(ConnectionError):
        scans.start_scan(
            db_session,
            FakeQueue(db_session, fail=True),
            org_id=parent.org_id,
            root_asset_id=parent.root_asset_id,
            profile="fixture",
            registry=fixture_registry(),
            profiles=PROFILES,
        )
    failed = db_session.scalars(scoped(Scan, parent.org_id).where(Scan.id != parent.id)).one()
    assert failed.status == ScanStatus.FAILED
    assert (
        db_session.scalars(scoped(Job, parent.org_id).where(Job.scan_id == failed.id)).one().status
        == JobStatus.FAILED
    )


def test_unexpected_orchestration_failure_fails_scan_without_leaking_messages(
    db_session: Session,
    pipeline_env: InProcessDispatcher,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    job = _check_job(db_session)
    monkeypatch.setitem(app.conf, "task_eager_propagates", False)

    def fail(*args: object, **kwargs: object) -> None:
        raise RuntimeError("secret driver URL")

    monkeypatch.setattr(scans, "dispatch_stage", fail)
    result = pipeline.discover.apply(kwargs={"org_id": str(job.org_id), "job_id": str(job.id)})
    db_session.expire_all()
    parent = db_session.get(Scan, job.scan_id)
    assert parent is not None
    assert parent.status == ScanStatus.FAILED
    assert "secret" not in repr(result.result)
    assert "secret" not in (job.error or "")


def test_finalize_refuses_pending_work(db_session: Session) -> None:
    job = _check_job(db_session)
    with pytest.raises(ValueError, match="pending"):
        scans.finalize_scan(db_session, job.org_id, job.id, InProcessDispatcher())


def test_scanner_timeout_fails_only_job_and_discards_late_findings(
    db_session: Session,
    pipeline_env: InProcessDispatcher,
) -> None:
    release, finished = Event(), Event()

    class SlowCheck(FakeCheck):
        name = "fixture.slow"
        timeout_seconds = 0.01

        def run(self, ctx: ScanContext, asset: AssetRef) -> ScanOutput:
            release.wait(timeout=2)
            finished.set()
            return super().run(ctx, asset)

    pipeline.registry.register(SlowCheck)
    job = _check_job(db_session, SlowCheck.name)
    try:
        result = pipeline.scan.apply(kwargs={"org_id": str(job.org_id), "job_id": str(job.id)})
        db_session.expire_all()
        assert result.successful()
        assert job.status == JobStatus.FAILED
        assert "time budget" in (job.error or "")
    finally:
        release.set()
        assert finished.wait(timeout=2)
    assert db_session.scalars(scoped(Finding, job.org_id)).all() == []


def test_malformed_plugin_result_fails_only_its_job(
    db_session: Session,
    pipeline_env: InProcessDispatcher,
) -> None:
    class UnknownRuleCheck(FakeCheck):
        name = "fixture.unknown_rule"

        def run(self, ctx: ScanContext, asset: AssetRef) -> ScanOutput:
            return ScanOutput(findings=(RawFinding(rule_id="unknown.fixture.issue"),))

    pipeline.registry.register(UnknownRuleCheck)
    job = _check_job(db_session, UnknownRuleCheck.name)
    result = pipeline.scan.apply(kwargs={"org_id": str(job.org_id), "job_id": str(job.id)})
    db_session.expire_all()
    assert result.successful()
    assert job.status == JobStatus.FAILED
    assert job.error == "UnknownRule"
    parent = db_session.get(Scan, job.scan_id)
    assert parent is not None
    assert parent.status == ScanStatus.RUNNING


def test_workflow_broker_failure_marks_committed_batch_and_scan_failed(db_session: Session) -> None:
    parent = make_scan(db_session)
    parent.profile = "fixture"
    kickoff = jobs.create_job(
        db_session,
        FakeQueue(db_session),
        org_id=parent.org_id,
        scan_id=parent.id,
        stage="discover",
        task_name="passive.discover",
    )
    sent = []

    class BrokenQueue:
        def enqueue_workflow(
            self,
            header: tuple[JobTask, ...],
            tail: tuple[JobTask, ...],
            error: JobTask,
        ) -> None:
            assert not db_session.in_transaction()
            sent.extend((*header, *tail))
            raise ConnectionError("fixture broker failure")

    with pytest.raises(ConnectionError):
        scans.dispatch_stage(
            db_session,
            BrokenQueue(),
            parent.org_id,
            kickoff.id,
            registry=fixture_registry(),
            profiles=PROFILES,
        )

    db_session.expire_all()
    assert parent.status == ScanStatus.FAILED
    assert sent
    for task in sent:
        row = db_session.get(Job, task.job_id)
        assert row is not None
        assert row.status == JobStatus.FAILED


def test_failure_callback_is_idempotent_and_cancels_queued_work(
    db_session: Session,
    pipeline_env: InProcessDispatcher,
) -> None:
    pending = _check_job(db_session)
    callback = jobs.create_job(
        db_session,
        FakeQueue(db_session),
        org_id=pending.org_id,
        scan_id=pending.scan_id,
        stage="failure",
        task_name="passive.fail_scan",
    )
    kwargs = {"org_id": str(callback.org_id), "job_id": str(callback.id)}
    pipeline.fail_scan.apply(kwargs=kwargs)
    pipeline.fail_scan.apply(kwargs=kwargs)
    db_session.expire_all()
    assert callback.attempts == 1
    assert callback.status == JobStatus.COMPLETED
    assert pending.status == JobStatus.CANCELLED
    parent = db_session.get(Scan, pending.scan_id)
    assert parent is not None
    assert parent.status == ScanStatus.FAILED


def _started_scan(session: Session, name: str) -> tuple[Scan, Job]:
    root = make_scan(session, name)
    scan = scans.start_scan(
        session,
        FakeQueue(session),
        org_id=root.org_id,
        root_asset_id=root.root_asset_id,
        profile="fixture",
        registry=fixture_registry(),
        profiles=PROFILES,
    )
    kickoff = session.scalars(scoped(Job, scan.org_id).where(Job.scan_id == scan.id)).one()
    return scan, kickoff


def _scanner_blocks_while_root_is_archived(
    session: Session, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Run the real plugin, but archive the root before its output is persisted.

    Stands in for an archive that commits while the scanner is still doing I/O: the same
    window in production, without touching the session from the scanner's daemon thread.
    """
    real = scanner_jobs.run_scanner

    def archive_then_return(scanner: object, ctx: ScanContext, asset: AssetRef) -> ScanOutput:
        scan = session.get(Scan, ctx.scan_id)
        assert scan is not None
        assets_service.archive_root_domain(session, scan.org_id, scan.root_asset_id, actor_id=None)
        return real(scanner, ctx, asset)  # type: ignore[arg-type]

    monkeypatch.setattr(scanner_jobs, "run_scanner", archive_then_return)


def test_archiving_during_discovery_leaves_no_active_assets_or_findings(
    db_session: Session,
    pipeline_env: InProcessDispatcher,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    scan, kickoff = _started_scan(db_session, "archived")
    _scanner_blocks_while_root_is_archived(db_session, monkeypatch)

    pipeline.discover.apply(kwargs={"org_id": str(scan.org_id), "job_id": str(kickoff.id)})

    db_session.expire_all()
    assert scan.status == ScanStatus.CANCELLED
    assert db_session.scalars(scoped(Finding, scan.org_id)).all() == []
    discovered = db_session.scalars(
        scoped(Asset, scan.org_id).where(Asset.parent_id == scan.root_asset_id)
    ).all()
    assert [asset for asset in discovered if asset.is_active] == []


def test_archiving_during_checks_records_no_findings_and_keeps_the_scan_cancelled(
    db_session: Session,
    pipeline_env: InProcessDispatcher,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    job = _check_job(db_session)
    _scanner_blocks_while_root_is_archived(db_session, monkeypatch)

    pipeline.scan.apply(kwargs={"org_id": str(job.org_id), "job_id": str(job.id)})

    db_session.expire_all()
    assert db_session.scalars(scoped(Finding, job.org_id)).all() == []
    assert job.status in {JobStatus.SKIPPED, JobStatus.CANCELLED}
    parent = db_session.get(Scan, job.scan_id)
    assert parent is not None
    assert parent.status == ScanStatus.CANCELLED


def test_persist_writes_nothing_for_an_archived_root_even_if_the_scan_reads_running(
    db_session: Session,
    pipeline_env: InProcessDispatcher,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The status check can lose a race with a concurrent archive; the root check must not."""
    job = _check_job(db_session)
    real_persist = scanner_jobs.persist_scan_output
    scan_id = job.scan_id

    def archive_then_persist(*args: object, **kwargs: object) -> list[FindingCreated]:
        # Same row order the real race produces; the scan row is left RUNNING on purpose.
        db_session.execute(
            update(Asset)
            .where(Asset.id == job.asset_id)
            .values(is_active=False, deactivated_at=datetime.now(UTC))
        )
        db_session.execute(update(Scan).where(Scan.id == scan_id).values(status=ScanStatus.RUNNING))
        return real_persist(*args, **kwargs)  # type: ignore[no-any-return]

    real_load = scans.load_job_scan

    def load_stale_status(session: Session, org_id: UUID, job_id: UUID) -> tuple[Job, Scan]:
        loaded = real_load(session, org_id, job_id)
        loaded[1].status = ScanStatus.RUNNING  # the status re-check misses the archive
        return loaded

    monkeypatch.setattr(scanner_jobs, "load_job_scan", load_stale_status)
    monkeypatch.setattr(scanner_jobs, "persist_scan_output", archive_then_persist)

    pipeline.scan.apply(kwargs={"org_id": str(job.org_id), "job_id": str(job.id)})

    db_session.expire_all()
    assert db_session.scalars(scoped(Finding, job.org_id)).all() == []
    assert job.status == JobStatus.FAILED
    assert job.error == "AssetNotFound"  # type only: not a JobError (ADR 0010)


def test_dispatch_of_a_scan_the_archive_missed_does_not_leave_it_queued(
    db_session: Session,
    pipeline_env: InProcessDispatcher,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Regression: the archive committed between `start_scan`'s read and the insert, so its
    cancellation never saw the scan. Dispatching used to return silently, leaving it `queued`.
    """
    scan, kickoff = _started_scan(db_session, "missed")
    real_root_active = scans.root_is_active
    monkeypatch.setattr(scans, "root_is_active", lambda *args: False)  # the root was archived

    pipeline.discover.apply(kwargs={"org_id": str(scan.org_id), "job_id": str(kickoff.id)})

    db_session.expire_all()
    assert real_root_active(db_session, scan.org_id, scan)  # this test archived nothing
    assert scan.status == ScanStatus.CANCELLED
    assert scan.finished_at is not None
    assert kickoff.status == JobStatus.SKIPPED
