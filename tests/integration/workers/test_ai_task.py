"""AI Celery tasks: the connection test and the triage run, with the TrackedTask lifecycle."""

import base64
from typing import Any
from uuid import UUID, uuid4

import pytest
from celery.backends.cache import CacheBackend
from pydantic import SecretStr
from sqlalchemy.orm import Session, sessionmaker

from attacksurf.domain.accounts import Role
from attacksurf.domain.assets import AssetSource, AssetType
from attacksurf.domain.llm import KeySource, LLMUnavailable, ProviderKind, TokenUsage
from attacksurf.domain.scans import JobStatus, ScanStatus
from attacksurf.infra.db.models import (
    Finding,
    FindingObservation,
    Job,
    LLMUsage,
    Membership,
    Org,
    Scan,
    User,
)
from attacksurf.infra.db.tenancy import scoped
from attacksurf.services import jobs, org_settings
from attacksurf.services import triage as triage_service
from attacksurf.services.assets import record_asset
from attacksurf.workers import runtime
from attacksurf.workers.app import app
from attacksurf.workers.tasks import ai as ai_tasks
from tests.fakes import FakeLLMProvider, FakeQueue
from tests.helpers import make_settings
from tests.integration.factories import make_finding, make_scan

APP_KEY = base64.urlsafe_b64encode(b"3" * 32).decode().rstrip("=")


class _FakeDns:
    def resolve_ipv4(self, host: str) -> tuple[str, ...]:
        return ("93.184.216.34",)

    def resolve_name(self, host: str) -> tuple[str, ...]:
        return ("93.184.216.34",)

    def lookup_many(self, queries: object) -> tuple[()]:
        return ()


@pytest.fixture
def worker_env(db_session: Session, monkeypatch: pytest.MonkeyPatch) -> sessionmaker[Session]:
    factory = sessionmaker(
        bind=db_session.connection(),
        join_transaction_mode="create_savepoint",
        expire_on_commit=False,
    )
    configured = make_settings(
        env="test",
        secret_key=SecretStr("test-secret-key"),
        app_encryption_key=SecretStr(APP_KEY),
    )
    monkeypatch.setattr(runtime, "session_factory", lambda: factory)
    monkeypatch.setattr(runtime, "settings", lambda: configured)
    monkeypatch.setattr(runtime, "dns_resolver", _FakeDns)
    monkeypatch.setitem(app.conf, "task_always_eager", True)
    monkeypatch.setitem(app.conf, "task_eager_propagates", False)
    return factory


def _setup_org(db_session: Session) -> tuple[Org, User, Job]:
    org = Org(name="acme", slug=f"acme-{uuid4().hex[:8]}")
    user = User(email=f"alice-{uuid4().hex[:8]}@example.com", password_hash="x")
    db_session.add_all([org, user])
    db_session.flush()
    db_session.add(Membership(org_id=org.id, user_id=user.id, role=Role.OWNER))
    db_session.commit()
    settings = runtime.settings()
    org_settings.update_org_settings(
        db_session,
        org.id,
        ai_enabled=True,
        provider=ProviderKind.ANTHROPIC,
        model="muse-spark-1.3",
        base_url=None,
        api_key="sk-ant-worker-test-1234",
        actor_id=user.id,
        settings=settings,
        resolver=_FakeDns(),
    )
    job = org_settings.queue_ai_connection_test(
        db_session,
        FakeQueue(db_session),
        org.id,
        settings,
        resolver=_FakeDns(),
    )
    return org, user, job


def test_ai_connection_test_task_completes_and_records_usage(
    worker_env: sessionmaker[Session],
    db_session: Session,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    org, _user, job = _setup_org(db_session)
    provider = FakeLLMProvider('{"ok": true}')
    monkeypatch.setattr(org_settings, "build_provider", lambda _cfg: provider)

    result = ai_tasks.test_connection.apply(kwargs={"org_id": str(org.id), "job_id": str(job.id)})

    assert result.successful()
    db_session.expire_all()
    refreshed = db_session.get(Job, job.id)
    assert refreshed is not None
    assert refreshed.status is JobStatus.COMPLETED
    assert refreshed.attempts == 1
    usage = db_session.scalars(scoped(LLMUsage, org.id)).one()
    assert usage.purpose == "connection_test"
    assert usage.key_source is KeySource.ORG
    assert usage.success is True


def test_ai_connection_test_task_fails_without_retrying_on_transient_llm_error(
    worker_env: sessionmaker[Session],
    db_session: Session,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    org, _user, job = _setup_org(db_session)
    provider = FakeLLMProvider(
        LLMUnavailable("The AI provider took too long to answer.", usage=TokenUsage(10, 5))
    )
    monkeypatch.setattr(org_settings, "build_provider", lambda _cfg: provider)

    result = ai_tasks.test_connection.apply(kwargs={"org_id": str(org.id), "job_id": str(job.id)})

    assert not result.successful()
    db_session.expire_all()
    refreshed = db_session.get(Job, job.id)
    assert refreshed is not None
    assert refreshed.status is JobStatus.FAILED
    assert refreshed.attempts == 1
    assert refreshed.error == "JobError: The AI provider took too long to answer."
    usage = db_session.scalars(scoped(LLMUsage, org.id)).one()
    assert usage.purpose == "connection_test"
    assert usage.success is False
    assert usage.error_type == "LLMUnavailable"
    assert usage.input_tokens == 10
    assert usage.output_tokens == 5


# --- ai.triage: runs after the scan, never changes it (ADR 0029) ---------------------------


def _ai_on(monkeypatch: pytest.MonkeyPatch, *, budget: int = 500_000) -> None:
    configured = make_settings(
        env="test",
        secret_key=SecretStr("test-secret-key"),
        llm_api_key=SecretStr("instance-key"),
        llm_model="muse-spark-1.3",
        llm_monthly_instance_token_budget=budget,
    )
    monkeypatch.setattr(runtime, "settings", lambda: configured)


def _triage_job(db_session: Session) -> Job:
    scan = make_scan(db_session)
    scan.status = ScanStatus.COMPLETED
    return jobs.create_job(
        db_session,
        FakeQueue(db_session),
        org_id=scan.org_id,
        scan_id=scan.id,
        stage="triage",
        task_name="ai.triage",
    )


def _run_triage(job: Job, org_id: UUID | None = None) -> Any:
    return ai_tasks.triage.apply(
        kwargs={"org_id": str(org_id or job.org_id), "job_id": str(job.id)}
    )


def _scan_status(db_session: Session, job: Job) -> ScanStatus:
    scan = db_session.get(Scan, job.scan_id)
    assert scan is not None
    return scan.status


def test_triage_task_is_skipped_with_a_notice_when_ai_is_off(
    worker_env: sessionmaker[Session], db_session: Session
) -> None:
    job = _triage_job(db_session)  # worker_env has no LLM key or model

    _run_triage(job)

    db_session.expire_all()
    assert job.status is JobStatus.SKIPPED
    assert job.error == "AI is disabled or not configured."


def test_triage_task_is_skipped_with_a_notice_when_the_budget_is_spent(
    worker_env: sessionmaker[Session], db_session: Session, monkeypatch: pytest.MonkeyPatch
) -> None:
    _ai_on(monkeypatch, budget=1_000)
    job = _triage_job(db_session)
    db_session.add(
        LLMUsage(
            org_id=job.org_id,
            provider=ProviderKind.ANTHROPIC,
            model="muse-spark-1.3",
            purpose="triage",
            key_source=KeySource.INSTANCE,
            input_tokens=700,
            output_tokens=300,
            usage_reported=True,
            estimated_cost_usd=None,
            latency_ms=100,
            success=True,
        )
    )
    db_session.commit()

    _run_triage(job)

    db_session.expire_all()
    assert job.status is JobStatus.SKIPPED
    assert "budget exceeded" in (job.error or "").lower()
    assert _scan_status(db_session, job) is ScanStatus.COMPLETED


def test_triage_task_completes_when_ai_is_on(
    worker_env: sessionmaker[Session], db_session: Session, monkeypatch: pytest.MonkeyPatch
) -> None:
    _ai_on(monkeypatch)
    job = _triage_job(db_session)

    result = _run_triage(job)

    assert result.successful()
    db_session.expire_all()
    assert job.status is JobStatus.COMPLETED


def test_a_failing_triage_task_fails_only_its_job(
    worker_env: sessionmaker[Session], db_session: Session, monkeypatch: pytest.MonkeyPatch
) -> None:
    def fail(*args: object, **kwargs: object) -> None:
        raise RuntimeError("secret driver detail")

    monkeypatch.setattr(org_settings, "enforce_triage_budget", fail)
    job = _triage_job(db_session)

    result = _run_triage(job)

    assert not result.successful()
    db_session.expire_all()
    assert job.status is JobStatus.FAILED
    assert job.error == "RuntimeError"  # the message never reaches the job row
    assert _scan_status(db_session, job) is ScanStatus.COMPLETED


def test_triage_task_never_touches_another_orgs_job(
    worker_env: sessionmaker[Session], db_session: Session
) -> None:
    job = _triage_job(db_session)
    other = make_scan(db_session, "other")

    _run_triage(job, org_id=other.org_id)

    db_session.expire_all()
    assert job.status is JobStatus.QUEUED


def _observed(db_session: Session, scan: Scan, asset_id: UUID, rule_id: str) -> Finding:
    finding = make_finding(db_session, scan.org_id, asset_id, rule_id=rule_id)
    db_session.add(
        FindingObservation(
            org_id=scan.org_id, scan_id=scan.id, finding_id=finding.id, severity=finding.severity
        )
    )
    db_session.flush()
    return finding


def _judgment_reply() -> str:
    return (
        '{"findings": [{"ref": "F1", "adjusted_severity": "high", "confidence": "high", '
        '"false_positive_likelihood": "low", "priority": "P2", "rationale": "Confirmed.", '
        '"exploitability": "", "remediation_steps": ["Fix the record."]}]}'
    )


def test_a_triage_run_judges_every_asset_and_closes_cleanly(
    worker_env: sessionmaker[Session], db_session: Session, monkeypatch: pytest.MonkeyPatch
) -> None:
    _ai_on(monkeypatch)
    # Celery's _backend property setter cannot restore None; patch its thread-local cache.
    monkeypatch.setattr(
        app.__dict__["_local"], "backend", CacheBackend(app=app, backend="memory"), raising=False
    )
    job = _triage_job(db_session)
    scan = db_session.get(Scan, job.scan_id)
    assert scan is not None
    cdn = record_asset(
        db_session,
        scan.org_id,
        AssetType.SUBDOMAIN,
        "cdn.acme.example",
        source=AssetSource.DISCOVERED,
        parent_id=scan.root_asset_id,
    )
    findings = [
        _observed(db_session, scan, scan.root_asset_id, "dns.email.dmarc_missing"),
        _observed(db_session, scan, cdn.id, "dns.takeover.dangling_cname"),
    ]
    db_session.commit()
    monkeypatch.setattr(
        triage_service,
        "build_provider",
        lambda _config: FakeLLMProvider(_judgment_reply()),
    )

    result = _run_triage(job)

    assert result.successful()
    db_session.expire_all()
    assert all(triage_service.stored_triage(finding) is not None for finding in findings)
    statuses = sorted(
        (row.stage, row.status)
        for row in db_session.scalars(scoped(Job, scan.org_id).where(Job.scan_id == scan.id))
    )
    assert statuses == [
        ("triage", JobStatus.COMPLETED),
        ("triage_batch", JobStatus.COMPLETED),
        ("triage_batch", JobStatus.COMPLETED),
        ("triage_done", JobStatus.COMPLETED),
        ("triage_failure", JobStatus.SKIPPED),
    ]
    assert len(db_session.scalars(scoped(LLMUsage, scan.org_id)).all()) == 2
    assert _scan_status(db_session, job) is ScanStatus.COMPLETED


def test_a_crashing_batch_task_stores_only_a_safe_error(
    worker_env: sessionmaker[Session], db_session: Session, monkeypatch: pytest.MonkeyPatch
) -> None:
    _ai_on(monkeypatch)
    job = _triage_job(db_session)
    scan = db_session.get(Scan, job.scan_id)
    assert scan is not None
    _observed(db_session, scan, scan.root_asset_id, "dns.email.dmarc_missing")
    batch = jobs.record_job(
        db_session,
        org_id=scan.org_id,
        scan_id=scan.id,
        stage="triage_batch",
        asset_id=scan.root_asset_id,
    )
    db_session.commit()

    def crash(_config: object) -> None:
        raise RuntimeError("secret provider detail")

    monkeypatch.setattr(triage_service, "build_provider", crash)

    result = ai_tasks.triage_batch.apply(
        kwargs={"org_id": str(batch.org_id), "job_id": str(batch.id)}
    )

    assert not result.successful()
    assert "secret" not in repr(result.result)
    db_session.expire_all()
    assert batch.status is JobStatus.FAILED
    assert "secret" not in (batch.error or "")
    assert _scan_status(db_session, job) is ScanStatus.COMPLETED
