"""AI Celery task tests: connection test runs asynchronously with TrackedTask lifecycle."""

import base64
from uuid import uuid4

import pytest
from pydantic import SecretStr
from sqlalchemy.orm import Session, sessionmaker

from attacksurf.domain.accounts import Role
from attacksurf.domain.llm import KeySource, LLMUnavailable, ProviderKind, TokenUsage
from attacksurf.domain.scans import JobStatus
from attacksurf.infra.db.models import Job, LLMUsage, Membership, Org, User
from attacksurf.infra.db.tenancy import scoped
from attacksurf.services import org_settings
from attacksurf.workers import runtime
from attacksurf.workers.app import app
from attacksurf.workers.tasks import ai as ai_tasks
from tests.fakes import FakeLLMProvider, FakeQueue
from tests.helpers import make_settings

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
