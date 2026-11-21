"""Organization LLM settings, encrypted keys, budget enforcement and connection tests (#24)."""

import base64
from datetime import UTC, datetime, timedelta
from decimal import Decimal
from typing import Any

import pytest
from pydantic import SecretStr
from sqlalchemy import event, select
from sqlalchemy.orm import Session

from attacksurf.domain.accounts import Role
from attacksurf.domain.jobs import JobError
from attacksurf.domain.llm import (
    KeySource,
    LLMAuthError,
    LLMConfig,
    LLMUnavailable,
    ProviderKind,
    TokenUsage,
)
from attacksurf.domain.scans import JobStatus
from attacksurf.domain.scope import ScopeError
from attacksurf.infra.db.models import AuditLog, Job, LLMUsage, Membership, Org, OrgSettings, User
from attacksurf.infra.db.tenancy import scoped
from attacksurf.services import jobs
from attacksurf.services.org_settings import (
    QUEUE_STALL_AFTER,
    AITestState,
    EncryptionNotConfigured,
    InvalidOrgSettings,
    OrgSettingsError,
    check_llm_budget,
    clear_org_api_key,
    enforce_triage_budget,
    get_ai_test_status,
    get_org_budget_overview,
    get_org_settings,
    load_org_llm_config,
    queue_ai_connection_test,
    resolve_org_llm_config,
    run_ai_connection_test,
    update_org_settings,
)
from tests.fakes import FakeLLMProvider, FakeQueue
from tests.helpers import make_settings
from tests.integration.factories import make_scan

APP_KEY_1 = base64.urlsafe_b64encode(b"1" * 32).decode().rstrip("=")
APP_KEY_2 = base64.urlsafe_b64encode(b"2" * 32).decode().rstrip("=")


class FakeDns:
    def __init__(self, answers: dict[str, tuple[str, ...]] | None = None) -> None:
        self.answers = answers or {}

    def resolve_ipv4(self, host: str) -> tuple[str, ...]:
        return self.answers.get(host, ("93.184.216.34",))

    def resolve_name(self, host: str) -> tuple[str, ...]:
        return self.answers.get(host, ("93.184.216.34",))

    def lookup_many(self, queries: object) -> tuple[()]:
        return ()


@pytest.fixture
def actor(db_session: Session) -> tuple[Org, User]:
    org = Org(name="acme", slug="acme")
    user = User(email="alice@example.com", password_hash="x")
    db_session.add_all([org, user])
    db_session.flush()
    db_session.add(Membership(org_id=org.id, user_id=user.id, role=Role.OWNER))
    db_session.commit()
    return org, user


def test_get_org_settings_returns_defaults_when_unset(
    db_session: Session, actor: tuple[Org, User]
) -> None:
    org, _ = actor

    view = get_org_settings(db_session, org.id)

    assert view.ai_enabled is True
    assert view.provider is ProviderKind.ANTHROPIC
    assert view.model is None
    assert view.base_url is None
    assert view.has_api_key is False
    assert view.api_key_last4 is None
    assert view.monthly_token_budget is None


def test_update_org_settings_encrypts_api_key_at_rest_and_audits(
    db_session: Session, actor: tuple[Org, User]
) -> None:
    org, user = actor
    secret = "sk-ant-api03-very-secret-token-9876"
    settings = make_settings(app_encryption_key=SecretStr(APP_KEY_1))

    view = update_org_settings(
        db_session,
        org.id,
        ai_enabled=True,
        provider=ProviderKind.OPENAI_COMPAT,
        model="gpt-4o",
        base_url="https://api.openai.com/v1",
        api_key=secret,
        monthly_token_budget="250000",
        actor_id=user.id,
        settings=settings,
        resolver=FakeDns(),
    )

    assert view.has_api_key is True
    assert view.api_key_last4 == "9876"
    assert secret not in repr(view)

    row = db_session.scalars(scoped(OrgSettings, org.id)).one()
    assert row.api_key_ciphertext is not None
    assert secret.encode() not in row.api_key_ciphertext
    assert row.api_key_last4 == "9876"

    audit_entry = db_session.scalars(
        scoped(AuditLog, org.id).where(AuditLog.action == "org.ai_settings_updated")
    ).one()
    assert audit_entry.details["api_key_action"] == "set"
    assert secret not in repr(audit_entry.details)
    assert "9876" not in repr(audit_entry.details)

    loaded = load_org_llm_config(db_session, org.id, settings, resolver=FakeDns())
    assert loaded is not None
    assert loaded.api_key is not None
    assert loaded.api_key.get_secret_value() == secret
    assert loaded.base_url == SecretStr("https://api.openai.com/v1")


def test_update_keeps_existing_key_and_clear_removes_it(
    db_session: Session, actor: tuple[Org, User]
) -> None:
    org, user = actor
    settings = make_settings(app_encryption_key=SecretStr(APP_KEY_1))
    update_org_settings(
        db_session,
        org.id,
        ai_enabled=True,
        provider=ProviderKind.ANTHROPIC,
        model="claude-sonnet-4-5",
        base_url=None,
        api_key="sk-ant-keep-1111",
        actor_id=user.id,
        settings=settings,
        resolver=FakeDns(),
    )

    kept = update_org_settings(
        db_session,
        org.id,
        ai_enabled=True,
        provider=ProviderKind.ANTHROPIC,
        model="claude-sonnet-4-6",
        base_url=None,
        api_key="",
        actor_id=user.id,
        settings=settings,
        resolver=FakeDns(),
    )
    assert kept.has_api_key is True
    assert kept.api_key_last4 == "1111"

    cleared = clear_org_api_key(db_session, org.id, actor_id=user.id)
    assert cleared.has_api_key is False
    assert cleared.api_key_last4 is None
    assert load_org_llm_config(db_session, org.id, settings, resolver=FakeDns()) is None


def test_key_rotation_decrypts_key_encrypted_under_old_app_key(
    db_session: Session, actor: tuple[Org, User]
) -> None:
    org, user = actor
    old_settings = make_settings(app_encryption_key=SecretStr(APP_KEY_1))
    update_org_settings(
        db_session,
        org.id,
        ai_enabled=True,
        provider=ProviderKind.ANTHROPIC,
        model="claude-sonnet-4-5",
        base_url=None,
        api_key="sk-ant-rotated-4321",
        actor_id=user.id,
        settings=old_settings,
        resolver=FakeDns(),
    )

    rotated_settings = make_settings(
        app_encryption_key=SecretStr(APP_KEY_2),
        app_encryption_old_keys=SecretStr(APP_KEY_1),
    )
    loaded = load_org_llm_config(db_session, org.id, rotated_settings, resolver=FakeDns())
    assert loaded is not None
    assert loaded.api_key is not None
    assert loaded.api_key.get_secret_value() == "sk-ant-rotated-4321"

    # Without the old key in APP_ENCRYPTION_OLD_KEYS, load fails closed (never falls back).
    without_old = make_settings(
        app_encryption_key=SecretStr(APP_KEY_2),
        llm_api_key=SecretStr("instance-key"),
        llm_model="muse-spark-1.3",
    )
    with pytest.raises(OrgSettingsError, match="decrypted"):
        resolve_org_llm_config(db_session, org.id, without_old, resolver=FakeDns())


def test_saving_api_key_requires_app_encryption_key_and_model(
    db_session: Session, actor: tuple[Org, User]
) -> None:
    org, user = actor
    no_enc = make_settings()

    with pytest.raises(EncryptionNotConfigured, match="APP_ENCRYPTION_KEY"):
        update_org_settings(
            db_session,
            org.id,
            ai_enabled=True,
            provider=ProviderKind.ANTHROPIC,
            model="claude-sonnet-4-5",
            base_url=None,
            api_key="sk-ant-1234",
            actor_id=user.id,
            settings=no_enc,
            resolver=FakeDns(),
        )

    # Toggling AI off or setting a budget still works without APP_ENCRYPTION_KEY.
    view = update_org_settings(
        db_session,
        org.id,
        ai_enabled=False,
        provider=ProviderKind.ANTHROPIC,
        model=None,
        base_url=None,
        monthly_token_budget=10_000,
        actor_id=user.id,
        settings=no_enc,
        resolver=FakeDns(),
    )
    assert view.ai_enabled is False
    assert view.monthly_token_budget == 10_000

    with_enc = make_settings(app_encryption_key=SecretStr(APP_KEY_1))
    with pytest.raises(InvalidOrgSettings, match="model"):
        update_org_settings(
            db_session,
            org.id,
            ai_enabled=True,
            provider=ProviderKind.ANTHROPIC,
            model="",
            base_url=None,
            api_key="sk-ant-1234",
            actor_id=user.id,
            settings=with_enc,
            resolver=FakeDns(),
        )


def test_ssrf_base_url_blocked_on_save_and_revalidated_on_load(
    db_session: Session, actor: tuple[Org, User]
) -> None:
    org, user = actor
    settings = make_settings(app_encryption_key=SecretStr(APP_KEY_1))

    with pytest.raises(InvalidOrgSettings):
        update_org_settings(
            db_session,
            org.id,
            ai_enabled=True,
            provider=ProviderKind.OPENAI_COMPAT,
            model="llama3",
            base_url="http://169.254.169.254/latest/meta-data",
            api_key="sk-1234",
            actor_id=user.id,
            settings=settings,
            resolver=FakeDns(),
        )

    # Save a valid public URL, then simulate DNS rebinding to metadata IP on load.
    update_org_settings(
        db_session,
        org.id,
        ai_enabled=True,
        provider=ProviderKind.OPENAI_COMPAT,
        model="gpt-4o",
        base_url="https://llm.example.com/v1",
        api_key="sk-1234",
        actor_id=user.id,
        settings=settings,
        resolver=FakeDns({"llm.example.com": ("93.184.216.34",)}),
    )
    loaded = load_org_llm_config(
        db_session,
        org.id,
        settings,
        resolver=FakeDns({"llm.example.com": ("93.184.216.34",)}),
    )
    assert loaded is not None
    assert loaded.allow_private_base_url is False
    # Keys shorter than 8 characters mask as "****" instead of exposing characters in last4.
    assert get_org_settings(db_session, org.id).api_key_last4 == "****"

    with pytest.raises(ScopeError):
        load_org_llm_config(
            db_session,
            org.id,
            settings,
            resolver=FakeDns({"llm.example.com": ("169.254.169.254",)}),
        )

    # Allowlisted local base_url sets allow_private_base_url=True so _DeadlineBackend allows it.
    allowed_settings = make_settings(
        app_encryption_key=SecretStr(APP_KEY_1),
        llm_allowed_base_hosts="localhost",
    )
    update_org_settings(
        db_session,
        org.id,
        ai_enabled=True,
        provider=ProviderKind.OPENAI_COMPAT,
        model="llama3.1",
        base_url="http://localhost:11434/v1",
        api_key="ollama",
        actor_id=user.id,
        settings=allowed_settings,
        resolver=FakeDns(),
    )
    allowed_cfg = load_org_llm_config(db_session, org.id, allowed_settings, resolver=FakeDns())
    assert allowed_cfg is not None
    assert allowed_cfg.allow_private_base_url is True


def test_disabled_ai_blocks_instance_fallback(db_session: Session, actor: tuple[Org, User]) -> None:
    org, user = actor
    settings = make_settings(
        app_encryption_key=SecretStr(APP_KEY_1),
        llm_api_key=SecretStr("instance-key"),
        llm_model="muse-spark-1.3",
    )
    update_org_settings(
        db_session,
        org.id,
        ai_enabled=False,
        provider=ProviderKind.ANTHROPIC,
        model="claude-sonnet-4-5",
        base_url=None,
        api_key="sk-ant-1234",
        actor_id=user.id,
        settings=settings,
        resolver=FakeDns(),
    )

    assert load_org_llm_config(db_session, org.id, settings, resolver=FakeDns()) is None
    assert resolve_org_llm_config(db_session, org.id, settings, resolver=FakeDns()) is None


def test_budget_enforcement_for_instance_and_org_keys(
    db_session: Session, actor: tuple[Org, User]
) -> None:
    org, user = actor
    now = datetime(2026, 11, 18, tzinfo=UTC)
    settings = make_settings(
        app_encryption_key=SecretStr(APP_KEY_1),
        llm_api_key=SecretStr("instance-key"),
        llm_model="muse-spark-1.3",
        llm_monthly_instance_token_budget=1_000,
    )
    instance_cfg = LLMConfig(
        provider=ProviderKind.ANTHROPIC,
        model="muse-spark-1.3",
        api_key=SecretStr("instance-key"),
        source=KeySource.INSTANCE,
    )
    db_session.add(
        LLMUsage(
            org_id=org.id,
            provider=ProviderKind.ANTHROPIC,
            model="muse-spark-1.3",
            purpose="triage",
            key_source=KeySource.INSTANCE,
            input_tokens=600,
            output_tokens=400,
            usage_reported=True,
            estimated_cost_usd=Decimal("0.002450"),
            latency_ms=100,
            success=True,
            created_at=now,
        )
    )
    db_session.commit()

    blocked = check_llm_budget(db_session, org.id, instance_cfg, settings, now=now)
    assert blocked.allowed is False
    assert blocked.used_tokens == 1_000
    assert blocked.limit_tokens == 1_000
    assert "instance" in (blocked.reason or "").lower()

    # Lower org budget caps instance key even before instance limit is hit.
    update_org_settings(
        db_session,
        org.id,
        ai_enabled=True,
        provider=ProviderKind.ANTHROPIC,
        model=None,
        base_url=None,
        monthly_token_budget=500,
        actor_id=user.id,
        settings=settings,
        resolver=FakeDns(),
    )
    org_capped = check_llm_budget(db_session, org.id, instance_cfg, settings, now=now)
    assert org_capped.allowed is False
    assert org_capped.limit_tokens == 500
    assert "organization" in (org_capped.reason or "").lower()

    # Switching to org's own key has its own key_source budget.
    org_cfg = LLMConfig(
        provider=ProviderKind.ANTHROPIC,
        model="claude-sonnet-4-5",
        api_key=SecretStr("org-key"),
        source=KeySource.ORG,
    )
    assert check_llm_budget(db_session, org.id, org_cfg, settings, now=now).allowed is True


def test_resolve_org_llm_config_reads_org_settings_once(
    db_session: Session, actor: tuple[Org, User]
) -> None:
    org, user = actor
    settings = make_settings(
        app_encryption_key=SecretStr(APP_KEY_1),
        llm_api_key=SecretStr("instance-key"),
        llm_model="muse-spark-1.3",
    )
    update_org_settings(
        db_session,
        org.id,
        ai_enabled=True,
        provider=ProviderKind.ANTHROPIC,
        model="claude-sonnet-4-5",
        base_url=None,
        api_key="sk-ant-single-read-1234",
        actor_id=user.id,
        settings=settings,
        resolver=FakeDns(),
    )

    executed: list[str] = []

    def _capture(_conn: Any, _cursor: Any, statement: str, *_args: Any, **_kwargs: Any) -> None:
        if "org_settings" in statement:
            executed.append(statement)

    bind = db_session.get_bind()
    event.listen(bind, "before_cursor_execute", _capture)
    try:
        resolved = resolve_org_llm_config(db_session, org.id, settings, resolver=FakeDns())
    finally:
        event.remove(bind, "before_cursor_execute", _capture)

    assert resolved is not None
    assert resolved.source is KeySource.ORG
    assert len(executed) == 1


def test_queue_and_run_ai_connection_test_records_usage_and_status(
    db_session: Session, actor: tuple[Org, User]
) -> None:
    org, user = actor
    now = datetime(2026, 11, 18, 12, 0, tzinfo=UTC)
    settings = make_settings(app_encryption_key=SecretStr(APP_KEY_1))
    assert get_ai_test_status(db_session, org.id, now=now).state is AITestState.NONE

    update_org_settings(
        db_session,
        org.id,
        ai_enabled=True,
        provider=ProviderKind.ANTHROPIC,
        model="muse-spark-1.3",
        base_url=None,
        api_key="sk-ant-test-4321",
        actor_id=user.id,
        settings=settings,
        resolver=FakeDns(),
    )

    queue = FakeQueue(db_session)
    job = queue_ai_connection_test(db_session, queue, org.id, settings, resolver=FakeDns(), now=now)
    assert queue.sent == [("ai.test_connection", org.id, job.id, True)]
    queued_at = job.updated_at or job.created_at
    assert queued_at is not None
    assert get_ai_test_status(db_session, org.id, now=queued_at).state is AITestState.QUEUED
    assert (
        get_ai_test_status(
            db_session, org.id, now=queued_at + QUEUE_STALL_AFTER + timedelta(seconds=1)
        ).state
        is AITestState.STALLED
    )

    job.status = JobStatus.RUNNING
    db_session.commit()
    assert get_ai_test_status(db_session, org.id, now=now).state is AITestState.RUNNING

    ok_provider = FakeLLMProvider('{"ok": true}')
    ok_res = run_ai_connection_test(
        db_session,
        org.id,
        job.id,
        settings,
        provider_factory=lambda _cfg: ok_provider,
        resolver=FakeDns(),
        now=now,
    )
    assert ok_res.ok is True
    assert ok_res.provider is ProviderKind.ANTHROPIC
    jobs.mark_job_completed(db_session, org.id, job.id)
    assert get_ai_test_status(db_session, org.id, now=now).state is AITestState.COMPLETED

    job2 = queue_ai_connection_test(
        db_session, queue, org.id, settings, resolver=FakeDns(), now=now
    )
    fail_provider = FakeLLMProvider(LLMAuthError("The AI provider rejected the API key."))
    with pytest.raises(JobError, match="rejected the API key"):
        run_ai_connection_test(
            db_session,
            org.id,
            job2.id,
            settings,
            provider_factory=lambda _cfg: fail_provider,
            resolver=FakeDns(),
            now=now,
        )

    job3 = queue_ai_connection_test(
        db_session, queue, org.id, settings, resolver=FakeDns(), now=now
    )
    transient_provider = FakeLLMProvider(
        LLMUnavailable("The AI provider took too long.", usage=TokenUsage(12, 8))
    )
    with pytest.raises(JobError, match="took too long") as caught:
        run_ai_connection_test(
            db_session,
            org.id,
            job3.id,
            settings,
            provider_factory=lambda _cfg: transient_provider,
            resolver=FakeDns(),
            now=now,
        )
    assert type(caught.value) is JobError
    jobs.mark_job_failed(db_session, org.id, job3.id, caught.value)
    failed_status = get_ai_test_status(db_session, org.id, now=now)
    assert failed_status.state is AITestState.FAILED
    assert "took too long" in (failed_status.message or "")

    rows = db_session.scalars(
        scoped(LLMUsage, org.id).order_by(LLMUsage.created_at, LLMUsage.id)
    ).all()
    assert len(rows) == 3
    assert all(r.purpose == "connection_test" for r in rows)
    assert [(r.success, r.error_type) for r in rows] == [
        (True, None),
        (False, "LLMAuthError"),
        (False, "LLMUnavailable"),
    ]
    assert rows[2].input_tokens == 12
    assert rows[2].output_tokens == 8


def test_budget_overview_reports_status_without_decrypting(
    db_session: Session, actor: tuple[Org, User]
) -> None:
    org, user = actor
    settings = make_settings(
        llm_api_key=SecretStr("instance-key"),
        llm_model="muse-spark-1.3",
        llm_monthly_instance_token_budget=100,
    )

    overview = get_org_budget_overview(db_session, org.id, settings)
    assert overview.status == "instance_key"
    assert overview.budget.allowed is True
    assert overview.budget.limit_tokens == 100

    update_org_settings(
        db_session,
        org.id,
        ai_enabled=False,
        provider=ProviderKind.ANTHROPIC,
        model=None,
        base_url=None,
        actor_id=user.id,
        settings=settings,
        resolver=FakeDns(),
    )
    disabled_overview = get_org_budget_overview(db_session, org.id, settings)
    assert disabled_overview.status == "disabled"
    assert disabled_overview.budget.allowed is False
    assert select(OrgSettings) is not None


def test_update_org_settings_validation_and_clear_noop(
    db_session: Session, actor: tuple[Org, User]
) -> None:
    org, user = actor
    settings = make_settings(app_encryption_key=SecretStr(APP_KEY_1))

    # Clearing when no key is stored is a safe no-op.
    assert clear_org_api_key(db_session, org.id, actor_id=user.id).has_api_key is False

    invalid_cases: list[dict[str, object]] = [
        {"provider": "unknown-provider"},
        {"model": "bad\nmodel"},
        {"model": "m" * 201},
        {"api_key": "sk\tbad"},
        {"api_key": "sk-non-ascii-é"},
        {"api_key": "abc"},
        {"api_key": "k" * 4097},
        {"monthly_token_budget": True},
        {"monthly_token_budget": "abc"},
        {"monthly_token_budget": -5},
    ]
    for overrides in invalid_cases:
        with pytest.raises(InvalidOrgSettings):
            update_org_settings(
                db_session,
                org.id,
                ai_enabled=True,
                provider=overrides.get("provider", ProviderKind.ANTHROPIC),  # type: ignore[arg-type]
                model=overrides.get("model", "claude-sonnet-4-5"),  # type: ignore[arg-type]
                base_url=None,
                api_key=overrides.get("api_key"),  # type: ignore[arg-type]
                monthly_token_budget=overrides.get("monthly_token_budget"),  # type: ignore[arg-type]
                actor_id=user.id,
                settings=settings,
                resolver=FakeDns(),
            )

    update_org_settings(
        db_session,
        org.id,
        ai_enabled=True,
        provider=ProviderKind.ANTHROPIC,
        model="claude-sonnet-4-5",
        base_url=None,
        api_key="sk-ant-clear-via-update",
        actor_id=user.id,
        settings=settings,
        resolver=FakeDns(),
    )
    cleared = update_org_settings(
        db_session,
        org.id,
        ai_enabled=True,
        provider=ProviderKind.ANTHROPIC,
        model="claude-sonnet-4-5",
        base_url=None,
        clear_api_key=True,
        actor_id=user.id,
        settings=settings,
        resolver=FakeDns(),
    )
    assert cleared.has_api_key is False
    assert cleared.api_key_last4 is None


def test_load_budget_and_connection_error_paths(
    db_session: Session, actor: tuple[Org, User]
) -> None:
    org, user = actor
    now = datetime(2026, 11, 18, tzinfo=UTC)
    enc_settings = make_settings(app_encryption_key=SecretStr(APP_KEY_1))
    no_enc_settings = make_settings()
    queue = FakeQueue(db_session)

    # Neither org nor instance configured -> queue check explains why cleanly.
    with pytest.raises(OrgSettingsError, match="No organization API key"):
        queue_ai_connection_test(db_session, queue, org.id, no_enc_settings, resolver=FakeDns())
    assert check_llm_budget(db_session, org.id, None, no_enc_settings, now=now).allowed is False

    # Save an encrypted key + org budget, then check missing APP_ENCRYPTION_KEY and org budget cap.
    update_org_settings(
        db_session,
        org.id,
        ai_enabled=True,
        provider=ProviderKind.ANTHROPIC,
        model="claude-sonnet-4-5",
        base_url=None,
        api_key="sk-ant-path-1234",
        monthly_token_budget=50,
        actor_id=user.id,
        settings=enc_settings,
        resolver=FakeDns(),
    )
    with pytest.raises(EncryptionNotConfigured):
        load_org_llm_config(db_session, org.id, no_enc_settings, resolver=FakeDns())

    with pytest.raises(OrgSettingsError, match="APP_ENCRYPTION_KEY"):
        queue_ai_connection_test(db_session, queue, org.id, no_enc_settings, resolver=FakeDns())

    job = queue_ai_connection_test(
        db_session, queue, org.id, enc_settings, resolver=FakeDns(), now=now
    )

    # Unexpected non-LLMError exception still commits a sanitized LLMUnavailable usage row.
    def boom(_cfg: LLMConfig) -> FakeLLMProvider:
        raise RuntimeError("boom with sk-ant-path-1234")

    with pytest.raises(JobError) as unexpected:
        run_ai_connection_test(
            db_session,
            org.id,
            job.id,
            enc_settings,
            provider_factory=boom,
            resolver=FakeDns(),
            now=now,
        )
    assert "sk-ant-path-1234" not in str(unexpected.value)

    # Exceeding the org budget blocks both check_llm_budget and connection tests.
    db_session.add(
        LLMUsage(
            org_id=org.id,
            provider=ProviderKind.ANTHROPIC,
            model="claude-sonnet-4-5",
            purpose="triage",
            key_source=KeySource.ORG,
            input_tokens=30,
            output_tokens=20,
            usage_reported=True,
            estimated_cost_usd=None,
            latency_ms=50,
            success=True,
            created_at=now,
        )
    )
    db_session.commit()
    with pytest.raises(OrgSettingsError, match="Monthly organization AI token budget"):
        queue_ai_connection_test(
            db_session, queue, org.id, enc_settings, resolver=FakeDns(), now=now
        )
    with pytest.raises(JobError, match="Monthly organization AI token budget"):
        run_ai_connection_test(
            db_session,
            org.id,
            job.id,
            enc_settings,
            provider_factory=lambda _cfg: FakeLLMProvider('{"ok": true}'),
            resolver=FakeDns(),
            now=now,
        )

    # Toggling AI off reports disabled cleanly on connection test.
    update_org_settings(
        db_session,
        org.id,
        ai_enabled=False,
        provider=ProviderKind.ANTHROPIC,
        model="claude-sonnet-4-5",
        base_url=None,
        actor_id=user.id,
        settings=enc_settings,
        resolver=FakeDns(),
    )
    with pytest.raises(OrgSettingsError, match="AI is disabled"):
        queue_ai_connection_test(db_session, queue, org.id, enc_settings, resolver=FakeDns())
    with pytest.raises(JobError, match="AI is disabled"):
        run_ai_connection_test(db_session, org.id, job.id, enc_settings, resolver=FakeDns())


def test_enforce_triage_budget_allows_valid_and_skips_errors(db_session: Session) -> None:
    scan = make_scan(db_session)
    queue = FakeQueue(db_session)
    enc_settings = make_settings(app_encryption_key=SecretStr(APP_KEY_1))
    no_enc_settings = make_settings()

    # Within budget returns the config the triage calls use.
    ok_job = jobs.create_job(
        db_session, queue, org_id=scan.org_id, scan_id=scan.id, stage="triage", task_name="t1"
    )
    inst_settings = make_settings(
        llm_api_key=SecretStr("instance-key"),
        llm_model="muse-spark-1.3",
        llm_monthly_instance_token_budget=1_000,
    )
    config = enforce_triage_budget(db_session, scan.org_id, ok_job.id, inst_settings)
    assert config is not None
    assert (config.model, config.source) == ("muse-spark-1.3", KeySource.INSTANCE)

    # Disabled AI skips triage with notice.
    disabled_job = jobs.create_job(
        db_session, queue, org_id=scan.org_id, scan_id=scan.id, stage="triage", task_name="t2"
    )
    assert enforce_triage_budget(db_session, scan.org_id, disabled_job.id, no_enc_settings) is None
    disabled_row = db_session.get(Job, disabled_job.id)
    assert disabled_row is not None
    assert disabled_row.status is JobStatus.SKIPPED

    # OrgSettingsError (e.g. missing APP_ENCRYPTION_KEY for saved key) also marks skipped.
    update_org_settings(
        db_session,
        scan.org_id,
        ai_enabled=True,
        provider=ProviderKind.ANTHROPIC,
        model="claude-sonnet-4-5",
        base_url=None,
        api_key="sk-ant-triage-1234",
        actor_id=None,
        settings=enc_settings,
        resolver=FakeDns(),
    )
    err_job = jobs.create_job(
        db_session, queue, org_id=scan.org_id, scan_id=scan.id, stage="triage", task_name="t3"
    )
    assert enforce_triage_budget(db_session, scan.org_id, err_job.id, no_enc_settings) is None
    err_row = db_session.get(Job, err_job.id)
    assert err_row is not None
    assert err_row.status is JobStatus.SKIPPED
    assert "APP_ENCRYPTION_KEY" in (err_row.error or "")
