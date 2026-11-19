"""Organization LLM settings, encrypted BYO API keys, budget enforcement and connection tests."""

import re
from collections.abc import Callable
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from enum import StrEnum
from typing import Literal
from uuid import UUID

import structlog
from pydantic import BaseModel, SecretStr
from sqlalchemy import select
from sqlalchemy.orm import Session

from attacksurf.ai.config import resolve_llm_config
from attacksurf.ai.factory import build_provider
from attacksurf.config import Settings
from attacksurf.domain.jobs import JobError, TaskQueue
from attacksurf.domain.llm import (
    KeySource,
    LLMConfig,
    LLMError,
    LLMProvider,
    LLMUnavailable,
    Message,
    OrgLLMConfig,
    ProviderKind,
)
from attacksurf.domain.net import DnsResolver
from attacksurf.domain.scans import JobStatus
from attacksurf.domain.scope import ScopeError
from attacksurf.infra.crypto import DecryptionError, SecretCipher
from attacksurf.infra.db.models import Job, Org, OrgSettings
from attacksurf.infra.db.tenancy import scoped
from attacksurf.infra.dns import DnsPythonResolver
from attacksurf.infra.scope_guard import is_allowlisted_llm_base_url, validate_llm_base_url
from attacksurf.services import jobs
from attacksurf.services.audit import audit
from attacksurf.services.llm_usage import monthly_tokens_used, record_llm_usage

log = structlog.get_logger(__name__)

_KEY_PURPOSE = b"org_api_key"
_MAX_MODEL_LENGTH = 200
_MIN_API_KEY_LENGTH = 4
_SHORT_KEY_MASK_LEN = 8
_MAX_API_KEY_LENGTH = 400  # ciphertext overhead (~90 bytes) stays within LargeBinary(512)
_MAX_BIGINT = 2**63 - 1
_CONTROL_CHARS = re.compile(r"[\x00-\x1f\x7f]")
QUEUE_STALL_AFTER = timedelta(minutes=5)
_CONNECTION_TEST_MAX_TOKENS = 1024  # reasoning models count thinking tokens toward max_tokens
_CONNECTION_TEST_MESSAGES = (
    Message("system", "Reply with a JSON object setting ok to true."),
    Message("user", "Connection test."),
)

AIStatusKind = Literal["org_key", "instance_key", "disabled", "unconfigured"]


class _ConnectionProbe(BaseModel):
    ok: bool


class OrgSettingsError(Exception):
    """Base exception for organization AI configuration errors."""


class InvalidOrgSettings(OrgSettingsError):
    """User input failed validation; carries the offending field name for inline form errors."""

    def __init__(self, message: str, *, field: str | None = None) -> None:
        super().__init__(message)
        self.field = field


class EncryptionNotConfigured(InvalidOrgSettings):
    """Saving or decrypting an organization API key requires `APP_ENCRYPTION_KEY`."""


@dataclass(frozen=True)
class OrgSettingsView:
    """What UI and callers see for an org's AI config. Never holds the plaintext key."""

    ai_enabled: bool
    provider: ProviderKind
    model: str | None
    base_url: str | None
    has_api_key: bool
    api_key_last4: str | None
    monthly_token_budget: int | None


@dataclass(frozen=True)
class BudgetStatus:
    """Whether an org may run another LLM call this UTC month."""

    allowed: bool
    used_tokens: int
    limit_tokens: int | None
    reason: str | None = None


@dataclass(frozen=True)
class OrgBudgetOverview:
    """Lightweight status for `GET /settings` without decrypting keys or calling DNS."""

    status: AIStatusKind
    key_source: KeySource | None
    budget: BudgetStatus


@dataclass(frozen=True)
class ConnectionTestResult:
    """Outcome of `run_ai_connection_test`; message is safe to display to users."""

    ok: bool
    message: str
    provider: ProviderKind | None = None
    model: str | None = None
    key_source: KeySource | None = None
    latency_ms: int | None = None


class AITestState(StrEnum):
    """Latest `ai_test` job state for `/settings` HTMX polling."""

    NONE = "none"
    QUEUED = "queued"
    RUNNING = "running"
    STALLED = "stalled"
    COMPLETED = "completed"
    FAILED = "failed"


@dataclass(frozen=True)
class AITestStatus:
    """Read-only view of an org's latest connection test job for `/settings`."""

    state: AITestState
    job_id: UUID | None = None
    message: str | None = None
    updated_at: datetime | None = None

    @property
    def in_flight(self) -> bool:
        return self.state in {AITestState.QUEUED, AITestState.RUNNING}


def get_org_settings(session: Session, org_id: UUID) -> OrgSettingsView:
    """Return the org's AI settings view (defaults when no row has been saved yet)."""
    row = session.scalars(scoped(OrgSettings, org_id)).one_or_none()
    return _to_view(row)


def update_org_settings(
    session: Session,
    org_id: UUID,
    *,
    ai_enabled: bool,
    provider: ProviderKind | str,
    model: str | None,
    base_url: str | None,
    api_key: str | None = None,
    clear_api_key: bool = False,
    monthly_token_budget: int | str | None = None,
    actor_id: UUID | None,
    settings: Settings,
    resolver: DnsResolver | None = None,
) -> OrgSettingsView:
    """Validate and persist org AI settings, encrypting any new API key at rest."""
    parsed_provider = _parse_provider(provider)
    clean_model = _clean_model(model)
    parsed_budget = _parse_budget(monthly_token_budget)
    clean_key = _clean_api_key(api_key)

    primary_key = _require_key_encryption(clean_key, clear_api_key=clear_api_key, settings=settings)
    clean_base_url = _validate_optional_base_url(base_url, settings=settings, resolver=resolver)

    # Serialise updates per org after any DNS validation I/O finishes.
    if session.scalar(select(Org.id).where(Org.id == org_id).with_for_update()) is None:
        raise OrgSettingsError("Organization not found.")
    row = session.scalars(
        scoped(OrgSettings, org_id).with_for_update(),
        execution_options={"populate_existing": True},
    ).one_or_none()

    existing_key = row is not None and row.api_key_ciphertext is not None
    will_have_key = clean_key is not None or (existing_key and not clear_api_key)
    if will_have_key and clean_model is None:
        session.rollback()
        raise InvalidOrgSettings(
            "Choose a model when using your own API key.",
            field="model",
        )

    if row is None:
        row = OrgSettings(org_id=org_id)
        session.add(row)

    row.ai_enabled = ai_enabled
    row.provider = parsed_provider
    row.model = clean_model
    row.base_url = clean_base_url
    row.monthly_token_budget = parsed_budget
    key_action = _apply_api_key_update(
        row,
        org_id=org_id,
        clean_key=clean_key,
        clear_api_key=clear_api_key,
        primary_key=primary_key,
        had_key=existing_key,
    )

    session.flush()
    _audit_settings_updated(session, org_id, row, actor_id=actor_id, key_action=key_action)
    session.commit()
    log.info(
        "org ai settings updated",
        org_id=str(org_id),
        provider=row.provider.value,
        ai_enabled=row.ai_enabled,
        key_action=key_action,
    )
    return _to_view(row)


def _require_key_encryption(
    clean_key: str | None, *, clear_api_key: bool, settings: Settings
) -> bytes | None:
    if clean_key is None:
        return None
    if clear_api_key:
        raise InvalidOrgSettings(
            "Cannot save a new API key and remove the saved key at the same time.",
            field="api_key",
        )
    primary_key = settings.app_encryption_key_bytes
    if primary_key is None:
        raise EncryptionNotConfigured(
            "Saving an organization API key requires APP_ENCRYPTION_KEY on the server.",
            field="api_key",
        )
    return primary_key


def _validate_optional_base_url(
    base_url: str | None, *, settings: Settings, resolver: DnsResolver | None
) -> str | None:
    stripped_url = base_url.strip() if base_url is not None else ""
    if not stripped_url:
        return None
    active_resolver = resolver or _default_resolver(settings)
    try:
        return validate_llm_base_url(
            stripped_url,
            allowed_hosts=settings.llm_allowed_base_host_set,
            resolver=active_resolver,
        )
    except ScopeError as exc:
        raise InvalidOrgSettings(str(exc), field="base_url") from None


def _apply_api_key_update(
    row: OrgSettings,
    *,
    org_id: UUID,
    clean_key: str | None,
    clear_api_key: bool,
    primary_key: bytes | None,
    had_key: bool,
) -> str:
    if clean_key is not None and primary_key is not None:
        row.api_key_ciphertext = SecretCipher(primary_key, purpose=_KEY_PURPOSE).encrypt_secret(
            clean_key, aad=org_id.bytes
        )
        row.api_key_last4 = _api_key_last4(clean_key)
        return "set"
    if clear_api_key:
        row.api_key_ciphertext = None
        row.api_key_last4 = None
        return "cleared" if had_key else "none"
    return "kept" if had_key else "none"


def clear_org_api_key(
    session: Session,
    org_id: UUID,
    *,
    actor_id: UUID | None,
) -> OrgSettingsView:
    """Erase the org's saved API key (if any), audit, and commit."""
    if session.scalar(select(Org.id).where(Org.id == org_id).with_for_update()) is None:
        raise OrgSettingsError("Organization not found.")
    row = session.scalars(
        scoped(OrgSettings, org_id).with_for_update(),
        execution_options={"populate_existing": True},
    ).one_or_none()
    if row is None or row.api_key_ciphertext is None:
        session.rollback()
        return _to_view(row)
    row.api_key_ciphertext = None
    row.api_key_last4 = None
    session.flush()
    _audit_settings_updated(session, org_id, row, actor_id=actor_id, key_action="cleared")
    session.commit()
    log.info("org ai api key cleared", org_id=str(org_id))
    return _to_view(row)


def _org_llm_config_from_row(
    row: OrgSettings | None,
    org_id: UUID,
    settings: Settings,
    *,
    resolver: DnsResolver | None = None,
) -> OrgLLMConfig | None:
    if row is None or not row.ai_enabled or row.api_key_ciphertext is None:
        return None
    primary_key = settings.app_encryption_key_bytes
    if primary_key is None:
        raise EncryptionNotConfigured(
            "Saved organization API key cannot be decrypted: APP_ENCRYPTION_KEY is not set."
        )
    cipher = SecretCipher(
        primary_key,
        old_keys=settings.app_encryption_old_key_bytes,
        purpose=_KEY_PURPOSE,
    )
    try:
        plaintext = cipher.decrypt_secret(row.api_key_ciphertext, aad=org_id.bytes)
    except DecryptionError:
        raise OrgSettingsError(
            "Saved organization API key could not be decrypted with the current encryption key."
        ) from None
    if not row.model:
        raise InvalidOrgSettings("Organization API key requires a configured model.", field="model")
    validated_url: SecretStr | None = None
    allow_private = False
    if row.base_url:
        active_resolver = resolver or _default_resolver(settings)
        clean_url = validate_llm_base_url(
            row.base_url,
            allowed_hosts=settings.llm_allowed_base_host_set,
            resolver=active_resolver,
        )
        allow_private = is_allowlisted_llm_base_url(clean_url, settings.llm_allowed_base_host_set)
        validated_url = SecretStr(clean_url)
    return OrgLLMConfig(
        provider=row.provider,
        model=row.model,
        api_key=SecretStr(plaintext),
        base_url=validated_url,
        ai_enabled=row.ai_enabled,
        allow_private_base_url=allow_private,
    )


def load_org_llm_config(
    session: Session,
    org_id: UUID,
    settings: Settings,
    *,
    resolver: DnsResolver | None = None,
) -> OrgLLMConfig | None:
    """Load the org's decrypted LLM config, re-validating `base_url` against SSRF before use.

    Returns `None` when AI is disabled for the org or no org API key is stored. Raises if a
    stored key cannot be decrypted or the stored `base_url` fails SSRF checks, so a broken org
    config never silently falls back to the instance key (ADR 0019).
    """
    row = session.scalars(scoped(OrgSettings, org_id)).one_or_none()
    return _org_llm_config_from_row(row, org_id, settings, resolver=resolver)


def resolve_org_llm_config(
    session: Session,
    org_id: UUID,
    settings: Settings,
    *,
    resolver: DnsResolver | None = None,
) -> LLMConfig | None:
    """Resolve the active `LLMConfig` for `org_id` from a single row read."""
    row = session.scalars(scoped(OrgSettings, org_id)).one_or_none()
    if row is not None and not row.ai_enabled:
        return None
    org_config = _org_llm_config_from_row(row, org_id, settings, resolver=resolver)
    return resolve_llm_config(org_config, settings)


def check_llm_budget(
    session: Session,
    org_id: UUID,
    config: LLMConfig | None,
    settings: Settings,
    *,
    now: datetime | None = None,
) -> BudgetStatus:
    """Check whether `org_id` has remaining monthly UTC token budget for `config`."""
    if config is None:
        return BudgetStatus(
            allowed=False,
            used_tokens=0,
            limit_tokens=None,
            reason="AI is disabled or not configured.",
        )
    org_budget = session.scalar(
        scoped(OrgSettings, org_id).with_only_columns(OrgSettings.monthly_token_budget)
    )
    return _evaluate_budget(
        session,
        org_id,
        source=config.source,
        org_budget=org_budget,
        settings=settings,
        now=now,
    )


def get_org_budget_overview(
    session: Session,
    org_id: UUID,
    settings: Settings,
    *,
    now: datetime | None = None,
) -> OrgBudgetOverview:
    """Read-only AI status and monthly budget summary for `GET /settings`."""
    row = session.scalars(scoped(OrgSettings, org_id)).one_or_none()
    if row is not None and not row.ai_enabled:
        return OrgBudgetOverview(
            status="disabled",
            key_source=None,
            budget=BudgetStatus(
                allowed=False,
                used_tokens=0,
                limit_tokens=None,
                reason="AI features are disabled for this organization.",
            ),
        )
    org_budget = row.monthly_token_budget if row is not None else None
    if row is not None and row.api_key_ciphertext is not None:
        return OrgBudgetOverview(
            status="org_key",
            key_source=KeySource.ORG,
            budget=_evaluate_budget(
                session,
                org_id,
                source=KeySource.ORG,
                org_budget=org_budget,
                settings=settings,
                now=now,
            ),
        )
    if settings.llm_api_key is not None and settings.llm_model is not None:
        return OrgBudgetOverview(
            status="instance_key",
            key_source=KeySource.INSTANCE,
            budget=_evaluate_budget(
                session,
                org_id,
                source=KeySource.INSTANCE,
                org_budget=org_budget,
                settings=settings,
                now=now,
            ),
        )
    return OrgBudgetOverview(
        status="unconfigured",
        key_source=None,
        budget=BudgetStatus(
            allowed=False,
            used_tokens=0,
            limit_tokens=None,
            reason="No organization API key or server instance LLM is configured.",
        ),
    )


def get_ai_test_status(
    session: Session,
    org_id: UUID,
    *,
    now: datetime | None = None,
) -> AITestStatus:
    """Return the latest `ai_test` job status for `/settings` HTMX polling."""
    row = session.scalars(
        scoped(Job, org_id)
        .where(Job.stage == "ai_test")
        .order_by(Job.created_at.desc(), Job.id.desc())
        .limit(1)
    ).one_or_none()
    if row is None:
        return AITestStatus(AITestState.NONE)
    if row.status is JobStatus.QUEUED:
        ref_time = row.updated_at or row.created_at
        current = now or datetime.now(UTC)
        if ref_time is not None and current - ref_time > QUEUE_STALL_AFTER:
            return AITestStatus(AITestState.STALLED, job_id=row.id, updated_at=ref_time)
        return AITestStatus(AITestState.QUEUED, job_id=row.id, updated_at=ref_time)
    if row.status is JobStatus.RUNNING:
        return AITestStatus(
            AITestState.RUNNING, job_id=row.id, updated_at=row.updated_at or row.created_at
        )
    if row.status is JobStatus.COMPLETED:
        return AITestStatus(
            AITestState.COMPLETED,
            job_id=row.id,
            message="Connection succeeded.",
            updated_at=row.finished_at or row.updated_at or row.created_at,
        )
    return AITestStatus(
        AITestState.FAILED,
        job_id=row.id,
        message=row.error or "The AI provider connection test failed.",
        updated_at=row.finished_at or row.updated_at or row.created_at,
    )


def _resolve_checked_config_for_test(
    session: Session,
    org_id: UUID,
    settings: Settings,
    *,
    resolver: DnsResolver | None,
    now: datetime | None,
) -> LLMConfig:
    row = session.scalars(scoped(OrgSettings, org_id)).one_or_none()
    if row is not None and not row.ai_enabled:
        raise OrgSettingsError("AI is disabled for this organization.")
    org_config = _org_llm_config_from_row(row, org_id, settings, resolver=resolver)
    config = resolve_llm_config(org_config, settings)
    if config is None:
        raise OrgSettingsError("No organization API key or server instance LLM is configured.")
    budget = _evaluate_budget(
        session,
        org_id,
        source=config.source,
        org_budget=row.monthly_token_budget if row is not None else None,
        settings=settings,
        now=now,
    )
    if not budget.allowed:
        raise OrgSettingsError(budget.reason or "Monthly AI token budget exceeded.")
    return config


def queue_ai_connection_test(
    session: Session,
    queue: TaskQueue,
    org_id: UUID,
    settings: Settings,
    *,
    resolver: DnsResolver | None = None,
    now: datetime | None = None,
) -> Job:
    """Validate config/SSRF/budget synchronously, then enqueue `ai.test_connection`."""
    _resolve_checked_config_for_test(session, org_id, settings, resolver=resolver, now=now)
    return jobs.create_job(
        session,
        queue,
        org_id=org_id,
        scan_id=None,
        stage="ai_test",
        task_name="ai.test_connection",
    )


def run_ai_connection_test(
    session: Session,
    org_id: UUID,
    job_id: UUID,
    settings: Settings,
    *,
    provider_factory: Callable[[LLMConfig], LLMProvider] | None = None,
    resolver: DnsResolver | None = None,
    now: datetime | None = None,
) -> ConnectionTestResult:
    """Execute an `ai_test` probe inside a Celery worker; fails non-retryably on provider error."""
    factory = provider_factory or build_provider
    try:
        config = _resolve_checked_config_for_test(
            session, org_id, settings, resolver=resolver, now=now
        )
    except ScopeError:
        raise
    except OrgSettingsError as exc:
        raise JobError(str(exc)) from None

    # Run the provider call without holding any write locks.
    try:
        provider = factory(config)
        result = provider.complete(
            _CONNECTION_TEST_MESSAGES,
            schema=_ConnectionProbe,
            max_tokens=_CONNECTION_TEST_MAX_TOKENS,
        )
    except LLMError as exc:
        record_llm_usage(session, org_id, config, purpose="connection_test", outcome=exc)
        session.commit()
        # Wrap even LLMUnavailable in a non-retryable JobError so UI polling fails on attempt 1.
        raise JobError(str(exc)) from None
    except Exception:
        fallback = LLMUnavailable("The AI provider connection test failed.")
        record_llm_usage(session, org_id, config, purpose="connection_test", outcome=fallback)
        session.commit()
        raise JobError(str(fallback)) from None

    record_llm_usage(session, org_id, config, purpose="connection_test", outcome=result)
    session.commit()
    log.info(
        "ai connection test succeeded",
        org_id=str(org_id),
        job_id=str(job_id),
        provider=config.provider.value,
        model=config.model,
        key_source=config.source.value,
        latency_ms=result.latency_ms,
    )
    return ConnectionTestResult(
        ok=True,
        provider=config.provider,
        model=config.model,
        key_source=config.source,
        latency_ms=result.latency_ms,
        message=(
            f"Connected to {config.provider.value} ({config.model}) in {result.latency_ms} ms."
        ),
    )


def enforce_triage_budget(
    session: Session,
    org_id: UUID,
    job_id: UUID,
    settings: Settings,
    *,
    resolver: DnsResolver | None = None,
    now: datetime | None = None,
) -> LLMConfig | None:
    """Gate an AI triage job: the config its calls use, or None after skipping `job_id` with
    a notice because AI is off, misconfigured or over its monthly token budget.
    """
    try:
        config = resolve_org_llm_config(session, org_id, settings, resolver=resolver)
    except (OrgSettingsError, ScopeError) as exc:
        reason = str(exc)
        jobs.mark_job_skipped(session, org_id, job_id, reason)
        log.warning("ai triage skipped", org_id=str(org_id), job_id=str(job_id), reason=reason)
        return None
    if config is None:
        reason = "AI is disabled or not configured."
        jobs.mark_job_skipped(session, org_id, job_id, reason)
        log.info("ai triage skipped", org_id=str(org_id), job_id=str(job_id), reason=reason)
        return None
    budget = check_llm_budget(session, org_id, config, settings, now=now)
    if not budget.allowed:
        reason = budget.reason or "Monthly AI token budget exceeded."
        jobs.mark_job_skipped(session, org_id, job_id, reason)
        log.info("ai triage skipped", org_id=str(org_id), job_id=str(job_id), reason=reason)
        return None
    return config


def _evaluate_budget(
    session: Session,
    org_id: UUID,
    *,
    source: KeySource,
    org_budget: int | None,
    settings: Settings,
    now: datetime | None,
) -> BudgetStatus:
    used = monthly_tokens_used(session, org_id, key_source=source, now=now)
    if source is KeySource.INSTANCE:
        instance_limit = settings.llm_monthly_instance_token_budget
        limit = min(instance_limit, org_budget) if org_budget is not None else instance_limit
        if used >= limit:
            reason = (
                "Monthly instance AI token budget exceeded."
                if org_budget is None or instance_limit <= org_budget
                else "Monthly organization AI token budget exceeded."
            )
            return BudgetStatus(allowed=False, used_tokens=used, limit_tokens=limit, reason=reason)
        return BudgetStatus(allowed=True, used_tokens=used, limit_tokens=limit)
    if org_budget is not None and used >= org_budget:
        return BudgetStatus(
            allowed=False,
            used_tokens=used,
            limit_tokens=org_budget,
            reason="Monthly organization AI token budget exceeded.",
        )
    return BudgetStatus(allowed=True, used_tokens=used, limit_tokens=org_budget)


def _to_view(row: OrgSettings | None) -> OrgSettingsView:
    if row is None:
        return OrgSettingsView(
            ai_enabled=True,
            provider=ProviderKind.ANTHROPIC,
            model=None,
            base_url=None,
            has_api_key=False,
            api_key_last4=None,
            monthly_token_budget=None,
        )
    return OrgSettingsView(
        ai_enabled=row.ai_enabled,
        provider=row.provider,
        model=row.model,
        base_url=row.base_url,
        has_api_key=row.api_key_ciphertext is not None,
        api_key_last4=row.api_key_last4,
        monthly_token_budget=row.monthly_token_budget,
    )


def _audit_settings_updated(
    session: Session,
    org_id: UUID,
    row: OrgSettings,
    *,
    actor_id: UUID | None,
    key_action: str,
) -> None:
    audit(
        session,
        org_id,
        "org.ai_settings_updated",
        actor_id=actor_id,
        target_type="org_settings",
        target_id=str(row.id),
        details={
            "ai_enabled": row.ai_enabled,
            "provider": row.provider.value,
            "model": row.model,
            "has_base_url": row.base_url is not None,
            "has_api_key": row.api_key_ciphertext is not None,
            "api_key_action": key_action,
            "monthly_token_budget": row.monthly_token_budget,
        },
    )


def _default_resolver(settings: Settings) -> DnsResolver:
    return DnsPythonResolver(
        nameservers=settings.dns_resolver_addresses,
        timeout=settings.dns_timeout_seconds,
        lifetime=settings.dns_lifetime_seconds,
        max_concurrency=settings.dns_max_concurrency,
    )


def _parse_provider(raw: ProviderKind | str) -> ProviderKind:
    if isinstance(raw, ProviderKind):
        return raw
    try:
        return ProviderKind(raw.strip())
    except ValueError:
        raise InvalidOrgSettings("Choose a supported AI provider.", field="provider") from None


def _clean_model(raw: str | None) -> str | None:
    if raw is None:
        return None
    stripped = raw.strip()
    if not stripped:
        return None
    if _CONTROL_CHARS.search(stripped):
        raise InvalidOrgSettings("Model name contains invalid characters.", field="model")
    if len(stripped) > _MAX_MODEL_LENGTH:
        raise InvalidOrgSettings(
            f"Model name can be at most {_MAX_MODEL_LENGTH} characters.", field="model"
        )
    return stripped


def _api_key_last4(clean_key: str) -> str:
    # Mask keys shorter than 8 characters so displaying last4 never leaks most of a short key.
    return "****" if len(clean_key) < _SHORT_KEY_MASK_LEN else clean_key[-4:]


def _clean_api_key(raw: str | None) -> str | None:
    if raw is None:
        return None
    stripped = raw.strip()
    if not stripped:
        return None
    if not stripped.isascii() or _CONTROL_CHARS.search(stripped):
        raise InvalidOrgSettings(
            "API key must contain printable ASCII characters only.",
            field="api_key",
        )
    if len(stripped) < _MIN_API_KEY_LENGTH:
        raise InvalidOrgSettings(
            f"API key must be at least {_MIN_API_KEY_LENGTH} characters.",
            field="api_key",
        )
    if len(stripped) > _MAX_API_KEY_LENGTH:
        raise InvalidOrgSettings(
            f"API key can be at most {_MAX_API_KEY_LENGTH} characters.", field="api_key"
        )
    return stripped


def _parse_budget(raw: int | str | None) -> int | None:
    if raw is None:
        return None
    if isinstance(raw, bool):
        raise InvalidOrgSettings(
            "Monthly token budget must be a non-negative whole number.",
            field="monthly_token_budget",
        )
    if isinstance(raw, str):
        stripped = raw.strip()
        if not stripped:
            return None
        try:
            value = int(stripped)
        except ValueError:
            raise InvalidOrgSettings(
                "Monthly token budget must be a non-negative whole number.",
                field="monthly_token_budget",
            ) from None
    else:
        value = raw
    if value < 0 or value > _MAX_BIGINT:
        raise InvalidOrgSettings(
            "Monthly token budget must be a non-negative whole number.",
            field="monthly_token_budget",
        )
    return value
