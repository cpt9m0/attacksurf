"""Settings UI routes against real Postgres, signed in through the real signup flow (#24)."""

import re
from datetime import UTC, datetime, timedelta
from uuid import UUID

import pytest
from flask import Flask
from flask.testing import FlaskClient
from pydantic import SecretStr
from sqlalchemy import select
from sqlalchemy.orm import Session

import attacksurf.web.ui as ui_module
from attacksurf.domain.accounts import Role
from attacksurf.domain.llm import KeySource, ProviderKind
from attacksurf.domain.scans import JobStatus
from attacksurf.infra.db.models import Job, LLMUsage, Membership, OrgSettings, User
from attacksurf.infra.db.tenancy import scoped
from attacksurf.services import org_settings as org_settings_service
from tests.helpers import make_settings

_CSRF = re.compile(r'name="csrf_token" value="([^"]+)"')
_INLINE_CODE = (
    re.compile(r"<script(?![^>]*\ssrc=)[^>]*>"),
    re.compile(r"\son[a-z]+\s*="),
    re.compile(r"\sstyle\s*="),
)
_ALPINE_EXPRESSION = re.compile(
    r"""\s(?:x-(?!data=|init|ref|text|show|model|bind)[a-z-]+|:[a-z-]+)=["'][^"']*[?:+*]"""
)
HTMX = {"HX-Request": "true"}
APP_KEY = "a2tra2tra2tra2tra2tra2tra2tra2tra2tra2tra2s"


class _RecordingQueue:
    def __init__(self, *, fail: bool = False) -> None:
        self.fail = fail
        self.sent: list[tuple[str, UUID, UUID]] = []

    def enqueue(self, task_name: str, *, org_id: UUID, job_id: UUID) -> str:
        self.sent.append((task_name, org_id, job_id))
        if self.fail:
            raise ConnectionError("broker unreachable")
        return "task-1"


class _StubDns:
    def __init__(self, answers: dict[str, tuple[str, ...]] | None = None) -> None:
        self.answers = answers or {}

    def resolve_ipv4(self, host: str) -> tuple[str, ...]:
        return self.answers.get(host, ("93.184.216.34",))

    def resolve_name(self, host: str) -> tuple[str, ...]:
        return self.answers.get(host, ("93.184.216.34",))

    def lookup_many(self, queries: object) -> tuple[()]:
        return ()


def _csrf(client: FlaskClient, path: str = "/settings") -> str:
    match = _CSRF.search(client.get(path).get_data(as_text=True))
    assert match
    return match.group(1)


def _signup(app: Flask, email: str) -> FlaskClient:
    client = app.test_client()
    response = client.post(
        "/signup",
        data={
            "email": email,
            "password": "correct horse battery",
            "org_name": email.split("@", maxsplit=1)[0],
            "csrf_token": _csrf(client, "/signup"),
        },
    )
    assert response.status_code == 302, response.get_data(as_text=True)
    return client


def _org_id(session: Session, email: str) -> UUID:
    user = session.scalars(select(User).where(User.email == email)).one()
    return session.scalars(select(Membership.org_id).where(Membership.user_id == user.id)).one()


@pytest.fixture
def alice(db_app: Flask, monkeypatch: pytest.MonkeyPatch) -> FlaskClient:
    monkeypatch.setattr(ui_module, "get_dns_resolver", _StubDns)
    monkeypatch.setattr(
        ui_module,
        "get_settings",
        lambda: make_settings(
            env="test",
            secret_key=SecretStr("test-secret-key"),
            app_encryption_key=SecretStr(APP_KEY),
            llm_allowed_base_hosts="localhost",
        ),
    )
    return _signup(db_app, "alice@example.com")


def test_settings_page_shows_data_sharing_notice_and_empty_usage(alice: FlaskClient) -> None:
    html = alice.get("/settings").get_data(as_text=True)

    assert "<h1>Settings</h1>" in html
    assert "Data sent to AI providers" in html
    assert "normalized findings only" in html
    assert "AI usage &amp; monthly budget" in html
    assert "No AI usage recorded yet" in html
    assert not any(pattern.search(html) for pattern in _INLINE_CODE)


def test_admin_saves_encrypted_key_renders_last4_only_and_clears_via_confirm(
    alice: FlaskClient, db_session: Session
) -> None:
    raw_key = "sk-ant-ui-super-secret-7890"
    response = alice.post(
        "/settings/ai",
        data={
            "ai_enabled": "1",
            "provider": "openai_compat",
            "model": "gpt-4o",
            "base_url": "https://api.openai.com/v1",
            "api_key": raw_key,
            "monthly_token_budget": "100000",
            "csrf_token": _csrf(alice),
        },
    )

    assert response.status_code == 303
    assert response.headers["Location"] == "/settings"

    html = alice.get("/settings").get_data(as_text=True)
    assert "••••7890" in html
    assert raw_key not in html
    assert 'data-has-key="true"' in html
    assert 'x-data="aiSettingsForm"' in html
    assert 'x-ref="replaceDialog"' in html
    assert "Replace saved API key?" in html
    assert 'action="/settings/ai/clear-key"' in html
    assert '<dialog class="dialog" x-ref="dialog"' in html
    assert not any(pattern.search(html) for pattern in _INLINE_CODE)
    assert not _ALPINE_EXPRESSION.search(html)

    org_id = _org_id(db_session, "alice@example.com")
    row = db_session.scalars(scoped(OrgSettings, org_id)).one()
    assert row.api_key_ciphertext is not None
    assert raw_key.encode() not in row.api_key_ciphertext

    cleared = alice.post("/settings/ai/clear-key", data={"csrf_token": _csrf(alice)})
    assert cleared.status_code == 303
    after = alice.get("/settings").get_data(as_text=True)
    assert "Organization API key removed." in after
    assert "••••7890" not in after
    assert 'data-has-key="false"' in after
    assert 'x-ref="replaceDialog"' not in after


def test_ssrf_base_url_returns_422_inline_error_without_echoing_api_key(
    alice: FlaskClient,
) -> None:
    submitted_key = "sk-do-not-echo-back-9999"
    response = alice.post(
        "/settings/ai",
        data={
            "ai_enabled": "1",
            "provider": "openai_compat",
            "model": "llama3",
            "base_url": "http://169.254.169.254/latest/meta-data/",
            "api_key": submitted_key,
            "monthly_token_budget": "",
            "csrf_token": _csrf(alice),
        },
        headers=HTMX,
    )

    html = response.get_data(as_text=True)
    assert response.status_code == 422
    assert html.lstrip().startswith('<form id="ai-settings-form"')
    assert 'aria-invalid="true"' in html
    assert " autofocus" in html
    assert submitted_key not in html


def test_allowlisted_self_hosted_host_is_accepted(alice: FlaskClient) -> None:
    response = alice.post(
        "/settings/ai",
        data={
            "ai_enabled": "1",
            "provider": "openai_compat",
            "model": "llama3.1",
            "base_url": "http://localhost:11434/v1",
            "api_key": "sk-local-4444",
            "monthly_token_budget": "",
            "csrf_token": _csrf(alice),
        },
    )

    assert response.status_code == 303
    html = alice.get("/settings").get_data(as_text=True)
    assert "http://localhost:11434/v1" in html
    assert "••••4444" in html


def test_test_connection_queues_worker_task_and_polls_status_fragment(
    alice: FlaskClient, db_session: Session, monkeypatch: pytest.MonkeyPatch
) -> None:
    queue = _RecordingQueue()
    monkeypatch.setattr(ui_module, "get_task_queue", lambda: queue)

    # Unconfigured org returns 422 status fragment on HTMX without enqueuing anything.
    unconfigured = alice.post("/settings/ai/test", data={"csrf_token": _csrf(alice)}, headers=HTMX)
    assert unconfigured.status_code == 422
    assert "No organization API key" in unconfigured.get_data(as_text=True)
    assert queue.sent == []

    alice.post(
        "/settings/ai",
        data={
            "ai_enabled": "1",
            "provider": "anthropic",
            "model": "muse-spark-1.3",
            "base_url": "",
            "api_key": "sk-ant-live-1234",
            "monthly_token_budget": "",
            "csrf_token": _csrf(alice),
        },
    )

    queued_res = alice.post("/settings/ai/test", data={"csrf_token": _csrf(alice)}, headers=HTMX)
    queued_html = queued_res.get_data(as_text=True)
    assert queued_res.status_code == 200
    assert queued_html.lstrip().startswith('<div id="ai-test-status"')
    assert 'hx-get="/settings/ai/test"' in queued_html
    assert 'hx-trigger="every 2s"' in queued_html
    assert 'aria-busy="true"' in queued_html
    assert "Testing" in queued_html
    assert "disabled" in queued_html
    assert len(queue.sent) == 1
    assert queue.sent[0][0] == "ai.test_connection"

    # GET /settings/ai/test tracks completion and stops polling.
    org_id = _org_id(db_session, "alice@example.com")
    job_id = db_session.scalars(scoped(Job, org_id).where(Job.stage == "ai_test")).one().id
    job = db_session.get_one(Job, job_id)
    job.status = JobStatus.COMPLETED
    db_session.commit()

    done_html = alice.get("/settings/ai/test", headers=HTMX).get_data(as_text=True)
    assert 'hx-trigger="every 2s"' not in done_html
    assert 'aria-busy="false"' in done_html
    assert "Connection succeeded." in done_html

    # Failed job stops polling and shows sanitized Job.error.
    job = db_session.get_one(Job, job_id)
    job.status = JobStatus.FAILED
    job.error = "JobError: The AI provider rejected the API key."
    db_session.commit()
    failed_html = alice.get("/settings/ai/test", headers=HTMX).get_data(as_text=True)
    assert 'hx-trigger="every 2s"' not in failed_html
    assert "Test failed" in failed_html
    assert "The AI provider rejected the API key." in failed_html

    # Stalled queue stops polling and explains worker status.
    job = db_session.get_one(Job, job_id)
    job.status = JobStatus.QUEUED
    job.updated_at = (
        datetime.now(UTC) - org_settings_service.QUEUE_STALL_AFTER - timedelta(minutes=1)
    )
    db_session.commit()
    stalled_html = alice.get("/settings/ai/test", headers=HTMX).get_data(as_text=True)
    assert 'hx-trigger="every 2s"' not in stalled_html
    assert "Stalled" in stalled_html
    assert "no AI worker" in stalled_html

    # Non-HTMX POST redirects cleanly to /settings and broken broker yields 503.
    plain_ok = alice.post("/settings/ai/test", data={"csrf_token": _csrf(alice)})
    assert plain_ok.status_code == 303
    assert plain_ok.headers["Location"] == "/settings"

    monkeypatch.setattr(ui_module, "get_task_queue", lambda: _RecordingQueue(fail=True))
    down_res = alice.post("/settings/ai/test", data={"csrf_token": _csrf(alice)}, headers=HTMX)
    assert down_res.status_code == 503
    assert "could not be queued" in down_res.get_data(as_text=True)


def test_non_admin_member_sees_read_only_view_and_cannot_post(
    alice: FlaskClient, db_session: Session
) -> None:
    alice.post(
        "/settings/ai",
        data={
            "ai_enabled": "1",
            "provider": "anthropic",
            "model": "claude-sonnet-4-5",
            "base_url": "",
            "api_key": "sk-ant-secret-5555",
            "monthly_token_budget": "50000",
            "csrf_token": _csrf(alice),
        },
    )
    user = db_session.scalars(select(User).where(User.email == "alice@example.com")).one()
    membership = db_session.scalars(select(Membership).where(Membership.user_id == user.id)).one()
    membership.role = Role.MEMBER
    db_session.commit()

    csrf = _csrf(alice)
    html = alice.get("/settings").get_data(as_text=True)
    assert "••••5555" in html
    assert "sk-ant-secret-5555" not in html
    assert 'id="ai-settings-form"' not in html
    assert "Test connection" not in html
    assert "Only organization administrators" in html

    assert alice.post("/settings/ai", data={"csrf_token": csrf}).status_code == 403
    assert alice.post("/settings/ai/clear-key", data={"csrf_token": csrf}).status_code == 403
    assert alice.post("/settings/ai/test", data={"csrf_token": csrf}).status_code == 403


def test_settings_posts_require_csrf(alice: FlaskClient) -> None:
    assert alice.post("/settings/ai", data={"provider": "anthropic"}).status_code == 400
    assert alice.post("/settings/ai/clear-key", data={}).status_code == 400
    assert alice.post("/settings/ai/test", data={}).status_code == 400


def test_settings_and_usage_are_tenant_isolated(
    alice: FlaskClient, db_app: Flask, db_session: Session
) -> None:
    alice.post(
        "/settings/ai",
        data={
            "ai_enabled": "1",
            "provider": "anthropic",
            "model": "alice-secret-model",
            "base_url": "",
            "api_key": "alice-token-6789",
            "monthly_token_budget": "",
            "csrf_token": _csrf(alice),
        },
    )
    alice_org = _org_id(db_session, "alice@example.com")
    db_session.add(
        LLMUsage(
            org_id=alice_org,
            provider=ProviderKind.ANTHROPIC,
            model="alice-secret-model",
            purpose="triage",
            key_source=KeySource.ORG,
            input_tokens=123,
            output_tokens=456,
            usage_reported=True,
            estimated_cost_usd=None,
            latency_ms=100,
            success=True,
        )
    )
    db_session.commit()

    bob = _signup(db_app, "bob@example.com")
    bob_html = bob.get("/settings").get_data(as_text=True)
    assert "alice-secret-model" not in bob_html
    assert "••••6789" not in bob_html
    assert "No AI usage recorded yet" in bob_html


def test_non_htmx_invalid_settings_submit_renders_full_422_page(alice: FlaskClient) -> None:
    submitted_key = "sk-do-not-echo-full-page"
    response = alice.post(
        "/settings/ai",
        data={
            "ai_enabled": "1",
            "provider": "anthropic",
            "model": "",
            "base_url": "",
            "api_key": submitted_key,
            "monthly_token_budget": "not-a-number",
            "csrf_token": _csrf(alice),
        },
    )

    html = response.get_data(as_text=True)
    assert response.status_code == 422
    assert "<!doctype html>" in html.lower()
    assert 'aria-invalid="true"' in html
    assert submitted_key not in html


def test_invalid_provider_renders_error_inside_field_div(alice: FlaskClient) -> None:
    response = alice.post(
        "/settings/ai",
        data={
            "ai_enabled": "1",
            "provider": "invalid-provider",
            "model": "",
            "base_url": "",
            "api_key": "",
            "monthly_token_budget": "",
            "csrf_token": _csrf(alice),
        },
        headers=HTMX,
    )

    html = response.get_data(as_text=True)
    assert response.status_code == 422
    assert 'id="f-provider"' in html
    assert 'aria-invalid="true"' in html
    assert 'aria-describedby="f-provider-error"' in html
    assert '<p class="field-error" id="f-provider-error">' in html
    assert not any(pattern.search(html) for pattern in _INLINE_CODE)
    assert not _ALPINE_EXPRESSION.search(html)
