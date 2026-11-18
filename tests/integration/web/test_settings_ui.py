"""Settings UI routes against real Postgres, signed in through the real signup flow (#24)."""

import re
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
from attacksurf.infra.db.models import LLMUsage, Membership, OrgSettings, User
from attacksurf.infra.db.tenancy import scoped
from attacksurf.services import org_settings as org_settings_service
from tests.fakes import FakeLLMProvider
from tests.helpers import make_settings

_CSRF = re.compile(r'name="csrf_token" value="([^"]+)"')
_INLINE_CODE = (
    re.compile(r"<script(?![^>]*\ssrc=)[^>]*>"),
    re.compile(r"\son[a-z]+\s*="),
    re.compile(r"\sstyle\s*="),
)
HTMX = {"HX-Request": "true"}
APP_KEY = "a2tra2tra2tra2tra2tra2tra2tra2tra2tra2tra2s"


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
    assert 'action="/settings/ai/clear-key"' in html
    assert '<dialog class="dialog" x-ref="dialog"' in html
    assert not any(pattern.search(html) for pattern in _INLINE_CODE)

    org_id = _org_id(db_session, "alice@example.com")
    row = db_session.scalars(scoped(OrgSettings, org_id)).one()
    assert row.api_key_ciphertext is not None
    assert raw_key.encode() not in row.api_key_ciphertext

    cleared = alice.post("/settings/ai/clear-key", data={"csrf_token": _csrf(alice)})
    assert cleared.status_code == 303
    after = alice.get("/settings").get_data(as_text=True)
    assert "Organization API key removed." in after
    assert "••••7890" not in after


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


def test_test_connection_button_runs_probe_and_shows_usage_row(
    alice: FlaskClient, db_session: Session, monkeypatch: pytest.MonkeyPatch
) -> None:
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
    provider = FakeLLMProvider('{"ok": true}')
    monkeypatch.setattr(org_settings_service, "build_provider", lambda _cfg: provider)

    response = alice.post("/settings/ai/test", data={"csrf_token": _csrf(alice)})

    assert response.status_code == 303
    html = alice.get("/settings").get_data(as_text=True)
    assert "Connected to anthropic (muse-spark-1.3)" in html
    assert "<code>connection_test</code>" in html
    assert "<code>muse-spark-1.3</code>" in html
    org_id = _org_id(db_session, "alice@example.com")
    assert len(db_session.scalars(scoped(LLMUsage, org_id)).all()) == 1


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
