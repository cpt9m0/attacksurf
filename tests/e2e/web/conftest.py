"""Fixtures for browser tests of the rendered UI (issue #114)."""

import pytest
from flask import Flask
from flask.testing import FlaskClient

from attacksurf.domain.llm import ProviderKind
from attacksurf.services import asset_views, llm_usage, org_settings, scan_views
from tests.conftest import LoginAs, make_session_user

# 40 characters: the email width the issue was reproduced with.
LONG_EMAIL = "ali.ayati.mobile.width.issue@example.com"


@pytest.fixture(autouse=True)
def _no_assets(monkeypatch: pytest.MonkeyPatch) -> None:
    """No database here: the asset pages render an empty org (DB-backed: tests/integration/web)."""
    empty = asset_views.AssetPage(items=(), page=1, pages=1, total=0)
    monkeypatch.setattr(asset_views, "list_assets", lambda *_args, **_kw: empty)
    monkeypatch.setattr(asset_views, "list_root_domains", lambda *_args, **_kw: ())
    no_scans = scan_views.ScanPage(items=(), page=1, pages=1, total=0)
    monkeypatch.setattr(scan_views, "list_scans", lambda *_args, **_kw: no_scans)
    monkeypatch.setattr(scan_views, "active_scan_for_root", lambda *_args, **_kw: None)
    default_settings = org_settings.OrgSettingsView(
        ai_enabled=True,
        provider=ProviderKind.ANTHROPIC,
        model=None,
        base_url=None,
        has_api_key=False,
        api_key_last4=None,
        monthly_token_budget=None,
    )
    default_overview = org_settings.OrgBudgetOverview(
        status="unconfigured",
        key_source=None,
        budget=org_settings.BudgetStatus(
            allowed=False,
            used_tokens=0,
            limit_tokens=None,
            reason="No organization API key or server instance LLM is configured.",
        ),
    )
    empty_usage = llm_usage.UsageSummary(
        months=6,
        current_month="2026-11",
        current_month_tokens=0,
        current_month_instance_tokens=0,
        current_month_org_tokens=0,
        current_month_cost_usd=None,
        total_tokens=0,
        total_cost_usd=None,
        rows=(),
    )
    monkeypatch.setattr(org_settings, "get_org_settings", lambda *_args, **_kw: default_settings)
    monkeypatch.setattr(
        org_settings, "get_org_budget_overview", lambda *_args, **_kw: default_overview
    )
    monkeypatch.setattr(llm_usage, "get_usage_summary", lambda *_args, **_kw: empty_usage)


@pytest.fixture
def phone_client(app: Flask, login_as: LoginAs) -> FlaskClient:
    """A signed-in client whose email is long enough to overflow a phone-width top bar."""
    client = app.test_client()
    login_as(client, make_session_user(email=LONG_EMAIL))
    return client
