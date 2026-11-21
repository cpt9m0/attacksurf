"""Logged-in clients without a database: the identity lookup is faked (see `tests/conftest.py`)."""

import pytest
from flask import Flask
from flask.testing import FlaskClient

from attacksurf.domain.findings import Severity
from attacksurf.domain.llm import ProviderKind
from attacksurf.services import (
    asset_views,
    finding_views,
    llm_usage,
    notifications,
    org_settings,
    scan_views,
    summary_views,
)
from attacksurf.services.auth import SessionUser
from tests.conftest import LoginAs, make_session_user


@pytest.fixture
def session_user() -> SessionUser:
    return make_session_user()


@pytest.fixture
def auth_client(app: Flask, login_as: LoginAs, session_user: SessionUser) -> FlaskClient:
    client = app.test_client()
    login_as(client, session_user)
    return client


@pytest.fixture(autouse=True)
def _no_scans(monkeypatch: pytest.MonkeyPatch) -> None:
    """No database here: the scans page renders an empty org (DB-backed: tests/integration/web).

    Its root filter and start form read `list_root_domains` too.
    """
    no_scans = scan_views.ScanPage(items=(), page=1, pages=1, total=0)
    monkeypatch.setattr(scan_views, "list_scans", lambda *_args, **_kw: no_scans)
    monkeypatch.setattr(scan_views, "active_scan_for_root", lambda *_args, **_kw: None)
    monkeypatch.setattr(asset_views, "list_root_domains", lambda *_args, **_kw: ())
    # Findings and the dashboard read the database too; render an empty org here.
    no_findings = finding_views.FindingPage(items=(), page=1, pages=1, total=0)
    monkeypatch.setattr(finding_views, "list_findings", lambda *_args, **_kw: no_findings)
    monkeypatch.setattr(
        finding_views,
        "list_filter_options",
        lambda *_args, **_kw: finding_views.FindingFilterOptions(roots=(), rules=()),
    )
    empty_dashboard = finding_views.DashboardData(
        open_findings=0,
        by_severity=(),
        newest=(),
        active_assets=0,
        roots=(),
    )
    monkeypatch.setattr(finding_views, "get_dashboard", lambda *_args, **_kw: empty_dashboard)
    monkeypatch.setattr(summary_views, "list_latest_root_summaries", lambda *_args, **_kw: ())
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
    monkeypatch.setattr(
        org_settings,
        "get_ai_test_status",
        lambda *_args, **_kw: org_settings.AITestStatus(org_settings.AITestState.NONE),
    )
    monkeypatch.setattr(llm_usage, "get_usage_summary", lambda *_args, **_kw: empty_usage)
    monkeypatch.setattr(
        notifications,
        "get_notification_preference",
        lambda *_args, **_kw: notifications.NotificationPreferenceView(
            email_enabled=True, min_severity=Severity.HIGH
        ),
    )
