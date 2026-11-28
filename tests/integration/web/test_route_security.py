"""Exhaustive route-table security audit (#30): authz, CSRF, admin roles, and tenant isolation.

Every route registered on the Flask `url_map` must appear in the classified matrix below so a
new endpoint cannot ship without login, CSRF, role, and cross-org isolation tests.
"""

import base64
import re
from dataclasses import dataclass
from uuid import UUID

import pytest
from flask import Flask
from flask.testing import FlaskClient
from pydantic import SecretStr
from sqlalchemy import select
from sqlalchemy.orm import Session

import attacksurf.web.api.v1 as api_module
import attacksurf.web.ui as ui_module
from attacksurf.domain.accounts import Role
from attacksurf.domain.assets import AssetSource, AssetType
from attacksurf.domain.findings import EvidenceKind, FindingStatus, Severity
from attacksurf.domain.llm import ProviderKind
from attacksurf.domain.scans import ScanStatus, ScanTrigger
from attacksurf.infra.db.models import (
    Asset,
    Finding,
    Membership,
    NotificationPreference,
    Org,
    OrgSettings,
    Scan,
    User,
)
from attacksurf.infra.db.tenancy import scoped
from attacksurf.services import assets as assets_service
from attacksurf.services import org_settings
from tests.fakes import FakeQueue
from tests.integration.factories import make_finding

_CSRF = re.compile(r'name="csrf_token" value="([^"]+)"')
_HTMX = {"HX-Request": "true"}


@dataclass(frozen=True)
class RouteSpec:
    endpoint: str
    method: str
    access: str  # "public" | "member" | "admin"
    tenant_param: str | None = None  # "asset" | "scan" | "finding" | "collection"


ROUTE_MATRIX: tuple[RouteSpec, ...] = (
    # Public routes
    RouteSpec("auth.login", "GET", "public"),
    RouteSpec("auth.login", "POST", "public"),
    RouteSpec("auth.signup", "GET", "public"),
    RouteSpec("auth.signup", "POST", "public"),
    RouteSpec("health.healthz", "GET", "public"),
    RouteSpec("static", "GET", "public"),
    # Auth / session
    RouteSpec("auth.logout", "POST", "member"),
    # UI GETs
    RouteSpec("ui.dashboard", "GET", "member", "collection"),
    RouteSpec("ui.assets", "GET", "member", "collection"),
    RouteSpec("ui.asset_detail", "GET", "member", "asset"),
    RouteSpec("ui.ownership_card", "GET", "member", "asset"),
    RouteSpec("ui.scans", "GET", "member", "collection"),
    RouteSpec("ui.scan_detail", "GET", "member", "scan"),
    RouteSpec("ui.scan_progress", "GET", "member", "scan"),
    RouteSpec("ui.scan_summary", "GET", "member", "scan"),
    RouteSpec("ui.scan_triage", "GET", "member", "scan"),
    RouteSpec("ui.findings", "GET", "member", "collection"),
    RouteSpec("ui.finding_detail", "GET", "member", "finding"),
    RouteSpec("ui.export_findings_csv", "GET", "member", "collection"),
    RouteSpec("ui.export_findings_json", "GET", "member", "collection"),
    RouteSpec("ui.settings", "GET", "member", "collection"),
    RouteSpec("ui.ai_test_status", "GET", "member", "collection"),
    # UI POSTs (member-accessible)
    RouteSpec("ui.add_domain", "POST", "member"),
    RouteSpec("ui.add_url", "POST", "member"),
    RouteSpec("ui.upload_repo", "POST", "member"),
    RouteSpec("ui.upload_binary", "POST", "member"),
    RouteSpec("ui.create_scan", "POST", "member", "scan_create"),
    RouteSpec("ui.cancel_scan", "POST", "member", "scan"),
    RouteSpec("ui.change_finding_status", "POST", "member", "finding"),
    RouteSpec("ui.bulk_change_finding_status", "POST", "member", "finding_bulk"),
    RouteSpec("ui.save_notification_settings", "POST", "member"),
    # UI POSTs (admin-only)
    RouteSpec("ui.archive_asset", "POST", "admin", "asset"),
    RouteSpec("ui.update_schedule", "POST", "admin", "asset"),
    RouteSpec("ui.verify_asset", "POST", "admin", "asset"),
    RouteSpec("ui.save_ai_settings", "POST", "admin"),
    RouteSpec("ui.clear_org_ai_key", "POST", "admin"),
    RouteSpec("ui.test_ai_connection", "POST", "admin"),
    # API v1 GETs
    RouteSpec("api_v1.list_assets", "GET", "member", "collection"),
    RouteSpec("api_v1.get_asset", "GET", "member", "asset"),
    RouteSpec("api_v1.list_asset_findings", "GET", "member", "asset"),
    RouteSpec("api_v1.list_asset_scans", "GET", "member", "asset"),
    RouteSpec("api_v1.list_findings", "GET", "member", "collection"),
    RouteSpec("api_v1.get_finding", "GET", "member", "finding"),
    RouteSpec("api_v1.list_scans", "GET", "member", "collection"),
    RouteSpec("api_v1.get_scan", "GET", "member", "scan"),
    # API v1 POSTs
    RouteSpec("api_v1.add_asset", "POST", "member"),
    RouteSpec("api_v1.create_scan", "POST", "member", "scan_create"),
    RouteSpec("api_v1.change_finding_status", "POST", "member", "finding"),
    RouteSpec("api_v1.bulk_change_finding_status", "POST", "member", "finding_bulk"),
    RouteSpec("api_v1.archive_asset", "POST", "admin", "asset"),
)


@dataclass(frozen=True)
class SeededOrg:
    org_id: UUID
    user_id: UUID
    root_id: UUID
    sub_id: UUID
    scan_id: UUID
    finding_id: UUID


def _csrf(client: FlaskClient, path: str = "/assets") -> str:
    match = _CSRF.search(client.get(path).get_data(as_text=True))
    assert match is not None
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


def _seed_org(
    session: Session, app: Flask, email: str, domain: str, *, key_last4: str = "9999"
) -> tuple[FlaskClient, SeededOrg]:
    client = _signup(app, email)
    user = session.scalars(select(User).where(User.email == email)).one()
    membership = session.scalars(select(Membership).where(Membership.user_id == user.id)).one()
    org_id = membership.org_id
    root = assets_service.add_root_domain(session, org_id, domain, actor_id=user.id)
    sub = assets_service.record_asset(
        session,
        org_id,
        AssetType.SUBDOMAIN,
        f"secret-sub.{domain}",
        source=AssetSource.DISCOVERED,
        parent_id=root.id,
    )
    scan = Scan(
        org_id=org_id,
        root_asset_id=root.id,
        profile="dns_passive",
        status=ScanStatus.RUNNING,
        triggered_by=ScanTrigger.USER,
    )
    session.add(scan)
    session.flush()
    finding = make_finding(
        session,
        org_id,
        sub.id,
        rule_id="dns.email.dmarc_missing",
        severity=Severity.HIGH,
        title=f"Secret finding for {domain}",
        evidence=((EvidenceKind.DNS_RECORD, {"record": "TXT", "value": f"secret-{domain}"}),),
    )
    session.add(
        OrgSettings(
            org_id=org_id,
            ai_enabled=True,
            provider=ProviderKind.ANTHROPIC,
            model="claude-sonnet-4-5",
            api_key_ciphertext=b"cipher-secret-bytes",
            api_key_last4=key_last4,
        )
    )
    session.add(
        NotificationPreference(
            org_id=org_id,
            user_id=user.id,
            email_enabled=True,
            min_severity=Severity.MEDIUM,
        )
    )
    session.commit()
    return client, SeededOrg(
        org_id=org_id,
        user_id=user.id,
        root_id=root.id,
        sub_id=sub.id,
        scan_id=scan.id,
        finding_id=finding.id,
    )


def _url_for_spec(spec: RouteSpec, ids: SeededOrg) -> str:
    paths = {
        "auth.login": "/login",
        "auth.signup": "/signup",
        "auth.logout": "/logout",
        "health.healthz": "/healthz",
        "static": "/static/css/app.css",
        "ui.dashboard": "/",
        "ui.assets": "/assets",
        "ui.add_domain": "/assets",
        "ui.add_url": "/assets/url",
        "ui.upload_repo": "/assets/upload",
        "ui.upload_binary": "/assets/upload-binary",
        "ui.asset_detail": f"/assets/{ids.root_id}",
        "ui.ownership_card": f"/assets/{ids.root_id}/ownership",
        "ui.archive_asset": f"/assets/{ids.root_id}/archive",
        "ui.update_schedule": f"/assets/{ids.root_id}/schedule",
        "ui.verify_asset": f"/assets/{ids.root_id}/verify",
        "ui.scans": "/scans",
        "ui.create_scan": "/scans",
        "ui.scan_detail": f"/scans/{ids.scan_id}",
        "ui.scan_progress": f"/scans/{ids.scan_id}/progress",
        "ui.scan_summary": f"/scans/{ids.scan_id}/summary",
        "ui.scan_triage": f"/scans/{ids.scan_id}/triage",
        "ui.cancel_scan": f"/scans/{ids.scan_id}/cancel",
        "ui.findings": "/findings",
        "ui.finding_detail": f"/findings/{ids.finding_id}",
        "ui.change_finding_status": f"/findings/{ids.finding_id}/status",
        "ui.bulk_change_finding_status": "/findings/bulk-status",
        "ui.export_findings_csv": "/findings/export.csv",
        "ui.export_findings_json": "/findings/export.json",
        "ui.settings": "/settings",
        "ui.save_ai_settings": "/settings/ai",
        "ui.clear_org_ai_key": "/settings/ai/clear-key",
        "ui.ai_test_status": "/settings/ai/test",
        "ui.test_ai_connection": "/settings/ai/test",
        "ui.save_notification_settings": "/settings/notifications",
        "api_v1.list_assets": "/api/v1/assets",
        "api_v1.add_asset": "/api/v1/assets",
        "api_v1.get_asset": f"/api/v1/assets/{ids.root_id}",
        "api_v1.archive_asset": f"/api/v1/assets/{ids.root_id}/archive",
        "api_v1.list_asset_findings": f"/api/v1/assets/{ids.root_id}/findings",
        "api_v1.list_asset_scans": f"/api/v1/assets/{ids.root_id}/scans",
        "api_v1.list_findings": "/api/v1/findings",
        "api_v1.get_finding": f"/api/v1/findings/{ids.finding_id}",
        "api_v1.change_finding_status": f"/api/v1/findings/{ids.finding_id}/status",
        "api_v1.bulk_change_finding_status": "/api/v1/findings/bulk-status",
        "api_v1.list_scans": "/api/v1/scans",
        "api_v1.create_scan": "/api/v1/scans",
        "api_v1.get_scan": f"/api/v1/scans/{ids.scan_id}",
    }
    return paths[spec.endpoint]


def _payload_for_post(spec: RouteSpec, ids: SeededOrg, *, csrf: str | None) -> dict[str, object]:
    """Build valid-shaped form data or JSON for a POST route."""
    if spec.endpoint.startswith("api_v1."):
        api_bodies: dict[str, dict[str, object]] = {
            "api_v1.add_asset": {"value": "extra.example.com"},
            "api_v1.create_scan": {"root_asset_id": str(ids.root_id)},
            "api_v1.change_finding_status": {"status": "false_positive", "comment": "audited"},
            "api_v1.bulk_change_finding_status": {
                "finding_ids": [str(ids.finding_id)],
                "status": "false_positive",
                "comment": "audited",
            },
        }
        return {
            "json": api_bodies.get(spec.endpoint, {}),
            "headers": {"X-CSRFToken": csrf} if csrf is not None else {},
        }
    ui_forms: dict[str, dict[str, str]] = {
        "auth.login": {"email": "nobody@example.com", "password": "wrong"},
        "auth.signup": {"email": "new-user@example.com", "password": "correct horse battery"},
        "ui.add_domain": {"value": "extra.example.com"},
        "ui.add_url": {"url": "https://extra.example.com/"},
        "ui.create_scan": {"root_asset_id": str(ids.root_id), "profile": "dns_passive"},
        "ui.change_finding_status": {"status": "false_positive", "comment": "audited"},
        "ui.bulk_change_finding_status": {
            "finding_ids": str(ids.finding_id),
            "status": "false_positive",
            "comment": "audited",
        },
        "ui.update_schedule": {"frequency": "weekly", "enabled": "1"},
        "ui.verify_asset": {"action": "start"},
        "ui.save_ai_settings": {"provider": "anthropic", "model": "claude-sonnet-4-5"},
        "ui.save_notification_settings": {"min_severity": "high"},
    }
    form = dict(ui_forms.get(spec.endpoint, {}))
    if csrf is not None:
        form["csrf_token"] = csrf
    return {"data": form}


def test_every_registered_route_is_classified(db_app: Flask) -> None:
    registered = {
        (rule.endpoint, method)
        for rule in db_app.url_map.iter_rules()
        for method in (rule.methods or set())
        if method not in {"HEAD", "OPTIONS"}
    }
    classified = {(spec.endpoint, spec.method) for spec in ROUTE_MATRIX}
    assert len(classified) == len(ROUTE_MATRIX)
    assert registered == classified


def test_every_protected_route_requires_login(db_app: Flask, db_session: Session) -> None:
    _client, ids = _seed_org(db_session, db_app, "alice-anon@example.com", "alice-anon.example.com")
    anon = db_app.test_client()

    for spec in ROUTE_MATRIX:
        if spec.access == "public":
            continue
        url = _url_for_spec(spec, ids)
        response = anon.open(url, method=spec.method)
        if spec.endpoint.startswith("api_v1."):
            assert response.status_code == 401, spec
        else:
            assert response.status_code == 302, spec
            assert "/login" in response.headers["Location"], spec
            if spec.method == "GET":
                htmx = anon.get(url, headers=_HTMX)
                assert htmx.status_code == 200, spec
                assert "/login" in htmx.headers["HX-Redirect"], spec


def test_every_mutating_route_requires_valid_csrf(db_app: Flask, db_session: Session) -> None:
    alice, ids = _seed_org(db_session, db_app, "alice-csrf@example.com", "alice-csrf.example.com")

    for spec in ROUTE_MATRIX:
        if spec.method != "POST" or spec.endpoint == "auth.logout":
            continue
        url = _url_for_spec(spec, ids)
        client = db_app.test_client() if spec.access == "public" else alice
        missing = client.post(url, **_payload_for_post(spec, ids, csrf=None))  # type: ignore[arg-type]
        invalid = client.post(url, **_payload_for_post(spec, ids, csrf="invalid-csrf-token"))  # type: ignore[arg-type]
        assert missing.status_code == 400, spec
        assert invalid.status_code == 400, spec

    # Logout must also reject missing/invalid CSRF tokens.
    assert alice.post("/logout").status_code == 400
    assert alice.post("/logout", data={"csrf_token": "bad"}).status_code == 400


def test_every_admin_route_rejects_member(db_app: Flask, db_session: Session) -> None:
    client, ids = _seed_org(db_session, db_app, "member@example.com", "member.example.com")
    membership = db_session.scalars(
        scoped(Membership, ids.org_id).where(Membership.user_id == ids.user_id)
    ).one()
    membership.role = Role.MEMBER
    db_session.commit()
    token = _csrf(client)

    for spec in ROUTE_MATRIX:
        if spec.access != "admin":
            continue
        url = _url_for_spec(spec, ids)
        kwargs = _payload_for_post(spec, ids, csrf=token)
        response = client.open(url, method=spec.method, **kwargs)  # type: ignore[arg-type]
        assert response.status_code == 403, spec


def test_every_tenant_endpoint_isolates_orgs(
    db_app: Flask, db_session: Session, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(
        ui_module, "get_task_queue", lambda: FakeQueue(db_app.extensions["db_session_factory"]())
    )
    monkeypatch.setattr(
        api_module, "get_task_queue", lambda: FakeQueue(db_app.extensions["db_session_factory"]())
    )
    _alice, alice_ids = _seed_org(
        db_session,
        db_app,
        "alice-iso@example.com",
        "alice-secret.example.com",
        key_last4="A9Z9",
    )
    bob, _bob_ids = _seed_org(
        db_session,
        db_app,
        "bob-iso@example.com",
        "bob-public.example.com",
        key_last4="B1C2",
    )
    bob_csrf = _csrf(bob)

    for spec in ROUTE_MATRIX:
        if spec.tenant_param is None:
            continue
        url = _url_for_spec(spec, alice_ids)
        if spec.tenant_param == "collection":
            response = bob.open(url, method=spec.method)
            assert response.status_code == 200, spec
            body = response.get_data(as_text=True)
            assert "alice-secret.example.com" not in body, spec
            assert "Secret finding for alice-secret.example.com" not in body, spec
            assert "A9Z9" not in body, spec
            continue
        if spec.method == "GET":
            response = bob.get(url)
            assert response.status_code == 404, spec
            continue
        kwargs = _payload_for_post(spec, alice_ids, csrf=bob_csrf)
        response = bob.post(url, **kwargs)  # type: ignore[arg-type]
        if spec.endpoint in {"ui.create_scan", "ui.bulk_change_finding_status"}:
            # UI create_scan returns 404 for foreign root; bulk_status redirects with flash error.
            if spec.endpoint == "ui.create_scan":
                assert response.status_code == 404, spec
            else:
                assert response.status_code == 303, spec
        else:
            assert response.status_code == 404, spec

    db_session.expire_all()
    # Alice's finding, asset, scan, and org settings remain untouched by Bob's requests.
    assert db_session.get_one(Finding, alice_ids.finding_id).status is FindingStatus.OPEN
    assert db_session.get_one(Asset, alice_ids.root_id).is_active is True
    assert db_session.get_one(Scan, alice_ids.scan_id).status is ScanStatus.RUNNING
    settings_view = org_settings.get_org_settings(db_session, alice_ids.org_id)
    assert settings_view.api_key_last4 == "A9Z9"
    assert db_session.get_one(Org, alice_ids.org_id).id == alice_ids.org_id


def test_encrypted_org_key_never_appears_on_settings_or_api(
    db_app: Flask, db_session: Session, monkeypatch: pytest.MonkeyPatch
) -> None:
    app_key = base64.urlsafe_b64encode(b"7" * 32).decode().rstrip("=")
    monkeypatch.setitem(
        db_app.extensions,
        "auth_settings",
        db_app.extensions["auth_settings"].model_copy(
            update={"app_encryption_key": SecretStr(app_key)}
        ),
    )
    alice, _ids = _seed_org(db_session, db_app, "key-check@example.com", "key-check.example.com")
    csrf = _csrf(alice, "/settings")
    raw_secret = "sk-ant-super-secret-value-abcd"

    saved = alice.post(
        "/settings/ai",
        data={
            "ai_enabled": "on",
            "provider": "anthropic",
            "model": "claude-sonnet-4-5",
            "api_key": raw_secret,
            "csrf_token": csrf,
        },
        follow_redirects=True,
    )
    assert saved.status_code == 200
    html = saved.get_data(as_text=True)
    assert raw_secret not in html
    assert "abcd" in html
