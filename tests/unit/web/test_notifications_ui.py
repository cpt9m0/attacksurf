import re

import pytest
from flask.testing import FlaskClient

from attacksurf.domain.accounts import Role
from attacksurf.domain.findings import Severity
from attacksurf.services import notifications
from tests.conftest import LoginAs, make_session_user


def _csrf(client: FlaskClient, path: str = "/settings") -> str:
    html = client.get(path).get_data(as_text=True)
    match = re.search(r'name="csrf_token" value="([^"]+)"', html)
    assert match
    return match.group(1)


def test_settings_renders_notification_preferences_for_member(app, login_as: LoginAs) -> None:
    client = app.test_client()
    login_as(client, make_session_user(role=Role.MEMBER))

    html = client.get("/settings").get_data(as_text=True)

    assert "Email notifications" in html
    assert 'action="/settings/notifications"' in html
    assert "Outbound SMTP is not configured on this server" in html


def test_save_notification_preferences_persists_and_redirects(
    auth_client: FlaskClient, monkeypatch: pytest.MonkeyPatch
) -> None:
    saved: list[tuple[bool, Severity]] = []

    def _fake_save(
        _session, _org_id, _user_id, *, email_enabled: bool, min_severity: Severity
    ) -> notifications.NotificationPreferenceView:
        saved.append((email_enabled, min_severity))
        return notifications.NotificationPreferenceView(
            email_enabled=email_enabled, min_severity=min_severity
        )

    monkeypatch.setattr(notifications, "save_notification_preference", _fake_save)
    csrf = _csrf(auth_client)

    res = auth_client.post(
        "/settings/notifications",
        data={"csrf_token": csrf, "min_severity": "medium"},
        headers={"HX-Request": "true"},
    )

    assert res.status_code == 200
    assert res.headers["HX-Redirect"] == "/settings"
    assert saved == [(False, Severity.MEDIUM)]


def test_save_notification_preferences_rejects_invalid_severity_with_422(
    auth_client: FlaskClient,
) -> None:
    csrf = _csrf(auth_client)

    res = auth_client.post(
        "/settings/notifications",
        data={"csrf_token": csrf, "email_enabled": "1", "min_severity": "extreme"},
        headers={"HX-Request": "true"},
    )
    html = res.get_data(as_text=True)

    assert res.status_code == 422
    assert "Choose a valid severity threshold." in html
    assert 'id="notification-settings-form"' in html


def test_save_notification_preferences_requires_csrf(auth_client: FlaskClient) -> None:
    res = auth_client.post("/settings/notifications", data={"min_severity": "high"})
    assert res.status_code == 400
