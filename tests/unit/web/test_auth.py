"""Web auth layer with faked services (DB-backed flows: tests/integration/web/test_auth_flow.py)."""

import json
import re
import time
from typing import Any
from unittest.mock import Mock
from uuid import UUID

import pytest
from flask import Flask
from flask.testing import FlaskClient
from itsdangerous import timed
from werkzeug.middleware.proxy_fix import ProxyFix

from attacksurf.app import create_app
from attacksurf.domain.accounts import InvalidCredentials, InvalidSignup, Role, SignupClosed
from attacksurf.services import accounts as accounts_service
from attacksurf.services import auth as auth_service
from attacksurf.services.accounts import Registration
from attacksurf.services.auth import SessionUser
from attacksurf.web.auth import _safe_next, require_role
from tests.helpers import PROD_SECRET_KEY, make_settings
from tests.unit.web.conftest import LoginAs, make_session_user

_CSRF = re.compile(r'name="csrf_token" value="([^"]+)"')
_HX_HEADERS = re.compile(r"<body hx-headers='([^']+)'>")


def csrf_token(client: FlaskClient, path: str = "/login") -> str:
    match = _CSRF.search(client.get(path).get_data(as_text=True))
    assert match
    return match.group(1)


def assert_csrf_valid(client: FlaskClient, token: str) -> None:
    """Assert the app *accepts* `token` as an HTMX header, i.e. it is a working CSRF token.

    Goes through the real request path instead of calling `validate_csrf` directly: a POST with
    the token in `X-CSRFToken` must succeed. That is the property the shell's header provides,
    and it needs no session plumbing of its own. The caller must have registered
    `add_csrf_probe_route` before the first request (routes can't be added afterwards).
    """
    response = client.post(
        "/_test/csrf_probe", headers={"HX-Request": "true", "X-CSRFToken": token}
    )

    assert response.status_code == 200, "the shell's CSRF header token was rejected"


def add_csrf_probe_route(app: Flask) -> None:
    """A pass-through POST target for `assert_csrf_valid`; must run before any request."""
    app.add_url_rule("/_test/csrf_probe", "csrf_probe", view_func=lambda: "ok", methods=["POST"])


@pytest.fixture
def fake_authenticate(monkeypatch: pytest.MonkeyPatch, login_as: LoginAs) -> Mock:
    """`authenticate` accepting password "right" and registering the user for the loader."""
    user = make_session_user()
    mock = Mock(side_effect=lambda _s, _h, _e, pw: _accept(pw, user))
    monkeypatch.setattr(auth_service, "authenticate", mock)
    # Make the user loadable on later requests, like a real DB lookup would.
    monkeypatch.setattr(
        auth_service, "load_session_user", lambda _s, uid: user if uid == user.user_id else None
    )
    return mock


def _accept(password: str, user: SessionUser) -> SessionUser:
    if password != "right":
        raise InvalidCredentials
    return user


@pytest.fixture
def signup_state(monkeypatch: pytest.MonkeyPatch) -> dict[str, Any]:
    state: dict[str, Any] = {"has_users": True}
    monkeypatch.setattr(auth_service, "has_users", lambda _s: state["has_users"])
    return state


# Login gate


def test_anonymous_page_request_redirects_to_login(client: FlaskClient) -> None:
    response = client.get("/findings?severity=high")

    assert response.status_code == 302
    assert response.headers["Location"] == "/login?next=/findings?severity%3Dhigh"


def test_anonymous_htmx_request_gets_hx_redirect(client: FlaskClient) -> None:
    response = client.get("/assets", headers={"HX-Request": "true"})

    assert response.status_code == 200
    assert response.headers["HX-Redirect"] == "/login?next=/assets"


def test_anonymous_api_request_gets_401_json(app: Flask) -> None:
    app.add_url_rule("/api/v1/_test/ping", "api_ping", view_func=lambda: {"ok": True})

    response = app.test_client().get("/api/v1/_test/ping")

    assert response.status_code == 401
    assert response.get_json() == {"error": "Unauthorized"}


@pytest.mark.parametrize("path", ["/healthz", "/static/css/app.css", "/login", "/no-such-page"])
def test_public_paths_do_not_redirect(client: FlaskClient, signup_state: dict, path: str) -> None:
    assert client.get(path).status_code in {200, 404}


def test_invalid_user_id_in_session_is_anonymous(client: FlaskClient) -> None:
    with client.session_transaction() as sess:
        sess["_user_id"] = "not-a-uuid"

    assert client.get("/").status_code == 302


def test_deactivated_user_is_logged_out(
    client: FlaskClient, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(auth_service, "load_session_user", lambda _s, _uid: None)
    with client.session_transaction() as sess:
        sess["_user_id"] = str(make_session_user().user_id)

    assert client.get("/").status_code == 302


# Login


def test_login_page_renders_without_app_shell(client: FlaskClient, signup_state: dict) -> None:
    html = client.get("/login").get_data(as_text=True)

    assert "<h1>Log in</h1>" in html
    assert 'class="shell"' not in html
    assert 'name="csrf_token"' in html
    assert 'autocomplete="current-password"' in html


def test_login_success_redirects_and_sets_session(
    client: FlaskClient, fake_authenticate: Mock, signup_state: dict
) -> None:
    token = csrf_token(client)

    response = client.post(
        "/login", data={"email": "a@example.com", "password": "right", "csrf_token": token}
    )

    assert response.status_code == 302
    assert response.headers["Location"] == "/"
    assert client.get("/").status_code == 200


def test_login_starts_a_fresh_session(
    client: FlaskClient, fake_authenticate: Mock, signup_state: dict
) -> None:
    token = csrf_token(client)
    with client.session_transaction() as sess:
        sess["planted"] = "attacker"

    client.post("/login", data={"email": "a@example.com", "password": "right", "csrf_token": token})

    with client.session_transaction() as sess:
        assert "planted" not in sess
        assert sess.permanent


def test_login_failure_shows_generic_error_and_keeps_email(
    client: FlaskClient, fake_authenticate: Mock, signup_state: dict
) -> None:
    token = csrf_token(client)

    response = client.post(
        "/login", data={"email": "a@example.com", "password": "wrong", "csrf_token": token}
    )
    html = response.get_data(as_text=True)

    assert response.status_code == 422
    assert "Invalid email or password." in html
    assert 'value="a@example.com"' in html
    assert "wrong" not in html


def test_login_redirects_to_safe_next(
    client: FlaskClient, fake_authenticate: Mock, signup_state: dict
) -> None:
    token = csrf_token(client)

    response = client.post(
        "/login",
        data={"email": "a@x.io", "password": "right", "csrf_token": token, "next": "/scans"},
    )

    assert response.headers["Location"] == "/scans"


@pytest.mark.parametrize(
    "target",
    ["https://evil.example/", "//evil.example", "/\\evil.example", "javascript:alert(1)", "", None],
)
def test_safe_next_rejects_offsite_targets(target: str | None) -> None:
    assert _safe_next(target) is None


@pytest.mark.parametrize("target", ["/", "/findings?severity=high"])
def test_safe_next_accepts_local_paths(target: str) -> None:
    assert _safe_next(target) == target


def test_logged_in_user_visiting_login_goes_to_dashboard(auth_client: FlaskClient) -> None:
    assert auth_client.get("/login").headers["Location"] == "/"


def test_login_without_csrf_token_is_rejected(client: FlaskClient, fake_authenticate: Mock) -> None:
    response = client.post("/login", data={"email": "a@example.com", "password": "right"})

    assert response.status_code == 400
    assert b"Reload the page and try again." in response.data
    fake_authenticate.assert_not_called()


# CSRF for HTMX


def test_shell_sends_csrf_token_header_for_htmx(app: Flask, auth_client: FlaskClient) -> None:
    """The shell's HTMX header carries a token that actually validates for this session.

    Comparing it to a token from a *second* GET was flaky: Flask-WTF signs with a timestamp, so
    two requests either side of a second boundary yield different (both valid) strings. Validate
    the header token instead — the property that matters — with one request only.
    """
    add_csrf_probe_route(app)
    html = auth_client.get("/").get_data(as_text=True)

    match = _HX_HEADERS.search(html)
    assert match
    header = json.loads(match.group(1))["X-CSRFToken"]
    assert_csrf_valid(auth_client, header)


def test_csrf_token_strings_are_not_stable_across_boundaries(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Why the old test was flaky: signing stamps the time, so strings legitimately differ.

    Both stamped values verify — the two tokens are equally valid, only their text differs.
    """

    clock = {"now": 1_000_000.9}
    monkeypatch.setattr(timed.TimestampSigner, "get_timestamp", lambda self: int(clock["now"]))
    signer = timed.TimestampSigner("secret")

    before = signer.sign(b"same-session-token")
    clock["now"] = 1_000_001.0  # one second later: the boundary the old test straddled
    after = signer.sign(b"same-session-token")

    assert before != after
    assert signer.unsign(before) == b"same-session-token"
    assert signer.unsign(after) == b"same-session-token"


def test_shell_csrf_header_rejects_a_corrupted_token(app: Flask, auth_client: FlaskClient) -> None:
    add_csrf_probe_route(app)
    html = auth_client.get("/").get_data(as_text=True)
    match = _HX_HEADERS.search(html)
    assert match
    header = json.loads(match.group(1))["X-CSRFToken"]

    corrupt = f"{header[:-1]}{'A' if header[-1] != 'A' else 'B'}"
    with pytest.raises(AssertionError, match="rejected"):
        assert_csrf_valid(auth_client, corrupt)


def test_shell_csrf_tokens_from_two_responses_both_validate(
    app: Flask, auth_client: FlaskClient
) -> None:
    """Two GETs may hand out different tokens; each must be accepted, which is what matters.

    Covers the case the old cross-request equality assertion got wrong: it compared the strings
    rather than validating either, so it failed whenever the two requests straddled a second.
    """
    add_csrf_probe_route(app)
    tokens = []
    for _ in range(2):
        match = _HX_HEADERS.search(auth_client.get("/").get_data(as_text=True))
        assert match
        tokens.append(json.loads(match.group(1))["X-CSRFToken"])

    for token in tokens:
        assert_csrf_valid(auth_client, token)


def test_anonymous_page_carries_a_valid_csrf_header(app: Flask, client: FlaskClient) -> None:
    """The login shell uses the shared layout too, so its header token must validate as well."""
    add_csrf_probe_route(app)
    match = _HX_HEADERS.search(client.get("/login").get_data(as_text=True))

    assert match
    assert_csrf_valid(client, json.loads(match.group(1))["X-CSRFToken"])


def test_htmx_post_needs_csrf_header(app: Flask, auth_client: FlaskClient) -> None:
    app.add_url_rule("/_test/action", "action", view_func=lambda: "done", methods=["POST"])
    token = csrf_token(auth_client, "/")

    assert auth_client.post("/_test/action", headers={"HX-Request": "true"}).status_code == 400
    ok = auth_client.post("/_test/action", headers={"HX-Request": "true", "X-CSRFToken": token})
    assert ok.status_code == 200


# Logout


def test_logout_records_event_and_clears_session(
    auth_client: FlaskClient, session_user: SessionUser, monkeypatch: pytest.MonkeyPatch
) -> None:
    record = Mock()
    monkeypatch.setattr(auth_service, "record_logout", record)
    token = csrf_token(auth_client, "/")

    response = auth_client.post("/logout", data={"csrf_token": token})

    assert response.headers["Location"] == "/login"
    record.assert_called_once()
    assert record.call_args.args[1] == session_user
    with auth_client.session_transaction() as sess:
        assert "_user_id" not in sess


def test_logout_needs_csrf_token(auth_client: FlaskClient) -> None:
    assert auth_client.post("/logout").status_code == 400


def test_shell_shows_user_and_logout_form(auth_client: FlaskClient) -> None:
    html = auth_client.get("/").get_data(as_text=True)

    assert "alice@example.com · Acme" in html
    assert 'action="/logout"' in html


# Signup


def test_signup_open_by_default(client: FlaskClient, signup_state: dict) -> None:
    response = client.get("/signup")

    assert response.status_code == 200
    assert b"Create your account" in response.data


def _app_with_signup_off() -> Flask:
    return create_app(make_settings(env="test", secret_key="k", allow_signup=False))


def test_signup_closed_returns_404_once_users_exist(signup_state: dict) -> None:
    client = _app_with_signup_off().test_client()

    assert client.get("/signup").status_code == 404
    assert b"Sign up" not in client.get("/login").data


def test_signup_closed_still_allows_first_user(signup_state: dict) -> None:
    signup_state["has_users"] = False

    assert _app_with_signup_off().test_client().get("/signup").status_code == 200


def test_signup_success_logs_in(
    client: FlaskClient, signup_state: dict, monkeypatch: pytest.MonkeyPatch
) -> None:
    user, org = Mock(id=UUID(int=1), email="new@example.com"), Mock(id=UUID(int=2))
    org.name = "New Org"
    monkeypatch.setattr(
        accounts_service, "register_user", Mock(return_value=Registration(user=user, org=org))
    )
    loaded = SessionUser(UUID(int=1), "new@example.com", UUID(int=2), "New Org", Role.OWNER)
    monkeypatch.setattr(auth_service, "load_session_user", lambda _s, _uid: loaded)
    token = csrf_token(client, "/signup")

    response = client.post(
        "/signup",
        data={"email": "new@example.com", "password": "long enough pass", "csrf_token": token},
    )

    assert response.headers["Location"] == "/"
    assert "Welcome to attacksurf." in client.get("/").get_data(as_text=True)


def test_signup_error_is_shown(
    client: FlaskClient, signup_state: dict, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(
        accounts_service, "register_user", Mock(side_effect=InvalidSignup("Password too short."))
    )
    token = csrf_token(client, "/signup")

    response = client.post(
        "/signup", data={"email": "n@example.com", "password": "x", "csrf_token": token}
    )

    assert response.status_code == 422
    assert b"Password too short." in response.data


# Roles


@pytest.mark.parametrize(
    ("role", "status"), [(Role.MEMBER, 403), (Role.ADMIN, 200), (Role.OWNER, 200)]
)
def test_require_role(app: Flask, login_as: LoginAs, role: Role, status: int) -> None:
    @require_role(Role.ADMIN)
    def admin_only() -> str:
        return "secret settings"

    app.add_url_rule("/_test/admin", "admin_only", view_func=admin_only)
    client = app.test_client()
    login_as(client, make_session_user(role=role))

    assert client.get("/_test/admin").status_code == status


# Rate limits


def test_login_rate_limited_per_ip(client: FlaskClient, fake_authenticate: Mock) -> None:
    token = csrf_token(client)
    data = {"email": "a@example.com", "password": "wrong", "csrf_token": token}

    statuses = [client.post("/login", data=data).status_code for _ in range(6)]

    assert statuses[:5] == [422] * 5
    assert statuses[5] == 429
    assert "Retry-After" in client.post("/login", data=data).headers


def test_login_rate_limited_per_email_across_ips(
    client: FlaskClient, fake_authenticate: Mock
) -> None:
    token = csrf_token(client)
    data = {"email": "victim@example.com", "password": "wrong", "csrf_token": token}

    statuses = [
        client.post("/login", data=data, environ_base={"REMOTE_ADDR": f"10.0.0.{i}"}).status_code
        for i in range(11)
    ]

    assert statuses[:10] == [422] * 10
    assert statuses[10] == 429


def test_signup_rate_limited(
    client: FlaskClient, signup_state: dict, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(accounts_service, "register_user", Mock(side_effect=InvalidSignup("no")))
    token = csrf_token(client, "/signup")
    data = {"email": "n@example.com", "password": "x", "csrf_token": token}

    statuses = [client.post("/signup", data=data).status_code for _ in range(6)]

    assert statuses[5] == 429


def test_rate_limit_page_is_html_error(client: FlaskClient, fake_authenticate: Mock) -> None:
    token = csrf_token(client)
    data = {"email": "a@example.com", "password": "wrong", "csrf_token": token}
    for _ in range(5):
        client.post("/login", data=data)

    response = client.post("/login", data=data)

    assert response.status_code == 429
    assert b"<h1>Too Many Requests</h1>" in response.data
    assert b"Wait a minute and try again." in response.data


# Cookies and proxies


def _login_cookie(app: Flask, monkeypatch: pytest.MonkeyPatch, base_url: str) -> str:
    user = make_session_user()
    monkeypatch.setattr(auth_service, "authenticate", lambda *_a: user)
    monkeypatch.setattr(auth_service, "has_users", lambda _s: True)
    client = app.test_client()
    token = _CSRF.search(client.get("/login", base_url=base_url).get_data(as_text=True))
    assert token
    response = client.post(
        "/login",
        data={"email": "a@x.io", "password": "p", "csrf_token": token.group(1)},
        base_url=base_url,
    )
    return response.headers["Set-Cookie"]


def test_dev_session_cookie_flags(app: Flask, monkeypatch: pytest.MonkeyPatch) -> None:
    cookie = _login_cookie(app, monkeypatch, "http://localhost")

    assert cookie.startswith("session=")
    assert "HttpOnly" in cookie
    assert "SameSite=Lax" in cookie
    assert "Secure" not in cookie
    assert "Expires=" in cookie


def test_prod_session_cookie_is_secure_host_cookie(monkeypatch: pytest.MonkeyPatch) -> None:
    app = create_app(make_settings(env="prod", secret_key=PROD_SECRET_KEY))

    cookie = _login_cookie(app, monkeypatch, "https://attacksurf.example")

    assert cookie.startswith("__Host-session=")
    assert "Secure" in cookie
    assert "Domain=" not in cookie
    assert "Path=/" in cookie


def test_proxy_count_enables_forwarded_headers() -> None:
    app = create_app(make_settings(env="test", secret_key="k", proxy_count=1))

    assert isinstance(app.wsgi_app, ProxyFix)


def test_no_proxy_fix_by_default(app: Flask) -> None:
    assert not isinstance(app.wsgi_app, ProxyFix)


# Regressions from review of #45


def test_anonymous_post_is_gated_before_csrf(app: Flask) -> None:
    app.add_url_rule("/api/v1/_test/do", "api_do", view_func=lambda: "x", methods=["POST"])
    client = app.test_client()

    assert client.post("/api/v1/_test/do").status_code == 401
    assert client.post("/logout").headers["Location"].startswith("/login")


def test_logout_clears_session_even_if_audit_fails(
    auth_client: FlaskClient, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(auth_service, "record_logout", Mock(side_effect=RuntimeError("db down")))
    token = csrf_token(auth_client, "/")

    response = auth_client.post("/logout", data={"csrf_token": token})

    assert response.headers["Location"] == "/login"
    with auth_client.session_transaction() as sess:
        assert "_user_id" not in sess


def test_session_expires_at_absolute_lifetime_despite_activity(
    client: FlaskClient, fake_authenticate: Mock, signup_state: dict
) -> None:
    token = csrf_token(client)
    client.post("/login", data={"email": "a@x.io", "password": "right", "csrf_token": token})
    assert client.get("/scans").status_code == 200

    with client.session_transaction() as sess:
        sess["auth_at"] = int(time.time()) - 12 * 3600 - 1  # logged in just over 12h ago

    assert client.get("/scans").status_code == 302
    with client.session_transaction() as sess:
        assert "_user_id" not in sess


def test_session_without_login_time_is_rejected(
    client: FlaskClient, monkeypatch: pytest.MonkeyPatch
) -> None:
    user = make_session_user()
    monkeypatch.setattr(auth_service, "load_session_user", lambda _s, _uid: user)
    with client.session_transaction() as sess:
        sess["_user_id"] = str(user.user_id)  # e.g. a cookie minted before this check existed

    assert client.get("/").status_code == 302


def test_unchanged_session_cookie_is_not_reissued(
    client: FlaskClient, fake_authenticate: Mock, signup_state: dict
) -> None:
    token = csrf_token(client)
    client.post("/login", data={"email": "a@x.io", "password": "right", "csrf_token": token})
    client.get("/scans")  # first page after login stores a fresh CSRF token

    assert "Set-Cookie" not in client.get("/scans").headers


def test_signup_with_signup_off_asks_service_for_first_user_only(
    signup_state: dict, monkeypatch: pytest.MonkeyPatch
) -> None:
    signup_state["has_users"] = False
    register = Mock(side_effect=SignupClosed("closed"))
    monkeypatch.setattr(accounts_service, "register_user", register)
    client = _app_with_signup_off().test_client()
    token = csrf_token(client, "/signup")

    response = client.post(
        "/signup", data={"email": "n@example.com", "password": "x" * 12, "csrf_token": token}
    )

    assert response.status_code == 404
    assert register.call_args.kwargs["first_user_only"] is True
