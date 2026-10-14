"""Authentication: login/signup/logout, login gate, CSRF, rate limits, roles (ADR 0009)."""

import time
from collections.abc import Callable
from datetime import timedelta
from functools import wraps
from typing import cast
from urllib.parse import urlsplit
from uuid import UUID

import structlog
from flask import (
    Blueprint,
    Flask,
    Response,
    abort,
    current_app,
    flash,
    jsonify,
    redirect,
    request,
    session,
    url_for,
)
from flask.typing import RouteCallable
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from flask_login import LoginManager, UserMixin, current_user, login_user, logout_user
from flask_wtf.csrf import CSRFProtect
from werkzeug.middleware.proxy_fix import ProxyFix
from werkzeug.wrappers.response import Response as BaseResponse

from attacksurf.config import Settings
from attacksurf.domain.accounts import (
    AccountError,
    InvalidCredentials,
    PasswordHasher,
    Role,
    SignupClosed,
    has_role,
)
from attacksurf.infra.crypto import Argon2PasswordHasher
from attacksurf.services import accounts as accounts_service
from attacksurf.services import auth as auth_service
from attacksurf.services.auth import SessionUser
from attacksurf.web.db import get_session
from attacksurf.web.rendering import is_htmx_request, render_page

log = structlog.get_logger(__name__)

bp = Blueprint("auth", __name__)

# Everything else requires a logged-in user (default deny).
PUBLIC_ENDPOINTS = frozenset({"auth.login", "auth.signup", "static", "health.healthz"})
LOGIN_LIMITS = ("5 per minute", "20 per hour")
LOGIN_PER_EMAIL_LIMIT = "10 per hour"
SIGNUP_LIMIT = "5 per hour"
_HASHER_KEY = "password_hasher"
_SETTINGS_KEY = "auth_settings"
_AUTH_AT = "auth_at"  # login time (epoch seconds) in the session


class WebUser(UserMixin):
    """Flask-Login adapter around the service-layer `SessionUser`."""

    def __init__(self, user: SessionUser) -> None:
        self.session_user = user

    def get_id(self) -> str:
        return str(self.session_user.user_id)

    @property
    def email(self) -> str:
        return self.session_user.email

    @property
    def org_name(self) -> str:
        return self.session_user.org_name

    @property
    def role(self) -> Role:
        return self.session_user.role


def init_auth(app: Flask, settings: Settings) -> None:
    if settings.proxy_count:
        n = settings.proxy_count
        app.wsgi_app = ProxyFix(app.wsgi_app, x_for=n, x_proto=n, x_host=n)  # type: ignore[method-assign]
    app.config.update(
        # __Host- prefix: browser only accepts it over HTTPS, host-only, path "/".
        SESSION_COOKIE_NAME="__Host-session" if settings.is_prod else "session",
        SESSION_COOKIE_SECURE=settings.is_prod,
        SESSION_COOKIE_HTTPONLY=True,
        SESSION_COOKIE_SAMESITE="Lax",
        PERMANENT_SESSION_LIFETIME=timedelta(hours=settings.session_lifetime_hours),
        # Fewer cookie re-issues; the absolute lifetime itself is enforced via _AUTH_AT below,
        # because any session change (e.g. a new CSRF token) would push the cookie expiry out.
        SESSION_REFRESH_EACH_REQUEST=False,
    )
    app.extensions[_HASHER_KEY] = Argon2PasswordHasher()
    app.extensions[_SETTINGS_KEY] = settings

    manager = LoginManager(app)
    manager.user_loader(_load_user)
    # Before CSRFProtect: anonymous requests get 401/redirect, not a CSRF 400.
    app.before_request(_require_login)
    CSRFProtect(app)
    app.register_blueprint(bp)
    _apply_rate_limits(app, settings)


def require_role[**P, R](role: Role) -> Callable[[Callable[P, R]], Callable[P, R]]:
    """403 unless the current user's role in their org grants at least `role`."""

    def decorator(view: Callable[P, R]) -> Callable[P, R]:
        @wraps(view)
        def wrapped(*args: P.args, **kwargs: P.kwargs) -> R:
            if not current_user.is_authenticated or not has_role(current_user.role, role):
                abort(403)
            return view(*args, **kwargs)

        return wrapped

    return decorator


@bp.route("/login", methods=["GET", "POST"])
def login() -> BaseResponse:
    if current_user.is_authenticated:
        return redirect(url_for("ui.dashboard"))
    next_url = _safe_next(request.values.get("next"))
    email = request.form.get("email", "")
    if request.method == "POST":
        try:
            user = auth_service.authenticate(
                get_session(), _hasher(), email, request.form.get("password", "")
            )
        except InvalidCredentials:
            return _render_form("auth/login.html", "Invalid email or password.", email, next_url)
        _start_session(user)
        return redirect(next_url or url_for("ui.dashboard"))
    return render_page(
        "auth/login.html", email=email, next_url=next_url, signup_open=_signup_open()
    )


@bp.route("/signup", methods=["GET", "POST"])
def signup() -> BaseResponse:
    if not _signup_open():
        abort(404)
    if current_user.is_authenticated:
        return redirect(url_for("ui.dashboard"))
    email = request.form.get("email", "")
    if request.method == "POST":
        org_name = request.form.get("org_name", "").strip() or None
        try:
            registration = accounts_service.register_user(
                get_session(),
                _hasher(),
                email,
                request.form.get("password", ""),
                org_name,
                first_user_only=not _settings().allow_signup,
            )
        except SignupClosed:
            abort(404)
        except AccountError as exc:
            return _render_form("auth/signup.html", str(exc), email, None)
        _start_session(
            SessionUser(
                user_id=registration.user.id,
                email=registration.user.email,
                org_id=registration.org.id,
                org_name=registration.org.name,
                role=Role.OWNER,
            )
        )
        flash("Welcome to attacksurf.", "success")
        return redirect(url_for("ui.dashboard"))
    return render_page("auth/signup.html", email=email)


@bp.post("/logout")
def logout() -> BaseResponse:
    try:
        auth_service.record_logout(get_session(), current_user.session_user)
    except Exception:
        # Never leave a live session behind because the audit write failed.
        log.exception("logout audit failed")
    logout_user()
    session.clear()
    flash("You have been logged out.", "info")
    return redirect(url_for("auth.login"))


def _start_session(user: SessionUser) -> None:
    # New session on login: drops anything set before (session fixation, stale CSRF token).
    session.clear()
    session.permanent = True
    session[_AUTH_AT] = int(time.time())
    login_user(WebUser(user))


def _require_login() -> BaseResponse | None:
    # Unknown URLs fall through to the 404 handler; the route list is public (AGPL) anyway.
    if request.endpoint is None or request.endpoint in PUBLIC_ENDPOINTS:
        return None
    if current_user.is_authenticated:
        return None
    if request.path.startswith("/api/"):
        response = jsonify(error="Unauthorized")
        response.status_code = 401
        return response
    target = url_for("auth.login", next=_safe_next(request.full_path.rstrip("?")))
    if is_htmx_request():
        # A redirect would be swapped into the page; HX-Redirect makes HTMX navigate instead.
        return Response(status=200, headers={"HX-Redirect": target})
    return redirect(target)


def _load_user(user_id: str) -> WebUser | None:
    if not _session_within_lifetime():
        session.clear()
        return None
    try:
        uid = UUID(user_id)
    except ValueError:
        return None
    user = auth_service.load_session_user(get_session(), uid)
    return WebUser(user) if user else None


def _session_within_lifetime() -> bool:
    """Absolute lifetime counted from login, however active the session has been since."""
    started = session.get(_AUTH_AT)
    if not isinstance(started, int):
        return False
    lifetime = timedelta(hours=_settings().session_lifetime_hours).total_seconds()
    return 0 <= time.time() - started <= lifetime


def _safe_next(target: str | None) -> str | None:
    """Only same-site paths: blocks open redirects like `//evil.example` or `https://…`."""
    if not target or not target.startswith("/") or target.startswith("//") or "\\" in target:
        return None
    parts = urlsplit(target)
    return None if parts.scheme or parts.netloc else target


def _settings() -> Settings:
    return current_app.extensions[_SETTINGS_KEY]


def _signup_open() -> bool:
    # The first user may always sign up, so a private instance can create its admin.
    # (Display check only; register_user re-checks atomically.)
    return _settings().allow_signup or not auth_service.has_users(get_session())


def _hasher() -> PasswordHasher:
    return current_app.extensions[_HASHER_KEY]


def _render_form(template: str, error: str, email: str, next_url: str | None) -> Response:
    return render_page(
        template,
        status=422,
        error=error,
        email=email,
        next_url=next_url,
        signup_open=_signup_open(),
    )


def _email_key() -> str:
    # Per-account budget, so one mailbox can't be brute-forced from many IPs.
    return "login-email:" + request.form.get("email", "").strip().lower()[:254]


def _apply_rate_limits(app: Flask, settings: Settings) -> None:
    storage = "memory://" if settings.env == "test" else settings.redis_url.get_secret_value()
    # One limiter per app (tests build many apps). Falls back to per-process memory if Redis
    # is down, so limits keep working instead of failing open or erroring.
    limiter = Limiter(
        get_remote_address,
        app=app,
        storage_uri=storage,
        headers_enabled=True,
        in_memory_fallback_enabled=True,
    )
    app.extensions["auth_limiter"] = limiter
    limits = {
        "auth.login": [
            *(limiter.limit(limit, methods=["POST"]) for limit in LOGIN_LIMITS),
            limiter.limit(LOGIN_PER_EMAIL_LIMIT, key_func=_email_key, methods=["POST"]),
        ],
        "auth.signup": [limiter.limit(SIGNUP_LIMIT, methods=["POST"])],
    }
    for endpoint, decorators in limits.items():
        view = app.view_functions[endpoint]
        for decorate in decorators:
            view = decorate(view)
        # Flask-Limiter types its wrapper as possibly async; these views are sync.
        app.view_functions[endpoint] = cast("RouteCallable", view)
