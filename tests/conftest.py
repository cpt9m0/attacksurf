import os
import time
from collections.abc import Callable

import pytest
from flask import Flask
from flask.testing import FlaskClient
from pydantic import SecretStr

from attacksurf import create_app
from attacksurf.config import SandboxProxySettings, Settings
from attacksurf.domain.accounts import Role
from attacksurf.domain.ids import uuid7
from attacksurf.services import auth as auth_service
from attacksurf.services.auth import SessionUser
from attacksurf.workers import runtime
from tests.helpers import llm_live_skip_reason, make_settings

type LoginAs = Callable[[FlaskClient, SessionUser], None]


def pytest_collection_modifyitems(items: list[pytest.Item]) -> None:
    """Skip every `llm_live` test unless live calls are enabled here (never in CI)."""
    live = [item for item in items if item.get_closest_marker("llm_live")]
    if not live:
        return
    reason = llm_live_skip_reason(os.environ, Settings)
    if reason is not None:
        for item in live:
            item.add_marker(pytest.mark.skip(reason=reason))


@pytest.fixture
def clean_env(monkeypatch: pytest.MonkeyPatch) -> pytest.MonkeyPatch:
    """Unset every variable read by application or proxy settings for env-loading tests."""
    for name in Settings.model_fields.keys() | SandboxProxySettings.model_fields.keys():
        monkeypatch.delenv(name.upper(), raising=False)
    return monkeypatch


@pytest.fixture
def settings() -> Settings:
    return make_settings(env="test", secret_key=SecretStr("test-secret-key"))


@pytest.fixture
def app(settings: Settings) -> Flask:
    return create_app(settings)


@pytest.fixture
def client(app: Flask) -> FlaskClient:
    return app.test_client()


def make_session_user(role: Role = Role.OWNER, email: str = "alice@example.com") -> SessionUser:
    return SessionUser(user_id=uuid7(), email=email, org_id=uuid7(), org_name="Acme", role=role)


@pytest.fixture
def login_as(monkeypatch: pytest.MonkeyPatch) -> LoginAs:
    """Log a client in as a fake user: the identity lookup is patched, no database needed."""
    users: dict[object, SessionUser] = {}
    monkeypatch.setattr(auth_service, "load_session_user", lambda _session, uid: users.get(uid))

    def _login(client: FlaskClient, user: SessionUser) -> None:
        users[user.user_id] = user
        with client.session_transaction() as sess:
            sess["_user_id"] = str(user.user_id)
            sess["_fresh"] = True
            sess["auth_at"] = int(time.time())

    return _login


def pytest_configure(config: pytest.Config) -> None:
    """Give the worker app test settings, not .env/env, before collection starts.

    Collecting a module-level Celery task finalizes the worker conf, which reads
    `runtime.settings()` once and caches it; a fixture would patch too late (#126).
    """
    worker_settings = make_settings(env="test", secret_key=SecretStr("test-secret-key"))
    mp = pytest.MonkeyPatch()
    mp.setattr(runtime, "settings", lambda: worker_settings)
    config.add_cleanup(mp.undo)
