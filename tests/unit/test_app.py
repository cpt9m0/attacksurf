from pathlib import Path

import pytest

from attacksurf import create_app
from attacksurf.config import Settings, get_settings
from tests.helpers import make_settings


def test_app_boots_from_environment_only(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    monkeypatch.chdir(tmp_path)  # no .env file in the working directory
    monkeypatch.setenv("ENV", "prod")
    monkeypatch.setenv("SECRET_KEY", "from-env")
    get_settings.cache_clear()

    try:
        app = create_app()
        response = app.test_client().get("/healthz")
    finally:
        get_settings.cache_clear()

    assert response.status_code == 200
    assert app.config["SECRET_KEY"] == "from-env"
    assert not app.config["TESTING"]


def test_create_app_uses_given_settings(settings: Settings) -> None:
    app = create_app(settings)

    assert app.extensions["settings"] is settings
    assert app.config["TESTING"]


def test_ephemeral_secret_key_logs_warning(capsys: pytest.CaptureFixture[str]) -> None:
    create_app(make_settings(env="dev"))

    assert "no SECRET_KEY set" in capsys.readouterr().out
