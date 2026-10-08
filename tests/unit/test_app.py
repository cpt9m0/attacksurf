import subprocess
import sys
from pathlib import Path

import pytest

import attacksurf
from attacksurf import create_app
from attacksurf.config import Settings, get_settings
from tests.helpers import PROD_SECRET_KEY, make_settings


def test_app_boots_from_environment_only(clean_env: pytest.MonkeyPatch, tmp_path: Path) -> None:
    clean_env.chdir(tmp_path)  # no .env file in the working directory
    clean_env.setenv("ENV", "prod")
    clean_env.setenv("SECRET_KEY", PROD_SECRET_KEY)
    get_settings.cache_clear()

    try:
        app = create_app()
        response = app.test_client().get("/healthz")
    finally:
        get_settings.cache_clear()

    assert response.status_code == 200
    assert app.config["SECRET_KEY"] == PROD_SECRET_KEY
    assert not app.config["TESTING"]


def test_create_app_uses_given_settings(settings: Settings) -> None:
    app = create_app(settings)

    assert app.extensions["settings"] is settings
    assert app.config["TESTING"]


def test_ephemeral_secret_key_logs_warning(capsys: pytest.CaptureFixture[str]) -> None:
    create_app(make_settings(env="dev"))

    assert "no SECRET_KEY set" in capsys.readouterr().out


def test_importing_inner_layers_does_not_load_flask() -> None:
    # Fresh interpreter: this test process has already imported Flask.
    code = (
        "import sys, attacksurf.domain, attacksurf.services, attacksurf.config; "
        "sys.exit('flask' in sys.modules or 'attacksurf.web' in sys.modules)"
    )

    result = subprocess.run([sys.executable, "-c", code], check=False)  # noqa: S603 (fixed argv)

    assert result.returncode == 0


def test_create_app_is_importable_from_package() -> None:
    assert attacksurf.create_app is create_app
    with pytest.raises(AttributeError):
        _ = attacksurf.nope  # pyright: ignore[reportAttributeAccessIssue]
