from pathlib import Path

import pytest
from pydantic import SecretStr, ValidationError

from attacksurf.config import (
    SANDBOX_MAX_WALL_TIME_SECONDS,
    SandboxLauncherSettings,
    SandboxProxySettings,
    get_settings,
)
from attacksurf.sandbox_proxy.server import RUN_TIMEOUT_SECONDS
from tests.helpers import PROD_SECRET_KEY, make_settings, settings_from_env


@pytest.fixture(autouse=True)
def _clean_settings_environment(clean_env: pytest.MonkeyPatch) -> None:
    """Direct proxy and launcher constructors must not inherit operator settings."""


def test_settings_defaults_to_dev() -> None:
    settings = make_settings()

    assert settings.env == "dev"
    assert settings.llm_provider == "anthropic"
    assert settings.llm_base_url is None
    assert not settings.is_prod


def test_settings_have_no_default_llm_model() -> None:
    # Model names come from config only (ADR 0019); no model means instance AI is off.
    assert make_settings().llm_model is None


def test_settings_read_from_environment(clean_env: pytest.MonkeyPatch) -> None:
    clean_env.setenv("ENV", "prod")
    clean_env.setenv("SECRET_KEY", PROD_SECRET_KEY)
    clean_env.setenv("REDIS_URL", "redis://cache:6379/1")
    clean_env.setenv("LLM_PROVIDER", "openai_compat")

    settings = settings_from_env()

    assert settings.is_prod
    assert settings.secret_key.get_secret_value() == PROD_SECRET_KEY
    assert settings.redis_url.get_secret_value() == "redis://cache:6379/1"
    assert settings.llm_provider == "openai_compat"


def test_empty_env_value_is_treated_as_unset(clean_env: pytest.MonkeyPatch) -> None:
    clean_env.setenv("LLM_BASE_URL", "")

    assert settings_from_env().llm_base_url is None


def test_llm_endpoint_from_environment_masks_credentials(clean_env: pytest.MonkeyPatch) -> None:
    endpoint = "https://endpoint-user:endpoint-password@gateway.example/v1"
    clean_env.setenv("LLM_BASE_URL", endpoint)

    settings = settings_from_env()

    assert "endpoint-password" not in repr(settings)
    assert isinstance(settings.llm_base_url, SecretStr)
    assert settings.llm_base_url.get_secret_value() == endpoint


def test_prod_without_secret_key_fails_fast() -> None:
    with pytest.raises(ValidationError, match="SECRET_KEY must be set"):
        make_settings(env="prod")


@pytest.mark.parametrize("weak", ["x", "change-me", "CHANGE-ME", "a" * 31])
def test_prod_rejects_weak_or_placeholder_secret_key(weak: str) -> None:
    with pytest.raises(ValidationError, match="at least 32 characters"):
        make_settings(env="prod", secret_key=SecretStr(weak))


def test_prod_accepts_strong_secret_key() -> None:
    settings = make_settings(env="prod", secret_key=SecretStr(PROD_SECRET_KEY))

    assert settings.secret_key.get_secret_value() == PROD_SECRET_KEY


def test_helper_settings_ignore_process_environment(clean_env: pytest.MonkeyPatch) -> None:
    clean_env.setenv("ENV", "prod")
    clean_env.setenv("LLM_PROVIDER", "openai_compat")

    settings = make_settings()

    assert settings.env == "dev"
    assert settings.llm_provider == "anthropic"


def test_dev_without_secret_key_generates_ephemeral_key() -> None:
    first, second = make_settings(), make_settings()

    assert first.secret_key_generated
    assert len(first.secret_key.get_secret_value()) >= 32
    assert first.secret_key.get_secret_value() != second.secret_key.get_secret_value()


def test_explicit_secret_key_is_kept() -> None:
    settings = make_settings(secret_key=SecretStr("given"))

    assert settings.secret_key.get_secret_value() == "given"
    assert not settings.secret_key_generated


def test_secrets_are_not_rendered_in_repr() -> None:
    settings = make_settings(
        secret_key=SecretStr("top-secret"), llm_api_key=SecretStr("sk-live-123")
    )

    assert "top-secret" not in repr(settings)
    assert "sk-live-123" not in repr(settings)


def test_secret_key_generated_cannot_be_set_from_env(clean_env: pytest.MonkeyPatch) -> None:
    clean_env.setenv("SECRET_KEY", "given")
    clean_env.setenv("SECRET_KEY_GENERATED", "true")

    assert not settings_from_env().secret_key_generated


@pytest.mark.usefixtures("clean_env")
def test_get_settings_is_cached() -> None:
    get_settings.cache_clear()

    assert get_settings() is get_settings()
    get_settings.cache_clear()


def test_auth_settings_defaults() -> None:
    settings = make_settings()

    assert settings.allow_signup is True
    assert settings.session_lifetime_hours == 12
    assert settings.proxy_count == 0


def test_auth_settings_read_from_environment(clean_env: pytest.MonkeyPatch) -> None:
    clean_env.setenv("ALLOW_SIGNUP", "false")
    clean_env.setenv("SESSION_LIFETIME_HOURS", "8")
    clean_env.setenv("PROXY_COUNT", "1")

    settings = settings_from_env()

    assert (settings.allow_signup, settings.session_lifetime_hours, settings.proxy_count) == (
        False,
        8,
        1,
    )


@pytest.mark.parametrize(
    ("field", "value"),
    [("session_lifetime_hours", 0), ("proxy_count", -1), ("proxy_count", 6)],
)
def test_auth_settings_reject_out_of_range(field: str, value: int) -> None:
    with pytest.raises(ValidationError):
        make_settings(**{field: value})


def test_sandbox_proxy_settings_need_no_app_secrets_in_prod() -> None:
    settings = SandboxProxySettings(env="prod", sandbox_artifact_root="/srv/artifacts")

    assert not hasattr(settings, "secret_key")
    assert not hasattr(settings, "database_url")
    assert settings.allowed_runtimes == frozenset({"runsc"})


def test_sandbox_proxy_settings_allow_runc_only_when_asked_outside_prod() -> None:
    settings = SandboxProxySettings(env="dev", sandbox_allow_runc=True)

    assert settings.allowed_runtimes == frozenset({"runsc", "runc"})


def test_sandbox_proxy_settings_refuse_runc_in_prod() -> None:
    with pytest.raises(ValueError, match="runc"):
        SandboxProxySettings(env="prod", sandbox_allow_runc=True)


@pytest.mark.parametrize("root", ["relative/path", "/", "/srv/../etc"])
def test_sandbox_proxy_settings_refuse_unsafe_artifact_roots(root: str) -> None:
    with pytest.raises(ValueError, match="artifact root"):
        SandboxProxySettings(sandbox_artifact_root=root)


def test_sandbox_launcher_settings_defaults() -> None:
    settings = SandboxLauncherSettings()

    assert settings.env == "dev"
    assert settings.sandbox_artifact_root == "/var/lib/attacksurf/artifacts"
    assert settings.sandbox_images_lock == "sandbox-images.lock"
    assert settings.sandbox_proxy_url == "http://sandbox-proxy:8790"
    assert settings.sandbox_launcher_port == 8791
    assert settings.sandbox_wall_time_seconds == 600
    assert settings.sandbox_max_concurrent_runs == 2
    assert settings.sandbox_allow_runc is False


def test_sandbox_launcher_settings_need_no_app_secrets_in_prod() -> None:
    settings = SandboxLauncherSettings(env="prod", sandbox_artifact_root="/srv/artifacts")

    assert not hasattr(settings, "secret_key")
    assert not hasattr(settings, "database_url")
    assert not hasattr(settings, "redis_url")
    assert not hasattr(settings, "sandbox_docker_socket")


def test_sandbox_launcher_settings_read_from_environment(clean_env: pytest.MonkeyPatch) -> None:
    clean_env.setenv("ENV", "prod")
    clean_env.setenv("SANDBOX_ARTIFACT_ROOT", "/srv/artifacts/")
    clean_env.setenv("SANDBOX_PROXY_URL", "http://proxy.internal:9000")
    clean_env.setenv("SANDBOX_LAUNCHER_PORT", "9001")
    clean_env.setenv("SANDBOX_WALL_TIME_SECONDS", "120")
    clean_env.setenv("SANDBOX_MAX_CONCURRENT_RUNS", "4")

    settings = SandboxLauncherSettings()

    assert settings.env == "prod"
    assert settings.sandbox_artifact_root == "/srv/artifacts"
    assert settings.sandbox_proxy_url == "http://proxy.internal:9000"
    assert settings.sandbox_launcher_port == 9001
    assert settings.sandbox_wall_time_seconds == 120
    assert settings.sandbox_max_concurrent_runs == 4


def test_sandbox_launcher_settings_ignore_dotenv_file(
    clean_env: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    (tmp_path / ".env").write_text("SANDBOX_ALLOW_RUNC=true\nSANDBOX_WALL_TIME_SECONDS=5\n")
    clean_env.chdir(tmp_path)

    settings = SandboxLauncherSettings()

    assert settings.sandbox_allow_runc is False
    assert settings.sandbox_wall_time_seconds == 600


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("sandbox_wall_time_seconds", 0),
        ("sandbox_wall_time_seconds", SANDBOX_MAX_WALL_TIME_SECONDS + 1),
        ("sandbox_max_concurrent_runs", 0),
        ("sandbox_max_concurrent_runs", 17),
        ("sandbox_launcher_port", 0),
        ("sandbox_launcher_port", 65536),
    ],
)
def test_sandbox_launcher_settings_reject_out_of_range(field: str, value: int) -> None:
    with pytest.raises(ValidationError, match=field):
        SandboxLauncherSettings.model_validate({field: value})


def test_sandbox_launcher_settings_accept_wall_time_ceiling() -> None:
    settings = SandboxLauncherSettings(sandbox_wall_time_seconds=SANDBOX_MAX_WALL_TIME_SECONDS)

    assert settings.sandbox_wall_time_seconds == SANDBOX_MAX_WALL_TIME_SECONDS


def test_sandbox_launcher_wall_time_ceiling_is_below_proxy_run_timeout() -> None:
    # The launcher must kill an overrunning container before the proxy drops the wait call.
    assert SANDBOX_MAX_WALL_TIME_SECONDS < RUN_TIMEOUT_SECONDS


@pytest.mark.parametrize(
    "url",
    ["http://sandbox-proxy:8790", "http://proxy.internal:9000", "http://127.0.0.1:8790/"],
)
def test_sandbox_launcher_settings_accept_http_proxy_urls(url: str) -> None:
    assert SandboxLauncherSettings(sandbox_proxy_url=url).sandbox_proxy_url == url


@pytest.mark.parametrize(
    "url",
    [
        "https://sandbox-proxy:8790",
        "unix:///var/run/docker.sock",
        "file:///etc/passwd",
        "ftp://sandbox-proxy",
        "sandbox-proxy:8790",
        "//sandbox-proxy:8790",
        "http://",
        "http:///path",
        "",
    ],
)
def test_sandbox_launcher_settings_refuse_non_http_proxy_urls(url: str) -> None:
    with pytest.raises(ValueError, match="SANDBOX_PROXY_URL"):
        SandboxLauncherSettings(sandbox_proxy_url=url)


def test_sandbox_launcher_proxy_url_error_does_not_echo_credentials() -> None:
    url = "ftp://user:hunter2@sandbox-proxy"

    with pytest.raises(ValueError, match="SANDBOX_PROXY_URL") as excinfo:
        SandboxLauncherSettings(sandbox_proxy_url=url)

    assert "hunter2" not in str(excinfo.value)


def test_sandbox_launcher_settings_allow_runc_only_when_asked_outside_prod() -> None:
    assert SandboxLauncherSettings(env="dev", sandbox_allow_runc=True).sandbox_allow_runc


def test_sandbox_launcher_settings_refuse_runc_in_prod() -> None:
    with pytest.raises(ValueError, match="runc"):
        SandboxLauncherSettings(env="prod", sandbox_allow_runc=True)


@pytest.mark.parametrize("root", ["relative/path", "/", "/srv/../etc"])
def test_sandbox_launcher_settings_refuse_unsafe_artifact_roots(root: str) -> None:
    with pytest.raises(ValueError, match="artifact root"):
        SandboxLauncherSettings(sandbox_artifact_root=root)
