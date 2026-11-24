import base64
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


def test_scan_quota_defaults_to_ten_starts_per_hour() -> None:
    assert make_settings().scan_max_starts_per_hour == 10


def test_scan_quota_reads_from_environment(clean_env: pytest.MonkeyPatch) -> None:
    clean_env.setenv("SCAN_MAX_STARTS_PER_HOUR", "3")

    assert settings_from_env().scan_max_starts_per_hour == 3


@pytest.mark.parametrize("value", ["0", "-1", "1001", "many"])
def test_scan_quota_rejects_out_of_range(value: str) -> None:
    with pytest.raises(ValidationError):
        make_settings(scan_max_starts_per_hour=value)  # type: ignore[arg-type]


def test_scan_schedule_setting_defaults_to_weekly() -> None:
    assert make_settings().scan_default_frequency == "weekly"


@pytest.mark.parametrize("raw", ["daily", "weekly", "off"])
def test_scan_schedule_setting_reads_environment(clean_env: pytest.MonkeyPatch, raw: str) -> None:
    clean_env.setenv("SCAN_DEFAULT_FREQUENCY", raw)

    assert settings_from_env().scan_default_frequency == raw


def test_scan_schedule_setting_rejects_an_unknown_frequency(clean_env: pytest.MonkeyPatch) -> None:
    clean_env.setenv("SCAN_DEFAULT_FREQUENCY", "monthly")

    with pytest.raises(ValidationError, match="scan_default_frequency"):
        settings_from_env()


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
    assert settings.sandbox_proxy_url.get_secret_value() == "http://sandbox-proxy:8790"
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
    assert settings.sandbox_proxy_url.get_secret_value() == "http://proxy.internal:9000"
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
    settings = SandboxLauncherSettings(sandbox_proxy_url=SecretStr(url))

    assert settings.sandbox_proxy_url.get_secret_value() == url


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
        SandboxLauncherSettings(sandbox_proxy_url=SecretStr(url))


def test_sandbox_launcher_proxy_url_error_does_not_echo_credentials() -> None:
    url = "ftp://user:hunter2@sandbox-proxy"

    with pytest.raises(ValueError, match="SANDBOX_PROXY_URL") as excinfo:
        SandboxLauncherSettings(sandbox_proxy_url=SecretStr(url))

    assert "hunter2" not in str(excinfo.value)


def test_sandbox_launcher_proxy_url_is_masked() -> None:
    url = "http://proxy-user:hunter2@proxy.internal:9000"

    settings = SandboxLauncherSettings(sandbox_proxy_url=SecretStr(url))

    assert isinstance(settings.sandbox_proxy_url, SecretStr)
    assert "hunter2" not in repr(settings)
    assert "hunter2" not in settings.model_dump_json()
    assert settings.sandbox_proxy_url.get_secret_value() == url


def test_sandbox_launcher_settings_allow_runc_only_when_asked_outside_prod() -> None:
    assert SandboxLauncherSettings(env="dev", sandbox_allow_runc=True).sandbox_allow_runc


def test_sandbox_launcher_settings_refuse_runc_in_prod() -> None:
    with pytest.raises(ValueError, match="runc"):
        SandboxLauncherSettings(env="prod", sandbox_allow_runc=True)


@pytest.mark.parametrize("root", ["relative/path", "/", "/srv/../etc"])
def test_sandbox_launcher_settings_refuse_unsafe_artifact_roots(root: str) -> None:
    with pytest.raises(ValueError, match="artifact root"):
        SandboxLauncherSettings(sandbox_artifact_root=root)


def test_dns_settings_defaults() -> None:
    settings = make_settings()

    assert settings.dns_resolver_addresses == ("1.1.1.1", "8.8.8.8")
    assert settings.dns_timeout_seconds == 3.0
    assert settings.dns_lifetime_seconds == 5.0
    assert settings.dns_max_concurrency == 20
    assert settings.ip_asn_db_path is None


def test_dns_settings_read_from_environment(clean_env: pytest.MonkeyPatch) -> None:
    clean_env.setenv("DNS_RESOLVERS", "9.9.9.9, 1.0.0.1")
    clean_env.setenv("DNS_TIMEOUT_SECONDS", "1.5")
    clean_env.setenv("DNS_LIFETIME_SECONDS", "2.5")
    clean_env.setenv("DNS_MAX_CONCURRENCY", "4")
    clean_env.setenv("IP_ASN_DB_PATH", "/srv/ip2asn.tsv")

    settings = settings_from_env()

    assert settings.dns_resolver_addresses == ("9.9.9.9", "1.0.0.1")
    assert settings.dns_timeout_seconds == 1.5
    assert settings.dns_lifetime_seconds == 2.5
    assert settings.dns_max_concurrency == 4
    assert settings.ip_asn_db_path == "/srv/ip2asn.tsv"


@pytest.mark.parametrize(
    "resolvers",
    ["", "127.0.0.1", "10.0.0.1,1.1.1.1", "not-an-ip"],
)
def test_dns_settings_require_public_resolver_addresses(resolvers: str) -> None:
    with pytest.raises(ValidationError, match="DNS_RESOLVERS"):
        make_settings(dns_resolvers=resolvers)


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("dns_timeout_seconds", 0),
        ("dns_timeout_seconds", 31),
        ("dns_lifetime_seconds", 0),
        ("dns_lifetime_seconds", 61),
        ("dns_max_concurrency", 0),
        ("dns_max_concurrency", 101),
    ],
)
def test_dns_settings_reject_out_of_range(field: str, value: int) -> None:
    with pytest.raises(ValidationError):
        make_settings(**{field: value})


def test_dns_lifetime_must_not_be_shorter_than_timeout() -> None:
    with pytest.raises(ValidationError, match="DNS_LIFETIME_SECONDS"):
        make_settings(dns_timeout_seconds=3.0, dns_lifetime_seconds=2.0)


def test_empty_ip_asn_path_is_unset() -> None:
    assert make_settings(ip_asn_db_path="  ").ip_asn_db_path is None


APP_KEY = "a2tra2tra2tra2tra2tra2tra2tra2tra2tra2tra2s"  # urlsafe base64 of b"k" * 32, unpadded


def test_artifact_settings_defaults() -> None:
    settings = make_settings()

    assert settings.app_encryption_key is None
    assert settings.app_encryption_key_bytes is None
    assert settings.artifact_max_bytes == 256 * 1024**2
    assert settings.artifact_retention_hours == 0
    assert settings.artifact_org_quota_bytes == 2 * 1024**3
    assert settings.artifact_store_root == "/var/lib/attacksurf/artifact-store"
    assert settings.sandbox_artifact_root == "/var/lib/attacksurf/artifacts"


def test_prod_starts_without_an_app_encryption_key() -> None:
    # Storage fails closed at use instead (ADR 0028), so existing deployments keep booting.
    settings = make_settings(env="prod", secret_key=SecretStr(PROD_SECRET_KEY))

    assert settings.app_encryption_key is None


def test_artifact_settings_read_from_environment(clean_env: pytest.MonkeyPatch) -> None:
    clean_env.setenv("APP_ENCRYPTION_KEY", APP_KEY)
    clean_env.setenv("ARTIFACT_MAX_BYTES", "1048576")
    clean_env.setenv("ARTIFACT_RETENTION_HOURS", "48")
    clean_env.setenv("ARTIFACT_ORG_QUOTA_BYTES", "2097152")
    clean_env.setenv("ARTIFACT_STORE_ROOT", "/srv/store")
    clean_env.setenv("SANDBOX_ARTIFACT_ROOT", "/srv/artifacts")

    settings = settings_from_env()

    assert settings.app_encryption_key_bytes == b"k" * 32
    assert APP_KEY not in repr(settings)
    assert (settings.artifact_max_bytes, settings.artifact_org_quota_bytes) == (1048576, 2097152)
    assert settings.artifact_retention_hours == 48
    assert (settings.artifact_store_root, settings.sandbox_artifact_root) == (
        "/srv/store",
        "/srv/artifacts",
    )


def test_app_encryption_key_accepts_padded_base64() -> None:
    settings = make_settings(app_encryption_key=SecretStr(APP_KEY + "="))

    assert settings.app_encryption_key_bytes == b"k" * 32


@pytest.mark.parametrize(
    "value",
    [
        "too-short-sentinel",
        "not base64 at all !! sentinel",
        "a2tra2tra2tra2tra2tra2tra2tra2tra2tra2tra2tra2tr",  # 36 bytes
    ],
)
def test_malformed_app_encryption_key_is_rejected_without_echoing_it(
    value: str, clean_env: pytest.MonkeyPatch
) -> None:
    clean_env.setenv("APP_ENCRYPTION_KEY", value)

    with pytest.raises(ValidationError, match="APP_ENCRYPTION_KEY") as error:
        settings_from_env()

    assert value not in str(error.value)
    assert "sentinel" not in str(error.value)
    assert "a2tra2" not in str(error.value)


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("artifact_max_bytes", 0),
        ("artifact_max_bytes", 512 * 1024**2 + 1),
        ("artifact_retention_hours", -1),
        ("artifact_retention_hours", 721),
        ("artifact_org_quota_bytes", 0),
        ("artifact_org_quota_bytes", 1024**4 + 1),
    ],
)
def test_artifact_limits_reject_out_of_range(field: str, value: int) -> None:
    with pytest.raises(ValidationError):
        make_settings(**{field: value})


def test_artifact_quota_below_the_per_artifact_limit_is_rejected() -> None:
    with pytest.raises(ValidationError, match="ARTIFACT_ORG_QUOTA_BYTES"):
        make_settings(artifact_max_bytes=2048, artifact_org_quota_bytes=1024)


@pytest.mark.parametrize("field", ["artifact_store_root", "sandbox_artifact_root"])
@pytest.mark.parametrize("root", ["relative/path", "/", "/srv/../etc"])
def test_unsafe_artifact_roots_are_rejected(field: str, root: str) -> None:
    with pytest.raises(ValidationError, match="absolute paths below /"):
        make_settings(**{field: root})


@pytest.mark.parametrize(
    ("store", "run"),
    [
        ("/srv/artifacts", "/srv/artifacts"),
        ("/srv/artifacts/", "/srv//artifacts"),
        ("/srv/artifacts/store", "/srv/artifacts"),  # ciphertext inside the sandbox mount
        ("/srv/data", "/srv/data/runs"),
    ],
)
def test_overlapping_artifact_roots_are_rejected(store: str, run: str) -> None:
    with pytest.raises(ValidationError, match="must not contain each other"):
        make_settings(artifact_store_root=store, sandbox_artifact_root=run)


def test_sibling_artifact_roots_with_a_shared_prefix_are_accepted() -> None:
    settings = make_settings(
        artifact_store_root="/srv/artifacts-store", sandbox_artifact_root="/srv/artifacts"
    )

    assert settings.artifact_store_root == "/srv/artifacts-store"


def test_sandbox_services_never_receive_the_app_encryption_key() -> None:
    for settings in (SandboxProxySettings(), SandboxLauncherSettings()):
        assert not hasattr(settings, "app_encryption_key")
        assert not hasattr(settings, "artifact_store_root")


def test_sandbox_launcher_url_defaults_to_none() -> None:
    assert make_settings().sandbox_launcher_url is None


def test_sandbox_launcher_url_reads_from_environment(clean_env: pytest.MonkeyPatch) -> None:
    clean_env.setenv("SANDBOX_LAUNCHER_URL", "http://sandbox-launcher:8791")

    url = settings_from_env().sandbox_launcher_url

    assert isinstance(url, SecretStr)
    assert url.get_secret_value() == "http://sandbox-launcher:8791"


def test_empty_sandbox_launcher_url_means_off(clean_env: pytest.MonkeyPatch) -> None:
    clean_env.setenv("SANDBOX_LAUNCHER_URL", "")

    assert settings_from_env().sandbox_launcher_url is None


@pytest.mark.parametrize(
    "url", ["http://sandbox-launcher:8791", "http://10.0.0.5:8791/", "http://launcher"]
)
def test_sandbox_launcher_url_accepts_plain_http(url: str) -> None:
    settings = make_settings(sandbox_launcher_url=SecretStr(url))

    assert settings.sandbox_launcher_url is not None
    assert settings.sandbox_launcher_url.get_secret_value() == url


@pytest.mark.parametrize(
    "url",
    [
        "https://l:1",
        "ftp://l",
        "l:8791",
        "http://",
        "http://u:hunter2@l:1",
        "http://u@l:1",
        "http://l:1/api",
        "http://l:1?x=1",
        "http://l:1#f",
        "http://l:99999",
        "http://[::1",
        "",
    ],
)
def test_sandbox_launcher_url_refuses_other_shapes(url: str) -> None:
    with pytest.raises(ValidationError, match="SANDBOX_LAUNCHER_URL"):
        make_settings(sandbox_launcher_url=SecretStr(url))


def test_sandbox_launcher_url_error_does_not_echo_credentials() -> None:
    with pytest.raises(ValidationError, match="SANDBOX_LAUNCHER_URL") as excinfo:
        make_settings(sandbox_launcher_url=SecretStr("ftp://user:hunter2@launcher"))

    assert "hunter2" not in str(excinfo.value)


def test_sandbox_launcher_url_is_masked() -> None:
    settings = make_settings(sandbox_launcher_url=SecretStr("http://launcher-marker.internal:8791"))

    assert "launcher-marker" not in repr(settings)
    assert "launcher-marker" not in settings.model_dump_json()


OLD_KEY_1 = base64.urlsafe_b64encode(b"1" * 32).decode().rstrip("=")
OLD_KEY_2 = base64.urlsafe_b64encode(b"2" * 32).decode().rstrip("=")


def test_org_llm_settings_defaults() -> None:
    settings = make_settings()

    assert settings.llm_monthly_instance_token_budget == 500_000
    assert settings.llm_allowed_base_hosts == ""
    assert settings.llm_allowed_base_host_set == frozenset()
    assert settings.app_encryption_old_keys is None
    assert settings.app_encryption_old_key_bytes == ()


def test_smtp_defaults_disable_outbound_email() -> None:
    settings = make_settings()

    assert settings.smtp_host is None
    assert settings.smtp_port == 587
    assert settings.smtp_tls == "starttls"
    assert settings.smtp_from == "noreply@attacksurf.local"
    assert settings.app_base_url is None


def test_smtp_reads_environment_and_masks_password(clean_env: pytest.MonkeyPatch) -> None:
    clean_env.setenv("SMTP_HOST", "smtp.example")
    clean_env.setenv("SMTP_PORT", "2525")
    clean_env.setenv("SMTP_USER", "mailer")
    clean_env.setenv("SMTP_PASSWORD", "super-secret-smtp-pass")
    clean_env.setenv("SMTP_FROM", "alerts@example.com")
    clean_env.setenv("SMTP_TLS", "ssl")
    clean_env.setenv("APP_BASE_URL", "https://app.example.com/")

    settings = settings_from_env()

    assert settings.smtp_host == "smtp.example"
    assert settings.smtp_port == 2525
    assert settings.smtp_user == "mailer"
    assert isinstance(settings.smtp_password, SecretStr)
    assert "super-secret-smtp-pass" not in repr(settings)
    assert settings.smtp_from == "alerts@example.com"
    assert settings.smtp_tls == "ssl"
    assert settings.app_base_url == "https://app.example.com"


@pytest.mark.parametrize("bad_from", ["", "not-an-email", "a@b\r\nBcc: evil@x", "a b@example.com"])
def test_smtp_from_rejects_invalid_or_multiline_addresses(bad_from: str) -> None:
    with pytest.raises(ValidationError, match="SMTP_FROM"):
        make_settings(smtp_from=bad_from)


@pytest.mark.parametrize(
    "bad_url",
    [
        "ftp://app.example",
        "https://user:pass@app.example",
        "https://app.example?x=1",
        "https://app.example#frag",
        "not-a-url",
    ],
)
def test_app_base_url_rejects_invalid_urls(bad_url: str) -> None:
    with pytest.raises(ValidationError, match="APP_BASE_URL"):
        make_settings(app_base_url=bad_url)


def test_org_llm_settings_read_from_environment(clean_env: pytest.MonkeyPatch) -> None:
    clean_env.setenv("LLM_MONTHLY_INSTANCE_TOKEN_BUDGET", "120000")
    clean_env.setenv("LLM_ALLOWED_BASE_HOSTS", " localhost, Ollama.Internal. , [::1], 127.0.0.1 ")
    clean_env.setenv("APP_ENCRYPTION_OLD_KEYS", f"{OLD_KEY_1}, {OLD_KEY_2}")

    settings = settings_from_env()

    assert settings.llm_monthly_instance_token_budget == 120_000
    assert settings.llm_allowed_base_host_set == frozenset(
        {"localhost", "ollama.internal", "::1", "127.0.0.1"}
    )
    assert len(settings.app_encryption_old_key_bytes) == 2
    assert OLD_KEY_1 not in repr(settings)


def test_llm_budget_accepts_zero_and_rejects_negative() -> None:
    assert make_settings(llm_monthly_instance_token_budget=0).llm_monthly_instance_token_budget == 0
    with pytest.raises(ValidationError):
        make_settings(llm_monthly_instance_token_budget=-1)


def test_triage_skips_info_findings_by_default() -> None:
    assert make_settings().llm_triage_include_info is False


def test_triage_info_findings_can_be_switched_on(clean_env: pytest.MonkeyPatch) -> None:
    clean_env.setenv("LLM_TRIAGE_INCLUDE_INFO", "true")

    assert settings_from_env().llm_triage_include_info is True


def test_malformed_old_encryption_key_is_rejected_without_echoing_it(
    clean_env: pytest.MonkeyPatch,
) -> None:
    clean_env.setenv("APP_ENCRYPTION_OLD_KEYS", f"{OLD_KEY_1},bad-old-sentinel")

    with pytest.raises(ValidationError, match="APP_ENCRYPTION_OLD_KEYS") as error:
        settings_from_env()

    assert "bad-old-sentinel" not in str(error.value)


def test_whitespace_only_old_encryption_keys_treated_as_unset(
    clean_env: pytest.MonkeyPatch,
) -> None:
    clean_env.setenv("APP_ENCRYPTION_OLD_KEYS", " , ")

    settings = settings_from_env()

    assert settings.app_encryption_old_keys is None
    assert settings.app_encryption_old_key_bytes == ()


def test_sentry_settings_defaults() -> None:
    settings = make_settings()

    assert settings.sentry_dsn is None
    assert settings.sentry_environment is None
    assert settings.sentry_release is None
    assert settings.sentry_traces_sample_rate == 0.0


def test_sentry_settings_read_from_environment(clean_env: pytest.MonkeyPatch) -> None:
    dsn = "https://publickey@o1.ingest.sentry.io/42"
    clean_env.setenv("SENTRY_DSN", dsn)
    clean_env.setenv("SENTRY_ENVIRONMENT", "staging")
    clean_env.setenv("SENTRY_RELEASE", "v0.1.0")
    clean_env.setenv("SENTRY_TRACES_SAMPLE_RATE", "0.25")

    settings = settings_from_env()

    assert settings.sentry_dsn is not None
    assert settings.sentry_dsn.get_secret_value() == dsn
    assert "publickey" not in repr(settings)
    assert "publickey" not in settings.model_dump_json()
    assert settings.sentry_environment == "staging"
    assert settings.sentry_release == "v0.1.0"
    assert settings.sentry_traces_sample_rate == 0.25


@pytest.mark.parametrize(
    "dsn",
    [
        "not-a-dsn",
        "ftp://publickey@sentry.example/1",
        "https://sentry.example",
        "https://sentry.example/",
        "https://publickey@sentry.example/1?debug=1",
        "https://publickey@sentry.example:99999/1",
    ],
)
def test_invalid_sentry_dsn_rejected_without_echoing_value(
    clean_env: pytest.MonkeyPatch, dsn: str
) -> None:
    clean_env.setenv("SENTRY_DSN", dsn)

    with pytest.raises(ValidationError, match="SENTRY_DSN") as excinfo:
        settings_from_env()

    assert dsn not in str(excinfo.value)


def test_whitespace_sentry_fields_treated_as_unset() -> None:
    settings = make_settings(
        sentry_dsn=SecretStr("   "),
        sentry_environment="  ",
        sentry_release="  ",
    )

    assert settings.sentry_dsn is None
    assert settings.sentry_environment is None
    assert settings.sentry_release is None


@pytest.mark.parametrize("rate", [-0.1, 1.1])
def test_sentry_traces_sample_rate_rejects_out_of_range(rate: float) -> None:
    with pytest.raises(ValidationError):
        make_settings(sentry_traces_sample_rate=rate)


def test_active_scan_settings_default_safe_and_disabled() -> None:
    settings = make_settings()

    assert settings.active_scans_enabled is False
    assert settings.active_target_rate_limit_rps == 2.0
    assert settings.active_target_rate_limit_burst == 5
    assert settings.active_target_max_concurrency == 2
    assert settings.scanner_contact_url is None
    assert settings.scanner_user_agent.startswith("attacksurf/")
    assert "+https://github.com/cpt9m0/attacksurf)" in settings.scanner_user_agent


def test_active_scan_settings_read_from_environment(clean_env: pytest.MonkeyPatch) -> None:
    clean_env.setenv("ACTIVE_SCANS_ENABLED", "true")
    clean_env.setenv("ACTIVE_TARGET_RATE_LIMIT_RPS", "4.5")
    clean_env.setenv("ACTIVE_TARGET_RATE_LIMIT_BURST", "10")
    clean_env.setenv("ACTIVE_TARGET_MAX_CONCURRENCY", "3")
    clean_env.setenv("SCANNER_CONTACT_URL", "https://security.example.com/scanner/")

    settings = settings_from_env()

    assert settings.active_scans_enabled is True
    assert settings.active_target_rate_limit_rps == 4.5
    assert settings.active_target_rate_limit_burst == 10
    assert settings.active_target_max_concurrency == 3
    assert settings.scanner_contact_url == "https://security.example.com/scanner"
    assert settings.scanner_user_agent.endswith("(+https://security.example.com/scanner)")


def test_scanner_user_agent_falls_back_to_app_base_url() -> None:
    settings = make_settings(app_base_url="https://asm.example.org/")

    assert settings.scanner_user_agent.endswith("(+https://asm.example.org)")


@pytest.mark.parametrize(
    "bad_url",
    [
        "ftp://example.com",
        "https://user:pass@example.com",
        "https://example.com?a=1",
        "https://example.com#frag",
        "not-a-url",
    ],
)
def test_scanner_contact_url_rejects_invalid_values(bad_url: str) -> None:
    with pytest.raises(ValidationError, match="SCANNER_CONTACT_URL"):
        make_settings(scanner_contact_url=bad_url)


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("active_target_rate_limit_rps", 0.0),
        ("active_target_rate_limit_rps", 10.1),
        ("active_target_rate_limit_burst", 0),
        ("active_target_rate_limit_burst", 21),
        ("active_target_max_concurrency", 0),
        ("active_target_max_concurrency", 6),
    ],
)
def test_active_rate_limit_settings_reject_out_of_range(field: str, value: float | int) -> None:
    with pytest.raises(ValidationError):
        make_settings(**{field: value})
