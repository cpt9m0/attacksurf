"""Typed application settings, read from environment variables and `.env`."""

import base64
import binascii
import ipaddress
import secrets
from functools import lru_cache
from pathlib import PurePosixPath
from typing import Literal, Self
from urllib.parse import urlsplit

import idna
from pydantic import Field, PrivateAttr, SecretStr, field_validator, model_validator
from pydantic_settings import BaseSettings, SettingsConfigDict

from attacksurf.domain.llm import ProviderKind
from attacksurf.domain.scope import is_blocked_address

MIN_PROD_SECRET_KEY_LENGTH = 32
# Values that appear in docs/examples; using one in prod means a publicly known signing key.
_PLACEHOLDER_SECRET_KEYS = frozenset({"change-me", "changeme", "secret", "dev", "test"})
# Below the proxy's 900 s wait timeout, so the launcher's own kill always fires first.
SANDBOX_MAX_WALL_TIME_SECONDS = 840
APP_ENCRYPTION_KEY_BYTES = 32
# ADR 0017's extraction cap: a larger artifact could never be analysed.
ARTIFACT_MAX_BYTES_CEILING = 512 * 1024**2


def _decode_app_key(value: str, *, setting: str = "APP_ENCRYPTION_KEY") -> bytes:
    """Bytes of an app encryption key; the error never repeats the value."""
    try:
        key = base64.b64decode(value + "=" * (-len(value) % 4), altchars=b"-_", validate=True)
    except (binascii.Error, ValueError):
        key = b""
    if len(key) != APP_ENCRYPTION_KEY_BYTES:
        raise ValueError(f"{setting} must be URL-safe base64 of exactly 32 bytes")
    return key


def _parse_old_app_keys(raw: str) -> tuple[bytes, ...]:
    parts = [part.strip() for part in raw.split(",") if part.strip()]
    return tuple(_decode_app_key(part, setting="APP_ENCRYPTION_OLD_KEYS") for part in parts)


def _normalize_allowed_host(raw: str) -> str:
    candidate = raw.strip()
    if not candidate:
        return ""
    if candidate.startswith("[") and candidate.endswith("]"):
        candidate = candidate[1:-1]
    try:
        return str(ipaddress.ip_address(candidate))
    except ValueError:
        pass
    stripped = candidate.removesuffix(".")
    try:
        return idna.encode(stripped, uts46=True).decode("ascii").removesuffix(".")
    except idna.IDNAError:
        return stripped.lower()


class Settings(BaseSettings):
    # hide_input_in_errors: a rejected value (a key, a URL with a password) must not be printed
    # by the startup error.
    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        env_ignore_empty=True,
        extra="ignore",
        hide_input_in_errors=True,
    )

    env: Literal["dev", "test", "prod"] = "dev"
    secret_key: SecretStr = SecretStr("")
    log_level: str = "INFO"

    # URLs can embed passwords, so they are secrets too; unwrap only where connecting.
    # Defaults match the local Docker Compose services (#3); used from #4 / #10 on.
    database_url: SecretStr = SecretStr(
        "postgresql+psycopg://attacksurf:attacksurf@localhost:5432/attacksurf"
    )
    redis_url: SecretStr = SecretStr("redis://localhost:6379/0")

    # DNS resolution (#16). Public recursive resolvers only; comma-separated in env.
    dns_resolvers: str = "1.1.1.1,8.8.8.8"
    dns_timeout_seconds: float = Field(default=3.0, gt=0, le=30)
    dns_lifetime_seconds: float = Field(default=5.0, gt=0, le=60)
    dns_max_concurrency: int = Field(default=20, ge=1, le=100)
    # Optional offline ip2asn TSV (start end asn country org); empty disables enrichment.
    ip_asn_db_path: str | None = None

    # Auth (#7). With signup off, only the very first user can still sign up (instance admin).
    allow_signup: bool = True
    session_lifetime_hours: int = Field(default=12, ge=1, le=720)
    # Scans UI (#21): per-org hourly quota for starting scans of one profile. Upload scans
    # (#87, #101) use their own profiles and their own limiter, so they don't consume this.
    scan_max_starts_per_hour: int = Field(
        default=10, ge=1, le=1000
    )  # Reverse proxies in front of the app. Count trusted hops, not components: Caddy alone = 1;
    # Cloudflare Tunnel -> Caddy = 1 (cloudflared is not a proxy hop, Cloudflare is); Cloudflare
    # proxying to Caddy directly = 2. Decides which X-Forwarded-For entry is the client IP for
    # rate limiting; leave 0 when the app is reached directly.
    proxy_count: int = Field(default=0, ge=0, le=5)

    # Instance LLM config (ADR 0019): orgs without their own key use it, capped (#24). Model
    # names come only from config, so there is no default; no key or no model means AI is off.
    llm_provider: ProviderKind = ProviderKind.ANTHROPIC
    llm_model: str | None = None
    llm_base_url: SecretStr | None = None
    llm_api_key: SecretStr | None = None
    llm_monthly_instance_token_budget: int = Field(default=500_000, ge=0)
    # Comma-separated exact hostnames (e.g. localhost,ollama.internal) permitted for self-hosted
    # org LLM base URLs, bypassing the public-HTTPS SSRF guard.
    llm_allowed_base_hosts: str = ""

    # Wraps data keys for encryption at rest (ADR 0028) and org LLM API keys (#24). Unset:
    # artifact storage and org API key saving refuse to write/read (deleting still works).
    app_encryption_key: SecretStr | None = None
    # Comma-separated rotated keys (URL-safe base64 of 32 bytes) kept for decrypting older keys.
    app_encryption_old_keys: SecretStr | None = None
    artifact_max_bytes: int = Field(default=256 * 1024**2, ge=1, le=ARTIFACT_MAX_BYTES_CEILING)
    # 0: delete once analysis completes (never analysed: after 24 h).
    artifact_retention_hours: int = Field(default=0, ge=0, le=720)
    artifact_org_quota_bytes: int = Field(default=2 * 1024**3, ge=1, le=1024**4)
    # Ciphertext only. Never inside `sandbox_artifact_root`, which the sandbox launcher mounts
    # from and where the plaintext for one run is staged.
    artifact_store_root: str = "/var/lib/attacksurf/artifact-store"
    sandbox_artifact_root: str = "/var/lib/attacksurf/artifacts"
    # Sandboxed analysis (ADR 0016, #84): the launcher workers ask to run analyzers. Unset means
    # every sandbox request is refused. May embed credentials, so it is a secret.
    sandbox_launcher_url: SecretStr | None = None

    _secret_key_generated: bool = PrivateAttr(default=False)

    @model_validator(mode="after")
    def _require_secret_key(self) -> Self:
        key = self.secret_key.get_secret_value()
        if self.env == "prod":
            if len(key) < MIN_PROD_SECRET_KEY_LENGTH or key.lower() in _PLACEHOLDER_SECRET_KEYS:
                raise ValueError(
                    f"SECRET_KEY must be set to a random value of at least "
                    f"{MIN_PROD_SECRET_KEY_LENGTH} characters when ENV=prod"
                )
            return self
        if not key:
            # Dev/test only: an ephemeral key means sessions reset on every restart.
            self.secret_key = SecretStr(secrets.token_urlsafe(32))
            self._secret_key_generated = True
        return self

    @field_validator("ip_asn_db_path")
    @classmethod
    def _empty_ip_asn_path(cls, value: str | None) -> str | None:
        return value.strip() or None if isinstance(value, str) else value

    @field_validator("app_encryption_key")
    @classmethod
    def _check_app_encryption_key(cls, value: SecretStr | None) -> SecretStr | None:
        if value is not None:
            _decode_app_key(value.get_secret_value())
        return value

    @field_validator("app_encryption_old_keys")
    @classmethod
    def _check_app_encryption_old_keys(cls, value: SecretStr | None) -> SecretStr | None:
        if value is None:
            return None
        if not _parse_old_app_keys(value.get_secret_value()):
            return None
        return value

    @model_validator(mode="after")
    def _validate_artifacts(self) -> Self:
        if self.artifact_org_quota_bytes < self.artifact_max_bytes:
            raise ValueError("ARTIFACT_ORG_QUOTA_BYTES must be at least ARTIFACT_MAX_BYTES")
        store, run = (
            PurePosixPath(self.artifact_store_root),
            PurePosixPath(self.sandbox_artifact_root),
        )
        for root in (store, run):
            if not root.is_absolute() or root == root.parent or ".." in root.parts:
                raise ValueError(
                    "ARTIFACT_STORE_ROOT and SANDBOX_ARTIFACT_ROOT must be absolute paths below /"
                )
        if store == run or store in run.parents or run in store.parents:
            raise ValueError(
                "ARTIFACT_STORE_ROOT and SANDBOX_ARTIFACT_ROOT must not contain each other"
            )
        return self

    @field_validator("sandbox_launcher_url")
    @classmethod
    def _require_plain_launcher_url(cls, value: SecretStr | None) -> SecretStr | None:
        # The same rule as `infra.sandbox.LauncherSandboxRunner`, checked at startup so a typo
        # stops the worker instead of failing the first scan. The message never repeats the
        # value, which may embed credentials.
        if value is None:
            return value
        message = "SANDBOX_LAUNCHER_URL must be http://host[:port] only"
        try:
            parts = urlsplit(value.get_secret_value())
            parts.port  # noqa: B018 - raises ValueError for a bad port; the value isn't needed
        except ValueError:
            raise ValueError(message) from None
        plain = (
            parts.scheme == "http"
            and parts.hostname
            and parts.username is None
            and parts.password is None
            and parts.path in ("", "/")
            and not parts.query
            and not parts.fragment
        )
        if not plain:
            raise ValueError(message)
        return value

    @model_validator(mode="after")
    def _validate_dns(self) -> Self:
        addresses = self.dns_resolver_addresses
        if not addresses:
            raise ValueError("DNS_RESOLVERS must list at least one resolver")
        for raw in addresses:
            try:
                address = ipaddress.ip_address(raw)
            except ValueError:
                raise ValueError("DNS_RESOLVERS must contain IP addresses") from None
            if is_blocked_address(address):
                raise ValueError("DNS_RESOLVERS must be public IP addresses")
        if self.dns_lifetime_seconds < self.dns_timeout_seconds:
            raise ValueError("DNS_LIFETIME_SECONDS must be at least DNS_TIMEOUT_SECONDS")
        return self

    @property
    def dns_resolver_addresses(self) -> tuple[str, ...]:
        return tuple(part.strip() for part in self.dns_resolvers.split(",") if part.strip())

    @property
    def app_encryption_key_bytes(self) -> bytes | None:
        """The decoded key, or None when unset. Unwrap only where a cipher is built."""
        key = self.app_encryption_key
        return None if key is None else _decode_app_key(key.get_secret_value())

    @property
    def app_encryption_old_key_bytes(self) -> tuple[bytes, ...]:
        """Previous app keys kept for rotation decryption; empty when unset."""
        keys = self.app_encryption_old_keys
        return () if keys is None else _parse_old_app_keys(keys.get_secret_value())

    @property
    def llm_allowed_base_host_set(self) -> frozenset[str]:
        """Normalized hostnames explicitly permitted as self-hosted org LLM base URLs."""
        return frozenset(
            normalized
            for part in self.llm_allowed_base_hosts.split(",")
            if (normalized := _normalize_allowed_host(part))
        )

    @property
    def secret_key_generated(self) -> bool:
        """True when no SECRET_KEY was given (dev/test only), so callers can warn about it."""
        return self._secret_key_generated

    @property
    def is_prod(self) -> bool:
        return self.env == "prod"


class _SandboxServiceSettings(BaseSettings):
    """Fields and checks shared by the sandbox services (ADR 0016), kept apart from app secrets.

    Environment only, no `.env`: services that drive Docker must not pick up a stray file.
    """

    # hide_input_in_errors: a bad value (e.g. a URL with a password) must not appear in startup
    # errors that land in logs.
    model_config = SettingsConfigDict(
        env_ignore_empty=True, extra="ignore", hide_input_in_errors=True
    )

    env: Literal["dev", "test", "prod"] = "dev"
    sandbox_artifact_root: str = "/var/lib/attacksurf/artifacts"
    sandbox_images_lock: str = "sandbox-images.lock"
    sandbox_allow_runc: bool = False  # dev/CI hosts without gVisor; refused in prod

    @model_validator(mode="after")
    def _validate_sandbox(self) -> Self:
        if self.env == "prod" and self.sandbox_allow_runc:
            raise ValueError("SANDBOX_ALLOW_RUNC (runc) is not allowed when ENV=prod")
        root = self.sandbox_artifact_root
        if not root.startswith("/") or root == "/" or ".." in root.split("/"):
            raise ValueError("the sandbox artifact root must be an absolute path below /")
        self.sandbox_artifact_root = root.rstrip("/")
        return self


class SandboxProxySettings(_SandboxServiceSettings):
    """`sandbox-proxy` only: the one process that holds the Docker socket."""

    sandbox_docker_socket: str = "/var/run/docker.sock"
    sandbox_proxy_host: str = "0.0.0.0"  # noqa: S104 - reachable only on an internal network
    sandbox_proxy_port: int = Field(default=8790, ge=1, le=65535)

    @property
    def allowed_runtimes(self) -> frozenset[str]:
        return frozenset({"runsc", "runc"} if self.sandbox_allow_runc else {"runsc"})


class SandboxLauncherSettings(_SandboxServiceSettings):
    """`sandbox-launcher` only: runs analyzers through the proxy, never touches Docker itself."""

    # May embed proxy credentials, so it is a secret; unwrap only where connecting.
    sandbox_proxy_url: SecretStr = SecretStr("http://sandbox-proxy:8790")
    sandbox_launcher_host: str = "0.0.0.0"  # noqa: S104 - reachable only on an internal network
    sandbox_launcher_port: int = Field(default=8791, ge=1, le=65535)
    sandbox_wall_time_seconds: int = Field(default=600, ge=1, le=SANDBOX_MAX_WALL_TIME_SECONDS)
    sandbox_max_concurrent_runs: int = Field(default=2, ge=1, le=16)

    @field_validator("sandbox_proxy_url")
    @classmethod
    def _require_http_proxy_url(cls, value: SecretStr) -> SecretStr:
        # Plain http only for now: the proxy is reached over an internal network. The message
        # never repeats the value, which may embed credentials.
        parts = urlsplit(value.get_secret_value())
        if parts.scheme != "http" or not parts.hostname:
            raise ValueError("SANDBOX_PROXY_URL must be an http:// URL with a host")
        return value


@lru_cache
def get_settings() -> Settings:
    return Settings()
