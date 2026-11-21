"""Per-process worker state: settings, the database session factory and the scanner gate."""

from functools import lru_cache
from pathlib import Path

import redis
from sqlalchemy.orm import Session, sessionmaker

from attacksurf.config import Settings, get_settings
from attacksurf.domain.artifacts import ArtifactPolicy, ArtifactStore
from attacksurf.domain.cache import ScanCache
from attacksurf.domain.net import IpIntel, TxtLookup
from attacksurf.domain.notifications import EmailSender
from attacksurf.domain.sandbox import SandboxRunner, UnconfiguredSandboxRunner
from attacksurf.domain.scanners import ScannerGate
from attacksurf.infra.authoritative_dns import AuthoritativeTxtLookup
from attacksurf.infra.cache import RedisScanCache
from attacksurf.infra.crypto import EnvelopeCipher
from attacksurf.infra.db.session import create_db_engine, create_session_factory
from attacksurf.infra.dns import DnsPythonResolver
from attacksurf.infra.email import SmtpEmailSender
from attacksurf.infra.http import SafeHttpClient
from attacksurf.infra.ip_intel import Ip2AsnLookup
from attacksurf.infra.sandbox import LauncherSandboxRunner
from attacksurf.infra.scope_guard import ScopeGuard
from attacksurf.infra.storage import LocalArtifactStore
from attacksurf.services.ownership import DbOwnershipChecker

# crt.sh regularly takes several seconds; the client's 5 s default is too tight for it.
SCANNER_HTTP_TIMEOUT_SECONDS = 15.0
REDIS_SOCKET_TIMEOUT_SECONDS = 1.0


def settings() -> Settings:
    return get_settings()


@lru_cache(maxsize=1)
def session_factory() -> sessionmaker[Session]:
    """Created on first use in each worker process, never shared across a fork."""
    return create_session_factory(create_db_engine(settings()))


@lru_cache(maxsize=1)
def dns_resolver() -> DnsPythonResolver:
    current = settings()
    return DnsPythonResolver(
        nameservers=current.dns_resolver_addresses,
        timeout=current.dns_timeout_seconds,
        lifetime=current.dns_lifetime_seconds,
        max_concurrency=current.dns_max_concurrency,
    )


@lru_cache(maxsize=1)
def txt_lookup() -> TxtLookup:
    """Ownership checks: needs the A/AAAA/NS answers, so it takes the dnspython resolver."""
    return AuthoritativeTxtLookup(dns_resolver())


@lru_cache(maxsize=1)
def ip_intel() -> IpIntel:
    """Offline ASN/org enrichment; an unset path means lookups return None."""
    return Ip2AsnLookup(settings().ip_asn_db_path)


@lru_cache(maxsize=1)
def scan_cache() -> ScanCache:
    """Public source-data cache; created after fork and shared by this process's runs.

    Redis errors are converted to misses by the adapter, so sending a scan through it never
    turns a cache outage into a job failure.
    """
    return RedisScanCache(
        redis.Redis.from_url(
            settings().redis_url.get_secret_value(),
            decode_responses=True,
            socket_connect_timeout=REDIS_SOCKET_TIMEOUT_SECONDS,
            socket_timeout=REDIS_SOCKET_TIMEOUT_SECONDS,
        )
    )


@lru_cache(maxsize=1)
def artifact_store() -> ArtifactStore:
    """Encrypted artifact storage (ADR 0028). Without `APP_ENCRYPTION_KEY` it only deletes."""
    current = settings()
    key = current.app_encryption_key_bytes
    return LocalArtifactStore(
        Path(current.artifact_store_root),
        Path(current.sandbox_artifact_root),
        EnvelopeCipher(key, purpose=b"artifact") if key else None,
    )


@lru_cache(maxsize=1)
def artifact_policy() -> ArtifactPolicy:
    current = settings()
    return ArtifactPolicy(
        max_bytes=current.artifact_max_bytes,
        org_quota_bytes=current.artifact_org_quota_bytes,
        retention_hours=current.artifact_retention_hours,
    )


@lru_cache(maxsize=1)
def sandbox_runner() -> SandboxRunner:
    """Off unless SANDBOX_LAUNCHER_URL is set; one client and pool per process."""
    url = settings().sandbox_launcher_url
    if url is None:
        return UnconfiguredSandboxRunner()
    return LauncherSandboxRunner(url.get_secret_value())


def scanner_gate() -> ScannerGate:
    """The production gate: active checks run only on assets whose root proved ownership (#14)."""
    return ScopeGuard(
        dns=dns_resolver(),
        http=http_client(),
        ownership=DbOwnershipChecker(session_factory()),
        cache=scan_cache(),
        ip_intel=ip_intel(),
        sandbox=sandbox_runner(),
    )


@lru_cache(maxsize=1)
def email_sender() -> EmailSender | None:
    """Outbound SMTP sender (#28); None when SMTP_HOST is unset."""
    current = settings()
    if current.smtp_host is None:
        return None
    return SmtpEmailSender(
        host=current.smtp_host,
        port=current.smtp_port,
        from_addr=current.smtp_from,
        tls=current.smtp_tls,
        user=current.smtp_user,
        password=current.smtp_password,
        timeout_seconds=current.smtp_timeout_seconds,
    )


def http_client() -> SafeHttpClient:
    """Base client: refuses every redirect on its own; runs get an allowlisted copy."""
    return SafeHttpClient(dns_resolver(), timeout_seconds=SCANNER_HTTP_TIMEOUT_SECONDS)
