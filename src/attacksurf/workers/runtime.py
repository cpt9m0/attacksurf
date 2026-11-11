"""Per-process worker state: settings, the database session factory and the scanner gate."""

from functools import lru_cache

import redis
from sqlalchemy.orm import Session, sessionmaker

from attacksurf.config import Settings, get_settings
from attacksurf.domain.cache import ScanCache
from attacksurf.domain.net import DnsResolver, TxtLookup
from attacksurf.domain.scanners import ScannerGate
from attacksurf.infra.authoritative_dns import AuthoritativeTxtLookup
from attacksurf.infra.cache import RedisScanCache
from attacksurf.infra.db.session import create_db_engine, create_session_factory
from attacksurf.infra.dns import DnsPythonResolver
from attacksurf.infra.http import SafeHttpClient
from attacksurf.infra.scope_guard import ScopeGuard
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
def dns_resolver() -> DnsResolver:
    return DnsPythonResolver()


@lru_cache(maxsize=1)
def txt_lookup() -> TxtLookup:
    """Ownership checks: needs the A/AAAA/NS answers, so it takes the dnspython resolver."""
    return AuthoritativeTxtLookup(DnsPythonResolver())


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


def scanner_gate() -> ScannerGate:
    """The production gate: active checks run only on assets whose root proved ownership (#14)."""
    return ScopeGuard(
        dns=dns_resolver(),
        http=http_client(),
        ownership=DbOwnershipChecker(session_factory()),
        cache=scan_cache(),
    )


def http_client() -> SafeHttpClient:
    """Base client: refuses every redirect on its own; runs get an allowlisted copy."""
    return SafeHttpClient(dns_resolver(), timeout_seconds=SCANNER_HTTP_TIMEOUT_SECONDS)
