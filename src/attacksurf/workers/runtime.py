"""Per-process worker state: settings, the database session factory and the scanner gate."""

from functools import lru_cache

import redis
from sqlalchemy.orm import Session, sessionmaker

from attacksurf.config import Settings, get_settings
from attacksurf.domain.cache import ScanCache
from attacksurf.domain.net import IpIntel, TxtLookup
from attacksurf.domain.scanners import ScannerGate
from attacksurf.infra.authoritative_dns import AuthoritativeTxtLookup
from attacksurf.infra.cache import RedisScanCache
from attacksurf.infra.db.session import create_db_engine, create_session_factory
from attacksurf.infra.dns import DnsPythonResolver
from attacksurf.infra.http import SafeHttpClient
from attacksurf.infra.ip_intel import Ip2AsnLookup
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


def scanner_gate() -> ScannerGate:
    """The production gate: active checks run only on assets whose root proved ownership (#14)."""
    return ScopeGuard(
        dns=dns_resolver(),
        http=http_client(),
        ownership=DbOwnershipChecker(session_factory()),
        cache=scan_cache(),
        ip_intel=ip_intel(),
    )


def http_client() -> SafeHttpClient:
    """Base client: refuses every redirect on its own; runs get an allowlisted copy."""
    return SafeHttpClient(dns_resolver(), timeout_seconds=SCANNER_HTTP_TIMEOUT_SECONDS)
