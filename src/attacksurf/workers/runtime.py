"""Per-process worker state: settings, the database session factory and the scanner gate."""

from functools import lru_cache

from sqlalchemy.orm import Session, sessionmaker

from attacksurf.config import Settings, get_settings
from attacksurf.domain.net import DnsResolver
from attacksurf.domain.scanners import ScannerGate
from attacksurf.infra.db.session import create_db_engine, create_session_factory
from attacksurf.infra.dns import DnsPythonResolver
from attacksurf.infra.http import SafeHttpClient
from attacksurf.infra.scope_guard import ScopeGuard, UnverifiedOwnership


def settings() -> Settings:
    return get_settings()


@lru_cache(maxsize=1)
def session_factory() -> sessionmaker[Session]:
    """Created on first use in each worker process, never shared across a fork."""
    return create_session_factory(create_db_engine(settings()))


@lru_cache(maxsize=1)
def dns_resolver() -> DnsResolver:
    return DnsPythonResolver()


def scanner_gate() -> ScannerGate:
    """The production gate. Ownership verification lands with #14, so active checks stay denied."""
    return ScopeGuard(dns=dns_resolver(), http=http_client(), ownership=UnverifiedOwnership())


def http_client() -> SafeHttpClient:
    """Base client: refuses every redirect on its own; runs get an allowlisted copy."""
    return SafeHttpClient(dns_resolver())
