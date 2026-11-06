"""Per-process worker state: settings, the database session factory and the scanner gate."""

from functools import lru_cache

from sqlalchemy.orm import Session, sessionmaker

from attacksurf.config import Settings, get_settings
from attacksurf.domain.net import DnsResolver, TxtLookup
from attacksurf.domain.scanners import ScannerGate
from attacksurf.infra.authoritative_dns import AuthoritativeTxtLookup
from attacksurf.infra.db.session import create_db_engine, create_session_factory
from attacksurf.infra.dns import DnsPythonResolver
from attacksurf.infra.http import SafeHttpClient
from attacksurf.infra.scope_guard import ScopeGuard
from attacksurf.services.ownership import DbOwnershipChecker


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


def scanner_gate() -> ScannerGate:
    """The production gate: active checks run only on assets whose root proved ownership (#14)."""
    return ScopeGuard(
        dns=dns_resolver(),
        http=http_client(),
        ownership=DbOwnershipChecker(session_factory()),
    )


def http_client() -> SafeHttpClient:
    """Base client: refuses every redirect on its own; runs get an allowlisted copy."""
    return SafeHttpClient(dns_resolver())
