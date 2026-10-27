"""Per-process worker state: settings and the database session factory."""

from functools import lru_cache

from sqlalchemy.orm import Session, sessionmaker

from attacksurf.config import Settings, get_settings
from attacksurf.domain.scanners import ClosedGate, ScannerGate
from attacksurf.infra.db.session import create_db_engine, create_session_factory


def settings() -> Settings:
    return get_settings()


@lru_cache(maxsize=1)
def session_factory() -> sessionmaker[Session]:
    """Created on first use in each worker process, never shared across a fork."""
    return create_session_factory(create_db_engine(settings()))


def scanner_gate() -> ScannerGate:
    """Fail closed until ScopeGuard lands (#12); tests inject a fixture-only gate."""
    return ClosedGate()
