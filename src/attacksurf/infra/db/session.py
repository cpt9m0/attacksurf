"""Engine and session factory, built from Settings."""

from sqlalchemy import Engine, create_engine
from sqlalchemy.orm import Session, sessionmaker

from attacksurf.config import Settings


def create_db_engine(settings: Settings) -> Engine:
    # pre_ping: a restarted Postgres must not surface as errors on stale pooled connections.
    return create_engine(settings.database_url.get_secret_value(), pool_pre_ping=True)


def create_session_factory(engine: Engine) -> sessionmaker[Session]:
    """Celery tasks use `with factory.begin() as session:` (commit on success, else rollback)."""
    return sessionmaker(engine, expire_on_commit=False)
