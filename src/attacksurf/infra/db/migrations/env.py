"""Alembic environment: URL from Settings, metadata from the ORM models."""

from alembic import context
from sqlalchemy import Connection

from attacksurf.config import get_settings
from attacksurf.infra.db import models  # noqa: F401  (registers every table on Base.metadata)
from attacksurf.infra.db.base import Base
from attacksurf.infra.db.session import create_db_engine
from attacksurf.infra.logging import configure_logging


def run_migrations(connection: Connection) -> None:
    context.configure(connection=connection, target_metadata=Base.metadata, compare_type=True)
    with context.begin_transaction():
        context.run_migrations()


# Tests (and future tooling) pass an open connection; the CLI connects via Settings.
shared_connection: Connection | None = context.config.attributes.get("connection")
if shared_connection is not None:
    run_migrations(shared_connection)
elif context.is_offline_mode():
    settings = get_settings()
    context.configure(url=settings.database_url.get_secret_value(), literal_binds=True)
    with context.begin_transaction():
        context.run_migrations()
else:
    settings = get_settings()
    configure_logging(settings)
    with create_db_engine(settings).connect() as connection:
        run_migrations(connection)
