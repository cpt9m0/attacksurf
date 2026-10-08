"""A test-only tenant table, kept off the app's metadata so `alembic check` stays meaningful."""

from sqlalchemy import Connection, MetaData, String
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column

from attacksurf.infra.db.base import NAMING_CONVENTION, TenantScoped, Timestamps
from attacksurf.infra.db.models import Org


class _TestBase(DeclarativeBase):
    metadata = MetaData(naming_convention=NAMING_CONVENTION)


# Lets the mixin's ForeignKey("orgs.id") resolve within the test metadata.
Org.metadata.tables[Org.__tablename__].to_metadata(_TestBase.metadata)


class Widget(TenantScoped, Timestamps, _TestBase):
    __tablename__ = "test_widgets"

    name: Mapped[str] = mapped_column(String(50))


def create_test_tables(connection: Connection) -> None:
    _TestBase.metadata.tables[Widget.__tablename__].create(connection)
