"""Declarative base and the mixins every model builds on."""

from datetime import datetime
from uuid import UUID

from sqlalchemy import DateTime, ForeignKey, MetaData, func
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column

from attacksurf.domain.ids import uuid7

# Deterministic constraint names, so Alembic can drop/alter them in later migrations.
NAMING_CONVENTION = {
    "ix": "ix_%(column_0_label)s",
    "uq": "uq_%(table_name)s_%(column_0_name)s",
    "ck": "ck_%(table_name)s_%(constraint_name)s",
    "fk": "fk_%(table_name)s_%(column_0_name)s_%(referred_table_name)s",
    "pk": "pk_%(table_name)s",
}


class Base(DeclarativeBase):
    metadata = MetaData(naming_convention=NAMING_CONVENTION)
    type_annotation_map = {datetime: DateTime(timezone=True)}  # noqa: RUF012


class UUIDPrimaryKey:
    # sort_order: key columns first in CREATE TABLE, whatever the mixin order.
    id: Mapped[UUID] = mapped_column(primary_key=True, default=uuid7, sort_order=-2)


class Timestamps:
    created_at: Mapped[datetime] = mapped_column(server_default=func.now())
    updated_at: Mapped[datetime] = mapped_column(server_default=func.now(), onupdate=func.now())


class TenantScoped(UUIDPrimaryKey):
    """A row owned by one org. Query it only through `attacksurf.infra.db.tenancy`."""

    org_id: Mapped[UUID] = mapped_column(
        ForeignKey("orgs.id", ondelete="CASCADE"), index=True, nullable=False, sort_order=-1
    )
