"""ORM models. Alembic autogenerate sees every model imported here."""

from sqlalchemy import String
from sqlalchemy.orm import Mapped, mapped_column

from attacksurf.infra.db.base import Base, Timestamps, UUIDPrimaryKey


class Org(UUIDPrimaryKey, Timestamps, Base):
    """Tenant. Slug, plan, users and memberships arrive with #5."""

    __tablename__ = "orgs"

    name: Mapped[str] = mapped_column(String(200))
