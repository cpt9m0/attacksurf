"""ORM models. Alembic autogenerate sees every model imported here."""

from datetime import datetime
from typing import Any
from uuid import UUID

from sqlalchemy import Enum, ForeignKey, String, UniqueConstraint, func, text
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import Mapped, mapped_column

from attacksurf.domain.accounts import Role
from attacksurf.infra.db.base import Base, TenantScoped, Timestamps, UUIDPrimaryKey


class Org(UUIDPrimaryKey, Timestamps, Base):
    """Tenant. Every tenant-owned row points here via `org_id`."""

    __tablename__ = "orgs"

    name: Mapped[str] = mapped_column(String(200))
    slug: Mapped[str] = mapped_column(String(63), unique=True)
    plan: Mapped[str] = mapped_column(String(20), server_default="free")


class User(UUIDPrimaryKey, Timestamps, Base):
    """A login. Not tenant-scoped: one user can belong to several orgs via memberships."""

    __tablename__ = "users"

    email: Mapped[str] = mapped_column(String(254), unique=True)  # stored normalized (lowercase)
    password_hash: Mapped[str] = mapped_column(String(255))
    is_active: Mapped[bool] = mapped_column(server_default=text("true"))
    last_login_at: Mapped[datetime | None]


class Membership(TenantScoped, Timestamps, Base):
    __tablename__ = "memberships"
    __table_args__ = (UniqueConstraint("org_id", "user_id"),)

    user_id: Mapped[UUID] = mapped_column(ForeignKey("users.id", ondelete="CASCADE"), index=True)
    # VARCHAR + CHECK, not a native enum: a new role is a constraint change, not ALTER TYPE.
    role: Mapped[Role] = mapped_column(
        Enum(
            Role,
            name="role",
            native_enum=False,
            create_constraint=True,
            length=20,
            values_callable=lambda roles: [r.value for r in roles],
        )
    )


class AuditLog(TenantScoped, Base):
    """Append-only trail of security-relevant actions. `details` must never hold secrets."""

    __tablename__ = "audit_log"

    actor_user_id: Mapped[UUID | None] = mapped_column(ForeignKey("users.id", ondelete="SET NULL"))
    action: Mapped[str] = mapped_column(String(100))  # dotted, e.g. "user.registered"
    target_type: Mapped[str | None] = mapped_column(String(50))
    target_id: Mapped[str | None] = mapped_column(String(100))
    details: Mapped[dict[str, Any]] = mapped_column(
        JSONB, default=dict, server_default=text("'{}'::jsonb")
    )
    created_at: Mapped[datetime] = mapped_column(server_default=func.now())
