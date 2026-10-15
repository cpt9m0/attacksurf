"""ORM models. Alembic autogenerate sees every model imported here."""

from datetime import datetime
from enum import StrEnum
from typing import Any
from uuid import UUID

from sqlalchemy import (
    CheckConstraint,
    Enum,
    ForeignKey,
    ForeignKeyConstraint,
    String,
    UniqueConstraint,
    func,
    text,
)
from sqlalchemy.dialects.postgresql import ARRAY, JSONB
from sqlalchemy.orm import Mapped, mapped_column

from attacksurf.domain.accounts import Role
from attacksurf.domain.assets import MAX_URL_LENGTH, AssetSource, AssetType, RelationKind
from attacksurf.infra.db.base import Base, TenantScoped, Timestamps, UUIDPrimaryKey


def _str_enum(enum_cls: type[StrEnum], name: str) -> Enum:
    """VARCHAR + CHECK, not a native enum: a new value is a constraint change, not ALTER TYPE."""
    return Enum(
        enum_cls,
        name=name,
        native_enum=False,
        create_constraint=True,
        length=20,
        values_callable=lambda members: [m.value for m in members],
    )


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
    role: Mapped[Role] = mapped_column(_str_enum(Role, "role"))


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


class Asset(TenantScoped, Timestamps, Base):
    """Anything an org owns or we discovered for it: domain, subdomain, IP, URL (repo/binary later).

    `value` is always the normalized form (`domain.assets.normalize_asset_value`).
    """

    __tablename__ = "assets"
    __table_args__ = (
        UniqueConstraint("org_id", "type", "value"),
        # Target of the composite FKs below: links can only point at assets of the same org.
        UniqueConstraint("id", "org_id"),
        ForeignKeyConstraint(
            ["parent_id", "org_id"], ["assets.id", "assets.org_id"], ondelete="CASCADE"
        ),
    )

    type: Mapped[AssetType] = mapped_column(_str_enum(AssetType, "asset_type"))
    value: Mapped[str] = mapped_column(String(MAX_URL_LENGTH))
    source: Mapped[AssetSource] = mapped_column(_str_enum(AssetSource, "asset_source"))
    parent_id: Mapped[UUID | None] = mapped_column(index=True)  # the root asset it was found under
    tags: Mapped[list[str]] = mapped_column(
        ARRAY(String(50)), default=list, server_default=text("'{}'")
    )
    first_seen: Mapped[datetime]
    last_seen: Mapped[datetime]
    is_active: Mapped[bool] = mapped_column(server_default=text("true"))
    details: Mapped[dict[str, Any]] = mapped_column(
        JSONB, default=dict, server_default=text("'{}'::jsonb")
    )


class AssetRelation(TenantScoped, Base):
    """Directed edge in the asset graph, e.g. `www.example.com --resolves_to--> 192.0.2.1`."""

    __tablename__ = "asset_relations"
    __table_args__ = (
        UniqueConstraint("org_id", "from_asset_id", "to_asset_id", "kind"),
        ForeignKeyConstraint(
            ["from_asset_id", "org_id"], ["assets.id", "assets.org_id"], ondelete="CASCADE"
        ),
        ForeignKeyConstraint(
            ["to_asset_id", "org_id"], ["assets.id", "assets.org_id"], ondelete="CASCADE"
        ),
        CheckConstraint("from_asset_id <> to_asset_id", name="no_self_relation"),
    )

    from_asset_id: Mapped[UUID]
    to_asset_id: Mapped[UUID] = mapped_column(index=True)
    kind: Mapped[RelationKind] = mapped_column(_str_enum(RelationKind, "relation_kind"))
    first_seen: Mapped[datetime]
    last_seen: Mapped[datetime]
