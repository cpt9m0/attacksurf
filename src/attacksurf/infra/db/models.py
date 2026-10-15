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
    Index,
    String,
    Text,
    UniqueConstraint,
    func,
    text,
)
from sqlalchemy.dialects.postgresql import ARRAY, JSONB
from sqlalchemy.orm import Mapped, mapped_column

from attacksurf.domain.accounts import Role
from attacksurf.domain.assets import MAX_URL_LENGTH, AssetSource, AssetType, RelationKind
from attacksurf.domain.findings import (
    FINGERPRINT_LENGTH,
    MAX_LOCATION_LENGTH,
    Confidence,
    EvidenceKind,
    FindingStatus,
    Severity,
)
from attacksurf.domain.rules import MAX_RULE_ID_LENGTH
from attacksurf.domain.scans import JobStatus, ScanStatus, ScanTrigger
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
    `parent_id` is the asset a discovered one was found under and is fixed at the first
    sighting (so the parent graph can't form cycles). Deleting a parent deletes what was
    discovered under it; user-added assets are always roots, so they never go with it.
    """

    __tablename__ = "assets"
    __table_args__ = (
        UniqueConstraint("org_id", "type", "value"),
        # Target of the composite FKs below: links can only point at assets of the same org.
        UniqueConstraint("id", "org_id"),
        ForeignKeyConstraint(
            ["parent_id", "org_id"], ["assets.id", "assets.org_id"], ondelete="CASCADE"
        ),
        CheckConstraint("parent_id IS NULL OR parent_id <> id", name="no_self_parent"),
        CheckConstraint("source = 'discovered' OR parent_id IS NULL", name="user_asset_is_root"),
        CheckConstraint("is_active = (deactivated_at IS NULL)", name="deactivated_at_matches"),
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
    # When a scan found it gone; only sightings after this reactivate it.
    deactivated_at: Mapped[datetime | None]
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


def _same_org_fk(column: str, target: str, ondelete: str = "CASCADE") -> ForeignKeyConstraint:
    """`(column, org_id) -> target(id, org_id)`: links can only point at the same org's rows."""
    return ForeignKeyConstraint(
        [column, "org_id"], [f"{target}.id", f"{target}.org_id"], ondelete=ondelete
    )


def _same_org_fk_set_null(column: str, target: str) -> ForeignKeyConstraint:
    # Postgres 15+ column list: plain SET NULL would also null org_id (NOT NULL) and fail.
    return _same_org_fk(column, target, ondelete=f"SET NULL ({column})")


class Scan(TenantScoped, Timestamps, Base):
    """One run of a scan profile against a root asset. `created_at` is when it was queued."""

    __tablename__ = "scans"
    __table_args__ = (
        UniqueConstraint("id", "org_id"),
        _same_org_fk("root_asset_id", "assets"),
        CheckConstraint("finished_at >= started_at", name="finished_after_started"),
        Index("ix_scans_root_asset_id_created_at", "root_asset_id", "created_at"),  # history
    )

    root_asset_id: Mapped[UUID]
    profile: Mapped[str] = mapped_column(String(50))  # e.g. "dns_passive"; validated in code
    status: Mapped[ScanStatus] = mapped_column(_str_enum(ScanStatus, "scan_status"))
    triggered_by: Mapped[ScanTrigger] = mapped_column(_str_enum(ScanTrigger, "scan_trigger"))
    started_at: Mapped[datetime | None]
    finished_at: Mapped[datetime | None]
    stats: Mapped[dict[str, Any]] = mapped_column(
        JSONB, default=dict, server_default=text("'{}'::jsonb")
    )


class Job(TenantScoped, Timestamps, Base):
    """One unit of a scan: a pipeline stage, or one scanner on one asset."""

    __tablename__ = "jobs"
    __table_args__ = (
        _same_org_fk("scan_id", "scans"),
        # Kept when the asset goes: the job is the scan's history.
        _same_org_fk_set_null("asset_id", "assets"),
        CheckConstraint("attempts >= 0", name="attempts_not_negative"),
        CheckConstraint("finished_at >= started_at", name="finished_after_started"),
    )

    scan_id: Mapped[UUID] = mapped_column(index=True)
    asset_id: Mapped[UUID | None] = mapped_column(index=True)
    stage: Mapped[str] = mapped_column(String(50))
    scanner: Mapped[str | None] = mapped_column(String(100))
    status: Mapped[JobStatus] = mapped_column(_str_enum(JobStatus, "job_status"))
    attempts: Mapped[int] = mapped_column(default=0, server_default=text("0"))
    error: Mapped[str | None] = mapped_column(String(2000))  # short and sanitized, no evidence
    celery_task_id: Mapped[str | None] = mapped_column(String(255))
    started_at: Mapped[datetime | None]
    finished_at: Mapped[datetime | None]


class Finding(TenantScoped, Timestamps, Base):
    """A normalized scanner result. One row per issue across scans: `(org_id, fingerprint)`.

    `fingerprint` is `domain.findings.finding_fingerprint(org_id, asset_id, rule_id, location)`.
    """

    __tablename__ = "findings"
    __table_args__ = (
        UniqueConstraint("org_id", "fingerprint"),
        UniqueConstraint("id", "org_id"),
        _same_org_fk("asset_id", "assets"),
        # Pruning old scans must never delete findings.
        _same_org_fk_set_null("first_seen_scan_id", "scans"),
        _same_org_fk_set_null("last_seen_scan_id", "scans"),
        CheckConstraint("last_seen >= first_seen", name="last_seen_after_first_seen"),
        CheckConstraint("(status = 'fixed') = (fixed_at IS NOT NULL)", name="fixed_at_matches"),
    )

    asset_id: Mapped[UUID] = mapped_column(index=True)
    first_seen_scan_id: Mapped[UUID | None] = mapped_column(index=True)
    last_seen_scan_id: Mapped[UUID | None] = mapped_column(index=True)
    rule_id: Mapped[str] = mapped_column(String(MAX_RULE_ID_LENGTH))
    fingerprint: Mapped[str] = mapped_column(String(FINGERPRINT_LENGTH))
    location: Mapped[str] = mapped_column(String(MAX_LOCATION_LENGTH), server_default="")
    title: Mapped[str] = mapped_column(String(300))
    description: Mapped[str] = mapped_column(Text)
    severity: Mapped[Severity] = mapped_column(_str_enum(Severity, "severity"))
    confidence: Mapped[Confidence] = mapped_column(_str_enum(Confidence, "confidence"))
    status: Mapped[FindingStatus] = mapped_column(
        _str_enum(FindingStatus, "finding_status"), server_default=FindingStatus.OPEN.value
    )
    first_seen: Mapped[datetime]
    last_seen: Mapped[datetime]
    fixed_at: Mapped[datetime | None]
    remediation: Mapped[str] = mapped_column(Text, server_default="")
    references: Mapped[list[str]] = mapped_column(
        ARRAY(String(MAX_URL_LENGTH)), default=list, server_default=text("'{}'")
    )
    ai_triage: Mapped[dict[str, Any] | None] = mapped_column(JSONB)


class Evidence(TenantScoped, Base):
    """What a human needs to confirm a finding: raw records, response snippets (size-capped)."""

    __tablename__ = "evidence"
    __table_args__ = (_same_org_fk("finding_id", "findings"),)

    finding_id: Mapped[UUID] = mapped_column(index=True)
    kind: Mapped[EvidenceKind] = mapped_column(_str_enum(EvidenceKind, "evidence_kind"))
    data: Mapped[dict[str, Any]] = mapped_column(JSONB)
    captured_at: Mapped[datetime]
