"""add verifications, make jobs.scan_id nullable

Revision ID: 0005
Revises: 0004
Create Date: 2026-11-03 10:00:00+00:00
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "0005"
down_revision: str | Sequence[str] | None = "0004"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.create_table(
        "verifications",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("org_id", sa.Uuid(), nullable=False),
        sa.Column("asset_id", sa.Uuid(), nullable=False),
        sa.Column(
            "method",
            sa.Enum(
                "dns_txt",
                name="verification_method",
                native_enum=False,
                create_constraint=False,  # explicit, convention-named CHECK below
                length=20,
            ),
            nullable=False,
        ),
        sa.Column("token", sa.String(length=128), nullable=False),
        sa.Column(
            "status",
            sa.Enum(
                "pending",
                "verified",
                "revoked",
                name="verification_status",
                native_enum=False,
                create_constraint=False,  # explicit, convention-named CHECK below
                length=20,
            ),
            nullable=False,
        ),
        sa.Column("verified_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("last_checked_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("now()"),
            nullable=False,
        ),
        sa.Column(
            "updated_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("now()"),
            nullable=False,
        ),
        # The enum columns above carry no constraint (same pattern as scans/findings): these
        # two are explicit and convention-named, so the table and the models agree on one name.
        sa.CheckConstraint(
            "method IN ('dns_txt')", name=op.f("ck_verifications_verification_method")
        ),
        sa.CheckConstraint(
            "status IN ('pending', 'verified', 'revoked')",
            name=op.f("ck_verifications_verification_status"),
        ),
        sa.CheckConstraint(
            "status <> 'pending' OR verified_at IS NULL",
            name=op.f("ck_verifications_verified_at_matches"),
        ),
        sa.ForeignKeyConstraint(
            ["asset_id", "org_id"],
            ["assets.id", "assets.org_id"],
            name=op.f("fk_verifications_asset_id_assets"),
            ondelete="CASCADE",
        ),
        sa.ForeignKeyConstraint(
            ["org_id"], ["orgs.id"], name=op.f("fk_verifications_org_id_orgs"), ondelete="CASCADE"
        ),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_verifications")),
        sa.UniqueConstraint("org_id", "asset_id", name=op.f("uq_verifications_org_id")),
    )
    op.create_index(op.f("ix_verifications_org_id"), "verifications", ["org_id"], unique=False)
    op.create_index(
        "ix_verifications_status_expires_at",
        "verifications",
        ["status", "expires_at"],
        unique=False,
    )
    # Verification jobs aren't part of a scan; a pruned scan must not delete them (ADR 0014).
    op.drop_constraint(op.f("fk_jobs_scan_id_scans"), "jobs", type_="foreignkey")
    op.alter_column("jobs", "scan_id", existing_type=sa.Uuid(), nullable=True)
    op.create_foreign_key(
        op.f("fk_jobs_scan_id_scans"),
        "jobs",
        "scans",
        ["scan_id", "org_id"],
        ["id", "org_id"],
        ondelete="SET NULL (scan_id)",
    )


def downgrade() -> None:
    # Jobs without a scan can't satisfy the old NOT NULL column: they go with the downgrade.
    op.execute(sa.text("DELETE FROM jobs WHERE scan_id IS NULL"))
    op.drop_constraint(op.f("fk_jobs_scan_id_scans"), "jobs", type_="foreignkey")
    op.alter_column("jobs", "scan_id", existing_type=sa.Uuid(), nullable=False)
    op.create_foreign_key(
        op.f("fk_jobs_scan_id_scans"),
        "jobs",
        "scans",
        ["scan_id", "org_id"],
        ["id", "org_id"],
        ondelete="CASCADE",
    )
    op.drop_index("ix_verifications_status_expires_at", table_name="verifications")
    op.drop_index(op.f("ix_verifications_org_id"), table_name="verifications")
    op.drop_table("verifications")
