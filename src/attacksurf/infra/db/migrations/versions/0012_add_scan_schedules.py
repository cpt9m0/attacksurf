"""Add recurring scan schedules

Revision ID: 0012
Revises: 0011
Create Date: 2026-11-19 18:20:00+00:00
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "0012"
down_revision: str | Sequence[str] | None = "0011"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.create_table(
        "scan_schedules",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("org_id", sa.Uuid(), nullable=False),
        sa.Column("root_asset_id", sa.Uuid(), nullable=False),
        sa.Column("profile", sa.String(length=50), nullable=False),
        sa.Column(
            "frequency",
            sa.Enum(
                "daily",
                "weekly",
                name="frequency",
                native_enum=False,
                create_constraint=False,  # explicit, convention-named CHECK below
                length=20,
            ),
            nullable=False,
        ),
        sa.Column("next_run_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("enabled", sa.Boolean(), nullable=False),
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
        sa.CheckConstraint(
            "enabled = (next_run_at IS NOT NULL)",
            name=op.f("ck_scan_schedules_enabled_matches_due"),
        ),
        sa.CheckConstraint(
            "frequency IN ('daily', 'weekly')",
            name=op.f("ck_scan_schedules_frequency"),
        ),
        sa.ForeignKeyConstraint(
            ["org_id"],
            ["orgs.id"],
            name=op.f("fk_scan_schedules_org_id_orgs"),
            ondelete="CASCADE",
        ),
        sa.ForeignKeyConstraint(
            ["root_asset_id", "org_id"],
            ["assets.id", "assets.org_id"],
            name=op.f("fk_scan_schedules_root_asset_id_assets"),
            ondelete="CASCADE",
        ),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_scan_schedules")),
        sa.UniqueConstraint("org_id", "root_asset_id", name=op.f("uq_scan_schedules_org_id")),
    )
    op.create_index(op.f("ix_scan_schedules_org_id"), "scan_schedules", ["org_id"])
    op.create_index(
        "ix_scan_schedules_due",
        "scan_schedules",
        ["next_run_at", "id"],
        postgresql_where=sa.text("enabled"),
    )


def downgrade() -> None:
    op.drop_index("ix_scan_schedules_due", table_name="scan_schedules")
    op.drop_index(op.f("ix_scan_schedules_org_id"), table_name="scan_schedules")
    op.drop_table("scan_schedules")
