"""Add notification preferences, deliveries, and observation regressed flag

Revision ID: 0014
Revises: 0013
Create Date: 2026-11-20 22:35:00+00:00
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "0014"
down_revision: str | Sequence[str] | None = "0013"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.add_column(
        "finding_observations",
        sa.Column("regressed", sa.Boolean(), server_default=sa.text("false"), nullable=False),
    )

    op.create_table(
        "notification_preferences",
        sa.Column("user_id", sa.Uuid(), nullable=False),
        sa.Column("email_enabled", sa.Boolean(), server_default=sa.text("true"), nullable=False),
        sa.Column(
            "min_severity",
            sa.Enum(
                "info",
                "low",
                "medium",
                "high",
                "critical",
                name="severity",
                native_enum=False,
                create_constraint=True,
                length=20,
            ),
            server_default="high",
            nullable=False,
        ),
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("org_id", sa.Uuid(), nullable=False),
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
        sa.ForeignKeyConstraint(["org_id"], ["orgs.id"], ondelete="CASCADE"),
        sa.ForeignKeyConstraint(["user_id"], ["users.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_notification_preferences")),
        sa.UniqueConstraint("org_id", "user_id", name=op.f("uq_notification_preferences_org_id")),
    )
    op.create_index(
        op.f("ix_notification_preferences_org_id"),
        "notification_preferences",
        ["org_id"],
        unique=False,
    )
    op.create_index(
        op.f("ix_notification_preferences_user_id"),
        "notification_preferences",
        ["user_id"],
        unique=False,
    )

    op.create_table(
        "notification_deliveries",
        sa.Column("scan_id", sa.Uuid(), nullable=False),
        sa.Column("user_id", sa.Uuid(), nullable=False),
        sa.Column(
            "sent_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("now()"),
            nullable=False,
        ),
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("org_id", sa.Uuid(), nullable=False),
        sa.ForeignKeyConstraint(["org_id"], ["orgs.id"], ondelete="CASCADE"),
        sa.ForeignKeyConstraint(
            ["scan_id", "org_id"],
            ["scans.id", "scans.org_id"],
            name=op.f("fk_notification_deliveries_scan_id_scans"),
            ondelete="CASCADE",
        ),
        sa.ForeignKeyConstraint(["user_id"], ["users.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_notification_deliveries")),
        sa.UniqueConstraint(
            "org_id", "scan_id", "user_id", name=op.f("uq_notification_deliveries_org_id")
        ),
    )
    op.create_index(
        op.f("ix_notification_deliveries_org_id"),
        "notification_deliveries",
        ["org_id"],
        unique=False,
    )
    op.create_index(
        op.f("ix_notification_deliveries_scan_id"),
        "notification_deliveries",
        ["scan_id"],
        unique=False,
    )


def downgrade() -> None:
    op.drop_index(op.f("ix_notification_deliveries_scan_id"), table_name="notification_deliveries")
    op.drop_index(op.f("ix_notification_deliveries_org_id"), table_name="notification_deliveries")
    op.drop_table("notification_deliveries")
    op.drop_index(
        op.f("ix_notification_preferences_user_id"), table_name="notification_preferences"
    )
    op.drop_index(op.f("ix_notification_preferences_org_id"), table_name="notification_preferences")
    op.drop_table("notification_preferences")
    op.drop_column("finding_observations", "regressed")
