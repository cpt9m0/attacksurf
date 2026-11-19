"""add org settings

Revision ID: 0011
Revises: 0010
Create Date: 2026-11-18 08:50:00+00:00
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "0011"
down_revision: str | Sequence[str] | None = "0010"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.create_table(
        "org_settings",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("org_id", sa.Uuid(), nullable=False),
        sa.Column("ai_enabled", sa.Boolean(), server_default=sa.text("true"), nullable=False),
        sa.Column(
            "provider",
            sa.Enum(
                "anthropic",
                "openai_compat",
                name="llm_provider",
                native_enum=False,
                create_constraint=False,  # explicit, convention-named CHECK below
                length=20,
            ),
            server_default="anthropic",
            nullable=False,
        ),
        sa.Column("model", sa.String(length=200), nullable=True),
        sa.Column("base_url", sa.String(length=2048), nullable=True),
        sa.Column("api_key_ciphertext", sa.LargeBinary(length=512), nullable=True),
        sa.Column("api_key_last4", sa.String(length=4), nullable=True),
        sa.Column("monthly_token_budget", sa.BigInteger(), nullable=True),
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
            "provider IN ('anthropic', 'openai_compat')",
            name=op.f("ck_org_settings_llm_provider"),
        ),
        sa.CheckConstraint(
            "monthly_token_budget IS NULL OR monthly_token_budget >= 0",
            name=op.f("ck_org_settings_monthly_token_budget_not_negative"),
        ),
        sa.CheckConstraint(
            "(api_key_ciphertext IS NULL) = (api_key_last4 IS NULL)",
            name=op.f("ck_org_settings_api_key_last4_matches"),
        ),
        sa.ForeignKeyConstraint(
            ["org_id"], ["orgs.id"], name=op.f("fk_org_settings_org_id_orgs"), ondelete="CASCADE"
        ),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_org_settings")),
        sa.UniqueConstraint("org_id", name=op.f("uq_org_settings_org_id")),
    )
    op.create_index(op.f("ix_org_settings_org_id"), "org_settings", ["org_id"], unique=False)


def downgrade() -> None:
    op.drop_index(op.f("ix_org_settings_org_id"), table_name="org_settings")
    op.drop_table("org_settings")
