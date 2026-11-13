"""add llm usage

Revision ID: 0009
Revises: 0008
Create Date: 2026-11-12 16:53:36.457564+00:00
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "0009"
down_revision: str | Sequence[str] | None = "0008"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.create_table(
        "llm_usage",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("org_id", sa.Uuid(), nullable=False),
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
            nullable=False,
        ),
        sa.Column("model", sa.String(length=200), nullable=False),
        sa.Column("purpose", sa.String(length=50), nullable=False),
        sa.Column(
            "key_source",
            sa.Enum(
                "org",
                "instance",
                name="llm_key_source",
                native_enum=False,
                create_constraint=False,  # explicit, convention-named CHECK below
                length=20,
            ),
            nullable=False,
        ),
        sa.Column("input_tokens", sa.Integer(), nullable=False),
        sa.Column("output_tokens", sa.Integer(), nullable=False),
        sa.Column("usage_reported", sa.Boolean(), nullable=False),
        sa.Column("estimated_cost_usd", sa.Numeric(precision=12, scale=6), nullable=True),
        sa.Column("latency_ms", sa.Integer(), nullable=True),
        sa.Column("success", sa.Boolean(), nullable=False),
        sa.Column("error_type", sa.String(length=50), nullable=True),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("now()"),
            nullable=False,
        ),
        sa.CheckConstraint(
            "provider IN ('anthropic', 'openai_compat')", name=op.f("ck_llm_usage_llm_provider")
        ),
        sa.CheckConstraint(
            "key_source IN ('org', 'instance')", name=op.f("ck_llm_usage_llm_key_source")
        ),
        sa.CheckConstraint(
            "input_tokens >= 0", name=op.f("ck_llm_usage_input_tokens_not_negative")
        ),
        sa.CheckConstraint(
            "output_tokens >= 0", name=op.f("ck_llm_usage_output_tokens_not_negative")
        ),
        sa.CheckConstraint(
            "estimated_cost_usd >= 0", name=op.f("ck_llm_usage_estimated_cost_not_negative")
        ),
        sa.CheckConstraint("latency_ms >= 0", name=op.f("ck_llm_usage_latency_ms_not_negative")),
        sa.CheckConstraint(
            "success = (error_type IS NULL)", name=op.f("ck_llm_usage_error_type_matches")
        ),
        sa.ForeignKeyConstraint(
            ["org_id"], ["orgs.id"], name=op.f("fk_llm_usage_org_id_orgs"), ondelete="CASCADE"
        ),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_llm_usage")),
    )
    op.create_index(op.f("ix_llm_usage_org_id"), "llm_usage", ["org_id"], unique=False)
    # #24's monthly cap sums one org's rows since the start of the month.
    op.create_index(
        "ix_llm_usage_org_id_created_at", "llm_usage", ["org_id", "created_at"], unique=False
    )


def downgrade() -> None:
    op.drop_index("ix_llm_usage_org_id_created_at", table_name="llm_usage")
    op.drop_index(op.f("ix_llm_usage_org_id"), table_name="llm_usage")
    op.drop_table("llm_usage")
