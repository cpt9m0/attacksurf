"""add artifacts

Revision ID: 0010
Revises: 0009
Create Date: 2026-11-13 10:00:00+00:00
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "0010"
down_revision: str | Sequence[str] | None = "0009"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.create_table(
        "artifacts",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("org_id", sa.Uuid(), nullable=False),
        sa.Column("asset_id", sa.Uuid(), nullable=False),
        sa.Column(
            "kind",
            sa.Enum(
                "repo",
                "binary",
                name="artifact_kind",
                native_enum=False,
                create_constraint=False,  # explicit, convention-named CHECK below
                length=20,
            ),
            nullable=False,
        ),
        sa.Column("sha256", sa.String(length=64), nullable=False),
        sa.Column("size_bytes", sa.BigInteger(), nullable=False),
        sa.Column("storage_key", sa.String(length=100), nullable=False),
        sa.Column("key_envelope", sa.LargeBinary(length=61), nullable=True),
        sa.Column("delete_after", sa.DateTime(timezone=True), nullable=False),
        sa.Column("deleted_at", sa.DateTime(timezone=True), nullable=True),
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
        sa.CheckConstraint("kind IN ('repo', 'binary')", name=op.f("ck_artifacts_artifact_kind")),
        sa.CheckConstraint("size_bytes >= 0", name=op.f("ck_artifacts_size_not_negative")),
        # A deleted artifact keeps its row but never its key: the blob is then undecryptable.
        sa.CheckConstraint(
            "(deleted_at IS NULL) = (key_envelope IS NOT NULL)",
            name=op.f("ck_artifacts_key_erased_on_delete"),
        ),
        sa.ForeignKeyConstraint(
            ["asset_id", "org_id"],
            ["assets.id", "assets.org_id"],
            name=op.f("fk_artifacts_asset_id_assets"),
            ondelete="CASCADE",
        ),
        sa.ForeignKeyConstraint(
            ["org_id"], ["orgs.id"], name=op.f("fk_artifacts_org_id_orgs"), ondelete="CASCADE"
        ),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_artifacts")),
        sa.UniqueConstraint("storage_key", name=op.f("uq_artifacts_storage_key")),
    )
    op.create_index(op.f("ix_artifacts_org_id"), "artifacts", ["org_id"], unique=False)
    op.create_index(op.f("ix_artifacts_asset_id"), "artifacts", ["asset_id"], unique=False)
    op.create_index("ix_artifacts_delete_after", "artifacts", ["delete_after"], unique=False)


def downgrade() -> None:
    op.drop_index("ix_artifacts_delete_after", table_name="artifacts")
    op.drop_index(op.f("ix_artifacts_asset_id"), table_name="artifacts")
    op.drop_index(op.f("ix_artifacts_org_id"), table_name="artifacts")
    op.drop_table("artifacts")
