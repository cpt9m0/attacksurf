"""add assets and asset relations

Revision ID: 0003
Revises: 0002
Create Date: 2026-10-15 01:53:01.375781+00:00
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision: str = "0003"
down_revision: str | Sequence[str] | None = "0002"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.create_table(
        "assets",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("org_id", sa.Uuid(), nullable=False),
        sa.Column(
            "type",
            sa.Enum(
                "domain",
                "subdomain",
                "ip",
                "url",
                "repo",
                "binary",
                name="asset_type",
                native_enum=False,
                create_constraint=False,  # explicit, convention-named CHECK below
                length=20,
            ),
            nullable=False,
        ),
        sa.Column("value", sa.String(length=2048), nullable=False),
        sa.Column(
            "source",
            sa.Enum(
                "user",
                "discovered",
                name="asset_source",
                native_enum=False,
                create_constraint=False,  # explicit, convention-named CHECK below
                length=20,
            ),
            nullable=False,
        ),
        sa.Column("parent_id", sa.Uuid(), nullable=True),
        sa.Column(
            "tags",
            postgresql.ARRAY(sa.String(length=50)),
            server_default=sa.text("'{}'"),
            nullable=False,
        ),
        sa.Column("first_seen", sa.DateTime(timezone=True), nullable=False),
        sa.Column("last_seen", sa.DateTime(timezone=True), nullable=False),
        sa.Column("is_active", sa.Boolean(), server_default=sa.text("true"), nullable=False),
        sa.Column("deactivated_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column(
            "details",
            postgresql.JSONB(astext_type=sa.Text()),
            server_default=sa.text("'{}'::jsonb"),
            nullable=False,
        ),
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
        sa.CheckConstraint("source IN ('user', 'discovered')", name=op.f("ck_assets_asset_source")),
        sa.CheckConstraint(
            "type IN ('domain', 'subdomain', 'ip', 'url', 'repo', 'binary')",
            name=op.f("ck_assets_asset_type"),
        ),
        sa.CheckConstraint(
            "is_active = (deactivated_at IS NULL)", name=op.f("ck_assets_deactivated_at_matches")
        ),
        sa.CheckConstraint(
            "parent_id IS NULL OR parent_id <> id", name=op.f("ck_assets_no_self_parent")
        ),
        sa.CheckConstraint(
            "source = 'discovered' OR parent_id IS NULL", name=op.f("ck_assets_user_asset_is_root")
        ),
        sa.ForeignKeyConstraint(
            ["org_id"], ["orgs.id"], name=op.f("fk_assets_org_id_orgs"), ondelete="CASCADE"
        ),
        sa.ForeignKeyConstraint(
            ["parent_id", "org_id"],
            ["assets.id", "assets.org_id"],
            name=op.f("fk_assets_parent_id_assets"),
            ondelete="CASCADE",
        ),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_assets")),
        sa.UniqueConstraint("id", "org_id", name=op.f("uq_assets_id")),
        sa.UniqueConstraint("org_id", "type", "value", name=op.f("uq_assets_org_id")),
    )
    op.create_index(op.f("ix_assets_org_id"), "assets", ["org_id"], unique=False)
    op.create_index(op.f("ix_assets_parent_id"), "assets", ["parent_id"], unique=False)
    op.create_table(
        "asset_relations",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("org_id", sa.Uuid(), nullable=False),
        sa.Column("from_asset_id", sa.Uuid(), nullable=False),
        sa.Column("to_asset_id", sa.Uuid(), nullable=False),
        sa.Column(
            "kind",
            sa.Enum(
                "resolves_to",
                "cname_to",
                "subdomain_of",
                "serves",
                name="relation_kind",
                native_enum=False,
                create_constraint=False,  # explicit, convention-named CHECK below
                length=20,
            ),
            nullable=False,
        ),
        sa.Column("first_seen", sa.DateTime(timezone=True), nullable=False),
        sa.Column("last_seen", sa.DateTime(timezone=True), nullable=False),
        sa.CheckConstraint(
            "kind IN ('resolves_to', 'cname_to', 'subdomain_of', 'serves')",
            name=op.f("ck_asset_relations_relation_kind"),
        ),
        sa.CheckConstraint(
            "from_asset_id <> to_asset_id", name=op.f("ck_asset_relations_no_self_relation")
        ),
        sa.ForeignKeyConstraint(
            ["from_asset_id", "org_id"],
            ["assets.id", "assets.org_id"],
            name=op.f("fk_asset_relations_from_asset_id_assets"),
            ondelete="CASCADE",
        ),
        sa.ForeignKeyConstraint(
            ["org_id"], ["orgs.id"], name=op.f("fk_asset_relations_org_id_orgs"), ondelete="CASCADE"
        ),
        sa.ForeignKeyConstraint(
            ["to_asset_id", "org_id"],
            ["assets.id", "assets.org_id"],
            name=op.f("fk_asset_relations_to_asset_id_assets"),
            ondelete="CASCADE",
        ),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_asset_relations")),
        sa.UniqueConstraint(
            "org_id", "from_asset_id", "to_asset_id", "kind", name=op.f("uq_asset_relations_org_id")
        ),
    )
    op.create_index(op.f("ix_asset_relations_org_id"), "asset_relations", ["org_id"], unique=False)
    op.create_index(
        op.f("ix_asset_relations_to_asset_id"), "asset_relations", ["to_asset_id"], unique=False
    )


def downgrade() -> None:
    op.drop_index(op.f("ix_asset_relations_to_asset_id"), table_name="asset_relations")
    op.drop_index(op.f("ix_asset_relations_org_id"), table_name="asset_relations")
    op.drop_table("asset_relations")
    op.drop_index(op.f("ix_assets_parent_id"), table_name="assets")
    op.drop_index(op.f("ix_assets_org_id"), table_name="assets")
    op.drop_table("assets")
