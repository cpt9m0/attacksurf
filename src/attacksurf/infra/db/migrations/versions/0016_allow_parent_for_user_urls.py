"""Allow parent_id on user-added URL assets under a covering root domain

Revision ID: 0016
Revises: 0015
Create Date: 2026-11-27 19:41:00+00:00
"""

from collections.abc import Sequence

from alembic import op

revision: str = "0016"
down_revision: str | Sequence[str] | None = "0015"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.drop_constraint(op.f("ck_assets_user_asset_is_root"), "assets", type_="check")
    op.create_check_constraint(
        op.f("ck_assets_user_asset_is_root"),
        "assets",
        "source = 'discovered' OR parent_id IS NULL OR type = 'url'",
    )


def downgrade() -> None:
    op.execute(
        "UPDATE assets SET parent_id = NULL "
        "WHERE source = 'user' AND type = 'url' AND parent_id IS NOT NULL"
    )
    op.drop_constraint(op.f("ck_assets_user_asset_is_root"), "assets", type_="check")
    op.create_check_constraint(
        op.f("ck_assets_user_asset_is_root"),
        "assets",
        "source = 'discovered' OR parent_id IS NULL",
    )
