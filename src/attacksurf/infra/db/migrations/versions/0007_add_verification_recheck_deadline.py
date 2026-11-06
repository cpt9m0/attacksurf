"""add verification recheck deadline

Revision ID: 0007
Revises: 0006
Create Date: 2026-11-06 01:27:04.906983+00:00
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "0007"
down_revision: str | Sequence[str] | None = "0006"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.add_column("verifications", sa.Column("recheck_at", sa.DateTime(timezone=True)))
    # Preserve existing authorization expiry while making renewal due four hours earlier.
    op.execute(
        sa.text(
            "UPDATE verifications SET recheck_at = expires_at - interval '4 hours' "
            "WHERE expires_at IS NOT NULL"
        )
    )


def downgrade() -> None:
    op.drop_column("verifications", "recheck_at")
