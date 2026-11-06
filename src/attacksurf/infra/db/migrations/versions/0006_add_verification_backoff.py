"""add verification retry backoff

Revision ID: 0006
Revises: 0005
Create Date: 2026-11-04 01:10:00+00:00
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "0006"
down_revision: str | Sequence[str] | None = "0005"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.add_column(
        "verifications",
        sa.Column("failed_attempts", sa.Integer(), server_default=sa.text("0"), nullable=False),
    )
    op.add_column("verifications", sa.Column("retry_after", sa.DateTime(timezone=True)))


def downgrade() -> None:
    op.drop_column("verifications", "retry_after")
    op.drop_column("verifications", "failed_attempts")
