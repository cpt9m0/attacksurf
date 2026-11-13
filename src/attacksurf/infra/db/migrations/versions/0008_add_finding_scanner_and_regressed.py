"""add finding scanner provenance and regressed status

Revision ID: 0008
Revises: 0007
Create Date: 2026-11-13 15:55:00.000000+00:00
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "0008"
down_revision: str | Sequence[str] | None = "0007"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

_STATUSES = "status IN ('open', 'fixed', 'regressed', 'accepted_risk', 'false_positive')"
# The pre-#20 set, for downgrade: it has no `regressed`.
_PREVIOUS_STATUSES = "status IN ('open', 'fixed', 'accepted_risk', 'false_positive')"


def upgrade() -> None:
    # Nullable: rows written before #20 have unknown provenance and are never auto-fixed.
    op.add_column("findings", sa.Column("scanner", sa.String(length=100), nullable=True))
    op.drop_constraint(op.f("ck_findings_finding_status"), "findings", type_="check")
    op.create_check_constraint(op.f("ck_findings_finding_status"), "findings", _STATUSES)


def downgrade() -> None:
    # The old CHECK rejects `regressed`; a regressed finding is still an observed issue, so it
    # becomes `open`. Only the "came back" distinction is lost.
    op.execute("UPDATE findings SET status = 'open' WHERE status = 'regressed'")
    op.drop_constraint(op.f("ck_findings_finding_status"), "findings", type_="check")
    op.create_check_constraint(op.f("ck_findings_finding_status"), "findings", _PREVIOUS_STATUSES)
    op.drop_column("findings", "scanner")
