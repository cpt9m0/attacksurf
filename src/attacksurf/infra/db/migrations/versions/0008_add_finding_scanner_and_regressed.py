"""add finding provenance, evidence digest, observations and regressed status

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
    # Nullable: NULL means "no evidence recorded yet", compared as the empty batch.
    op.add_column("findings", sa.Column("evidence_digest", sa.String(length=64), nullable=True))
    # Which scan discovered/deactivated an asset, so overlapping scans cannot claim each
    # other's asset changes (ADR 0027). NULL for user roots and pre-#20 rows.
    op.add_column("assets", sa.Column("first_seen_scan_id", sa.Uuid(), nullable=True))
    op.add_column("assets", sa.Column("deactivated_by_scan_id", sa.Uuid(), nullable=True))
    op.create_foreign_key(
        op.f("fk_assets_first_seen_scan_id_scans"),
        "assets",
        "scans",
        ["first_seen_scan_id", "org_id"],
        ["id", "org_id"],
        ondelete="SET NULL (first_seen_scan_id)",
    )
    op.create_foreign_key(
        op.f("fk_assets_deactivated_by_scan_id_scans"),
        "assets",
        "scans",
        ["deactivated_by_scan_id", "org_id"],
        ["id", "org_id"],
        ondelete="SET NULL (deactivated_by_scan_id)",
    )
    op.create_index(
        op.f("ix_assets_first_seen_scan_id"), "assets", ["first_seen_scan_id"], unique=False
    )
    op.create_index(
        op.f("ix_assets_deactivated_by_scan_id"), "assets", ["deactivated_by_scan_id"], unique=False
    )
    op.drop_constraint(op.f("ck_findings_finding_status"), "findings", type_="check")
    op.create_check_constraint(op.f("ck_findings_finding_status"), "findings", _STATUSES)
    op.create_table(
        "finding_observations",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("org_id", sa.Uuid(), nullable=False),
        sa.Column("scan_id", sa.Uuid(), nullable=False),
        sa.Column("finding_id", sa.Uuid(), nullable=False),
        sa.Column(
            "severity",
            sa.Enum(
                "info",
                "low",
                "medium",
                "high",
                "critical",
                name="severity",
                native_enum=False,
                create_constraint=False,  # explicit, convention-named CHECK below
                length=20,
            ),
            nullable=False,
        ),
        sa.CheckConstraint(
            "severity IN ('info', 'low', 'medium', 'high', 'critical')",
            name=op.f("ck_finding_observations_severity"),
        ),
        sa.ForeignKeyConstraint(
            ["finding_id", "org_id"],
            ["findings.id", "findings.org_id"],
            name=op.f("fk_finding_observations_finding_id_findings"),
            ondelete="CASCADE",
        ),
        sa.ForeignKeyConstraint(
            ["org_id"],
            ["orgs.id"],
            name=op.f("fk_finding_observations_org_id_orgs"),
            ondelete="CASCADE",
        ),
        sa.ForeignKeyConstraint(
            ["scan_id", "org_id"],
            ["scans.id", "scans.org_id"],
            name=op.f("fk_finding_observations_scan_id_scans"),
            ondelete="CASCADE",
        ),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_finding_observations")),
        sa.UniqueConstraint(
            "org_id", "scan_id", "finding_id", name=op.f("uq_finding_observations_org_id")
        ),
    )
    op.create_index(
        op.f("ix_finding_observations_finding_id"),
        "finding_observations",
        ["finding_id"],
        unique=False,
    )
    op.create_index(
        op.f("ix_finding_observations_org_id"), "finding_observations", ["org_id"], unique=False
    )
    op.create_index(
        op.f("ix_finding_observations_scan_id"), "finding_observations", ["scan_id"], unique=False
    )


def downgrade() -> None:
    op.drop_index(op.f("ix_assets_deactivated_by_scan_id"), table_name="assets")
    op.drop_index(op.f("ix_assets_first_seen_scan_id"), table_name="assets")
    op.drop_constraint(op.f("fk_assets_deactivated_by_scan_id_scans"), "assets", type_="foreignkey")
    op.drop_constraint(op.f("fk_assets_first_seen_scan_id_scans"), "assets", type_="foreignkey")
    op.drop_column("assets", "deactivated_by_scan_id")
    op.drop_column("assets", "first_seen_scan_id")
    op.drop_table("finding_observations")
    # The old CHECK rejects `regressed`; a regressed finding is still an observed issue, so it
    # becomes `open`. Only the "came back" distinction is lost.
    op.execute("UPDATE findings SET status = 'open' WHERE status = 'regressed'")
    op.drop_constraint(op.f("ck_findings_finding_status"), "findings", type_="check")
    op.create_check_constraint(op.f("ck_findings_finding_status"), "findings", _PREVIOUS_STATUSES)
    op.drop_column("findings", "evidence_digest")
    op.drop_column("findings", "scanner")
