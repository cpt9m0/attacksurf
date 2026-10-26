"""add scans jobs findings evidence

Revision ID: 0004
Revises: 0003
Create Date: 2026-10-15 14:07:21.203161+00:00
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision: str = "0004"
down_revision: str | Sequence[str] | None = "0003"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.create_table(
        "scans",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("org_id", sa.Uuid(), nullable=False),
        sa.Column("root_asset_id", sa.Uuid(), nullable=False),
        sa.Column("profile", sa.String(length=50), nullable=False),
        sa.Column(
            "status",
            sa.Enum(
                "queued",
                "running",
                "completed",
                "failed",
                "cancelled",
                name="scan_status",
                native_enum=False,
                create_constraint=False,  # explicit, convention-named CHECK below
                length=20,
            ),
            nullable=False,
        ),
        sa.Column(
            "triggered_by",
            sa.Enum(
                "user",
                "schedule",
                name="scan_trigger",
                native_enum=False,
                create_constraint=False,  # explicit, convention-named CHECK below
                length=20,
            ),
            nullable=False,
        ),
        sa.Column("started_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("finished_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column(
            "stats",
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
        sa.CheckConstraint(
            "status IN ('queued', 'running', 'completed', 'failed', 'cancelled')",
            name=op.f("ck_scans_scan_status"),
        ),
        sa.CheckConstraint(
            "triggered_by IN ('user', 'schedule')", name=op.f("ck_scans_scan_trigger")
        ),
        sa.CheckConstraint(
            "finished_at >= started_at", name=op.f("ck_scans_finished_after_started")
        ),
        sa.ForeignKeyConstraint(
            ["org_id"], ["orgs.id"], name=op.f("fk_scans_org_id_orgs"), ondelete="CASCADE"
        ),
        sa.ForeignKeyConstraint(
            ["root_asset_id", "org_id"],
            ["assets.id", "assets.org_id"],
            name=op.f("fk_scans_root_asset_id_assets"),
            ondelete="CASCADE",
        ),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_scans")),
        sa.UniqueConstraint("id", "org_id", name=op.f("uq_scans_id")),
    )
    op.create_index(op.f("ix_scans_org_id"), "scans", ["org_id"], unique=False)
    op.create_index(
        "ix_scans_root_asset_id_created_at", "scans", ["root_asset_id", "created_at"], unique=False
    )
    op.create_table(
        "findings",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("org_id", sa.Uuid(), nullable=False),
        sa.Column("asset_id", sa.Uuid(), nullable=False),
        sa.Column("first_seen_scan_id", sa.Uuid(), nullable=True),
        sa.Column("last_seen_scan_id", sa.Uuid(), nullable=True),
        sa.Column("rule_id", sa.String(length=100), nullable=False),
        sa.Column("fingerprint", sa.String(length=64), nullable=False),
        sa.Column("location", sa.String(length=500), server_default="", nullable=False),
        sa.Column("title", sa.String(length=300), nullable=False),
        sa.Column("description", sa.Text(), nullable=False),
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
        sa.Column(
            "confidence",
            sa.Enum(
                "low",
                "medium",
                "high",
                name="confidence",
                native_enum=False,
                create_constraint=False,  # explicit, convention-named CHECK below
                length=20,
            ),
            nullable=False,
        ),
        sa.Column(
            "status",
            sa.Enum(
                "open",
                "fixed",
                "accepted_risk",
                "false_positive",
                name="finding_status",
                native_enum=False,
                create_constraint=False,  # explicit, convention-named CHECK below
                length=20,
            ),
            server_default="open",
            nullable=False,
        ),
        sa.Column("first_seen", sa.DateTime(timezone=True), nullable=False),
        sa.Column("last_seen", sa.DateTime(timezone=True), nullable=False),
        sa.Column("fixed_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("remediation", sa.Text(), server_default="", nullable=False),
        sa.Column(
            "references",
            postgresql.ARRAY(sa.String(length=2048)),
            server_default=sa.text("'{}'"),
            nullable=False,
        ),
        sa.Column("ai_triage", postgresql.JSONB(astext_type=sa.Text()), nullable=True),
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
            "(status = 'fixed') = (fixed_at IS NOT NULL)", name=op.f("ck_findings_fixed_at_matches")
        ),
        sa.CheckConstraint(
            "confidence IN ('low', 'medium', 'high')", name=op.f("ck_findings_confidence")
        ),
        sa.CheckConstraint(
            "severity IN ('info', 'low', 'medium', 'high', 'critical')",
            name=op.f("ck_findings_severity"),
        ),
        sa.CheckConstraint(
            "status IN ('open', 'fixed', 'accepted_risk', 'false_positive')",
            name=op.f("ck_findings_finding_status"),
        ),
        sa.CheckConstraint(
            "last_seen >= first_seen", name=op.f("ck_findings_last_seen_after_first_seen")
        ),
        sa.ForeignKeyConstraint(
            ["asset_id", "org_id"],
            ["assets.id", "assets.org_id"],
            name=op.f("fk_findings_asset_id_assets"),
            ondelete="CASCADE",
        ),
        sa.ForeignKeyConstraint(
            ["first_seen_scan_id", "org_id"],
            ["scans.id", "scans.org_id"],
            name=op.f("fk_findings_first_seen_scan_id_scans"),
            ondelete="SET NULL (first_seen_scan_id)",
        ),
        sa.ForeignKeyConstraint(
            ["last_seen_scan_id", "org_id"],
            ["scans.id", "scans.org_id"],
            name=op.f("fk_findings_last_seen_scan_id_scans"),
            ondelete="SET NULL (last_seen_scan_id)",
        ),
        sa.ForeignKeyConstraint(
            ["org_id"], ["orgs.id"], name=op.f("fk_findings_org_id_orgs"), ondelete="CASCADE"
        ),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_findings")),
        sa.UniqueConstraint("id", "org_id", name=op.f("uq_findings_id")),
        sa.UniqueConstraint("org_id", "fingerprint", name=op.f("uq_findings_org_id")),
    )
    op.create_index(op.f("ix_findings_asset_id"), "findings", ["asset_id"], unique=False)
    op.create_index(
        op.f("ix_findings_first_seen_scan_id"), "findings", ["first_seen_scan_id"], unique=False
    )
    op.create_index(
        op.f("ix_findings_last_seen_scan_id"), "findings", ["last_seen_scan_id"], unique=False
    )
    op.create_index(op.f("ix_findings_org_id"), "findings", ["org_id"], unique=False)
    op.create_table(
        "jobs",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("org_id", sa.Uuid(), nullable=False),
        sa.Column("scan_id", sa.Uuid(), nullable=False),
        sa.Column("asset_id", sa.Uuid(), nullable=True),
        sa.Column("stage", sa.String(length=50), nullable=False),
        sa.Column("scanner", sa.String(length=100), nullable=True),
        sa.Column(
            "status",
            sa.Enum(
                "queued",
                "running",
                "completed",
                "failed",
                "cancelled",
                "skipped",
                name="job_status",
                native_enum=False,
                create_constraint=False,  # explicit, convention-named CHECK below
                length=20,
            ),
            nullable=False,
        ),
        sa.Column("attempts", sa.Integer(), server_default=sa.text("0"), nullable=False),
        sa.Column("error", sa.String(length=2000), nullable=True),
        sa.Column("celery_task_id", sa.String(length=255), nullable=True),
        sa.Column("started_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("finished_at", sa.DateTime(timezone=True), nullable=True),
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
            "status IN ('queued', 'running', 'completed', 'failed', 'cancelled', 'skipped')",
            name=op.f("ck_jobs_job_status"),
        ),
        sa.CheckConstraint("attempts >= 0", name=op.f("ck_jobs_attempts_not_negative")),
        sa.CheckConstraint(
            "finished_at >= started_at", name=op.f("ck_jobs_finished_after_started")
        ),
        sa.ForeignKeyConstraint(
            ["asset_id", "org_id"],
            ["assets.id", "assets.org_id"],
            name=op.f("fk_jobs_asset_id_assets"),
            ondelete="SET NULL (asset_id)",
        ),
        sa.ForeignKeyConstraint(
            ["org_id"], ["orgs.id"], name=op.f("fk_jobs_org_id_orgs"), ondelete="CASCADE"
        ),
        sa.ForeignKeyConstraint(
            ["scan_id", "org_id"],
            ["scans.id", "scans.org_id"],
            name=op.f("fk_jobs_scan_id_scans"),
            ondelete="CASCADE",
        ),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_jobs")),
    )
    op.create_index(op.f("ix_jobs_asset_id"), "jobs", ["asset_id"], unique=False)
    op.create_index(op.f("ix_jobs_org_id"), "jobs", ["org_id"], unique=False)
    op.create_index(op.f("ix_jobs_scan_id"), "jobs", ["scan_id"], unique=False)
    op.create_table(
        "evidence",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("org_id", sa.Uuid(), nullable=False),
        sa.Column("finding_id", sa.Uuid(), nullable=False),
        sa.Column(
            "kind",
            sa.Enum(
                "dns_record",
                "http_response",
                "raw",
                name="evidence_kind",
                native_enum=False,
                create_constraint=False,  # explicit, convention-named CHECK below
                length=20,
            ),
            nullable=False,
        ),
        sa.Column("data", postgresql.JSONB(astext_type=sa.Text()), nullable=False),
        sa.Column("captured_at", sa.DateTime(timezone=True), nullable=False),
        sa.CheckConstraint(
            "kind IN ('dns_record', 'http_response', 'raw')", name=op.f("ck_evidence_evidence_kind")
        ),
        sa.ForeignKeyConstraint(
            ["finding_id", "org_id"],
            ["findings.id", "findings.org_id"],
            name=op.f("fk_evidence_finding_id_findings"),
            ondelete="CASCADE",
        ),
        sa.ForeignKeyConstraint(
            ["org_id"], ["orgs.id"], name=op.f("fk_evidence_org_id_orgs"), ondelete="CASCADE"
        ),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_evidence")),
    )
    op.create_index(op.f("ix_evidence_finding_id"), "evidence", ["finding_id"], unique=False)
    op.create_index(op.f("ix_evidence_org_id"), "evidence", ["org_id"], unique=False)


def downgrade() -> None:
    op.drop_index(op.f("ix_evidence_org_id"), table_name="evidence")
    op.drop_index(op.f("ix_evidence_finding_id"), table_name="evidence")
    op.drop_table("evidence")
    op.drop_index(op.f("ix_jobs_scan_id"), table_name="jobs")
    op.drop_index(op.f("ix_jobs_org_id"), table_name="jobs")
    op.drop_index(op.f("ix_jobs_asset_id"), table_name="jobs")
    op.drop_table("jobs")
    op.drop_index(op.f("ix_findings_org_id"), table_name="findings")
    op.drop_index(op.f("ix_findings_last_seen_scan_id"), table_name="findings")
    op.drop_index(op.f("ix_findings_first_seen_scan_id"), table_name="findings")
    op.drop_index(op.f("ix_findings_asset_id"), table_name="findings")
    op.drop_table("findings")
    op.drop_index("ix_scans_root_asset_id_created_at", table_name="scans")
    op.drop_index(op.f("ix_scans_org_id"), table_name="scans")
    op.drop_table("scans")
