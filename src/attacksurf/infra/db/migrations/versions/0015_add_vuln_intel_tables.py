"""Add global vulnerability intelligence reference tables

Revision ID: 0015
Revises: 0014
Create Date: 2026-11-23 21:44:00+00:00
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "0015"
down_revision: str | Sequence[str] | None = "0014"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.create_table(
        "vuln_cves",
        sa.Column("cve_id", sa.String(length=32), nullable=False),
        sa.Column("description", sa.Text(), server_default="", nullable=False),
        sa.Column("published_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("last_modified_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("cvss_v3_score", sa.Float(), nullable=True),
        sa.Column("cvss_v3_vector", sa.String(length=128), nullable=True),
        sa.Column("cvss_v4_score", sa.Float(), nullable=True),
        sa.Column("cvss_v4_vector", sa.String(length=160), nullable=True),
        sa.Column("in_kev", sa.Boolean(), server_default=sa.text("false"), nullable=False),
        sa.Column("kev_date_added", sa.Date(), nullable=True),
        sa.Column("epss_score", sa.Float(), nullable=True),
        sa.Column("epss_percentile", sa.Float(), nullable=True),
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
            "cvss_v3_score IS NULL OR (cvss_v3_score >= 0 AND cvss_v3_score <= 10)",
            name=op.f("ck_vuln_cves_cvss_v3_range"),
        ),
        sa.CheckConstraint(
            "cvss_v4_score IS NULL OR (cvss_v4_score >= 0 AND cvss_v4_score <= 10)",
            name=op.f("ck_vuln_cves_cvss_v4_range"),
        ),
        sa.CheckConstraint(
            "epss_score IS NULL OR (epss_score >= 0 AND epss_score <= 1)",
            name=op.f("ck_vuln_cves_epss_score_range"),
        ),
        sa.CheckConstraint(
            "epss_percentile IS NULL OR (epss_percentile >= 0 AND epss_percentile <= 1)",
            name=op.f("ck_vuln_cves_epss_percentile_range"),
        ),
        sa.PrimaryKeyConstraint("cve_id", name=op.f("pk_vuln_cves")),
    )
    op.create_index(op.f("ix_vuln_cves_in_kev"), "vuln_cves", ["in_kev"], unique=False)
    op.create_index(
        op.f("ix_vuln_cves_last_modified_at"), "vuln_cves", ["last_modified_at"], unique=False
    )

    op.create_table(
        "vuln_cpe_ranges",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("cve_id", sa.String(length=32), nullable=False),
        sa.Column("vendor", sa.String(length=128), nullable=False),
        sa.Column("product", sa.String(length=128), nullable=False),
        sa.Column("exact_version", sa.String(length=128), nullable=True),
        sa.Column("version_start_including", sa.String(length=128), nullable=True),
        sa.Column("version_start_excluding", sa.String(length=128), nullable=True),
        sa.Column("version_end_including", sa.String(length=128), nullable=True),
        sa.Column("version_end_excluding", sa.String(length=128), nullable=True),
        sa.ForeignKeyConstraint(
            ["cve_id"],
            ["vuln_cves.cve_id"],
            name=op.f("fk_vuln_cpe_ranges_cve_id_vuln_cves"),
            ondelete="CASCADE",
        ),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_vuln_cpe_ranges")),
    )
    op.create_index(op.f("ix_vuln_cpe_ranges_cve_id"), "vuln_cpe_ranges", ["cve_id"], unique=False)
    op.create_index(
        "ix_vuln_cpe_ranges_vendor_product",
        "vuln_cpe_ranges",
        ["vendor", "product"],
        unique=False,
    )

    op.create_table(
        "vuln_sync_state",
        sa.Column("source", sa.String(length=32), nullable=False),
        sa.Column("last_synced_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("cursor_timestamp", sa.DateTime(timezone=True), nullable=True),
        sa.Column("cursor_tag", sa.String(length=128), nullable=True),
        sa.Column("records_processed", sa.Integer(), server_default=sa.text("0"), nullable=False),
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
        sa.PrimaryKeyConstraint("source", name=op.f("pk_vuln_sync_state")),
    )


def downgrade() -> None:
    op.drop_table("vuln_sync_state")
    op.drop_index("ix_vuln_cpe_ranges_vendor_product", table_name="vuln_cpe_ranges")
    op.drop_index(op.f("ix_vuln_cpe_ranges_cve_id"), table_name="vuln_cpe_ranges")
    op.drop_table("vuln_cpe_ranges")
    op.drop_index(op.f("ix_vuln_cves_last_modified_at"), table_name="vuln_cves")
    op.drop_index(op.f("ix_vuln_cves_in_kev"), table_name="vuln_cves")
    op.drop_table("vuln_cves")
