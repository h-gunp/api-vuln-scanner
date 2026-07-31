"""Align findings, evidence, and Scanner approval state with final contracts.

Revision ID: 20260729_0002
Revises: 20260727_0001
Create Date: 2026-07-29
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision: str = "20260729_0002"
down_revision: str | None = "20260727_0001"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.add_column(
        "findings",
        sa.Column("vulnerability_type", sa.String(length=40), nullable=True),
    )
    op.alter_column("findings", "severity", existing_type=sa.String(length=20), nullable=True)
    op.create_index(
        "ix_findings_vulnerability_type",
        "findings",
        ["vulnerability_type"],
    )

    op.add_column(
        "external_jobs",
        sa.Column("plan_id", sa.String(length=255), nullable=True),
    )
    op.add_column(
        "external_jobs",
        sa.Column("approval_status", sa.String(length=20), nullable=True),
    )
    op.add_column(
        "external_jobs",
        sa.Column(
            "approval_reason_codes_json",
            postgresql.JSONB(astext_type=sa.Text()),
            nullable=True,
        ),
    )

    op.execute(
        """
        UPDATE findings
        SET vulnerability_type = CASE module_id
            WHEN 'BOLA-001' THEN 'BOLA'
            WHEN 'INPUT-001' THEN 'INPUT_VALIDATION'
            WHEN 'DATA-001' THEN 'DATA_EXPOSURE'
        END
        """
    )
    op.alter_column(
        "findings",
        "vulnerability_type",
        existing_type=sa.String(length=40),
        nullable=False,
    )


def downgrade() -> None:
    op.drop_column("external_jobs", "approval_reason_codes_json")
    op.drop_column("external_jobs", "approval_status")
    op.drop_column("external_jobs", "plan_id")
    op.drop_index("ix_findings_vulnerability_type", table_name="findings")
    op.alter_column("findings", "severity", existing_type=sa.String(length=20), nullable=False)
    op.drop_column("findings", "vulnerability_type")
