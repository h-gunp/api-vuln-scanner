"""Create the initial scanner orchestration schema.

Revision ID: 20260727_0001
Revises:
Create Date: 2026-07-27
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision: str = "20260727_0001"
down_revision: str | None = None
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

scan_status = sa.Enum(
    "PENDING", "RUNNING", "COMPLETED", "FAILED", "CANCELLED", "TIMED_OUT",
    name="scanstatus", native_enum=False, length=20,
)
scan_stage = sa.Enum(
    "TARGET_VALIDATION", "HEALTH_CHECK", "API_DISCOVERY", "API_NORMALIZATION",
    "RELATIONSHIP_ANALYSIS", "PLAN_GENERATION", "PLAN_VALIDATION",
    "MODULE_EXECUTION", "RESULT_VALIDATION", "REPORT_GENERATION", "COMPLETED",
    name="scanstage", native_enum=False, length=40,
)
step_status = sa.Enum(
    "PENDING", "RUNNING", "COMPLETED", "FAILED",
    name="stepstatus", native_enum=False, length=20,
)
artifact_type = sa.Enum(
    "TARGET_PROFILE", "NORMALIZED_API_GRAPH", "RELATIONSHIP_ANALYSIS", "SCAN_PLAN",
    "SCAN_RESULT", "AI_REPORT", "PDF_REPORT",
    name="artifacttype", native_enum=False, length=40,
)
job_type = sa.Enum(
    "SCANNER", "RELATIONSHIP_ANALYSIS", "PLAN_GENERATION", "MODULE_EXECUTION",
    "REPORT_GENERATION", name="jobtype", native_enum=False, length=40,
)
job_status = sa.Enum(
    "PENDING", "RUNNING", "COMPLETED", "FAILED", "TIMED_OUT",
    name="jobstatus", native_enum=False, length=20,
)
severity = sa.Enum(
    "CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO",
    name="severity", native_enum=False, length=20,
)
report_status = sa.Enum(
    "PENDING", "GENERATING", "COMPLETED", "FAILED",
    name="reportstatus", native_enum=False, length=20,
)


def upgrade() -> None:
    op.create_table(
        "scans",
        sa.Column("id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("target_url", sa.String(length=2048), nullable=False),
        sa.Column("status", scan_status, nullable=False),
        sa.Column("stage", scan_stage, nullable=False),
        sa.Column("progress", sa.Integer(), nullable=False),
        sa.Column("api_count", sa.Integer(), nullable=False),
        sa.Column("finding_count", sa.Integer(), nullable=False),
        sa.Column("planned_module_count", sa.Integer(), nullable=False),
        sa.Column("completed_module_count", sa.Integer(), nullable=False),
        sa.Column("max_requests", sa.Integer(), nullable=False),
        sa.Column("requests_used", sa.Integer(), nullable=False),
        sa.Column("error_code", sa.String(length=80), nullable=True),
        sa.Column("error_message", sa.String(length=1000), nullable=True),
        sa.Column("started_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("completed_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column(
            "created_at", sa.DateTime(timezone=True),
            server_default=sa.func.now(), nullable=False,
        ),
        sa.Column(
            "updated_at", sa.DateTime(timezone=True),
            server_default=sa.func.now(), nullable=False,
        ),
        sa.PrimaryKeyConstraint("id", name="pk_scans"),
    )
    op.create_index("ix_scans_status", "scans", ["status"])

    op.create_table(
        "scan_steps",
        sa.Column("id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("scan_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("stage", scan_stage, nullable=False),
        sa.Column("status", step_status, nullable=False),
        sa.Column("progress", sa.Integer(), nullable=False),
        sa.Column("attempt", sa.Integer(), nullable=False),
        sa.Column("metadata_json", postgresql.JSONB(), nullable=False),
        sa.Column("error_code", sa.String(length=80), nullable=True),
        sa.Column("error_message", sa.String(length=1000), nullable=True),
        sa.Column("started_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("completed_at", sa.DateTime(timezone=True), nullable=True),
        sa.ForeignKeyConstraint(["scan_id"], ["scans.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id", name="pk_scan_steps"),
    )
    op.create_index("ix_scan_steps_scan_id", "scan_steps", ["scan_id"])

    op.create_table(
        "scan_artifacts",
        sa.Column("id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("scan_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("artifact_type", artifact_type, nullable=False),
        sa.Column("schema_version", sa.String(length=20), nullable=True),
        sa.Column("storage_path", sa.String(length=2048), nullable=False),
        sa.Column("checksum_sha256", sa.String(length=64), nullable=False),
        sa.Column("file_size", sa.Integer(), nullable=False),
        sa.Column("content_type", sa.String(length=100), nullable=False),
        sa.Column(
            "created_at", sa.DateTime(timezone=True),
            server_default=sa.func.now(), nullable=False,
        ),
        sa.ForeignKeyConstraint(["scan_id"], ["scans.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id", name="pk_scan_artifacts"),
        sa.UniqueConstraint(
            "scan_id", "artifact_type", "checksum_sha256",
            name="uq_scan_artifacts_scan_type_checksum",
        ),
    )
    op.create_index("ix_scan_artifacts_scan_id", "scan_artifacts", ["scan_id"])

    op.create_table(
        "external_jobs",
        sa.Column("id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("scan_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("job_type", job_type, nullable=False),
        sa.Column("external_job_id", sa.String(length=255), nullable=True),
        sa.Column("status", job_status, nullable=False),
        sa.Column("retry_count", sa.Integer(), nullable=False),
        sa.Column("error_code", sa.String(length=80), nullable=True),
        sa.Column("error_message", sa.String(length=1000), nullable=True),
        sa.Column(
            "requested_at", sa.DateTime(timezone=True),
            server_default=sa.func.now(), nullable=False,
        ),
        sa.Column("started_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("completed_at", sa.DateTime(timezone=True), nullable=True),
        sa.ForeignKeyConstraint(["scan_id"], ["scans.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id", name="pk_external_jobs"),
    )
    op.create_index("ix_external_jobs_scan_id", "external_jobs", ["scan_id"])
    op.create_index("ix_external_jobs_external_job_id", "external_jobs", ["external_job_id"])

    op.create_table(
        "operations",
        sa.Column("id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("scan_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("operation_id", sa.String(length=2100), nullable=False),
        sa.Column("method", sa.String(length=10), nullable=False),
        sa.Column("path_template", sa.String(length=2048), nullable=False),
        sa.Column("inputs_json", postgresql.JSONB(), nullable=False),
        sa.Column("outputs_json", postgresql.JSONB(), nullable=False),
        sa.Column(
            "created_at", sa.DateTime(timezone=True),
            server_default=sa.func.now(), nullable=False,
        ),
        sa.ForeignKeyConstraint(["scan_id"], ["scans.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id", name="pk_operations"),
        sa.UniqueConstraint("scan_id", "operation_id", name="uq_operations_scan_operation"),
    )
    op.create_index("ix_operations_scan_id", "operations", ["scan_id"])

    op.create_table(
        "findings",
        sa.Column("id", sa.String(length=255), nullable=False),
        sa.Column("scan_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("operation_id", sa.String(length=2100), nullable=False),
        sa.Column("operation_pk", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("module_id", sa.String(length=80), nullable=False),
        sa.Column("severity", severity, nullable=False),
        sa.Column("rule_id", sa.String(length=255), nullable=False),
        sa.Column("verified_conditions_json", postgresql.JSONB(), nullable=False),
        sa.Column("affected_fields_json", postgresql.JSONB(), nullable=False),
        sa.Column("evidence_refs_json", postgresql.JSONB(), nullable=False),
        sa.Column("title", sa.String(length=500), nullable=False),
        sa.Column("summary", sa.String(length=2000), nullable=False),
        sa.Column(
            "created_at", sa.DateTime(timezone=True),
            server_default=sa.func.now(), nullable=False,
        ),
        sa.ForeignKeyConstraint(["operation_pk"], ["operations.id"], ondelete="RESTRICT"),
        sa.ForeignKeyConstraint(["scan_id"], ["scans.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id", name="pk_findings"),
    )
    op.create_index("ix_findings_scan_id", "findings", ["scan_id"])
    op.create_index("ix_findings_operation_id", "findings", ["operation_id"])
    op.create_index("ix_findings_module_id", "findings", ["module_id"])
    op.create_index("ix_findings_severity", "findings", ["severity"])

    op.create_table(
        "reports",
        sa.Column("id", sa.String(length=255), nullable=False),
        sa.Column("scan_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("status", report_status, nullable=False),
        sa.Column("ai_report_artifact_id", postgresql.UUID(as_uuid=True), nullable=True),
        sa.Column("pdf_artifact_id", postgresql.UUID(as_uuid=True), nullable=True),
        sa.Column("error_code", sa.String(length=80), nullable=True),
        sa.Column("error_message", sa.String(length=1000), nullable=True),
        sa.Column(
            "created_at", sa.DateTime(timezone=True),
            server_default=sa.func.now(), nullable=False,
        ),
        sa.Column("completed_at", sa.DateTime(timezone=True), nullable=True),
        sa.ForeignKeyConstraint(
            ["ai_report_artifact_id"], ["scan_artifacts.id"], ondelete="SET NULL"
        ),
        sa.ForeignKeyConstraint(
            ["pdf_artifact_id"], ["scan_artifacts.id"], ondelete="SET NULL"
        ),
        sa.ForeignKeyConstraint(["scan_id"], ["scans.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id", name="pk_reports"),
    )
    op.create_index("ix_reports_scan_id", "reports", ["scan_id"])
    op.create_index("ix_reports_status", "reports", ["status"])


def downgrade() -> None:
    op.drop_table("reports")
    op.drop_table("findings")
    op.drop_table("operations")
    op.drop_table("external_jobs")
    op.drop_table("scan_artifacts")
    op.drop_table("scan_steps")
    op.drop_table("scans")
