"""add persisted triage assessment fields to reports

Revision ID: 0017_add_triage_persistence
Revises: 0016_original_message_artifact
Create Date: 2026-04-20 00:00:00.000000

"""

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql


revision = "0017_add_triage_persistence"
down_revision = "0016_original_message_artifact"
branch_labels = None
depends_on = None


def upgrade():
    op.add_column("reports", sa.Column("triage_bucket", sa.String(length=32), nullable=True))
    op.add_column("reports", sa.Column("triage_threat_score", sa.Integer(), nullable=True))
    op.add_column("reports", sa.Column("triage_bulk_benign_score", sa.Integer(), nullable=True))
    op.add_column("reports", sa.Column("triage_investigation_priority_score", sa.Integer(), nullable=True))
    op.add_column("reports", sa.Column("triage_automation_confidence_score", sa.Integer(), nullable=True))
    op.add_column("reports", sa.Column("triage_analyst_worthy", sa.Boolean(), nullable=True))
    op.add_column("reports", sa.Column("triage_assessment_version", sa.String(length=16), nullable=True))
    op.add_column("reports", sa.Column("triage_assessment_json", postgresql.JSONB(astext_type=sa.Text()), nullable=True))
    op.create_index("ix_reports_triage_bucket", "reports", ["triage_bucket"], unique=False)
    op.create_index(
        "ix_reports_triage_investigation_priority_score",
        "reports",
        ["triage_investigation_priority_score"],
        unique=False,
    )


def downgrade():
    op.drop_index("ix_reports_triage_investigation_priority_score", table_name="reports")
    op.drop_index("ix_reports_triage_bucket", table_name="reports")
    op.drop_column("reports", "triage_assessment_json")
    op.drop_column("reports", "triage_assessment_version")
    op.drop_column("reports", "triage_analyst_worthy")
    op.drop_column("reports", "triage_automation_confidence_score")
    op.drop_column("reports", "triage_investigation_priority_score")
    op.drop_column("reports", "triage_bulk_benign_score")
    op.drop_column("reports", "triage_threat_score")
    op.drop_column("reports", "triage_bucket")
