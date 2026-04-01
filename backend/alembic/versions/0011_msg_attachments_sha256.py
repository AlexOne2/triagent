"""add attachment sha256 for msg ingestion

Revision ID: 0011_msg_attachments_sha256
Revises: 0010_audit_trail_v1
Create Date: 2026-02-20 00:00:00.000000

"""

from alembic import op
import sqlalchemy as sa


revision = "0011_msg_attachments_sha256"
down_revision = "0010_audit_trail_v1"
branch_labels = None
depends_on = None


def upgrade():
    op.add_column("attachments", sa.Column("sha256", sa.String(length=64), nullable=True))
    op.create_check_constraint(
        "ck_attachments_sha256_format",
        "attachments",
        "sha256 IS NULL OR sha256 ~ '^[0-9a-f]{64}$'",
    )
    op.create_index(
        "ix_attachments_report_id_created_at",
        "attachments",
        ["report_id", "created_at"],
        unique=False,
    )


def downgrade():
    op.drop_index("ix_attachments_report_id_created_at", table_name="attachments")
    op.drop_constraint("ck_attachments_sha256_format", "attachments", type_="check")
    op.drop_column("attachments", "sha256")
