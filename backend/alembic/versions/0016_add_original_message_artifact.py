"""add original message artifact metadata to reports

Revision ID: 0016_original_message_artifact
Revises: 0015_add_report_url_analysis
Create Date: 2026-04-14 00:00:00.000000

"""

from alembic import op
import sqlalchemy as sa


revision = "0016_original_message_artifact"
down_revision = "0015_add_report_url_analysis"
branch_labels = None
depends_on = None


def upgrade():
    op.add_column("reports", sa.Column("original_filename", sa.String(length=255), nullable=True))
    op.add_column("reports", sa.Column("original_content_type", sa.String(length=255), nullable=True))
    op.add_column("reports", sa.Column("original_size_bytes", sa.Integer(), nullable=True))
    op.add_column("reports", sa.Column("original_sha256", sa.String(length=64), nullable=True))
    op.add_column("reports", sa.Column("original_s3_key", sa.String(length=512), nullable=True))


def downgrade():
    op.drop_column("reports", "original_s3_key")
    op.drop_column("reports", "original_sha256")
    op.drop_column("reports", "original_size_bytes")
    op.drop_column("reports", "original_content_type")
    op.drop_column("reports", "original_filename")
