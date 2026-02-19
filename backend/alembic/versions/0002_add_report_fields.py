"""add report fields

Revision ID: 0002_add_report_fields
Revises: 0001_create_tables
Create Date: 2026-01-30 00:00:00.000000

"""
from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

revision = "0002_add_report_fields"
down_revision = "0001_create_tables"
branch_labels = None
depends_on = None


def upgrade():
    op.add_column("reports", sa.Column("sender", sa.String(length=320), nullable=True))
    op.add_column("reports", sa.Column("reply_to", postgresql.JSONB(astext_type=sa.Text()), nullable=True))
    op.add_column("reports", sa.Column("in_reply_to", sa.String(length=255), nullable=True))
    op.add_column("reports", sa.Column("return_path", sa.String(length=320), nullable=True))
    op.add_column("reports", sa.Column("originating_ip", sa.String(length=64), nullable=True))
    op.add_column("reports", sa.Column("originating_rdns", sa.String(length=255), nullable=True))


def downgrade():
    op.drop_column("reports", "originating_rdns")
    op.drop_column("reports", "originating_ip")
    op.drop_column("reports", "return_path")
    op.drop_column("reports", "in_reply_to")
    op.drop_column("reports", "reply_to")
    op.drop_column("reports", "sender")
