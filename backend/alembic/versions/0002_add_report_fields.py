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
    bind = op.get_bind()
    inspector = sa.inspect(bind)
    existing_columns = {column["name"] for column in inspector.get_columns("reports")}

    if "sender" not in existing_columns:
        op.add_column("reports", sa.Column("sender", sa.String(length=320), nullable=True))
    if "reply_to" not in existing_columns:
        op.add_column("reports", sa.Column("reply_to", postgresql.JSONB(astext_type=sa.Text()), nullable=True))
    if "in_reply_to" not in existing_columns:
        op.add_column("reports", sa.Column("in_reply_to", sa.String(length=255), nullable=True))
    if "return_path" not in existing_columns:
        op.add_column("reports", sa.Column("return_path", sa.String(length=320), nullable=True))
    if "originating_ip" not in existing_columns:
        op.add_column("reports", sa.Column("originating_ip", sa.String(length=64), nullable=True))
    if "originating_rdns" not in existing_columns:
        op.add_column("reports", sa.Column("originating_rdns", sa.String(length=255), nullable=True))


def downgrade():
    bind = op.get_bind()
    inspector = sa.inspect(bind)
    existing_columns = {column["name"] for column in inspector.get_columns("reports")}

    if "originating_rdns" in existing_columns:
        op.drop_column("reports", "originating_rdns")
    if "originating_ip" in existing_columns:
        op.drop_column("reports", "originating_ip")
    if "return_path" in existing_columns:
        op.drop_column("reports", "return_path")
    if "in_reply_to" in existing_columns:
        op.drop_column("reports", "in_reply_to")
    if "reply_to" in existing_columns:
        op.drop_column("reports", "reply_to")
    if "sender" in existing_columns:
        op.drop_column("reports", "sender")
