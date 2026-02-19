"""add from display name

Revision ID: 0003_add_from_display_name
Revises: 0002_add_report_fields
Create Date: 2026-01-30 00:00:00.000000

"""
from alembic import op
import sqlalchemy as sa

revision = "0003_add_from_display_name"
down_revision = "0002_add_report_fields"
branch_labels = None
depends_on = None


def upgrade():
    op.add_column("reports", sa.Column("from_display_name", sa.String(length=255), nullable=True))


def downgrade():
    op.drop_column("reports", "from_display_name")
