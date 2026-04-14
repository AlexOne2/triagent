"""add persisted url analysis to reports

Revision ID: 0015_add_report_url_analysis
Revises: 0014_add_ldap_user_fields
Create Date: 2026-04-14 00:00:00.000000

"""

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql


revision = "0015_add_report_url_analysis"
down_revision = "0014_add_ldap_user_fields"
branch_labels = None
depends_on = None


def upgrade():
    op.add_column("reports", sa.Column("url_analysis_json", postgresql.JSONB(astext_type=sa.Text()), nullable=True))


def downgrade():
    op.drop_column("reports", "url_analysis_json")
