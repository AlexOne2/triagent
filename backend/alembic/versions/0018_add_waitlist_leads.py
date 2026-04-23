"""add waitlist leads

Revision ID: 0018_add_waitlist_leads
Revises: 0017_add_triage_persistence
Create Date: 2026-04-22 00:00:00.000000

"""

from alembic import op
import sqlalchemy as sa


revision = "0018_add_waitlist_leads"
down_revision = "0017_add_triage_persistence"
branch_labels = None
depends_on = None


def upgrade():
    op.create_table(
        "waitlist_leads",
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column("name", sa.String(length=255), nullable=True),
        sa.Column("work_email", sa.String(length=255), nullable=False),
        sa.Column("company", sa.String(length=255), nullable=True),
        sa.Column("role_title", sa.String(length=255), nullable=True),
        sa.Column("notes", sa.Text(), nullable=True),
        sa.Column("source", sa.String(length=64), nullable=False, server_default=sa.text("'landing_page'")),
        sa.Column("ip", sa.String(length=64), nullable=True),
        sa.Column("user_agent", sa.Text(), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.text("now()")),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.text("now()")),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("work_email", name="uq_waitlist_leads_work_email"),
    )
    op.create_index("ix_waitlist_leads_created_at", "waitlist_leads", ["created_at"], unique=False)
def downgrade():
    op.drop_index("ix_waitlist_leads_created_at", table_name="waitlist_leads")
    op.drop_table("waitlist_leads")
