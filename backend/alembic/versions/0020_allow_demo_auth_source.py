"""allow demo auth source

Revision ID: 0020_allow_demo_auth_source
Revises: 0019_add_demo_workspaces
Create Date: 2026-04-24 00:00:00.000001

"""

from alembic import op


revision = "0020_allow_demo_auth_source"
down_revision = "0019_add_demo_workspaces"
branch_labels = None
depends_on = None


def upgrade():
    op.drop_constraint("ck_users_auth_source", "users", type_="check")
    op.create_check_constraint(
        "ck_users_auth_source",
        "users",
        "auth_source IN ('LOCAL', 'LDAP', 'DEMO')",
    )


def downgrade():
    op.drop_constraint("ck_users_auth_source", "users", type_="check")
    op.create_check_constraint(
        "ck_users_auth_source",
        "users",
        "auth_source IN ('LOCAL', 'LDAP')",
    )
