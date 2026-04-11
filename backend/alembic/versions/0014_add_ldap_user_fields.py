"""add ldap user fields

Revision ID: 0014_add_ldap_user_fields
Revises: 0013_campaign_permissions
Create Date: 2026-04-11 00:00:00.000000

"""

from alembic import op
import sqlalchemy as sa


revision = "0014_add_ldap_user_fields"
down_revision = "0013_campaign_permissions"
branch_labels = None
depends_on = None


def upgrade():
    op.add_column("users", sa.Column("auth_source", sa.String(length=32), nullable=False, server_default="LOCAL"))
    op.add_column("users", sa.Column("external_dn", sa.String(length=1024), nullable=True))
    op.create_check_constraint(
        "ck_users_auth_source",
        "users",
        "auth_source IN ('LOCAL', 'LDAP')",
    )
    op.create_index("ix_users_auth_source", "users", ["auth_source"], unique=False)
    op.create_index("ix_users_external_dn", "users", ["external_dn"], unique=False)


def downgrade():
    op.drop_index("ix_users_external_dn", table_name="users")
    op.drop_index("ix_users_auth_source", table_name="users")
    op.drop_constraint("ck_users_auth_source", "users", type_="check")
    op.drop_column("users", "external_dn")
    op.drop_column("users", "auth_source")
