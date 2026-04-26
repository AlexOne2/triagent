"""add demo workspace support

Revision ID: 0019_add_demo_workspaces
Revises: 0018_add_waitlist_leads
Create Date: 2026-04-24 00:00:00.000000

"""

from alembic import op
import sqlalchemy as sa


revision = "0019_add_demo_workspaces"
down_revision = "0018_add_waitlist_leads"
branch_labels = None
depends_on = None


ROLE_NAME = "Demo User"
ROLE_DESCRIPTION = "Restricted temporary workspace for public demo sessions."
ROLE_KEY = "DEMO"
ROLE_PERMISSIONS = (
    "reports.read",
    "reports.resolve",
    "reports.reopen",
    "resolutions.read",
    "dashboard.read",
)


def upgrade():
    op.drop_constraint("ck_users_auth_source", "users", type_="check")
    op.create_check_constraint(
        "ck_users_auth_source",
        "users",
        "auth_source IN ('LOCAL', 'LDAP', 'DEMO')",
    )
    op.add_column("reports", sa.Column("demo_user_id", sa.Integer(), nullable=True))
    op.create_index("ix_reports_demo_user_id", "reports", ["demo_user_id"], unique=False)
    op.create_foreign_key(
        "fk_reports_demo_user_id_users",
        "reports",
        "users",
        ["demo_user_id"],
        ["id"],
        ondelete="CASCADE",
    )

    bind = op.get_bind()
    bind.execute(
        sa.text(
            """
            INSERT INTO roles (key, name, description, is_system)
            VALUES (:key, :name, :description, true)
            ON CONFLICT (key) DO NOTHING
            """
        ),
        {"key": ROLE_KEY, "name": ROLE_NAME, "description": ROLE_DESCRIPTION},
    )
    role_row = bind.execute(sa.text("SELECT id FROM roles WHERE key = :key"), {"key": ROLE_KEY}).mappings().first()
    permission_rows = bind.execute(
        sa.text("SELECT id, key FROM permissions WHERE key = ANY(:permission_keys)"),
        {"permission_keys": list(ROLE_PERMISSIONS)},
    ).mappings().all()
    if role_row and permission_rows:
        role_permission_table = sa.table(
            "role_permissions",
            sa.column("role_id", sa.Integer),
            sa.column("permission_id", sa.Integer),
        )
        op.bulk_insert(
            role_permission_table,
            [{"role_id": role_row["id"], "permission_id": row["id"]} for row in permission_rows],
        )


def downgrade():
    bind = op.get_bind()
    bind.execute(sa.text("DELETE FROM role_permissions WHERE role_id = (SELECT id FROM roles WHERE key = :key)"), {"key": ROLE_KEY})
    bind.execute(sa.text("DELETE FROM roles WHERE key = :key"), {"key": ROLE_KEY})
    op.drop_constraint("fk_reports_demo_user_id_users", "reports", type_="foreignkey")
    op.drop_index("ix_reports_demo_user_id", table_name="reports")
    op.drop_column("reports", "demo_user_id")
    op.drop_constraint("ck_users_auth_source", "users", type_="check")
    op.create_check_constraint(
        "ck_users_auth_source",
        "users",
        "auth_source IN ('LOCAL', 'LDAP')",
    )
