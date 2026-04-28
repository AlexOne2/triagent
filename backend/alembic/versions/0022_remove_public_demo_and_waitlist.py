"""remove public demo and waitlist storage

Revision ID: 0022_remove_public_demo
Revises: 0021_make_demo_role_read_only
Create Date: 2026-04-28 00:00:00.000000

"""

from alembic import op
import sqlalchemy as sa


revision = "0022_remove_public_demo"
down_revision = "0021_make_demo_role_read_only"
branch_labels = None
depends_on = None


DEMO_ROLE_KEY = "DEMO"
DEMO_ROLE_NAME = "Demo Viewer"
DEMO_ROLE_DESCRIPTION = "Shared read-only workspace for public demo sessions."
DEMO_ROLE_PERMISSIONS = (
    "reports.read",
    "resolutions.read",
    "dashboard.read",
)


def _demo_users_cte() -> str:
    return """
        SELECT id FROM users
        WHERE auth_source = 'DEMO'
           OR username = 'demo_public'
           OR username LIKE 'demo\\_%' ESCAPE '\\'
    """


def _retire_demo_data() -> None:
    bind = op.get_bind()
    bind.execute(
        sa.text(
            """
            WITH demo_reports AS (
                SELECT id FROM reports WHERE demo_user_id IS NOT NULL
            )
            DELETE FROM attachments
            WHERE report_id IN (SELECT id FROM demo_reports)
            """
        )
    )
    bind.execute(
        sa.text(
            """
            WITH demo_reports AS (
                SELECT id FROM reports WHERE demo_user_id IS NOT NULL
            )
            DELETE FROM report_features
            WHERE report_id IN (SELECT id FROM demo_reports)
            """
        )
    )
    bind.execute(sa.text("DELETE FROM reports WHERE demo_user_id IS NOT NULL"))
    bind.execute(sa.text("DELETE FROM campaigns WHERE NOT EXISTS (SELECT 1 FROM reports WHERE reports.campaign_id = campaigns.id)"))

    bind.execute(sa.text(f"DELETE FROM auth_sessions WHERE user_id IN ({_demo_users_cte()})"))
    bind.execute(sa.text(f"DELETE FROM user_roles WHERE user_id IN ({_demo_users_cte()})"))
    bind.execute(
        sa.text(
            f"""
            UPDATE users
            SET auth_source = 'LOCAL',
                is_active = false,
                must_change_password = true,
                locked_until = now()
            WHERE id IN ({_demo_users_cte()})
            """
        )
    )
    bind.execute(
        sa.text("DELETE FROM role_permissions WHERE role_id = (SELECT id FROM roles WHERE key = :key)"),
        {"key": DEMO_ROLE_KEY},
    )
    bind.execute(sa.text("DELETE FROM user_roles WHERE role_id = (SELECT id FROM roles WHERE key = :key)"), {"key": DEMO_ROLE_KEY})
    bind.execute(sa.text("DELETE FROM roles WHERE key = :key"), {"key": DEMO_ROLE_KEY})


def _create_demo_role() -> None:
    bind = op.get_bind()
    bind.execute(
        sa.text(
            """
            INSERT INTO roles (key, name, description, is_system)
            VALUES (:key, :name, :description, true)
            ON CONFLICT (key) DO NOTHING
            """
        ),
        {"key": DEMO_ROLE_KEY, "name": DEMO_ROLE_NAME, "description": DEMO_ROLE_DESCRIPTION},
    )
    role_row = bind.execute(sa.text("SELECT id FROM roles WHERE key = :key"), {"key": DEMO_ROLE_KEY}).mappings().first()
    permission_rows = bind.execute(
        sa.text("SELECT id FROM permissions WHERE key = ANY(:permission_keys)"),
        {"permission_keys": list(DEMO_ROLE_PERMISSIONS)},
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


def upgrade():
    _retire_demo_data()

    op.drop_constraint("fk_reports_demo_user_id_users", "reports", type_="foreignkey")
    op.drop_index("ix_reports_demo_user_id", table_name="reports")
    op.drop_column("reports", "demo_user_id")

    op.drop_constraint("ck_users_auth_source", "users", type_="check")
    op.create_check_constraint(
        "ck_users_auth_source",
        "users",
        "auth_source IN ('LOCAL', 'LDAP')",
    )

    op.drop_index("ix_waitlist_leads_created_at", table_name="waitlist_leads")
    op.drop_table("waitlist_leads")


def downgrade():
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

    _create_demo_role()
