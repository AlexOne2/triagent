"""make demo role read only

Revision ID: 0021_make_demo_role_read_only
Revises: 0020_allow_demo_auth_source
Create Date: 2026-04-24 00:20:00.000000

"""

from alembic import op
import sqlalchemy as sa


revision = "0021_make_demo_role_read_only"
down_revision = "0020_allow_demo_auth_source"
branch_labels = None
depends_on = None


ROLE_KEY = "DEMO"
ROLE_NAME = "Demo Viewer"
ROLE_DESCRIPTION = "Shared read-only workspace for public demo sessions."
ROLE_PERMISSIONS = (
    "reports.read",
    "resolutions.read",
    "dashboard.read",
)
PREVIOUS_ROLE_PERMISSIONS = (
    "reports.read",
    "reports.resolve",
    "reports.reopen",
    "resolutions.read",
    "dashboard.read",
)


def _apply_permissions(permission_keys: tuple[str, ...]) -> None:
    bind = op.get_bind()
    bind.execute(
        sa.text("UPDATE roles SET name = :name, description = :description WHERE key = :key"),
        {"key": ROLE_KEY, "name": ROLE_NAME, "description": ROLE_DESCRIPTION},
    )
    bind.execute(sa.text("DELETE FROM role_permissions WHERE role_id = (SELECT id FROM roles WHERE key = :key)"), {"key": ROLE_KEY})
    permission_rows = bind.execute(
        sa.text("SELECT id FROM permissions WHERE key = ANY(:permission_keys)"),
        {"permission_keys": list(permission_keys)},
    ).mappings().all()
    role_row = bind.execute(sa.text("SELECT id FROM roles WHERE key = :key"), {"key": ROLE_KEY}).mappings().first()
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
    _apply_permissions(ROLE_PERMISSIONS)


def downgrade():
    _apply_permissions(PREVIOUS_ROLE_PERMISSIONS)

