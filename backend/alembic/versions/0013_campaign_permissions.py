"""add campaign permissions and role mappings

Revision ID: 0013_campaign_permissions
Revises: 0012_campaign_core
Create Date: 2026-03-07 00:00:00.000000

"""

from alembic import op
import sqlalchemy as sa


revision = "0013_campaign_permissions"
down_revision = "0012_campaign_core"
branch_labels = None
depends_on = None


PERMISSIONS = (
    ("campaigns.read", "Read campaign clusters"),
    ("campaigns.write", "Manage campaign clusters"),
    ("campaigns.run", "Run campaign clustering jobs"),
)

ROLE_PERMISSION_MAP = {
    "ADMIN": ("campaigns.read", "campaigns.write", "campaigns.run"),
    "ANALYST": ("campaigns.read", "campaigns.write", "campaigns.run"),
    "REVIEWER": ("campaigns.read", "campaigns.write"),
    "READ_ONLY": ("campaigns.read",),
}


def upgrade():
    bind = op.get_bind()

    for key, description in PERMISSIONS:
        bind.execute(
            sa.text(
                """
                INSERT INTO permissions (key, description)
                VALUES (:key, :description)
                ON CONFLICT (key) DO NOTHING
                """
            ),
            {"key": key, "description": description},
        )

    for role_key, perm_keys in ROLE_PERMISSION_MAP.items():
        for perm_key in perm_keys:
            bind.execute(
                sa.text(
                    """
                    INSERT INTO role_permissions (role_id, permission_id)
                    SELECT r.id, p.id
                    FROM roles r
                    JOIN permissions p ON p.key = :perm_key
                    WHERE r.key = :role_key
                    ON CONFLICT DO NOTHING
                    """
                ),
                {"role_key": role_key, "perm_key": perm_key},
            )


def downgrade():
    bind = op.get_bind()

    bind.execute(
        sa.text(
            """
            DELETE FROM role_permissions
            WHERE permission_id IN (
                SELECT id FROM permissions
                WHERE key IN ('campaigns.read', 'campaigns.write', 'campaigns.run')
            )
            """
        )
    )
    bind.execute(
        sa.text(
            """
            DELETE FROM permissions
            WHERE key IN ('campaigns.read', 'campaigns.write', 'campaigns.run')
            """
        )
    )
