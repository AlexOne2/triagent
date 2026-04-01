"""add RBAC auth foundation

Revision ID: 0008_rbac_base
Revises: 0007_report_resolution
Create Date: 2026-02-19 00:00:00.000000

"""

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql


revision = "0008_rbac_base"
down_revision = "0007_report_resolution"
branch_labels = None
depends_on = None

PERMISSIONS = (
    ("reports.read", "Read reports"),
    ("reports.ingest", "Ingest reports"),
    ("reports.resolve", "Resolve reports"),
    ("reports.reopen", "Reopen reports"),
    ("reports.admin_override", "Admin patch override"),
    ("resolutions.read", "Read resolution history"),
    ("dashboard.read", "Read dashboard"),
    ("admin.users.read", "Read users"),
    ("admin.users.write", "Manage users"),
    ("admin.roles.read", "Read roles and permissions"),
    ("admin.api_keys.manage", "Manage API keys"),
)

ROLES = (
    ("ADMIN", "Administrator", "Full platform administration access"),
    ("ANALYST", "Analyst", "Can ingest and resolve reports"),
    ("REVIEWER", "Reviewer", "Can resolve and reopen reports"),
    ("READ_ONLY", "Read Only", "Read-only report and dashboard access"),
    ("INGESTOR", "Ingestor", "Service role for ingestion"),
)

ROLE_PERMISSIONS = {
    "ADMIN": [perm for perm, _ in PERMISSIONS],
    "ANALYST": [
        "reports.read",
        "reports.ingest",
        "reports.resolve",
        "resolutions.read",
        "dashboard.read",
    ],
    "REVIEWER": [
        "reports.read",
        "reports.resolve",
        "reports.reopen",
        "resolutions.read",
        "dashboard.read",
    ],
    "READ_ONLY": [
        "reports.read",
        "resolutions.read",
        "dashboard.read",
    ],
    "INGESTOR": [
        "reports.ingest",
    ],
}


def upgrade():
    op.create_table(
        "users",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("username", sa.String(length=100), nullable=False),
        sa.Column("email", sa.String(length=255), nullable=True),
        sa.Column("password_hash", sa.String(length=255), nullable=False),
        sa.Column("is_active", sa.Boolean(), nullable=False, server_default=sa.text("true")),
        sa.Column("must_change_password", sa.Boolean(), nullable=False, server_default=sa.text("false")),
        sa.Column("failed_login_attempts", sa.Integer(), nullable=False, server_default=sa.text("0")),
        sa.Column("locked_until", sa.DateTime(timezone=True), nullable=True),
        sa.Column("last_login_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.text("now()")),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.text("now()")),
        sa.UniqueConstraint("username", name="uq_users_username"),
        sa.UniqueConstraint("email", name="uq_users_email"),
    )
    op.create_index("ix_users_username", "users", ["username"], unique=False)
    op.create_index("ix_users_email", "users", ["email"], unique=False)

    op.create_table(
        "roles",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("key", sa.String(length=64), nullable=False),
        sa.Column("name", sa.String(length=128), nullable=False),
        sa.Column("description", sa.Text(), nullable=True),
        sa.Column("is_system", sa.Boolean(), nullable=False, server_default=sa.text("true")),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.text("now()")),
        sa.UniqueConstraint("key", name="uq_roles_key"),
    )
    op.create_index("ix_roles_key", "roles", ["key"], unique=False)

    op.create_table(
        "permissions",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("key", sa.String(length=128), nullable=False),
        sa.Column("description", sa.Text(), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.text("now()")),
        sa.UniqueConstraint("key", name="uq_permissions_key"),
    )
    op.create_index("ix_permissions_key", "permissions", ["key"], unique=False)

    op.create_table(
        "role_permissions",
        sa.Column("role_id", sa.Integer(), sa.ForeignKey("roles.id", ondelete="CASCADE"), nullable=False),
        sa.Column("permission_id", sa.Integer(), sa.ForeignKey("permissions.id", ondelete="CASCADE"), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.text("now()")),
        sa.PrimaryKeyConstraint("role_id", "permission_id"),
        sa.UniqueConstraint("role_id", "permission_id", name="uq_role_permissions_role_permission"),
    )

    op.create_table(
        "user_roles",
        sa.Column("user_id", sa.Integer(), sa.ForeignKey("users.id", ondelete="CASCADE"), nullable=False),
        sa.Column("role_id", sa.Integer(), sa.ForeignKey("roles.id", ondelete="CASCADE"), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.text("now()")),
        sa.PrimaryKeyConstraint("user_id", "role_id"),
        sa.UniqueConstraint("user_id", "role_id", name="uq_user_roles_user_role"),
    )

    op.create_table(
        "auth_sessions",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("user_id", sa.Integer(), sa.ForeignKey("users.id", ondelete="CASCADE"), nullable=False),
        sa.Column("token_hash", sa.String(length=64), nullable=False),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("revoked_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.text("now()")),
        sa.Column("last_seen_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("created_ip", sa.String(length=64), nullable=True),
        sa.Column("user_agent", sa.String(length=512), nullable=True),
        sa.UniqueConstraint("token_hash", name="uq_auth_sessions_token_hash"),
    )
    op.create_index("ix_auth_sessions_token_hash", "auth_sessions", ["token_hash"], unique=False)
    op.create_index("ix_auth_sessions_user_id_expires_at", "auth_sessions", ["user_id", "expires_at"], unique=False)

    op.create_table(
        "api_keys",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("name", sa.String(length=128), nullable=False),
        sa.Column("key_prefix", sa.String(length=16), nullable=False),
        sa.Column("key_hash", sa.String(length=64), nullable=False),
        sa.Column("role_id", sa.Integer(), sa.ForeignKey("roles.id", ondelete="RESTRICT"), nullable=False),
        sa.Column("created_by_user_id", sa.Integer(), sa.ForeignKey("users.id", ondelete="SET NULL"), nullable=True),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("revoked_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("last_used_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.text("now()")),
        sa.UniqueConstraint("key_hash", name="uq_api_keys_key_hash"),
    )
    op.create_index("ix_api_keys_key_hash", "api_keys", ["key_hash"], unique=False)
    op.create_index("ix_api_keys_role_revoked_expires", "api_keys", ["role_id", "revoked_at", "expires_at"], unique=False)

    op.create_table(
        "security_audit_events",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("actor_user_id", sa.Integer(), sa.ForeignKey("users.id", ondelete="SET NULL"), nullable=True),
        sa.Column("actor_api_key_id", sa.Integer(), sa.ForeignKey("api_keys.id", ondelete="SET NULL"), nullable=True),
        sa.Column("action", sa.String(length=64), nullable=False),
        sa.Column("target_type", sa.String(length=64), nullable=True),
        sa.Column("target_id", sa.String(length=128), nullable=True),
        sa.Column("outcome", sa.String(length=32), nullable=False, server_default="SUCCESS"),
        sa.Column("metadata_json", postgresql.JSONB(astext_type=sa.Text()), nullable=True),
        sa.Column("ip", sa.String(length=64), nullable=True),
        sa.Column("user_agent", sa.Text(), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.text("now()")),
    )
    op.create_index("ix_security_audit_events_created_at", "security_audit_events", ["created_at"], unique=False)
    op.create_index("ix_security_audit_events_action_created_at", "security_audit_events", ["action", "created_at"], unique=False)
    op.create_index("ix_security_audit_events_actor_user_id_created_at", "security_audit_events", ["actor_user_id", "created_at"], unique=False)

    permission_table = sa.table(
        "permissions",
        sa.column("key", sa.String),
        sa.column("description", sa.Text),
    )
    op.bulk_insert(
        permission_table,
        [{"key": key, "description": description} for key, description in PERMISSIONS],
    )

    role_table = sa.table(
        "roles",
        sa.column("key", sa.String),
        sa.column("name", sa.String),
        sa.column("description", sa.Text),
        sa.column("is_system", sa.Boolean),
    )
    op.bulk_insert(
        role_table,
        [
            {"key": key, "name": name, "description": description, "is_system": True}
            for key, name, description in ROLES
        ],
    )

    bind = op.get_bind()
    permission_rows = bind.execute(sa.text("SELECT id, key FROM permissions")).mappings().all()
    role_rows = bind.execute(sa.text("SELECT id, key FROM roles")).mappings().all()

    permission_ids = {row["key"]: row["id"] for row in permission_rows}
    role_ids = {row["key"]: row["id"] for row in role_rows}

    role_permission_table = sa.table(
        "role_permissions",
        sa.column("role_id", sa.Integer),
        sa.column("permission_id", sa.Integer),
    )

    inserts = []
    for role_key, permission_keys in ROLE_PERMISSIONS.items():
        role_id = role_ids.get(role_key)
        if role_id is None:
            continue
        for permission_key in permission_keys:
            permission_id = permission_ids.get(permission_key)
            if permission_id is None:
                continue
            inserts.append({"role_id": role_id, "permission_id": permission_id})

    if inserts:
        op.bulk_insert(role_permission_table, inserts)


def downgrade():
    op.drop_index("ix_security_audit_events_actor_user_id_created_at", table_name="security_audit_events")
    op.drop_index("ix_security_audit_events_action_created_at", table_name="security_audit_events")
    op.drop_index("ix_security_audit_events_created_at", table_name="security_audit_events")
    op.drop_table("security_audit_events")

    op.drop_index("ix_api_keys_role_revoked_expires", table_name="api_keys")
    op.drop_index("ix_api_keys_key_hash", table_name="api_keys")
    op.drop_table("api_keys")

    op.drop_index("ix_auth_sessions_user_id_expires_at", table_name="auth_sessions")
    op.drop_index("ix_auth_sessions_token_hash", table_name="auth_sessions")
    op.drop_table("auth_sessions")

    op.drop_table("user_roles")
    op.drop_table("role_permissions")

    op.drop_index("ix_permissions_key", table_name="permissions")
    op.drop_table("permissions")

    op.drop_index("ix_roles_key", table_name="roles")
    op.drop_table("roles")

    op.drop_index("ix_users_email", table_name="users")
    op.drop_index("ix_users_username", table_name="users")
    op.drop_table("users")
