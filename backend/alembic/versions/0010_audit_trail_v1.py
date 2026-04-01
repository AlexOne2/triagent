"""audit trail v1 tamper-evident chain

Revision ID: 0010_audit_trail_v1
Revises: 0009_resolution_actor
Create Date: 2026-02-20 00:00:00.000000

"""

from __future__ import annotations

import hashlib
import json
import uuid
from datetime import timezone
from typing import Any

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql


revision = "0010_audit_trail_v1"
down_revision = "0009_resolution_actor"
branch_labels = None
depends_on = None


AUDIT_PERMISSIONS = (
    ("audit.read", "Read security audit events"),
    ("audit.export", "Export security audit events"),
    ("audit.verify", "Verify security audit chain integrity"),
    ("audit.archive.manage", "Run audit archive and prune operations"),
)


def _canonical_event_payload(row: dict[str, Any]) -> str:
    created_at = row.get("created_at")
    created_at_iso = None
    if created_at is not None:
        if created_at.tzinfo is None:
            created_at = created_at.replace(tzinfo=timezone.utc)
        created_at_iso = created_at.astimezone(timezone.utc).isoformat()

    payload = {
        "event_uuid": row["event_uuid"],
        "actor_type": row["actor_type"],
        "actor_user_id": row.get("actor_user_id"),
        "actor_api_key_id": row.get("actor_api_key_id"),
        "action": row["action"],
        "target_type": row.get("target_type"),
        "target_id": row.get("target_id"),
        "outcome": row["outcome"],
        "request_id": row.get("request_id"),
        "correlation_id": row.get("correlation_id"),
        "schema_version": int(row.get("schema_version") or 1),
        "metadata_json": row.get("metadata_json"),
        "ip": row.get("ip"),
        "user_agent": row.get("user_agent"),
        "created_at": created_at_iso,
    }
    return json.dumps(payload, sort_keys=True, separators=(",", ":"), default=str)


def upgrade():
    op.execute("CREATE TYPE audit_actor_type AS ENUM ('USER', 'API_KEY', 'SYSTEM', 'LEGACY')")

    op.add_column("security_audit_events", sa.Column("event_uuid", sa.String(length=36), nullable=True))
    op.add_column(
        "security_audit_events",
        sa.Column(
            "actor_type",
            sa.Enum("USER", "API_KEY", "SYSTEM", "LEGACY", name="audit_actor_type"),
            nullable=True,
        ),
    )
    op.add_column("security_audit_events", sa.Column("request_id", sa.String(length=128), nullable=True))
    op.add_column("security_audit_events", sa.Column("correlation_id", sa.String(length=128), nullable=True))
    op.add_column(
        "security_audit_events",
        sa.Column("schema_version", sa.Integer(), nullable=False, server_default=sa.text("1")),
    )
    op.add_column("security_audit_events", sa.Column("prev_hash", sa.String(length=64), nullable=True))
    op.add_column("security_audit_events", sa.Column("event_hash", sa.String(length=64), nullable=True))

    bind = op.get_bind()

    rows = bind.execute(
        sa.text(
            """
            SELECT id, actor_user_id, actor_api_key_id, action, target_type, target_id, outcome,
                   metadata_json, ip, user_agent, created_at, request_id, correlation_id, schema_version
            FROM security_audit_events
            ORDER BY created_at ASC, id ASC
            """
        )
    ).mappings().all()

    previous_hash = "0" * 64
    for row in rows:
        if row["actor_user_id"] is not None:
            actor_type = "USER"
        elif row["actor_api_key_id"] is not None:
            actor_type = "API_KEY"
        elif str(row.get("action") or "").startswith("AUTH_"):
            actor_type = "LEGACY"
        else:
            actor_type = "SYSTEM"

        event_uuid = str(uuid.uuid4())
        record = {
            **row,
            "event_uuid": event_uuid,
            "actor_type": actor_type,
        }
        canonical = _canonical_event_payload(record)
        event_hash = hashlib.sha256(f"{canonical}|{previous_hash}".encode("utf-8")).hexdigest()
        bind.execute(
            sa.text(
                """
                UPDATE security_audit_events
                SET event_uuid = :event_uuid,
                    actor_type = :actor_type,
                    prev_hash = :prev_hash,
                    event_hash = :event_hash
                WHERE id = :event_id
                """
            ),
            {
                "event_uuid": event_uuid,
                "actor_type": actor_type,
                "prev_hash": previous_hash,
                "event_hash": event_hash,
                "event_id": row["id"],
            },
        )
        previous_hash = event_hash

    op.alter_column("security_audit_events", "event_uuid", nullable=False)
    op.alter_column("security_audit_events", "actor_type", nullable=False)
    op.alter_column("security_audit_events", "prev_hash", nullable=False)
    op.alter_column("security_audit_events", "event_hash", nullable=False)

    op.create_index("ix_security_audit_events_event_uuid", "security_audit_events", ["event_uuid"], unique=True)
    op.create_index("ix_security_audit_events_event_hash", "security_audit_events", ["event_hash"], unique=False)
    op.create_index("ix_security_audit_events_created_at_id", "security_audit_events", ["created_at", "id"], unique=False)
    op.create_index(
        "ix_security_audit_events_target_type_target_id_created_at",
        "security_audit_events",
        ["target_type", "target_id", "created_at"],
        unique=False,
    )
    op.create_index("ix_security_audit_events_request_id", "security_audit_events", ["request_id"], unique=False)

    op.create_table(
        "audit_chain_state",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("last_event_id", sa.Integer(), sa.ForeignKey("security_audit_events.id", ondelete="SET NULL"), nullable=True),
        sa.Column("last_hash", sa.String(length=64), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.text("now()")),
    )

    last_row = bind.execute(
        sa.text("SELECT id, event_hash FROM security_audit_events ORDER BY created_at DESC, id DESC LIMIT 1")
    ).mappings().first()
    bind.execute(
        sa.text(
            """
            INSERT INTO audit_chain_state (id, last_event_id, last_hash)
            VALUES (1, :last_event_id, :last_hash)
            """
        ),
        {
            "last_event_id": last_row["id"] if last_row else None,
            "last_hash": last_row["event_hash"] if last_row else "0" * 64,
        },
    )

    op.create_table(
        "audit_exports",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("range_start", sa.DateTime(timezone=True), nullable=False),
        sa.Column("range_end", sa.DateTime(timezone=True), nullable=False),
        sa.Column("event_count", sa.Integer(), nullable=False),
        sa.Column("root_hash", sa.String(length=64), nullable=False),
        sa.Column("manifest_json", postgresql.JSONB(astext_type=sa.Text()), nullable=False),
        sa.Column("storage_uri", sa.Text(), nullable=False),
        sa.Column("created_by", sa.String(length=255), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.text("now()")),
    )

    op.create_index("ix_audit_exports_created_at", "audit_exports", ["created_at"], unique=False)
    op.create_index("ix_audit_exports_range_start_range_end", "audit_exports", ["range_start", "range_end"], unique=False)

    op.execute(
        """
        CREATE OR REPLACE FUNCTION enforce_security_audit_immutability()
        RETURNS trigger AS $$
        BEGIN
          IF TG_OP = 'UPDATE' THEN
            RAISE EXCEPTION 'security_audit_events are immutable';
          ELSIF TG_OP = 'DELETE' THEN
            IF current_setting('app.audit_prune', true) IS DISTINCT FROM 'on' THEN
              RAISE EXCEPTION 'security_audit_events delete is restricted';
            END IF;
          END IF;
          RETURN OLD;
        END;
        $$ LANGUAGE plpgsql;
        """
    )
    op.execute(
        """
        CREATE TRIGGER trg_security_audit_events_immutable
        BEFORE UPDATE OR DELETE ON security_audit_events
        FOR EACH ROW EXECUTE FUNCTION enforce_security_audit_immutability();
        """
    )

    for key, description in AUDIT_PERMISSIONS:
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

    bind.execute(
        sa.text(
            """
            INSERT INTO role_permissions (role_id, permission_id)
            SELECT r.id, p.id
            FROM roles r
            JOIN permissions p ON p.key IN ('audit.read', 'audit.export', 'audit.verify', 'audit.archive.manage')
            WHERE r.key = 'ADMIN'
            ON CONFLICT DO NOTHING
            """
        )
    )


def downgrade():
    op.execute("DROP TRIGGER IF EXISTS trg_security_audit_events_immutable ON security_audit_events")
    op.execute("DROP FUNCTION IF EXISTS enforce_security_audit_immutability")

    op.drop_index("ix_audit_exports_range_start_range_end", table_name="audit_exports")
    op.drop_index("ix_audit_exports_created_at", table_name="audit_exports")
    op.drop_table("audit_exports")

    op.drop_table("audit_chain_state")

    op.drop_index("ix_security_audit_events_request_id", table_name="security_audit_events")
    op.drop_index("ix_security_audit_events_target_type_target_id_created_at", table_name="security_audit_events")
    op.drop_index("ix_security_audit_events_created_at_id", table_name="security_audit_events")
    op.drop_index("ix_security_audit_events_event_hash", table_name="security_audit_events")
    op.drop_index("ix_security_audit_events_event_uuid", table_name="security_audit_events")

    op.drop_column("security_audit_events", "event_hash")
    op.drop_column("security_audit_events", "prev_hash")
    op.drop_column("security_audit_events", "schema_version")
    op.drop_column("security_audit_events", "correlation_id")
    op.drop_column("security_audit_events", "request_id")
    op.drop_column("security_audit_events", "actor_type")
    op.drop_column("security_audit_events", "event_uuid")

    op.execute("DROP TYPE IF EXISTS audit_actor_type")

    op.execute(
        sa.text(
            """
            DELETE FROM role_permissions
            WHERE permission_id IN (
                SELECT id FROM permissions
                WHERE key IN ('audit.read', 'audit.export', 'audit.verify', 'audit.archive.manage')
            )
            """
        )
    )
    op.execute(
        sa.text(
            """
            DELETE FROM permissions
            WHERE key IN ('audit.read', 'audit.export', 'audit.verify', 'audit.archive.manage')
            """
        )
    )
