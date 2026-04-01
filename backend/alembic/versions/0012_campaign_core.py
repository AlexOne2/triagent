"""add campaign clustering core schema

Revision ID: 0012_campaign_core
Revises: 0011_msg_attachments_sha256
Create Date: 2026-03-07 00:00:00.000000

"""

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql


revision = "0012_campaign_core"
down_revision = "0011_msg_attachments_sha256"
branch_labels = None
depends_on = None


def upgrade():
    campaign_assignment_method = postgresql.ENUM(
        "AUTO",
        "MANUAL",
        name="campaign_assignment_method",
        create_type=True,
    )
    campaign_event_action = postgresql.ENUM(
        "AUTO_ASSIGN",
        "MANUAL_REASSIGN",
        "MERGE",
        "SPLIT",
        "LOCK",
        "UNLOCK",
        "RECLUSTER",
        name="campaign_event_action",
        create_type=True,
    )
    campaign_assignment_method.create(op.get_bind(), checkfirst=True)
    campaign_event_action.create(op.get_bind(), checkfirst=True)

    op.create_table(
        "campaigns",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("campaign_key", sa.String(length=64), nullable=False),
        sa.Column("name", sa.String(length=255), nullable=True),
        sa.Column("first_seen", sa.DateTime(timezone=True), nullable=True),
        sa.Column("last_seen", sa.DateTime(timezone=True), nullable=True),
        sa.Column("report_count", sa.Integer(), nullable=False, server_default=sa.text("0")),
        sa.Column("confidence_score", sa.Float(), nullable=True),
        sa.Column("is_locked", sa.Boolean(), nullable=False, server_default=sa.text("false")),
        sa.Column("lock_reason", sa.Text(), nullable=True),
        sa.Column("algorithm_version", sa.String(length=64), nullable=False, server_default=sa.text("'v1'")),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.text("now()")),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.text("now()")),
        sa.UniqueConstraint("campaign_key", name="uq_campaigns_campaign_key"),
    )
    op.create_index("ix_campaigns_id", "campaigns", ["id"], unique=False)
    op.create_index("ix_campaigns_campaign_key", "campaigns", ["campaign_key"], unique=True)
    op.create_index("ix_campaigns_last_seen", "campaigns", ["last_seen"], unique=False)
    op.create_index("ix_campaigns_is_locked_last_seen", "campaigns", ["is_locked", "last_seen"], unique=False)

    op.create_table(
        "report_features",
        sa.Column("report_id", sa.Integer(), sa.ForeignKey("reports.id", ondelete="CASCADE"), primary_key=True),
        sa.Column("subject_norm", sa.Text(), nullable=True),
        sa.Column("body_simhash", sa.String(length=16), nullable=True),
        sa.Column("from_domain", sa.String(length=255), nullable=True),
        sa.Column("reply_to_domains_json", postgresql.JSONB(astext_type=sa.Text()), nullable=True),
        sa.Column("return_path_domain", sa.String(length=255), nullable=True),
        sa.Column("originating_ip", sa.String(length=64), nullable=True),
        sa.Column("url_domains_json", postgresql.JSONB(astext_type=sa.Text()), nullable=True),
        sa.Column("attachment_hashes_json", postgresql.JSONB(astext_type=sa.Text()), nullable=True),
        sa.Column("semantic_vector_json", postgresql.JSONB(astext_type=sa.Text()), nullable=True),
        sa.Column("feature_version", sa.Integer(), nullable=False, server_default=sa.text("1")),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.text("now()")),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.text("now()")),
    )
    op.create_index(
        "ix_report_features_url_domains_json",
        "report_features",
        ["url_domains_json"],
        unique=False,
        postgresql_using="gin",
    )
    op.create_index(
        "ix_report_features_attachment_hashes_json",
        "report_features",
        ["attachment_hashes_json"],
        unique=False,
        postgresql_using="gin",
    )

    op.create_table(
        "campaign_events",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("campaign_id", sa.Integer(), sa.ForeignKey("campaigns.id", ondelete="CASCADE"), nullable=False),
        sa.Column("action", postgresql.ENUM(name="campaign_event_action", create_type=False), nullable=False),
        sa.Column("report_id", sa.Integer(), sa.ForeignKey("reports.id", ondelete="SET NULL"), nullable=True),
        sa.Column("from_campaign_id", sa.Integer(), sa.ForeignKey("campaigns.id", ondelete="SET NULL"), nullable=True),
        sa.Column("to_campaign_id", sa.Integer(), sa.ForeignKey("campaigns.id", ondelete="SET NULL"), nullable=True),
        sa.Column("score", sa.Float(), nullable=True),
        sa.Column("features_json", postgresql.JSONB(astext_type=sa.Text()), nullable=True),
        sa.Column("actor_user_id", sa.Integer(), sa.ForeignKey("users.id", ondelete="SET NULL"), nullable=True),
        sa.Column("actor_api_key_id", sa.Integer(), sa.ForeignKey("api_keys.id", ondelete="SET NULL"), nullable=True),
        sa.Column("actor_snapshot", sa.String(length=255), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.text("now()")),
    )
    op.create_index("ix_campaign_events_id", "campaign_events", ["id"], unique=False)
    op.create_index("ix_campaign_events_campaign_id", "campaign_events", ["campaign_id"], unique=False)
    op.create_index("ix_campaign_events_report_id", "campaign_events", ["report_id"], unique=False)
    op.create_index(
        "ix_campaign_events_campaign_id_created_at",
        "campaign_events",
        ["campaign_id", "created_at"],
        unique=False,
    )
    op.create_index(
        "ix_campaign_events_report_id_created_at",
        "campaign_events",
        ["report_id", "created_at"],
        unique=False,
    )

    op.add_column("reports", sa.Column("campaign_id", sa.Integer(), nullable=True))
    op.add_column(
        "reports",
        sa.Column("campaign_assignment_method", postgresql.ENUM(name="campaign_assignment_method", create_type=False), nullable=True),
    )
    op.add_column("reports", sa.Column("campaign_assignment_score", sa.Float(), nullable=True))
    op.add_column(
        "reports",
        sa.Column("campaign_assignment_explanation_json", postgresql.JSONB(astext_type=sa.Text()), nullable=True),
    )
    op.create_foreign_key(
        "fk_reports_campaign_id_campaigns",
        "reports",
        "campaigns",
        ["campaign_id"],
        ["id"],
        ondelete="SET NULL",
    )
    op.create_index("ix_reports_campaign_id", "reports", ["campaign_id"], unique=False)
    op.create_index("ix_reports_campaign_id_created_at", "reports", ["campaign_id", "created_at"], unique=False)


def downgrade():
    op.drop_index("ix_reports_campaign_id_created_at", table_name="reports")
    op.drop_index("ix_reports_campaign_id", table_name="reports")
    op.drop_constraint("fk_reports_campaign_id_campaigns", "reports", type_="foreignkey")
    op.drop_column("reports", "campaign_assignment_explanation_json")
    op.drop_column("reports", "campaign_assignment_score")
    op.drop_column("reports", "campaign_assignment_method")
    op.drop_column("reports", "campaign_id")

    op.drop_index("ix_campaign_events_report_id_created_at", table_name="campaign_events")
    op.drop_index("ix_campaign_events_campaign_id_created_at", table_name="campaign_events")
    op.drop_index("ix_campaign_events_report_id", table_name="campaign_events")
    op.drop_index("ix_campaign_events_campaign_id", table_name="campaign_events")
    op.drop_index("ix_campaign_events_id", table_name="campaign_events")
    op.drop_table("campaign_events")

    op.drop_index("ix_report_features_attachment_hashes_json", table_name="report_features")
    op.drop_index("ix_report_features_url_domains_json", table_name="report_features")
    op.drop_table("report_features")

    op.drop_index("ix_campaigns_is_locked_last_seen", table_name="campaigns")
    op.drop_index("ix_campaigns_last_seen", table_name="campaigns")
    op.drop_index("ix_campaigns_campaign_key", table_name="campaigns")
    op.drop_index("ix_campaigns_id", table_name="campaigns")
    op.drop_table("campaigns")

    op.execute("DROP TYPE IF EXISTS campaign_event_action")
    op.execute("DROP TYPE IF EXISTS campaign_assignment_method")
