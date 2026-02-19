"""create tables

Revision ID: 0001_create_tables
Revises: 
Create Date: 2024-12-27 00:00:00.000000

"""
from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

revision = "0001_create_tables"
down_revision = None
branch_labels = None
depends_on = None


def upgrade():
    op.create_table(
        "clusters",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("fingerprint", sa.String(length=64), nullable=False),
        sa.Column("subject_norm", sa.Text(), nullable=False),
        sa.Column("from_domain", sa.String(length=255), nullable=True),
        sa.Column("first_seen", sa.DateTime(timezone=True), nullable=False),
        sa.Column("last_seen", sa.DateTime(timezone=True), nullable=False),
        sa.Column("report_count", sa.Integer(), nullable=False),
        sa.Column("risk_score", sa.Integer(), nullable=False),
        sa.Column(
            "status",
            sa.Enum("OPEN", "BENIGN", "PHISHING", name="cluster_status"),
            nullable=False,
        ),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.text("now()")),
    )
    op.create_index("ix_clusters_id", "clusters", ["id"])
    op.create_index("ix_clusters_fingerprint", "clusters", ["fingerprint"], unique=True)

    op.create_table(
        "reports",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("cluster_id", sa.Integer(), sa.ForeignKey("clusters.id"), nullable=False),
        sa.Column("message_id", sa.String(length=255), nullable=True),
        sa.Column("received_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("subject", sa.Text(), nullable=True),
        sa.Column("from_addr", sa.String(length=320), nullable=True),
        sa.Column("to_addrs", postgresql.JSONB(astext_type=sa.Text()), nullable=True),
        sa.Column("cc_addrs", postgresql.JSONB(astext_type=sa.Text()), nullable=True),
        sa.Column("date", sa.DateTime(timezone=True), nullable=True),
        sa.Column("body_text", sa.Text(), nullable=True),
        sa.Column("body_html", sa.Text(), nullable=True),
        sa.Column("headers_json", postgresql.JSONB(astext_type=sa.Text()), nullable=True),
        sa.Column("urls_json", postgresql.JSONB(astext_type=sa.Text()), nullable=True),
        sa.Column("reporter_hash", sa.String(length=128), nullable=True),
        sa.Column("mailbox_domain", sa.String(length=255), nullable=True),
        sa.Column("raw_source", sa.Text(), nullable=True),
        sa.Column("sender", sa.String(length=320), nullable=True),
        sa.Column("reply_to", postgresql.JSONB(astext_type=sa.Text()), nullable=True),
        sa.Column("in_reply_to", sa.String(length=255), nullable=True),
        sa.Column("return_path", sa.String(length=320), nullable=True),
        sa.Column("originating_ip", sa.String(length=64), nullable=True),
        sa.Column("originating_rdns", sa.String(length=255), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.text("now()")),
    )
    op.create_index("ix_reports_id", "reports", ["id"])
    op.create_index("ix_reports_cluster_id", "reports", ["cluster_id"])

    op.create_table(
        "attachments",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("report_id", sa.Integer(), sa.ForeignKey("reports.id"), nullable=False),
        sa.Column("filename", sa.String(length=512), nullable=True),
        sa.Column("content_type", sa.String(length=255), nullable=True),
        sa.Column("size_bytes", sa.Integer(), nullable=True),
        sa.Column("s3_key", sa.String(length=1024), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.text("now()")),
    )
    op.create_index("ix_attachments_id", "attachments", ["id"])
    op.create_index("ix_attachments_report_id", "attachments", ["report_id"])



def downgrade():
    op.drop_index("ix_attachments_report_id", table_name="attachments")
    op.drop_index("ix_attachments_id", table_name="attachments")
    op.drop_table("attachments")

    op.drop_index("ix_reports_cluster_id", table_name="reports")
    op.drop_index("ix_reports_id", table_name="reports")
    op.drop_table("reports")

    op.drop_index("ix_clusters_fingerprint", table_name="clusters")
    op.drop_index("ix_clusters_id", table_name="clusters")
    op.drop_table("clusters")

    op.execute("DROP TYPE IF EXISTS cluster_status")
