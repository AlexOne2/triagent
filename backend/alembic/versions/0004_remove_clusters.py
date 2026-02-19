"""remove clusters and add report status

Revision ID: 0004_remove_clusters
Revises: 0003_add_from_display_name
Create Date: 2026-01-30 00:00:00.000000

"""
from alembic import op
import sqlalchemy as sa

revision = "0004_remove_clusters"
down_revision = "0003_add_from_display_name"
branch_labels = None
depends_on = None


def upgrade():
    op.execute("ALTER TABLE reports DROP CONSTRAINT IF EXISTS reports_cluster_id_fkey")
    op.execute("DROP INDEX IF EXISTS ix_reports_cluster_id")
    op.drop_column("reports", "cluster_id")

    report_status = sa.Enum("OPEN", "BENIGN", "PHISHING", name="report_status")
    report_status.create(op.get_bind(), checkfirst=True)
    op.add_column(
        "reports",
        sa.Column("status", report_status, nullable=False, server_default="OPEN"),
    )
    op.add_column("reports", sa.Column("risk_score", sa.Integer(), nullable=False, server_default="0"))
    op.execute("ALTER TABLE reports ALTER COLUMN status DROP DEFAULT")
    op.execute("ALTER TABLE reports ALTER COLUMN risk_score DROP DEFAULT")

    op.drop_index("ix_clusters_fingerprint", table_name="clusters")
    op.drop_index("ix_clusters_id", table_name="clusters")
    op.drop_table("clusters")
    op.execute("DROP TYPE IF EXISTS cluster_status")


def downgrade():
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

    op.add_column("reports", sa.Column("cluster_id", sa.Integer(), nullable=True))
    op.execute("ALTER TABLE reports ADD CONSTRAINT reports_cluster_id_fkey FOREIGN KEY (cluster_id) REFERENCES clusters (id)")

    op.drop_column("reports", "risk_score")
    op.drop_column("reports", "status")
    op.execute("DROP TYPE IF EXISTS report_status")
