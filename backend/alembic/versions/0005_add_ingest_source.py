"""add ingest source

Revision ID: 0005_add_ingest_source
Revises: 0004_remove_clusters
Create Date: 2026-01-30 00:00:00.000000

"""
from alembic import op
import sqlalchemy as sa

revision = "0005_add_ingest_source"
down_revision = "0004_remove_clusters"
branch_labels = None
depends_on = None


def upgrade():
    ingest_source = sa.Enum("UPLOAD", "AUTO", name="ingest_source")
    ingest_source.create(op.get_bind(), checkfirst=True)
    op.add_column(
        "reports",
        sa.Column("ingest_source", ingest_source, nullable=False, server_default="UPLOAD"),
    )
    op.execute("ALTER TABLE reports ALTER COLUMN ingest_source DROP DEFAULT")


def downgrade():
    op.drop_column("reports", "ingest_source")
    op.execute("DROP TYPE IF EXISTS ingest_source")
