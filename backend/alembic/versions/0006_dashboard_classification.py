"""add classification code and dashboard indexes

Revision ID: 0006_dashboard_classification
Revises: 0005_add_ingest_source
Create Date: 2026-01-30 00:00:00.000000

"""

from alembic import op
import sqlalchemy as sa


revision = "0006_dashboard_classification"
down_revision = "0005_add_ingest_source"
branch_labels = None
depends_on = None

CLASSIFICATION_CODES = (
    "CRED_HARV",
    "DRIVE_BY",
    "RECON",
    "REPLY_SOLICIT",
    "SPOOF",
    "MAL_ATTACH",
    "MAL_URL",
    "MAL_WEBAPP",
    "MALWARE",
    "COMPRO_SEND",
    "THREAD_HIJACK",
    "FIN_FRAUD",
    "WEBMAIL",
    "WHALE",
    "VOLUME",
    "SPEAR",
    "POLY",
    "IMPER",
    "GOV_IMPER",
    "3P_IMPER",
    "T3P_IMPER",
    "VIP_IMPER",
)



def upgrade():
    op.add_column("reports", sa.Column("classification_code", sa.String(length=32), nullable=True))
    allowed = ", ".join([f"'{code}'" for code in CLASSIFICATION_CODES])
    op.create_check_constraint(
        "ck_reports_classification_code",
        "reports",
        f"classification_code IS NULL OR classification_code IN ({allowed})",
    )

    op.create_index("ix_reports_created_at", "reports", ["created_at"])
    op.create_index("ix_reports_status_created_at", "reports", ["status", "created_at"])
    op.create_index(
        "ix_reports_classification_code_created_at",
        "reports",
        ["classification_code", "created_at"],
    )
    op.create_index("ix_reports_ingest_source_created_at", "reports", ["ingest_source", "created_at"])



def downgrade():
    op.drop_index("ix_reports_ingest_source_created_at", table_name="reports")
    op.drop_index("ix_reports_classification_code_created_at", table_name="reports")
    op.drop_index("ix_reports_status_created_at", table_name="reports")
    op.drop_index("ix_reports_created_at", table_name="reports")

    op.drop_constraint("ck_reports_classification_code", "reports", type_="check")
    op.drop_column("reports", "classification_code")
