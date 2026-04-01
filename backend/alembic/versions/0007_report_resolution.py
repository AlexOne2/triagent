"""add report resolution tracking

Revision ID: 0007_report_resolution
Revises: 0006_dashboard_classification
Create Date: 2026-02-19 00:00:00.000000

"""

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql


revision = "0007_report_resolution"
down_revision = "0006_dashboard_classification"
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
    bind = op.get_bind()
    postgresql.ENUM("RESOLVE", "REOPEN", name="resolution_action").create(bind, checkfirst=True)
    postgresql.ENUM("MALICIOUS", "SAFE", name="resolution_disposition").create(bind, checkfirst=True)

    op.add_column("reports", sa.Column("resolution_note", sa.Text(), nullable=True))
    op.add_column("reports", sa.Column("flagged_artifacts_json", postgresql.JSONB(astext_type=sa.Text()), nullable=True))
    op.add_column("reports", sa.Column("resolved_at", sa.DateTime(timezone=True), nullable=True))
    op.add_column("reports", sa.Column("last_resolved_by", sa.String(length=255), nullable=True))

    allowed = ", ".join([f"'{code}'" for code in CLASSIFICATION_CODES])
    op.execute(
        f"""
        CREATE TABLE report_resolutions (
            id SERIAL PRIMARY KEY,
            report_id INTEGER NOT NULL REFERENCES reports (id) ON DELETE CASCADE,
            action resolution_action NOT NULL,
            disposition resolution_disposition NULL,
            status_after report_status NOT NULL,
            classification_code VARCHAR(32) NULL,
            note TEXT NULL,
            flagged_artifacts_json JSONB NULL,
            actor VARCHAR(255) NOT NULL,
            created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
            CONSTRAINT ck_report_resolutions_classification_code
                CHECK (classification_code IS NULL OR classification_code IN ({allowed})),
            CONSTRAINT ck_report_resolutions_action_disposition
                CHECK (
                    (action = 'REOPEN' AND disposition IS NULL AND status_after = 'OPEN')
                    OR
                    (action = 'RESOLVE' AND disposition IS NOT NULL AND status_after IN ('BENIGN', 'PHISHING'))
                )
        )
        """
    )

    op.create_index(
        "ix_report_resolutions_report_id_created_at",
        "report_resolutions",
        ["report_id", "created_at"],
    )
    op.create_index(
        "ix_report_resolutions_status_after_created_at",
        "report_resolutions",
        ["status_after", "created_at"],
    )


def downgrade():
    op.drop_index("ix_report_resolutions_status_after_created_at", table_name="report_resolutions")
    op.drop_index("ix_report_resolutions_report_id_created_at", table_name="report_resolutions")
    op.drop_table("report_resolutions")

    op.drop_column("reports", "last_resolved_by")
    op.drop_column("reports", "resolved_at")
    op.drop_column("reports", "flagged_artifacts_json")
    op.drop_column("reports", "resolution_note")

    op.execute("DROP TYPE IF EXISTS resolution_disposition")
    op.execute("DROP TYPE IF EXISTS resolution_action")
