"""add actor refs to report resolutions

Revision ID: 0009_resolution_actor
Revises: 0008_rbac_base
Create Date: 2026-02-19 00:05:00.000000

"""

from alembic import op
import sqlalchemy as sa


revision = "0009_resolution_actor"
down_revision = "0008_rbac_base"
branch_labels = None
depends_on = None


def upgrade():
    op.add_column("report_resolutions", sa.Column("actor_user_id", sa.Integer(), nullable=True))
    op.add_column("report_resolutions", sa.Column("actor_api_key_id", sa.Integer(), nullable=True))

    op.create_foreign_key(
        "fk_report_resolutions_actor_user_id_users",
        "report_resolutions",
        "users",
        ["actor_user_id"],
        ["id"],
        ondelete="SET NULL",
    )
    op.create_foreign_key(
        "fk_report_resolutions_actor_api_key_id_api_keys",
        "report_resolutions",
        "api_keys",
        ["actor_api_key_id"],
        ["id"],
        ondelete="SET NULL",
    )

    op.create_index("ix_report_resolutions_actor_user_id", "report_resolutions", ["actor_user_id"], unique=False)
    op.create_index("ix_report_resolutions_actor_api_key_id", "report_resolutions", ["actor_api_key_id"], unique=False)


def downgrade():
    op.drop_index("ix_report_resolutions_actor_api_key_id", table_name="report_resolutions")
    op.drop_index("ix_report_resolutions_actor_user_id", table_name="report_resolutions")

    op.drop_constraint("fk_report_resolutions_actor_api_key_id_api_keys", "report_resolutions", type_="foreignkey")
    op.drop_constraint("fk_report_resolutions_actor_user_id_users", "report_resolutions", type_="foreignkey")

    op.drop_column("report_resolutions", "actor_api_key_id")
    op.drop_column("report_resolutions", "actor_user_id")
