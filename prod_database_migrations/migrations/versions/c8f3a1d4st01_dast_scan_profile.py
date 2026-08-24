"""Add DastScanProfile for scheduled and Jenkins DAST.

Revision ID: c8f3a1d4st01
Revises: b7479fc393e1
Create Date: 2026-08-24 13:50:00.000000

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa
import sqlmodel


revision: str = "c8f3a1d4st01"
down_revision: Union[str, Sequence[str], None] = "b7479fc393e1"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.create_table(
        "dastscanprofile",
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column("team_id", sa.Integer(), nullable=False),
        sa.Column("owner_user_id", sa.Integer(), nullable=False),
        sa.Column("title", sqlmodel.sql.sqltypes.AutoString(), nullable=False),
        sa.Column("enabled", sa.Boolean(), nullable=False),
        sa.Column("target_url", sqlmodel.sql.sqltypes.AutoString(), nullable=False),
        sa.Column("allowed_hosts", sa.JSON(), nullable=True),
        sa.Column("auth_encrypted", sa.JSON(), nullable=True),
        sa.Column("scan_speed", sqlmodel.sql.sqltypes.AutoString(), nullable=False),
        sa.Column("max_urls", sa.Integer(), nullable=False),
        sa.Column("additional_urls_to_scan", sa.JSON(), nullable=True),
        sa.Column("exclude_url_patterns", sa.JSON(), nullable=True),
        sa.Column("include_url_patterns", sa.JSON(), nullable=True),
        sa.Column("schedule_kind", sqlmodel.sql.sqltypes.AutoString(), nullable=False),
        sa.Column("schedule_time", sqlmodel.sql.sqltypes.AutoString(), nullable=True),
        sa.Column("schedule_weekday", sa.Integer(), nullable=True),
        sa.Column("next_run_at", sa.DateTime(), nullable=True),
        sa.Column("inflight_scan_id", sa.Integer(), nullable=True),
        sa.Column("last_scan_id", sa.Integer(), nullable=True),
        sa.Column("last_run_at", sa.DateTime(), nullable=True),
        sa.Column("consent_ok", sa.Boolean(), nullable=False),
        sa.Column("created_at", sa.DateTime(), nullable=True),
        sa.Column("last_updated", sa.DateTime(), nullable=True),
        sa.ForeignKeyConstraint(["owner_user_id"], ["user.id"]),
        sa.ForeignKeyConstraint(["team_id"], ["team.id"]),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index(op.f("ix_dastscanprofile_team_id"), "dastscanprofile", ["team_id"], unique=False)
    op.create_index(op.f("ix_dastscanprofile_next_run_at"), "dastscanprofile", ["next_run_at"], unique=False)


def downgrade() -> None:
    op.drop_index(op.f("ix_dastscanprofile_next_run_at"), table_name="dastscanprofile")
    op.drop_index(op.f("ix_dastscanprofile_team_id"), table_name="dastscanprofile")
    op.drop_table("dastscanprofile")
