"""#150: CbomHostKeyReset, an admin's accept / forget decision for a trust-on-first-use host key pin.

Revision ID: i150hkreset001
Revises: cb14credit001
Create Date: 2026-11-15 12:00:00.000000

"""
from collections.abc import Sequence

import sqlalchemy as sa
import sqlmodel
from alembic import op

revision: str = "i150hkreset001"
down_revision: str | Sequence[str] | None = "cb14credit001"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.create_table(
        "cbomhostkeyreset",
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column("team_id", sa.Integer(), nullable=False),
        sa.Column("source_id", sa.Integer(), nullable=False),
        sa.Column("node_id", sa.Integer(), nullable=False),
        sa.Column("job_id", sa.Integer(), nullable=False),
        sa.Column("target", sqlmodel.sql.sqltypes.AutoString(length=255), nullable=False),
        sa.Column("port", sa.Integer(), nullable=False),
        sa.Column("action", sqlmodel.sql.sqltypes.AutoString(length=8), nullable=False),
        sa.Column("fingerprint", sqlmodel.sql.sqltypes.AutoString(length=64), nullable=True),
        sa.Column("pinned_fingerprint", sqlmodel.sql.sqltypes.AutoString(length=64), nullable=True),
        sa.Column("status", sqlmodel.sql.sqltypes.AutoString(length=12), nullable=False),
        sa.Column("requested_by_user_id", sa.Integer(), nullable=False),
        sa.Column("requested_at", sa.DateTime(), nullable=True),
        sa.Column("applied_at", sa.DateTime(), nullable=True),
        sa.Column("applied_job_id", sa.Integer(), nullable=True),
        sa.ForeignKeyConstraint(["team_id"], ["team.id"]),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index(op.f("ix_cbomhostkeyreset_team_id"), "cbomhostkeyreset", ["team_id"], unique=False)
    op.create_index(op.f("ix_cbomhostkeyreset_source_id"), "cbomhostkeyreset", ["source_id"], unique=False)


def downgrade() -> None:
    op.drop_index(op.f("ix_cbomhostkeyreset_source_id"), table_name="cbomhostkeyreset")
    op.drop_index(op.f("ix_cbomhostkeyreset_team_id"), table_name="cbomhostkeyreset")
    op.drop_table("cbomhostkeyreset")
