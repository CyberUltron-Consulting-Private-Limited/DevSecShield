"""Add DastScanProfile.schedule_config JSON for IST presets/cron.

Revision ID: d9e4b2c5st02
Revises: c8f3a1d4st01
Create Date: 2026-08-24 17:50:00.000000

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


revision: str = "d9e4b2c5st02"
down_revision: Union[str, Sequence[str], None] = "c8f3a1d4st01"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.add_column("dastscanprofile", sa.Column("schedule_config", sa.JSON(), nullable=True))


def downgrade() -> None:
    op.drop_column("dastscanprofile", "schedule_config")
