"""cbom estate store (CB-32 PR-B): ``cbomestateteam.stale_marks``

Revision ID: cb32index001
Revises: cb226apikey001
Create Date: 2026-11-15 12:00:00.000000

Counts the writes a team's store has missed (a run deferred to the scheduler by a request whose process had no warm
key index, or a failed write). The repair clears the stale flag only if no write was missed while it ran.
"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


revision: str = 'cb32index001'
down_revision: Union[str, Sequence[str], None] = 'cb226apikey001'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    with op.batch_alter_table('cbomestateteam') as batch:
        batch.add_column(sa.Column('stale_marks', sa.Integer(), nullable=False, server_default='0'))


def downgrade() -> None:
    with op.batch_alter_table('cbomestateteam') as batch:
        batch.drop_column('stale_marks')
