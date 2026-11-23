"""cbomcollectionrun.trigger: what started a CBOM Sources run, "scheduled" or "manual" (S4)

Revision ID: rsched1trig001
Revises: rpdf1brand001
Create Date: 2026-11-23 16:00:00.000000

Upgrade: adds ``cbomcollectionrun.trigger`` (varchar 16, NOT NULL, server default 'manual') with a check constraint
(``ck_cbomcollectionrun_trigger``: 'manual' or 'scheduled'), then backfills it from the existing ``schedule_id``
column (wp10a0drift001): a run a schedule started (``schedule_id IS NOT NULL``) becomes 'scheduled', every other run
keeps 'manual'.  ``schedule_id`` stays as it is (the schedule may since have been deleted; its runs keep the id).
One UPDATE over the runs table; no other table is touched.

Downgrade: drops the constraint and the column.  ``schedule_id`` still says which runs a schedule started.
"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa
import sqlmodel


# revision identifiers, used by Alembic.
revision: str = 'rsched1trig001'
down_revision: Union[str, Sequence[str], None] = 'rpdf1brand001'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    """Upgrade schema."""
    with op.batch_alter_table('cbomcollectionrun') as batch:
        batch.add_column(sa.Column('trigger', sqlmodel.sql.sqltypes.AutoString(length=16), nullable=False,
                                   server_default='manual'))
        batch.create_check_constraint('ck_cbomcollectionrun_trigger', "trigger IN ('manual', 'scheduled')")
    op.execute("UPDATE cbomcollectionrun SET trigger = 'scheduled' WHERE schedule_id IS NOT NULL")


def downgrade() -> None:
    """Downgrade schema."""
    with op.batch_alter_table('cbomcollectionrun') as batch:
        batch.drop_constraint('ck_cbomcollectionrun_trigger', type_='check')
        batch.drop_column('trigger')
