"""cbomcollectionjob history index: a source's collect jobs, newest last (staging QA2 Q1-02, #497 review M3)

Revision ID: q102hist001
Revises: rsched1trig001
Create Date: 2026-11-25 10:00:00.000000

D1's Sources rows, the CBOM scans list and the team dashboard read each source's collection history
(``collections_view.collection_history``): its successful collections, the first one and its latest attempt. Without
an index that is a scan of the whole job table, JSON parameters included, on every request. The partial index
``ix_cbomcollectionjob_team_source_hist`` (team, source, created_at) over the run's collect jobs, with the status and
finish time stored in it, lets the per-source totals be read from the index alone and the newest job of each source be
found by its key.

On PostgreSQL the index is built CONCURRENTLY (outside the revision's transaction), so the job table keeps taking
writes while it is built.

Downgrade: drops the index (CONCURRENTLY on PostgreSQL). No data changes.
"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


revision: str = 'q102hist001'
down_revision: Union[str, Sequence[str], None] = 'rsched1trig001'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None

NAME = 'ix_cbomcollectionjob_team_source_hist'
WHERE = "kind = 'collect' AND run_id IS NOT NULL"


def _pg() -> bool:
    return op.get_bind().dialect.name == 'postgresql'


def upgrade() -> None:
    """Upgrade schema. PostgreSQL: CONCURRENTLY, outside the revision's transaction (as ``cb19grade002``), so job
    inserts, claims, lease renewals and status updates are never blocked while the table is read (#497 review
    6057627810 m1); ``if_not_exists`` makes a retry after an interrupted build safe."""
    if _pg():
        with op.get_context().autocommit_block():
            op.create_index(NAME, 'cbomcollectionjob', ['team_id', 'source_id', 'created_at'], unique=False,
                            postgresql_include=['status', 'finished_at'], postgresql_where=sa.text(WHERE),
                            postgresql_concurrently=True, if_not_exists=True)
    else:
        op.create_index(NAME, 'cbomcollectionjob', ['team_id', 'source_id', 'created_at'], unique=False,
                        sqlite_where=sa.text(WHERE))


def downgrade() -> None:
    """Downgrade schema."""
    if _pg():
        with op.get_context().autocommit_block():
            op.drop_index(NAME, table_name='cbomcollectionjob', postgresql_concurrently=True, if_exists=True)
    else:
        op.drop_index(NAME, table_name='cbomcollectionjob')
