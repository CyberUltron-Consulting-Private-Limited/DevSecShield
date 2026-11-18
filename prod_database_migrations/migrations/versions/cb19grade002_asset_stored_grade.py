"""CB-19 PR-3: the quantum risk grade stored on each collected asset at ingest

Revision ID: cb19grade002
Revises: cb14credit001
Create Date: 2026-11-15 12:00:00.000000

* ``cbomcollectedasset.q_grade`` ("Q0".."Q4", NULL = no grade) and ``q_reason`` (the qg-1 reason code): the record
  grade ``qgrade.ingest_grades`` writes when the row is inserted (rows are insert-only; nothing is UPDATEd later).
* ``ix_cbomcollectedasset_run_qgrade (run_id, q_grade)``: the run asset list's grade filter and facet. Built
  ``CONCURRENTLY`` on PostgreSQL (outside the migration's transaction) so a large table keeps taking inserts.

Both columns are nullable with no default (metadata-only on PostgreSQL >= 11: the table is not rewritten). Old rows
are never backfilled: NULL ``q_reason`` means "graded at view", and the run list hides the grade filter for such runs.
"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = 'cb19grade002'
down_revision: Union[str, Sequence[str], None] = 'cb14credit001'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None

INDEX = 'ix_cbomcollectedasset_run_qgrade'


def _postgresql() -> bool:
    return op.get_bind().dialect.name == 'postgresql'


def upgrade() -> None:
    """Upgrade schema."""
    op.add_column('cbomcollectedasset', sa.Column('q_grade', sa.String(length=2), nullable=True))
    op.add_column('cbomcollectedasset', sa.Column('q_reason', sa.String(length=32), nullable=True))
    if _postgresql():
        with op.get_context().autocommit_block():
            op.create_index(INDEX, 'cbomcollectedasset', ['run_id', 'q_grade'], postgresql_concurrently=True,
                            if_not_exists=True)
    else:
        op.create_index(INDEX, 'cbomcollectedasset', ['run_id', 'q_grade'])


def downgrade() -> None:
    """Downgrade schema."""
    if _postgresql():
        with op.get_context().autocommit_block():
            op.drop_index(INDEX, table_name='cbomcollectedasset', postgresql_concurrently=True, if_exists=True)
    else:
        op.drop_index(INDEX, table_name='cbomcollectedasset')
    op.drop_column('cbomcollectedasset', 'q_reason')
    op.drop_column('cbomcollectedasset', 'q_grade')
