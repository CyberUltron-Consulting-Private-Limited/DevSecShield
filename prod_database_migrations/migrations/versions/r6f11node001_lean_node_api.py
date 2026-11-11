"""cbom lean node API (F1.1): per-node replay window, segment jobs, hot-path indexes

Revision ID: r6f11node001
Revises: rv6p1nodename001
Create Date: 2026-11-11 12:00:00.000000

* ``cbomscannode.replay_hwm`` / ``replay_bits`` (BIGINT, 0): the protocol-2 anti-replay window (highest request
  sequence accepted + a bitmap of the 63 below it), checked and advanced by one conditional UPDATE per request
  instead of a ``cbomnodenonce`` row (protocol-1 nodes keep using that table).
* ``cbomcollectionsource.node_segment`` / ``cbomcollectionjob.node_segment`` (varchar 64, NULL): a source with a
  segment and no node queues segment jobs that any agentless node of the team in that ``cbomscannode.segment``
  may claim; NULL everywhere for existing rows, so every existing source and job behaves as before.
* Indexes for the claim, heartbeat, reaper and run-status paths; the partial ones cover only open jobs.

At merge time this revision's ``down_revision`` is re-chained to the head ``alembic heads`` shows on dev (F1 contract,
section 2); ``backend/tests/test_alembic_single_head.py`` fails on two heads.
"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa
import sqlmodel


# revision identifiers, used by Alembic.
revision: str = 'r6f11node001'
down_revision: Union[str, Sequence[str], None] = 'rv6p1nodename001'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None

PENDING = "status = 'pending'"
CLAIMED = "status = 'claimed'"
# (name, columns, partial predicate or None)
INDEXES = (
    ('ix_cbomcollectionjob_run_status', ['run_id', 'status'], None),
    ('ix_cbomcollectionjob_node_pending', ['node_id', 'id'], PENDING),
    ('ix_cbomcollectionjob_node_claimed', ['node_id'], CLAIMED),
    ('ix_cbomcollectionjob_claimed_lease', ['lease_expires_at'], CLAIMED),
    ('ix_cbomcollectionjob_pending_created', ['created_at'], PENDING),
    ('ix_cbomcollectionjob_team_status_segment', ['team_id', 'status', 'node_segment', 'id'], None),
)


def upgrade() -> None:
    """Upgrade schema."""
    op.add_column('cbomscannode', sa.Column('replay_hwm', sa.BigInteger(), nullable=False, server_default='0'))
    op.add_column('cbomscannode', sa.Column('replay_bits', sa.BigInteger(), nullable=False, server_default='0'))
    op.add_column('cbomcollectionsource',
                  sa.Column('node_segment', sqlmodel.sql.sqltypes.AutoString(length=64), nullable=True))
    op.add_column('cbomcollectionjob',
                  sa.Column('node_segment', sqlmodel.sql.sqltypes.AutoString(length=64), nullable=True))
    for name, columns, where in INDEXES:
        kwargs = {'postgresql_where': sa.text(where), 'sqlite_where': sa.text(where)} if where else {}
        op.create_index(name, 'cbomcollectionjob', columns, unique=False, **kwargs)


def downgrade() -> None:
    """Downgrade schema."""
    for name, _columns, _where in reversed(INDEXES):
        op.drop_index(name, table_name='cbomcollectionjob')
    op.drop_column('cbomcollectionjob', 'node_segment')
    op.drop_column('cbomcollectionsource', 'node_segment')
    op.drop_column('cbomscannode', 'replay_bits')
    op.drop_column('cbomscannode', 'replay_hwm')
