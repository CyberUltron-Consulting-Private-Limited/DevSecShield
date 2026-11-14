"""cbom quantum risk register (CB-23 PR-A): the Q0 gap lifecycle table

Revision ID: cb23q0gap001
Revises: cb38ticket001
Create Date: 2026-11-14 18:30:00.000000

* ``cbomq0gap``: one row per opening of a Q0 item of a team's register (evidence area or vendor at E0, unread scope,
  asset with an unknown class, missing Mosca input): reason, detail, opened / last seen / closed, the closing cause and
  the grade it closed to, the run that last saw it.
* ``uq_cbomq0gap_open_item``: at most one OPEN row per (team, kind, key) (partial unique index, PostgreSQL and SQLite);
  closed rows are history, so an item can reopen.
* ``ix_cbomq0gap_team_closed_opened``: the register list (open or closed, newest opening first).

A new, empty table: nothing is backfilled (the first evidence write, the first register read or the daily tick opens
the current gaps; scope / asset items appear with the next run).
"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa
import sqlmodel


# revision identifiers, used by Alembic.
revision: str = 'cb23q0gap001'
down_revision: Union[str, Sequence[str], None] = 'cb38ticket001'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    """Upgrade schema."""
    op.create_table(
        'cbomq0gap',
        sa.Column('id', sa.Integer(), nullable=False),
        sa.Column('team_id', sa.Integer(), nullable=False),
        sa.Column('item_kind', sqlmodel.sql.sqltypes.AutoString(length=16), nullable=False),
        sa.Column('item_key', sqlmodel.sql.sqltypes.AutoString(length=128), nullable=False),
        sa.Column('reason', sqlmodel.sql.sqltypes.AutoString(length=32), nullable=False),
        sa.Column('detail', sa.JSON(), nullable=True),
        sa.Column('opened_at', sa.DateTime(), nullable=False),
        sa.Column('as_of', sqlmodel.sql.sqltypes.AutoString(length=10), nullable=True),
        sa.Column('last_seen_at', sa.DateTime(), nullable=True),
        sa.Column('closed_at', sa.DateTime(), nullable=True),
        sa.Column('close_cause', sqlmodel.sql.sqltypes.AutoString(length=16), nullable=True),
        sa.Column('closed_grade', sqlmodel.sql.sqltypes.AutoString(length=2), nullable=True),
        sa.Column('run_id', sa.Integer(), nullable=True),
        sa.ForeignKeyConstraint(['team_id'], ['team.id']),
        sa.PrimaryKeyConstraint('id'),
    )
    op.create_index('uq_cbomq0gap_open_item', 'cbomq0gap', ['team_id', 'item_kind', 'item_key'], unique=True,
                    postgresql_where=sa.text('closed_at IS NULL'), sqlite_where=sa.text('closed_at IS NULL'))
    op.create_index('ix_cbomq0gap_team_closed_opened', 'cbomq0gap', ['team_id', 'closed_at', 'opened_at'],
                    unique=False)


def downgrade() -> None:
    """Downgrade schema."""
    op.drop_index('ix_cbomq0gap_team_closed_opened', table_name='cbomq0gap')
    op.drop_index('uq_cbomq0gap_open_item', table_name='cbomq0gap')
    op.drop_table('cbomq0gap')
