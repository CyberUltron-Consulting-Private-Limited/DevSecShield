"""cbom quantum risk register (CB-23 PR-B): one row per estate asset key with its current grade

Revision ID: cb23register001
Revises: cb23q0gap001
Create Date: 2026-11-14 21:00:00.000000

* ``cbomriskregister``: per team and estate asset key (CB-20/CB-21), the current quantum risk grade (Q0..Q4 or
  NULL = no grade), its rank (keyset order), reason, label, type, algorithm family, the observation it comes from
  (source ref and name, application, exposure), presence, number of sources, the run that last graded it, and the
  model version, team inputs digest and graded-content digest it was graded with.
* Indexes: unique ``(team_id, item_key)``; keyset ``(team_id, q_rank, item_key)``; ``(team_id, q_reason)``;
  ``(team_id, family, source_ref, q_grade)``.

A new, empty table: the scheduler's re-grade job fills it from the estate store (batches per tick), then the estate
hook keeps it current.
"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa
import sqlmodel


# revision identifiers, used by Alembic.
revision: str = 'cb23register001'
down_revision: Union[str, Sequence[str], None] = 'cb23q0gap001'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def _s(n: int):
    return sqlmodel.sql.sqltypes.AutoString(length=n)


def upgrade() -> None:
    """Upgrade schema."""
    op.create_table(
        'cbomriskregister',
        sa.Column('id', sa.Integer(), nullable=False),
        sa.Column('team_id', sa.Integer(), nullable=False),
        sa.Column('item_key', _s(64), nullable=False),
        sa.Column('item_kind', _s(16), nullable=False),
        sa.Column('q_grade', _s(2), nullable=True),
        sa.Column('q_rank', sa.Integer(), nullable=False),
        sa.Column('q_reason', _s(32), nullable=False),
        sa.Column('label', _s(255), nullable=True),
        sa.Column('asset_type', _s(32), nullable=True),
        sa.Column('family', _s(32), nullable=True),
        sa.Column('source_ref', _s(255), nullable=True),
        sa.Column('source_name', _s(255), nullable=True),
        sa.Column('application', _s(128), nullable=True),
        sa.Column('exposure', _s(16), nullable=True),
        sa.Column('presence', _s(16), nullable=False),
        sa.Column('sources', sa.Integer(), nullable=False),
        sa.Column('last_run_id', sa.Integer(), nullable=True),
        sa.Column('last_observed_at', sa.DateTime(), nullable=True),
        sa.Column('model_version', _s(32), nullable=False),
        sa.Column('inputs_digest', _s(16), nullable=False),
        sa.Column('grade_digest', _s(16), nullable=False),
        sa.Column('updated_at', sa.DateTime(), nullable=True),
        sa.ForeignKeyConstraint(['team_id'], ['team.id']),
        sa.PrimaryKeyConstraint('id'),
        sa.UniqueConstraint('team_id', 'item_key', name='uq_cbomriskregister_team_key'),
    )
    op.create_index('ix_cbomriskregister_team_rank_key', 'cbomriskregister', ['team_id', 'q_rank', 'item_key'])
    op.create_index('ix_cbomriskregister_team_reason', 'cbomriskregister', ['team_id', 'q_reason'])
    op.create_index('ix_cbomriskregister_team_family_source_grade', 'cbomriskregister',
                    ['team_id', 'family', 'source_ref', 'q_grade'])


def downgrade() -> None:
    """Downgrade schema."""
    op.drop_index('ix_cbomriskregister_team_family_source_grade', table_name='cbomriskregister')
    op.drop_index('ix_cbomriskregister_team_reason', table_name='cbomriskregister')
    op.drop_index('ix_cbomriskregister_team_rank_key', table_name='cbomriskregister')
    op.drop_table('cbomriskregister')
