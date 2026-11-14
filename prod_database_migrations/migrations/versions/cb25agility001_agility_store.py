"""cbom agility on the estate store (CB-25 PR-B): fix-class columns on ``cbomestateasset`` / ``cbomestateobservation``,
the ``(team_id, system_key, fix_class)`` index, and ``cbomagilitybaseline`` (one baseline per run)

Revision ID: cb25agility001
Revises: cb20estate001
Create Date: 2026-11-14 16:00:00.000000

Nullable columns only (no default, no rewrite, no long lock on PostgreSQL) and one new table. NULL means "not
computed yet": ``agility_store`` fills the columns in each run's estate write (an estate hook) and heals any row it
finds missing or stale when the baseline is read. The downgrade drops the table, the index and the columns.
"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa
import sqlmodel


revision: str = 'cb25agility001'
down_revision: Union[str, Sequence[str], None] = 'cb20estate001'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def _s(length: int):
    return sqlmodel.sql.sqltypes.AutoString(length=length)


_SHARED = (('fix_class', 16), ('fix_class_excl_pq', 16), ('fix_floor', 16), ('fix_reasons', 200), ('fix_codes', 300),
           ('fix_version', 32), ('system_key', 300), ('system_label', 255), ('system_kind', 16))
_ASSET = ('fix_at', 'fix_observations')
_OBS = ('fix_job_id', 'fix_attempt', 'fix_recheck_on', 'fix_at', 'cert_cnb_key', 'cert_cn_key')


def upgrade() -> None:
    with op.batch_alter_table('cbomestateasset') as batch:
        for name, length in _SHARED:
            batch.add_column(sa.Column(name, _s(length), nullable=True))
        batch.add_column(sa.Column('fix_at', sa.DateTime(), nullable=True))
        batch.add_column(sa.Column('fix_observations', sa.Integer(), nullable=True))
    op.create_index('ix_cbomestateasset_team_system_fix', 'cbomestateasset', ['team_id', 'system_key', 'fix_class'])
    with op.batch_alter_table('cbomestateobservation') as batch:
        for name, length in _SHARED:
            batch.add_column(sa.Column(name, _s(length), nullable=True))
        batch.add_column(sa.Column('fix_job_id', sa.Integer(), nullable=True))
        batch.add_column(sa.Column('fix_attempt', sa.Integer(), nullable=True))
        batch.add_column(sa.Column('fix_recheck_on', sa.Date(), nullable=True))
        batch.add_column(sa.Column('fix_at', sa.DateTime(), nullable=True))
        batch.add_column(sa.Column('cert_cnb_key', _s(46), nullable=True))
        batch.add_column(sa.Column('cert_cn_key', _s(46), nullable=True))
    op.create_table(
        'cbomagilitybaseline',
        sa.Column('id', sa.Integer(), nullable=False),
        sa.Column('team_id', sa.Integer(), nullable=False),
        sa.Column('run_id', sa.Integer(), nullable=False),
        sa.Column('scope', _s(16), nullable=False),
        sa.Column('agility_version', _s(32), nullable=False),
        sa.Column('assets', sa.Integer(), nullable=False),
        sa.Column('self_fixable_pct', sa.Float(), nullable=True),
        sa.Column('counts', sa.JSON(), nullable=True),
        sa.Column('counts_excl_pq', sa.JSON(), nullable=True),
        sa.Column('unknown_reasons', sa.JSON(), nullable=True),
        sa.Column('systems', sa.JSON(), nullable=True),
        sa.Column('systems_truncated', sa.Boolean(), nullable=False),
        sa.Column('created_at', sa.DateTime(), nullable=True),
        sa.ForeignKeyConstraint(['team_id'], ['team.id']),
        sa.PrimaryKeyConstraint('id'),
        sa.UniqueConstraint('team_id', 'run_id', name='uq_cbomagilitybaseline_team_run'),
    )


def downgrade() -> None:
    op.drop_table('cbomagilitybaseline')
    with op.batch_alter_table('cbomestateobservation') as batch:
        for name in (*_OBS, *(n for n, _l in reversed(_SHARED))):
            batch.drop_column(name)
    op.drop_index('ix_cbomestateasset_team_system_fix', table_name='cbomestateasset')
    with op.batch_alter_table('cbomestateasset') as batch:
        for name in (*_ASSET, *(n for n, _l in reversed(_SHARED))):
            batch.drop_column(name)
