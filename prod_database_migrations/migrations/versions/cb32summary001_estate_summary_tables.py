"""cbom estate store at scale (CB-32): summary tables kept by triggers

Revision ID: cb32summary001
Revises: cb199proxyuser001
Create Date: 2026-11-15 16:00:00.000000

* ``cbomagilitygroup``: the agility roll-up's GROUP BY (live classed assets per system, class, class without PQ codes,
  unknown reasons);
* ``cbomregistersummary``: the risk register summary (rows per grade, reason, family, presence);
* ``cbomestatecount``: team counters (live assets, live not-correlated assets, live observations).

Kept by triggers on ``cbomestateasset``, ``cbomestateobservation`` and ``cbomriskregister``, in the writing
transaction: statement-level with transition tables on PostgreSQL, row-level on SQLite
(``backend/utilities/cbom_sources/estate_summary_ddl.py`` generates them). The upgrade fills the summaries from the
current rows. The downgrade drops the triggers, their functions and the tables.
"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa
import sqlmodel


revision: str = 'cb32summary001'
down_revision: Union[str, Sequence[str], None] = 'cb199proxyuser001'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def _s(length: int):
    return sqlmodel.sql.sqltypes.AutoString(length=length)


def upgrade() -> None:
    from backend.utilities.cbom_sources import estate_summary_ddl as SUMMARY

    op.create_table(
        'cbomagilitygroup',
        sa.Column('id', sa.Integer(), nullable=False),
        sa.Column('team_id', sa.Integer(), nullable=False),
        sa.Column('system_key', _s(300), nullable=False),
        sa.Column('fix_class', _s(16), nullable=False),
        sa.Column('fix_class_excl_pq', _s(16), nullable=False),
        sa.Column('fix_reasons', _s(200), nullable=False),
        sa.Column('n', sa.Integer(), nullable=False),
        sa.Column('system_label', _s(255), nullable=True),
        sa.Column('system_kind', _s(16), nullable=True),
        sa.ForeignKeyConstraint(['team_id'], ['team.id']),
        sa.PrimaryKeyConstraint('id'),
        sa.UniqueConstraint('team_id', 'system_key', 'fix_class', 'fix_class_excl_pq', 'fix_reasons',
                            name='uq_cbomagilitygroup_team_group'),
    )
    op.create_table(
        'cbomregistersummary',
        sa.Column('id', sa.Integer(), nullable=False),
        sa.Column('team_id', sa.Integer(), nullable=False),
        sa.Column('q_grade', _s(2), nullable=False),
        sa.Column('q_reason', _s(32), nullable=False),
        sa.Column('family', _s(32), nullable=False),
        sa.Column('presence', _s(16), nullable=False),
        sa.Column('n', sa.Integer(), nullable=False),
        sa.ForeignKeyConstraint(['team_id'], ['team.id']),
        sa.PrimaryKeyConstraint('id'),
        sa.UniqueConstraint('team_id', 'q_grade', 'q_reason', 'family', 'presence',
                            name='uq_cbomregistersummary_team_group'),
    )
    op.create_table(
        'cbomestatecount',
        sa.Column('id', sa.Integer(), nullable=False),
        sa.Column('team_id', sa.Integer(), nullable=False),
        sa.Column('kind', _s(32), nullable=False),
        sa.Column('n', sa.Integer(), nullable=False),
        sa.ForeignKeyConstraint(['team_id'], ['team.id']),
        sa.PrimaryKeyConstraint('id'),
        sa.UniqueConstraint('team_id', 'kind', name='uq_cbomestatecount_team_kind'),
    )
    bind = op.get_bind()
    SUMMARY.install(bind)
    SUMMARY.rebuild(bind)


def downgrade() -> None:
    from backend.utilities.cbom_sources import estate_summary_ddl as SUMMARY

    bind = op.get_bind()
    for stmt in SUMMARY.drop_ddl(bind.dialect.name == "postgresql"):
        bind.execute(sa.text(stmt))
    op.drop_table('cbomestatecount')
    op.drop_table('cbomregistersummary')
    op.drop_table('cbomagilitygroup')
