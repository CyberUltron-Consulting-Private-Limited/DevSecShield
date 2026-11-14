"""cbom estate correlation (engine step 3): ``cbomestatelink`` (an estate asset and the code / SBOM scan component
that uses it) and ``cbomestatelinkstate`` (per team: the fingerprint the links were built from)

Revision ID: cbcorr001
Revises: cb226apikey001
Create Date: 2026-11-15 12:00:00.000000

Two new tables, no change to existing ones. The links are derived data: ``estate_links.refresh`` rebuilds them when a
team's latest scans or estate change; the downgrade drops both tables.
"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa
import sqlmodel


revision: str = 'cbcorr001'
down_revision: Union[str, Sequence[str], None] = 'cb226apikey001'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def _s(length: int):
    return sqlmodel.sql.sqltypes.AutoString(length=length)


def upgrade() -> None:
    op.create_table(
        'cbomestatelink',
        sa.Column('id', sa.Integer(), nullable=False),
        sa.Column('team_id', sa.Integer(), nullable=False),
        sa.Column('asset_key', _s(64), nullable=False),
        sa.Column('kind', _s(8), nullable=False),
        sa.Column('scan_id', sa.Integer(), nullable=False),
        sa.Column('scan_title', _s(255), nullable=True),
        sa.Column('component', _s(255), nullable=False),
        sa.Column('purl', _s(512), nullable=True),
        sa.Column('match', _s(16), nullable=False),
        sa.ForeignKeyConstraint(['team_id'], ['team.id']),
        sa.PrimaryKeyConstraint('id'),
    )
    op.create_index('ix_cbomestatelink_team_key', 'cbomestatelink', ['team_id', 'asset_key'])
    op.create_table(
        'cbomestatelinkstate',
        sa.Column('id', sa.Integer(), nullable=False),
        sa.Column('team_id', sa.Integer(), nullable=False),
        sa.Column('fingerprint', _s(64), nullable=False),
        sa.Column('links', sa.Integer(), nullable=False),
        sa.Column('refreshed_at', sa.DateTime(), nullable=True),
        sa.ForeignKeyConstraint(['team_id'], ['team.id']),
        sa.PrimaryKeyConstraint('id'),
        sa.UniqueConstraint('team_id', name='uq_cbomestatelinkstate_team'),
    )


def downgrade() -> None:
    op.drop_table('cbomestatelinkstate')
    op.drop_index('ix_cbomestatelink_team_key', table_name='cbomestatelink')
    op.drop_table('cbomestatelink')
