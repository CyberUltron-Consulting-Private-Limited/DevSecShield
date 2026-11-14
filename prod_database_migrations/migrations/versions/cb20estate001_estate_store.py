"""cbom estate store (CB-20 PR-1): ``cbomestatesource``, ``cbomestateasset``, ``cbomestateobservation``

Revision ID: cb20estate001
Revises: r6f13trn001
Create Date: 2026-11-14 12:00:00.000000

Three new tables, no change to existing ones (so no lock on a busy table): one row per (team, source) with the newest
job written, one per (team, cross-source asset key) and one per (team, asset key, source) with the latest observation.
Indexes: the unique ``(team_id, asset_key)`` (the keyset page and the register's join), ``(team_id, asset_type,
asset_key)`` and ``(team_id, presence, asset_key)`` for the filtered pages, ``(team_id, updated_run_id)`` for "what did
this run change", ``(team_id, source_ref)`` for the per-source read of the stored observations. The data is filled by
``python -m backend.utilities.cbom_sources.estate backfill`` (idempotent), then by every run's drift recording.
"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa
import sqlmodel


revision: str = 'cb20estate001'
down_revision: Union[str, Sequence[str], None] = 'r6f13trn001'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def _s(length: int):
    return sqlmodel.sql.sqltypes.AutoString(length=length)


def upgrade() -> None:
    op.create_table(
        'cbomestatesource',
        sa.Column('id', sa.Integer(), nullable=False),
        sa.Column('team_id', sa.Integer(), nullable=False),
        sa.Column('source_ref', _s(255), nullable=False),
        sa.Column('source_id', sa.Integer(), nullable=True),
        sa.Column('source_name', _s(255), nullable=True),
        sa.Column('source_kind', _s(32), nullable=True),
        sa.Column('latest_job_id', sa.Integer(), nullable=False),
        sa.Column('latest_attempt', sa.Integer(), nullable=False),
        sa.Column('latest_run_id', sa.Integer(), nullable=True),
        sa.Column('latest_at', sa.DateTime(), nullable=True),
        sa.Column('latest_status', _s(16), nullable=False),
        sa.Column('latest_comparable', sa.Boolean(), nullable=False),
        sa.Column('updated_at', sa.DateTime(), nullable=True),
        sa.ForeignKeyConstraint(['team_id'], ['team.id']),
        sa.PrimaryKeyConstraint('id'),
        sa.UniqueConstraint('team_id', 'source_ref', name='uq_cbomestatesource_team_source'),
    )
    op.create_table(
        'cbomestateasset',
        sa.Column('id', sa.Integer(), nullable=False),
        sa.Column('team_id', sa.Integer(), nullable=False),
        sa.Column('asset_key', _s(64), nullable=False),
        sa.Column('key_kind', _s(16), nullable=False),
        sa.Column('key_basis', _s(16), nullable=True),
        sa.Column('asset_type', _s(32), nullable=False),
        sa.Column('label', _s(255), nullable=True),
        sa.Column('presence', _s(16), nullable=False),
        sa.Column('presence_reason', _s(300), nullable=True),
        sa.Column('first_seen_run_id', sa.Integer(), nullable=True),
        sa.Column('first_seen_at', sa.DateTime(), nullable=True),
        sa.Column('updated_run_id', sa.Integer(), nullable=False),
        sa.Column('updated_at', sa.DateTime(), nullable=True),
        sa.ForeignKeyConstraint(['team_id'], ['team.id']),
        sa.PrimaryKeyConstraint('id'),
        sa.UniqueConstraint('team_id', 'asset_key', name='uq_cbomestateasset_team_key'),
    )
    op.create_index('ix_cbomestateasset_team_type_key', 'cbomestateasset', ['team_id', 'asset_type', 'asset_key'])
    op.create_index('ix_cbomestateasset_team_presence_key', 'cbomestateasset', ['team_id', 'presence', 'asset_key'])
    op.create_index('ix_cbomestateasset_team_updated', 'cbomestateasset', ['team_id', 'updated_run_id'])
    op.create_table(
        'cbomestateobservation',
        sa.Column('id', sa.Integer(), nullable=False),
        sa.Column('team_id', sa.Integer(), nullable=False),
        sa.Column('asset_key', _s(64), nullable=False),
        sa.Column('source_ref', _s(255), nullable=False),
        sa.Column('observation_key', _s(40), nullable=False),
        sa.Column('row_key', _s(64), nullable=False),
        sa.Column('asset_type', _s(32), nullable=False),
        sa.Column('target', _s(255), nullable=True),
        sa.Column('location', _s(512), nullable=True),
        sa.Column('occurrences', sa.Integer(), nullable=False),
        sa.Column('presence', _s(16), nullable=False),
        sa.Column('presence_reason', _s(300), nullable=True),
        sa.Column('seen_job_id', sa.Integer(), nullable=False),
        sa.Column('seen_attempt', sa.Integer(), nullable=False),
        sa.Column('seen_run_id', sa.Integer(), nullable=True),
        sa.Column('seen_at', sa.DateTime(), nullable=True),
        sa.Column('first_seen_run_id', sa.Integer(), nullable=True),
        sa.Column('state_run_id', sa.Integer(), nullable=False),
        sa.Column('updated_at', sa.DateTime(), nullable=True),
        sa.ForeignKeyConstraint(['team_id'], ['team.id']),
        sa.PrimaryKeyConstraint('id'),
        sa.UniqueConstraint('team_id', 'asset_key', 'source_ref', name='uq_cbomestateobs_team_key_source'),
    )
    op.create_index('ix_cbomestateobs_team_source', 'cbomestateobservation', ['team_id', 'source_ref'])


def downgrade() -> None:
    op.drop_index('ix_cbomestateobs_team_source', table_name='cbomestateobservation')
    op.drop_table('cbomestateobservation')
    op.drop_index('ix_cbomestateasset_team_updated', table_name='cbomestateasset')
    op.drop_index('ix_cbomestateasset_team_presence_key', table_name='cbomestateasset')
    op.drop_index('ix_cbomestateasset_team_type_key', table_name='cbomestateasset')
    op.drop_table('cbomestateasset')
    op.drop_table('cbomestatesource')
