"""outputs B: stable source ids, schedules, drift events and remediation assignments

Revision ID: wp10a0drift001
Revises: wp5a0node001
Create Date: 2026-11-02 18:00:00.000000

* ``cbomcollectionsource.source_uid``: a stable id that survives deletion (snapshotted on collect jobs); existing rows
  get a random one here.
* ``cbomcollectionrun.schedule_id`` / ``drift_at``: the schedule that started a run, and when its drift events were
  recorded (recorded once).
* ``cbomcollectionschedule``: recurring runs (daily / weekly / monthly in the team's window time zone).
* ``cbomdriftevent``: finding opened / resolved, asset new / removed, certificate renewed / expiring (idempotent per
  ``(team_id, dedupe_key)``).
* ``cbomremediationassignment``: wave, owner, target date and status per stable asset identity.
"""
import uuid
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = 'wp10a0drift001'
down_revision: Union[str, Sequence[str], None] = 'wp5a0node001'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    """Upgrade schema."""
    op.add_column('cbomcollectionsource', sa.Column('source_uid', sa.String(length=32), nullable=True))
    op.create_index('ix_cbomcollectionsource_source_uid', 'cbomcollectionsource', ['source_uid'])
    bind = op.get_bind()
    ids = [row[0] for row in bind.execute(sa.text("SELECT id FROM cbomcollectionsource WHERE source_uid IS NULL"))]
    for source_id in ids:
        bind.execute(sa.text("UPDATE cbomcollectionsource SET source_uid = :uid WHERE id = :id"),
                     {"uid": uuid.uuid4().hex, "id": source_id})

    op.add_column('cbomcollectionrun', sa.Column('schedule_id', sa.Integer(), nullable=True))
    op.add_column('cbomcollectionrun', sa.Column('drift_at', sa.DateTime(), nullable=True))
    op.create_index('ix_cbomcollectionrun_schedule_id', 'cbomcollectionrun', ['schedule_id'])

    op.create_table(
        'cbomcollectionschedule',
        sa.Column('id', sa.Integer(), primary_key=True),
        sa.Column('team_id', sa.Integer(), sa.ForeignKey('team.id'), nullable=False),
        sa.Column('owner_user_id', sa.Integer(), nullable=False),
        sa.Column('updated_by_user_id', sa.Integer(), nullable=True),
        sa.Column('name', sa.String(length=64), nullable=False),
        sa.Column('enabled', sa.Boolean(), nullable=False),
        sa.Column('frequency', sa.String(length=8), nullable=False),
        sa.Column('time_of_day', sa.String(length=5), nullable=False),
        sa.Column('weekday', sa.Integer(), nullable=True),
        sa.Column('monthday', sa.Integer(), nullable=True),
        sa.Column('include', sa.JSON(), nullable=True),
        sa.Column('source_ids', sa.JSON(), nullable=True),
        sa.Column('min_criticality', sa.String(length=8), nullable=True),
        sa.Column('soc_ack_by', sa.Integer(), nullable=True),
        sa.Column('soc_ack_at', sa.DateTime(), nullable=True),
        sa.Column('next_run_at', sa.DateTime(), nullable=True),
        sa.Column('last_slot', sa.String(length=32), nullable=True),
        sa.Column('last_fired_at', sa.DateTime(), nullable=True),
        sa.Column('last_run_id', sa.Integer(), nullable=True),
        sa.Column('last_status', sa.String(length=16), nullable=True),
        sa.Column('last_message', sa.String(length=512), nullable=True),
        sa.Column('row_version', sa.Integer(), nullable=False),
        sa.Column('created_at', sa.DateTime(), nullable=True),
        sa.Column('last_updated', sa.DateTime(), nullable=True),
    )
    op.create_index('ix_cbomcollectionschedule_team_id', 'cbomcollectionschedule', ['team_id'])
    op.create_index('ix_cbomcollectionschedule_next_run_at', 'cbomcollectionschedule', ['next_run_at'])

    op.create_table(
        'cbomdriftevent',
        sa.Column('id', sa.Integer(), primary_key=True),
        sa.Column('team_id', sa.Integer(), sa.ForeignKey('team.id'), nullable=False),
        sa.Column('at', sa.DateTime(), nullable=True),
        sa.Column('scope', sa.String(length=8), nullable=False),
        sa.Column('kind', sa.String(length=24), nullable=False),
        sa.Column('run_id', sa.Integer(), nullable=True),
        sa.Column('baseline_run_id', sa.Integer(), nullable=True),
        sa.Column('scan_id', sa.Integer(), nullable=True),
        sa.Column('baseline_scan_id', sa.Integer(), nullable=True),
        sa.Column('source_ref', sa.String(length=255), nullable=False),
        sa.Column('source_name', sa.String(length=255), nullable=True),
        sa.Column('asset_key', sa.String(length=64), nullable=True),
        sa.Column('asset_label', sa.String(length=255), nullable=True),
        sa.Column('code', sa.String(length=48), nullable=True),
        sa.Column('severity', sa.String(length=16), nullable=True),
        sa.Column('detail', sa.JSON(), nullable=True),
        sa.Column('dedupe_key', sa.String(length=64), nullable=False),
        sa.Column('forwarded_at', sa.DateTime(), nullable=True),
        sa.UniqueConstraint('team_id', 'dedupe_key', name='uq_cbomdriftevent_team_key'),
    )
    for column in ('team_id', 'at', 'run_id', 'scan_id', 'asset_key'):
        op.create_index(f'ix_cbomdriftevent_{column}', 'cbomdriftevent', [column])

    op.create_table(
        'cbomremediationassignment',
        sa.Column('id', sa.Integer(), primary_key=True),
        sa.Column('team_id', sa.Integer(), sa.ForeignKey('team.id'), nullable=False),
        sa.Column('asset_key', sa.String(length=64), nullable=False),
        sa.Column('scope', sa.String(length=8), nullable=False),
        sa.Column('source_ref', sa.String(length=255), nullable=False),
        sa.Column('label', sa.String(length=255), nullable=True),
        sa.Column('wave', sa.Integer(), nullable=True),
        sa.Column('owner', sa.String(length=128), nullable=True),
        sa.Column('target_date', sa.String(length=10), nullable=True),
        sa.Column('status', sa.String(length=16), nullable=False),
        sa.Column('note', sa.String(length=500), nullable=True),
        sa.Column('updated_by_user_id', sa.Integer(), nullable=True),
        sa.Column('row_version', sa.Integer(), nullable=False),
        sa.Column('created_at', sa.DateTime(), nullable=True),
        sa.Column('last_updated', sa.DateTime(), nullable=True),
        sa.UniqueConstraint('team_id', 'asset_key', name='uq_cbomremediation_team_asset'),
    )
    op.create_index('ix_cbomremediationassignment_team_id', 'cbomremediationassignment', ['team_id'])


def downgrade() -> None:
    """Downgrade schema."""
    op.drop_index('ix_cbomremediationassignment_team_id', table_name='cbomremediationassignment')
    op.drop_table('cbomremediationassignment')
    for column in ('team_id', 'at', 'run_id', 'scan_id', 'asset_key'):
        op.drop_index(f'ix_cbomdriftevent_{column}', table_name='cbomdriftevent')
    op.drop_table('cbomdriftevent')
    op.drop_index('ix_cbomcollectionschedule_next_run_at', table_name='cbomcollectionschedule')
    op.drop_index('ix_cbomcollectionschedule_team_id', table_name='cbomcollectionschedule')
    op.drop_table('cbomcollectionschedule')
    op.drop_index('ix_cbomcollectionrun_schedule_id', table_name='cbomcollectionrun')
    op.drop_column('cbomcollectionrun', 'drift_at')
    op.drop_column('cbomcollectionrun', 'schedule_id')
    op.drop_index('ix_cbomcollectionsource_source_uid', table_name='cbomcollectionsource')
    op.drop_column('cbomcollectionsource', 'source_uid')
