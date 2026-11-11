"""code repositories at scale (F3): SCM connections, repository inventory, scan policies, runs, the fair queue and
the cross-repository finding roll-up

Revision ID: f3a0scm001
Revises: rv6p1nodename001
Create Date: 2026-11-11 13:00:00.000000

Additive only: seven new tables, no change to existing ones. Downgrade drops them (children first).
"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa
import sqlmodel


revision: str = 'f3a0scm001'
down_revision: Union[str, Sequence[str], None] = 'rv6p1nodename001'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None

S = sqlmodel.sql.sqltypes.AutoString


def upgrade() -> None:
    """Upgrade schema."""
    op.create_table('scmconnection',
    sa.Column('id', sa.Integer(), nullable=False),
    sa.Column('team_id', sa.Integer(), nullable=False),
    sa.Column('owner_user_id', sa.Integer(), nullable=False),
    sa.Column('updated_by_user_id', sa.Integer(), nullable=True),
    sa.Column('provider', S(length=16), nullable=False),
    sa.Column('auth_kind', S(length=16), nullable=False),
    sa.Column('name', S(length=64), nullable=False),
    sa.Column('name_lower', S(length=64), nullable=False),
    sa.Column('api_base', S(length=255), nullable=False),
    sa.Column('scope_kind', S(length=16), nullable=False),
    sa.Column('scope_name', S(length=255), nullable=False),
    sa.Column('config', sa.JSON(), nullable=True),
    sa.Column('filters', sa.JSON(), nullable=True),
    sa.Column('secret_encrypted', sa.Text(), nullable=True),
    sa.Column('secret_fields', sa.JSON(), nullable=True),
    sa.Column('webhook_uid', S(length=32), nullable=False),
    sa.Column('webhook_secret_encrypted', sa.Text(), nullable=True),
    sa.Column('enabled', sa.Boolean(), nullable=False),
    sa.Column('sync_interval_min', sa.Integer(), nullable=False),
    sa.Column('sync_status', S(length=16), nullable=False),
    sa.Column('sync_lease_until', sa.DateTime(), nullable=True),
    sa.Column('sync_requested_at', sa.DateTime(), nullable=True),
    sa.Column('last_sync_at', sa.DateTime(), nullable=True),
    sa.Column('next_sync_at', sa.DateTime(), nullable=True),
    sa.Column('last_sync_summary', sa.JSON(), nullable=True),
    sa.Column('last_sync_error', S(length=512), nullable=True),
    sa.Column('last_test_status', S(length=16), nullable=False),
    sa.Column('last_test_at', sa.DateTime(), nullable=True),
    sa.Column('last_test_message', S(length=255), nullable=True),
    sa.Column('row_version', sa.Integer(), nullable=False),
    sa.Column('created_at', sa.DateTime(), nullable=True),
    sa.Column('last_updated', sa.DateTime(), nullable=True),
    sa.ForeignKeyConstraint(['team_id'], ['team.id'], ),
    sa.PrimaryKeyConstraint('id'),
    sa.UniqueConstraint('team_id', 'name_lower', name='uq_scmconnection_team_name')
    )
    op.create_index(op.f('ix_scmconnection_team_id'), 'scmconnection', ['team_id'], unique=False)
    op.create_index(op.f('ix_scmconnection_webhook_uid'), 'scmconnection', ['webhook_uid'], unique=True)
    op.create_index(op.f('ix_scmconnection_next_sync_at'), 'scmconnection', ['next_sync_at'], unique=False)

    op.create_table('scmrepository',
    sa.Column('id', sa.Integer(), nullable=False),
    sa.Column('team_id', sa.Integer(), nullable=False),
    sa.Column('connection_id', sa.Integer(), nullable=False),
    sa.Column('external_id', S(length=64), nullable=False),
    sa.Column('full_name', S(length=255), nullable=False),
    sa.Column('name', S(length=255), nullable=False),
    sa.Column('owner', S(length=255), nullable=False),
    sa.Column('web_url', S(length=512), nullable=False),
    sa.Column('clone_url', S(length=512), nullable=False),
    sa.Column('default_branch', S(length=255), nullable=False),
    sa.Column('visibility', S(length=16), nullable=False),
    sa.Column('archived', sa.Boolean(), nullable=False),
    sa.Column('fork', sa.Boolean(), nullable=False),
    sa.Column('language', S(length=64), nullable=True),
    sa.Column('topics', sa.JSON(), nullable=True),
    sa.Column('size_kb', sa.Integer(), nullable=False),
    sa.Column('pushed_at', sa.DateTime(), nullable=True),
    sa.Column('in_scope', sa.Boolean(), nullable=False),
    sa.Column('scope_reason', S(length=64), nullable=False),
    sa.Column('manual_state', S(length=8), nullable=True),
    sa.Column('policy_id', sa.Integer(), nullable=True),
    sa.Column('first_seen_at', sa.DateTime(), nullable=True),
    sa.Column('last_seen_at', sa.DateTime(), nullable=True),
    sa.Column('removed_at', sa.DateTime(), nullable=True),
    sa.Column('last_scan_at', sa.DateTime(), nullable=True),
    sa.Column('last_scan_summary', sa.JSON(), nullable=True),
    sa.Column('row_version', sa.Integer(), nullable=False),
    sa.ForeignKeyConstraint(['connection_id'], ['scmconnection.id'], ondelete='CASCADE'),
    sa.ForeignKeyConstraint(['team_id'], ['team.id'], ),
    sa.PrimaryKeyConstraint('id'),
    sa.UniqueConstraint('connection_id', 'external_id', name='uq_scmrepository_connection_external')
    )
    op.create_index(op.f('ix_scmrepository_team_id'), 'scmrepository', ['team_id'], unique=False)
    op.create_index(op.f('ix_scmrepository_connection_id'), 'scmrepository', ['connection_id'], unique=False)
    op.create_index(op.f('ix_scmrepository_full_name'), 'scmrepository', ['full_name'], unique=False)
    op.create_index(op.f('ix_scmrepository_in_scope'), 'scmrepository', ['in_scope'], unique=False)

    op.create_table('scmscanpolicy',
    sa.Column('id', sa.Integer(), nullable=False),
    sa.Column('team_id', sa.Integer(), nullable=False),
    sa.Column('owner_user_id', sa.Integer(), nullable=False),
    sa.Column('updated_by_user_id', sa.Integer(), nullable=True),
    sa.Column('name', S(length=64), nullable=False),
    sa.Column('name_lower', S(length=64), nullable=False),
    sa.Column('position', sa.Integer(), nullable=False),
    sa.Column('enabled', sa.Boolean(), nullable=False),
    sa.Column('selector', sa.JSON(), nullable=True),
    sa.Column('products', sa.JSON(), nullable=True),
    sa.Column('branch', S(length=255), nullable=False),
    sa.Column('on_push', sa.Boolean(), nullable=False),
    sa.Column('schedule', sa.JSON(), nullable=True),
    sa.Column('options', sa.JSON(), nullable=True),
    sa.Column('next_run_at', sa.DateTime(), nullable=True),
    sa.Column('last_fired_at', sa.DateTime(), nullable=True),
    sa.Column('last_run_id', sa.Integer(), nullable=True),
    sa.Column('last_status', S(length=16), nullable=True),
    sa.Column('last_message', S(length=512), nullable=True),
    sa.Column('row_version', sa.Integer(), nullable=False),
    sa.Column('created_at', sa.DateTime(), nullable=True),
    sa.Column('last_updated', sa.DateTime(), nullable=True),
    sa.ForeignKeyConstraint(['team_id'], ['team.id'], ),
    sa.PrimaryKeyConstraint('id'),
    sa.UniqueConstraint('team_id', 'name_lower', name='uq_scmscanpolicy_team_name')
    )
    op.create_index(op.f('ix_scmscanpolicy_team_id'), 'scmscanpolicy', ['team_id'], unique=False)
    op.create_index(op.f('ix_scmscanpolicy_next_run_at'), 'scmscanpolicy', ['next_run_at'], unique=False)

    op.create_table('scmscanrun',
    sa.Column('id', sa.Integer(), nullable=False),
    sa.Column('team_id', sa.Integer(), nullable=False),
    sa.Column('owner_user_id', sa.Integer(), nullable=False),
    sa.Column('trigger', S(length=16), nullable=False),
    sa.Column('policy_id', sa.Integer(), nullable=True),
    sa.Column('client_request_id', S(length=64), nullable=False),
    sa.Column('status', S(length=16), nullable=False),
    sa.Column('totals', sa.JSON(), nullable=True),
    sa.Column('credits_c', sa.Integer(), nullable=False),
    sa.Column('refunded_c', sa.Integer(), nullable=False),
    sa.Column('created_at', sa.DateTime(), nullable=True),
    sa.Column('finished_at', sa.DateTime(), nullable=True),
    sa.ForeignKeyConstraint(['team_id'], ['team.id'], ),
    sa.PrimaryKeyConstraint('id'),
    sa.UniqueConstraint('team_id', 'client_request_id', name='uq_scmscanrun_team_request')
    )
    op.create_index(op.f('ix_scmscanrun_team_id'), 'scmscanrun', ['team_id'], unique=False)
    op.create_index(op.f('ix_scmscanrun_policy_id'), 'scmscanrun', ['policy_id'], unique=False)

    op.create_table('scmscanrequest',
    sa.Column('id', sa.Integer(), nullable=False),
    sa.Column('team_id', sa.Integer(), nullable=False),
    sa.Column('run_id', sa.Integer(), nullable=True),
    sa.Column('repo_id', sa.Integer(), nullable=False),
    sa.Column('owner_user_id', sa.Integer(), nullable=False),
    sa.Column('product', S(length=16), nullable=False),
    sa.Column('branch', S(length=255), nullable=False),
    sa.Column('trigger', S(length=16), nullable=False),
    sa.Column('priority', sa.Integer(), nullable=False),
    sa.Column('status', S(length=16), nullable=False),
    sa.Column('dedupe_key', S(length=64), nullable=False),
    sa.Column('commit_sha', S(length=64), nullable=True),
    sa.Column('credits_c', sa.Integer(), nullable=False),
    sa.Column('refunded', sa.Boolean(), nullable=False),
    sa.Column('scan_id', sa.Integer(), nullable=True),
    sa.Column('task_id', S(length=64), nullable=True),
    sa.Column('attempts', sa.Integer(), nullable=False),
    sa.Column('error', S(length=255), nullable=True),
    sa.Column('enqueued_at', sa.DateTime(), nullable=True),
    sa.Column('dispatched_at', sa.DateTime(), nullable=True),
    sa.Column('finished_at', sa.DateTime(), nullable=True),
    sa.ForeignKeyConstraint(['repo_id'], ['scmrepository.id'], ondelete='CASCADE'),
    sa.ForeignKeyConstraint(['run_id'], ['scmscanrun.id'], ondelete='CASCADE'),
    sa.ForeignKeyConstraint(['team_id'], ['team.id'], ),
    sa.PrimaryKeyConstraint('id'),
    sa.UniqueConstraint('team_id', 'dedupe_key', name='uq_scmscanrequest_team_dedupe')
    )
    op.create_index(op.f('ix_scmscanrequest_team_id'), 'scmscanrequest', ['team_id'], unique=False)
    op.create_index(op.f('ix_scmscanrequest_run_id'), 'scmscanrequest', ['run_id'], unique=False)
    op.create_index(op.f('ix_scmscanrequest_repo_id'), 'scmscanrequest', ['repo_id'], unique=False)
    op.create_index(op.f('ix_scmscanrequest_status'), 'scmscanrequest', ['status'], unique=False)
    op.create_index(op.f('ix_scmscanrequest_scan_id'), 'scmscanrequest', ['scan_id'], unique=False)
    op.create_index('ix_scmscanrequest_queue', 'scmscanrequest', ['status', 'team_id', 'priority', 'id'], unique=False)

    op.create_table('scmfinding',
    sa.Column('id', sa.Integer(), nullable=False),
    sa.Column('team_id', sa.Integer(), nullable=False),
    sa.Column('product', S(length=16), nullable=False),
    sa.Column('fingerprint', S(length=64), nullable=False),
    sa.Column('title', S(length=255), nullable=False),
    sa.Column('severity', S(length=16), nullable=False),
    sa.Column('key_fields', sa.JSON(), nullable=True),
    sa.Column('repo_count', sa.Integer(), nullable=False),
    sa.Column('occurrence_count', sa.Integer(), nullable=False),
    sa.Column('first_seen_at', sa.DateTime(), nullable=True),
    sa.Column('last_seen_at', sa.DateTime(), nullable=True),
    sa.Column('resolved_at', sa.DateTime(), nullable=True),
    sa.ForeignKeyConstraint(['team_id'], ['team.id'], ),
    sa.PrimaryKeyConstraint('id'),
    sa.UniqueConstraint('team_id', 'product', 'fingerprint', name='uq_scmfinding_team_product_fp')
    )
    op.create_index(op.f('ix_scmfinding_team_id'), 'scmfinding', ['team_id'], unique=False)

    op.create_table('scmfindingoccurrence',
    sa.Column('id', sa.Integer(), nullable=False),
    sa.Column('team_id', sa.Integer(), nullable=False),
    sa.Column('finding_id', sa.Integer(), nullable=False),
    sa.Column('repo_id', sa.Integer(), nullable=False),
    sa.Column('product', S(length=16), nullable=False),
    sa.Column('scan_id', sa.Integer(), nullable=True),
    sa.Column('count', sa.Integer(), nullable=False),
    sa.Column('locations', sa.JSON(), nullable=True),
    sa.Column('last_seen_at', sa.DateTime(), nullable=True),
    sa.ForeignKeyConstraint(['finding_id'], ['scmfinding.id'], ondelete='CASCADE'),
    sa.ForeignKeyConstraint(['repo_id'], ['scmrepository.id'], ondelete='CASCADE'),
    sa.ForeignKeyConstraint(['team_id'], ['team.id'], ),
    sa.PrimaryKeyConstraint('id'),
    sa.UniqueConstraint('finding_id', 'repo_id', name='uq_scmfindingoccurrence_finding_repo')
    )
    op.create_index(op.f('ix_scmfindingoccurrence_team_id'), 'scmfindingoccurrence', ['team_id'], unique=False)
    op.create_index(op.f('ix_scmfindingoccurrence_finding_id'), 'scmfindingoccurrence', ['finding_id'], unique=False)
    op.create_index(op.f('ix_scmfindingoccurrence_repo_id'), 'scmfindingoccurrence', ['repo_id'], unique=False)


def downgrade() -> None:
    """Downgrade schema."""
    op.drop_table('scmfindingoccurrence')
    op.drop_table('scmfinding')
    op.drop_index('ix_scmscanrequest_queue', table_name='scmscanrequest')
    op.drop_table('scmscanrequest')
    op.drop_table('scmscanrun')
    op.drop_table('scmscanpolicy')
    op.drop_table('scmrepository')
    op.drop_table('scmconnection')
