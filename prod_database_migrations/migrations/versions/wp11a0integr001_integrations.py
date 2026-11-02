"""integrations: team integrations (ServiceNow, syslog, Splunk HEC, webhook, OSCAL push) and their delivery queue

Revision ID: wp11a0integr001
Revises: wp10a0drift001
Create Date: 2026-11-02 21:00:00.000000

* ``teamintegration``: one row per (team, kind); config JSON, secrets as one Fernet token, last test, the dispatcher
  lease and back-off.
* ``integrationdelivery``: one row per (integration, event); at least once (``event_uid`` is stable), dead-letter
  status, short result (never a response body).
"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = 'wp11a0integr001'
down_revision: Union[str, Sequence[str], None] = 'wp10a0drift001'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    """Upgrade schema."""
    op.create_table(
        'teamintegration',
        sa.Column('id', sa.Integer(), primary_key=True),
        sa.Column('team_id', sa.Integer(), sa.ForeignKey('team.id'), nullable=False),
        sa.Column('kind', sa.String(length=16), nullable=False),
        sa.Column('enabled', sa.Boolean(), nullable=False),
        sa.Column('config', sa.JSON(), nullable=True),
        sa.Column('secret_encrypted', sa.Text(), nullable=True),
        sa.Column('secret_fields', sa.JSON(), nullable=True),
        sa.Column('last_test_status', sa.String(length=16), nullable=False),
        sa.Column('last_test_at', sa.DateTime(), nullable=True),
        sa.Column('last_test_message', sa.String(length=255), nullable=True),
        sa.Column('lease_until', sa.DateTime(), nullable=True),
        sa.Column('failures', sa.Integer(), nullable=False),
        sa.Column('next_attempt_at', sa.DateTime(), nullable=True),
        sa.Column('last_delivery_at', sa.DateTime(), nullable=True),
        sa.Column('last_error', sa.String(length=255), nullable=True),
        sa.Column('updated_by_user_id', sa.Integer(), nullable=True),
        sa.Column('row_version', sa.Integer(), nullable=False),
        sa.Column('created_at', sa.DateTime(), nullable=True),
        sa.Column('last_updated', sa.DateTime(), nullable=True),
        sa.UniqueConstraint('team_id', 'kind', name='uq_teamintegration_team_kind'),
    )
    op.create_index('ix_teamintegration_team_id', 'teamintegration', ['team_id'])

    op.create_table(
        'integrationdelivery',
        sa.Column('id', sa.Integer(), primary_key=True),
        sa.Column('team_id', sa.Integer(), sa.ForeignKey('team.id'), nullable=False),
        sa.Column('integration_id', sa.Integer(), sa.ForeignKey('teamintegration.id', ondelete='CASCADE'),
                  nullable=False),
        sa.Column('kind', sa.String(length=16), nullable=False),
        sa.Column('event_uid', sa.String(length=36), nullable=False),
        sa.Column('event_type', sa.String(length=32), nullable=False),
        sa.Column('payload', sa.JSON(), nullable=True),
        sa.Column('status', sa.String(length=16), nullable=False),
        sa.Column('attempts', sa.Integer(), nullable=False),
        sa.Column('last_attempt_at', sa.DateTime(), nullable=True),
        sa.Column('delivered_at', sa.DateTime(), nullable=True),
        sa.Column('last_result', sa.String(length=255), nullable=True),
        sa.Column('external_ref', sa.String(length=64), nullable=True),
        sa.Column('created_at', sa.DateTime(), nullable=True),
        sa.UniqueConstraint('integration_id', 'event_uid', name='uq_integrationdelivery_event'),
    )
    for column in ('team_id', 'integration_id', 'status', 'created_at'):
        op.create_index(f'ix_integrationdelivery_{column}', 'integrationdelivery', [column])


def downgrade() -> None:
    """Downgrade schema."""
    for column in ('team_id', 'integration_id', 'status', 'created_at'):
        op.drop_index(f'ix_integrationdelivery_{column}', table_name='integrationdelivery')
    op.drop_table('integrationdelivery')
    op.drop_index('ix_teamintegration_team_id', table_name='teamintegration')
    op.drop_table('teamintegration')
