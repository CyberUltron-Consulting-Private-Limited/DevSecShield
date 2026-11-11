"""cbom fleet (F1.2): tag policies, typed credentials, managed sources and schedules

Revision ID: r6f12pol001
Revises: r6f12inv001
Create Date: 2026-11-11 12:10:00.000000

* ``cbomfleetpolicy``: a selector over tags and fields, a priority (higher first, then lower id), and an action
  (never scan, or collect with a transport, credential, node or segment, tier, batch size and schedule).
* ``cbomcredential``: a typed login (node key, password, SSH certificate, vault, SSH CA) with the non-secret fields of a
  Linux servers source; secrets encrypted, write-only.
* ``cbomcollectionsource``: ``managed_by_policy_id`` (indexed), ``credential_id``, ``batch_key`` (nullable; every
  existing source is a hand-made one).
* ``cbomcollectionschedule``: ``policy_id`` (indexed, nullable).
"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa
import sqlmodel


# revision identifiers, used by Alembic.
revision: str = 'r6f12pol001'
down_revision: Union[str, Sequence[str], None] = 'r6f12inv001'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def _common() -> list[sa.Column]:
    return [
        sa.Column('owner_user_id', sa.Integer(), nullable=True),
        sa.Column('updated_by_user_id', sa.Integer(), nullable=True),
        sa.Column('deleted_at', sa.DateTime(), nullable=True),
        sa.Column('row_version', sa.Integer(), nullable=False, server_default='1'),
        sa.Column('created_at', sa.DateTime(), nullable=True),
        sa.Column('last_updated', sa.DateTime(), nullable=True),
    ]


def upgrade() -> None:
    """Upgrade schema."""
    op.create_table(
        'cbomfleetpolicy',
        sa.Column('id', sa.Integer(), nullable=False),
        sa.Column('team_id', sa.Integer(), nullable=False),
        sa.Column('name', sqlmodel.sql.sqltypes.AutoString(length=64), nullable=False),
        sa.Column('enabled', sa.Boolean(), nullable=False, server_default=sa.true()),
        sa.Column('priority', sa.Integer(), nullable=False, server_default='100'),
        sa.Column('selector', sa.JSON(), nullable=True),
        sa.Column('action', sa.JSON(), nullable=True),
        *_common(),
        sa.ForeignKeyConstraint(['team_id'], ['team.id'], ondelete='CASCADE'),
        sa.PrimaryKeyConstraint('id'),
    )
    op.create_index(op.f('ix_cbomfleetpolicy_team_id'), 'cbomfleetpolicy', ['team_id'], unique=False)
    op.create_table(
        'cbomcredential',
        sa.Column('id', sa.Integer(), nullable=False),
        sa.Column('team_id', sa.Integer(), nullable=False),
        sa.Column('name', sqlmodel.sql.sqltypes.AutoString(length=64), nullable=False),
        sa.Column('credential_type', sqlmodel.sql.sqltypes.AutoString(length=16), nullable=False),
        sa.Column('config', sa.JSON(), nullable=True),
        sa.Column('secret_encrypted', sa.Text(), nullable=True),
        sa.Column('secret_fields', sa.JSON(), nullable=True),
        *_common(),
        sa.ForeignKeyConstraint(['team_id'], ['team.id'], ondelete='CASCADE'),
        sa.PrimaryKeyConstraint('id'),
    )
    op.create_index(op.f('ix_cbomcredential_team_id'), 'cbomcredential', ['team_id'], unique=False)
    op.add_column('cbomcollectionsource', sa.Column('managed_by_policy_id', sa.Integer(), nullable=True))
    op.add_column('cbomcollectionsource', sa.Column('credential_id', sa.Integer(), nullable=True))
    op.add_column('cbomcollectionsource', sa.Column('batch_key', sqlmodel.sql.sqltypes.AutoString(length=64),
                                                    nullable=True))
    op.create_index(op.f('ix_cbomcollectionsource_managed_by_policy_id'), 'cbomcollectionsource',
                    ['managed_by_policy_id'], unique=False)
    op.add_column('cbomcollectionschedule', sa.Column('policy_id', sa.Integer(), nullable=True))
    op.create_index(op.f('ix_cbomcollectionschedule_policy_id'), 'cbomcollectionschedule', ['policy_id'], unique=False)


def downgrade() -> None:
    """Downgrade schema."""
    op.drop_index(op.f('ix_cbomcollectionschedule_policy_id'), table_name='cbomcollectionschedule')
    op.drop_column('cbomcollectionschedule', 'policy_id')
    op.drop_index(op.f('ix_cbomcollectionsource_managed_by_policy_id'), table_name='cbomcollectionsource')
    op.drop_column('cbomcollectionsource', 'batch_key')
    op.drop_column('cbomcollectionsource', 'credential_id')
    op.drop_column('cbomcollectionsource', 'managed_by_policy_id')
    op.drop_index(op.f('ix_cbomcredential_team_id'), table_name='cbomcredential')
    op.drop_table('cbomcredential')
    op.drop_index(op.f('ix_cbomfleetpolicy_team_id'), table_name='cbomfleetpolicy')
    op.drop_table('cbomfleetpolicy')
