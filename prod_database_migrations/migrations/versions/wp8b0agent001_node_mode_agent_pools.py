"""cbom scan nodes: agent mode and agent pool registration tokens (Helm DaemonSet)

Revision ID: wp8b0agent001
Revises: wp11a0integr001
Create Date: 2026-11-05 08:00:00.000000

* ``cbomnodepool``: one row per agent pool token (team, name, segment, token SHA-256, expiry, enrollment cap and
  count, revocation).  Pods of a DaemonSet enroll with it, each as its own node.
* ``cbomscannode.mode``: ``agentless`` (every existing node) or ``agent`` (collects only its own host and is never
  given a credential); ``cbomscannode.pool_id``: the pool an agent node enrolled with (SET NULL if it goes).
"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa
import sqlmodel


# revision identifiers, used by Alembic.
revision: str = 'wp8b0agent001'
down_revision: Union[str, Sequence[str], None] = 'wp11a0integr001'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    """Upgrade schema."""
    op.create_table(
        'cbomnodepool',
        sa.Column('id', sa.Integer(), nullable=False),
        sa.Column('team_id', sa.Integer(), nullable=False),
        sa.Column('owner_user_id', sa.Integer(), nullable=False),
        sa.Column('name', sqlmodel.sql.sqltypes.AutoString(length=64), nullable=False),
        sa.Column('segment', sqlmodel.sql.sqltypes.AutoString(length=64), nullable=False),
        sa.Column('token_hash', sqlmodel.sql.sqltypes.AutoString(length=64), nullable=False),
        sa.Column('expires_at', sa.DateTime(), nullable=False),
        sa.Column('max_enrollments', sa.Integer(), nullable=False),
        sa.Column('enrollments', sa.Integer(), nullable=False),
        sa.Column('revoked_at', sa.DateTime(), nullable=True),
        sa.Column('revoked_by_user_id', sa.Integer(), nullable=True),
        sa.Column('last_enrolled_at', sa.DateTime(), nullable=True),
        sa.Column('created_at', sa.DateTime(), nullable=True),
        sa.ForeignKeyConstraint(['team_id'], ['team.id']),
        sa.PrimaryKeyConstraint('id'),
    )
    op.create_index(op.f('ix_cbomnodepool_team_id'), 'cbomnodepool', ['team_id'], unique=False)
    op.create_index(op.f('ix_cbomnodepool_token_hash'), 'cbomnodepool', ['token_hash'], unique=True)
    op.add_column('cbomscannode', sa.Column('mode', sqlmodel.sql.sqltypes.AutoString(length=16),
                                            server_default='agentless', nullable=False))
    op.add_column('cbomscannode', sa.Column('pool_id', sa.Integer(), nullable=True))
    op.create_index(op.f('ix_cbomscannode_pool_id'), 'cbomscannode', ['pool_id'], unique=False)
    op.create_foreign_key('fk_cbomscannode_pool_id', 'cbomscannode', 'cbomnodepool', ['pool_id'], ['id'],
                          ondelete='SET NULL')


def downgrade() -> None:
    """Downgrade schema."""
    op.drop_constraint('fk_cbomscannode_pool_id', 'cbomscannode', type_='foreignkey')
    op.drop_index(op.f('ix_cbomscannode_pool_id'), table_name='cbomscannode')
    op.drop_column('cbomscannode', 'pool_id')
    op.drop_column('cbomscannode', 'mode')
    op.drop_index(op.f('ix_cbomnodepool_token_hash'), table_name='cbomnodepool')
    op.drop_index(op.f('ix_cbomnodepool_team_id'), table_name='cbomnodepool')
    op.drop_table('cbomnodepool')
