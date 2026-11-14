"""cbom API keys (issue #226): team-scoped, hash-only keys for scripted onboarding

Revision ID: cb226apikey001
Revises: cb23register001
Create Date: 2026-11-14 20:00:00.000000

* ``cbomapikey``: one row per key: team, name, scopes (JSON list), the SHA-256 of the secret (``key_hash``, unique:
  the lookup), the secret's last four characters (``hint``), creator, created / expires / revoked / last used.  The
  secret itself is never stored.
* ``ix_cbomapikey_team_created``: the team's key list.

A new, empty table: nothing is backfilled.
"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa
import sqlmodel


# revision identifiers, used by Alembic.
revision: str = 'cb226apikey001'
down_revision: Union[str, Sequence[str], None] = 'cb23register001'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    """Upgrade schema."""
    op.create_table(
        'cbomapikey',
        sa.Column('id', sa.Integer(), nullable=False),
        sa.Column('team_id', sa.Integer(), nullable=False),
        sa.Column('name', sqlmodel.sql.sqltypes.AutoString(length=64), nullable=False),
        sa.Column('scopes', sa.JSON(), nullable=True),
        sa.Column('key_hash', sqlmodel.sql.sqltypes.AutoString(length=64), nullable=False),
        sa.Column('hint', sqlmodel.sql.sqltypes.AutoString(length=4), nullable=False),
        sa.Column('created_by_user_id', sa.Integer(), nullable=False),
        sa.Column('created_at', sa.DateTime(), nullable=True),
        sa.Column('expires_at', sa.DateTime(), nullable=True),
        sa.Column('revoked_at', sa.DateTime(), nullable=True),
        sa.Column('revoked_by_user_id', sa.Integer(), nullable=True),
        sa.Column('last_used_at', sa.DateTime(), nullable=True),
        sa.ForeignKeyConstraint(['team_id'], ['team.id']),
        sa.PrimaryKeyConstraint('id'),
        sa.UniqueConstraint('key_hash'),
    )
    op.create_index(op.f('ix_cbomapikey_team_id'), 'cbomapikey', ['team_id'], unique=False)
    op.create_index('ix_cbomapikey_team_created', 'cbomapikey', ['team_id', 'created_at'], unique=False)


def downgrade() -> None:
    """Downgrade schema."""
    op.drop_index('ix_cbomapikey_team_created', table_name='cbomapikey')
    op.drop_index(op.f('ix_cbomapikey_team_id'), table_name='cbomapikey')
    op.drop_table('cbomapikey')
