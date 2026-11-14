"""cbom fleet (F1.2): inventory sources and inventory targets

Revision ID: r6f12inv001
Revises: r6f13trn001
Create Date: 2026-11-11 12:00:00.000000

* ``cbominventorysource``: where targets come from (an AWS account through its validated read-only role, a CSV/JSON
  import, the API), its sync cadence, last sync status/summary, per region/service coverage, the sync lease and a
  soft delete.
* ``cbominventorytarget``: one discovered or imported target, unique per (team, external_id); tags, addresses,
  handles, attributes, the fingerprint of the normalised target, first/last seen, missing since, deleted (by a
  person) and pending (a managed-source change waiting for a busy source), the policy decision (JSON, plus its action
  and winning policy as indexed columns) and the managed source (sticky batch) it is assigned to.

New tables only; nothing existing changes.  At merge time this revision's ``down_revision`` is re-chained to the head
of ``origin/dev`` (F1 contract, section 2).
"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa
import sqlmodel


# revision identifiers, used by Alembic.
revision: str = 'r6f12inv001'
down_revision: Union[str, Sequence[str], None] = 'r6f13trn001'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def _common() -> list[sa.Column]:
    return [
        sa.Column('row_version', sa.Integer(), nullable=False, server_default='1'),
        sa.Column('created_at', sa.DateTime(), nullable=True),
        sa.Column('last_updated', sa.DateTime(), nullable=True),
    ]


def upgrade() -> None:
    """Upgrade schema."""
    op.create_table(
        'cbominventorysource',
        sa.Column('id', sa.Integer(), nullable=False),
        sa.Column('team_id', sa.Integer(), nullable=False),
        sa.Column('owner_user_id', sa.Integer(), nullable=True),
        sa.Column('updated_by_user_id', sa.Integer(), nullable=True),
        sa.Column('kind', sqlmodel.sql.sqltypes.AutoString(length=8), nullable=False),
        sa.Column('name', sqlmodel.sql.sqltypes.AutoString(length=64), nullable=False),
        sa.Column('config', sa.JSON(), nullable=True),
        sa.Column('sync_every_min', sa.Integer(), nullable=False, server_default='60'),
        sa.Column('enabled', sa.Boolean(), nullable=False, server_default=sa.true()),
        sa.Column('last_sync_at', sa.DateTime(), nullable=True),
        sa.Column('last_sync_status', sqlmodel.sql.sqltypes.AutoString(length=16), nullable=False,
                  server_default='never'),
        sa.Column('last_sync_summary', sa.JSON(), nullable=True),
        sa.Column('coverage', sa.JSON(), nullable=True),
        sa.Column('lease_until', sa.DateTime(), nullable=True),
        sa.Column('deleted_at', sa.DateTime(), nullable=True),
        *_common(),
        sa.ForeignKeyConstraint(['team_id'], ['team.id'], ondelete='CASCADE'),
        sa.PrimaryKeyConstraint('id'),
    )
    op.create_index(op.f('ix_cbominventorysource_team_id'), 'cbominventorysource', ['team_id'], unique=False)

    op.create_table(
        'cbominventorytarget',
        sa.Column('id', sa.Integer(), nullable=False),
        sa.Column('team_id', sa.Integer(), nullable=False),
        sa.Column('inventory_source_id', sa.Integer(), nullable=False),
        sa.Column('external_id', sqlmodel.sql.sqltypes.AutoString(length=255), nullable=False),
        sa.Column('kind', sqlmodel.sql.sqltypes.AutoString(length=24), nullable=False),
        sa.Column('address', sqlmodel.sql.sqltypes.AutoString(length=253), nullable=True),
        sa.Column('addresses', sa.JSON(), nullable=True),
        sa.Column('hostname', sqlmodel.sql.sqltypes.AutoString(length=253), nullable=True),
        sa.Column('tags', sa.JSON(), nullable=True),
        sa.Column('account_id', sqlmodel.sql.sqltypes.AutoString(length=32), nullable=True),
        sa.Column('region', sqlmodel.sql.sqltypes.AutoString(length=32), nullable=True),
        sa.Column('platform', sqlmodel.sql.sqltypes.AutoString(length=64), nullable=True),
        sa.Column('handles', sa.JSON(), nullable=True),
        sa.Column('attributes', sa.JSON(), nullable=True),
        sa.Column('fingerprint', sqlmodel.sql.sqltypes.AutoString(length=64), nullable=False),
        sa.Column('first_seen_at', sa.DateTime(), nullable=True),
        sa.Column('last_seen_at', sa.DateTime(), nullable=True),
        sa.Column('missing_since', sa.DateTime(), nullable=True),
        sa.Column('decision', sa.JSON(), nullable=True),
        sa.Column('decision_action', sqlmodel.sql.sqltypes.AutoString(length=16), nullable=True),
        sa.Column('decision_policy_id', sa.Integer(), nullable=True),
        sa.Column('deleted_at', sa.DateTime(), nullable=True),
        sa.Column('pending_since', sa.DateTime(), nullable=True),
        sa.Column('managed_source_id', sa.Integer(), nullable=True),
        *_common(),
        sa.ForeignKeyConstraint(['team_id'], ['team.id'], ondelete='CASCADE'),
        sa.PrimaryKeyConstraint('id'),
        sa.UniqueConstraint('team_id', 'external_id', name='uq_cbominventorytarget_team_external'),
    )
    # (team_id, id): every list and evaluation pages a team's targets by id; it also serves team_id lookups
    op.create_index('ix_cbominventorytarget_team_id_id', 'cbominventorytarget', ['team_id', 'id'], unique=False)
    op.create_index('ix_cbominventorytarget_team_source', 'cbominventorytarget', ['team_id', 'inventory_source_id'],
                    unique=False)
    op.create_index('ix_cbominventorytarget_team_kind', 'cbominventorytarget', ['team_id', 'kind'], unique=False)
    op.create_index('ix_cbominventorytarget_team_managed', 'cbominventorytarget', ['team_id', 'managed_source_id'],
                    unique=False)
    op.create_index('ix_cbominventorytarget_team_action', 'cbominventorytarget', ['team_id', 'decision_action'],
                    unique=False)
    op.create_index('ix_cbominventorytarget_team_policy', 'cbominventorytarget', ['team_id', 'decision_policy_id'],
                    unique=False)


def downgrade() -> None:
    """Downgrade schema."""
    op.drop_index('ix_cbominventorytarget_team_policy', table_name='cbominventorytarget')
    op.drop_index('ix_cbominventorytarget_team_action', table_name='cbominventorytarget')
    op.drop_index('ix_cbominventorytarget_team_managed', table_name='cbominventorytarget')
    op.drop_index('ix_cbominventorytarget_team_kind', table_name='cbominventorytarget')
    op.drop_index('ix_cbominventorytarget_team_source', table_name='cbominventorytarget')
    op.drop_index('ix_cbominventorytarget_team_id_id', table_name='cbominventorytarget')
    op.drop_table('cbominventorytarget')
    op.drop_index(op.f('ix_cbominventorysource_team_id'), table_name='cbominventorysource')
    op.drop_table('cbominventorysource')
