"""CBOM CI/CD gate policy per team or integration, and integration test tickets (SOW S1, S2)

Revision ID: fd2gate001
Revises: rpdf1brand001
Create Date: 2026-11-23 18:00:00.000000

Upgrade: creates two tables.

* ``cbomgatepolicy``: the CBOM CI/CD gate policy of a team (``scope`` = ``team``) or of one CBOM CI/CD integration
  (``scope`` = ``integration:<id>``, ``integration_id`` a foreign key to ``cicdintegration.id`` with ON DELETE
  CASCADE). One row per (team_id, scope). ``policy`` is JSON (banned algorithms, minimum key sizes, quantum-vulnerable
  and deprecated modes, allow-list exceptions with expiry). No data is written: every team keeps the default policy
  (the code-scan CLI's high codes plus SP 800-131A key sizes) until an admin saves one.
* ``integrationtestticket``: one row per "Raise test ticket" click (Jira or ServiceNow), unique per (team_id, kind,
  click_id), holding the ticket key and link the integration returned. No credential is stored here.

Downgrade: drops both tables. The gate then uses the default policy for every team (saved policies are lost); the
record of test tickets is lost (the tickets themselves stay in Jira / ServiceNow).
"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa
import sqlmodel


# revision identifiers, used by Alembic.
revision: str = 'fd2gate001'
down_revision: Union[str, Sequence[str], None] = 'rpdf1brand001'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    """Upgrade schema."""
    op.create_table('cbomgatepolicy',
    sa.Column('id', sa.Integer(), nullable=False),
    sa.Column('team_id', sa.Integer(), nullable=False),
    sa.Column('scope', sqlmodel.sql.sqltypes.AutoString(length=40), nullable=False),
    sa.Column('integration_id', sa.Integer(), nullable=True),
    sa.Column('policy', sa.JSON(), nullable=False),
    sa.Column('row_version', sa.Integer(), nullable=False),
    sa.Column('created_at', sa.DateTime(), nullable=False),
    sa.Column('updated_at', sa.DateTime(), nullable=False),
    sa.Column('updated_by_user_id', sa.Integer(), nullable=True),
    sa.ForeignKeyConstraint(['integration_id'], ['cicdintegration.id'], ondelete='CASCADE'),
    sa.ForeignKeyConstraint(['team_id'], ['team.id'], ondelete='CASCADE'),
    sa.PrimaryKeyConstraint('id'),
    sa.UniqueConstraint('team_id', 'scope', name='uq_cbomgatepolicy_team_scope')
    )
    op.create_index(op.f('ix_cbomgatepolicy_team_id'), 'cbomgatepolicy', ['team_id'], unique=False)
    op.create_table('integrationtestticket',
    sa.Column('id', sa.Integer(), nullable=False),
    sa.Column('team_id', sa.Integer(), nullable=False),
    sa.Column('kind', sqlmodel.sql.sqltypes.AutoString(length=16), nullable=False),
    sa.Column('click_id', sqlmodel.sql.sqltypes.AutoString(length=36), nullable=False),
    sa.Column('status', sqlmodel.sql.sqltypes.AutoString(length=16), nullable=False),
    sa.Column('ticket_key', sqlmodel.sql.sqltypes.AutoString(length=64), nullable=True),
    sa.Column('ticket_url', sqlmodel.sql.sqltypes.AutoString(length=500), nullable=True),
    sa.Column('message', sqlmodel.sql.sqltypes.AutoString(length=255), nullable=True),
    sa.Column('created_at', sa.DateTime(), nullable=False),
    sa.Column('updated_at', sa.DateTime(), nullable=False),
    sa.Column('user_id', sa.Integer(), nullable=True),
    sa.ForeignKeyConstraint(['team_id'], ['team.id'], ondelete='CASCADE'),
    sa.PrimaryKeyConstraint('id'),
    sa.UniqueConstraint('team_id', 'kind', 'click_id', name='uq_integrationtestticket_click')
    )
    op.create_index(op.f('ix_integrationtestticket_team_id'), 'integrationtestticket', ['team_id'], unique=False)


def downgrade() -> None:
    """Downgrade schema."""
    op.drop_index(op.f('ix_integrationtestticket_team_id'), table_name='integrationtestticket')
    op.drop_table('integrationtestticket')
    op.drop_index(op.f('ix_cbomgatepolicy_team_id'), table_name='cbomgatepolicy')
    op.drop_table('cbomgatepolicy')
