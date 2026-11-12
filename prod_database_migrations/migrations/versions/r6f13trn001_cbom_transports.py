"""cbom transports (AWX/AAP, Salt, AWS SSM) and verified zs-collect releases (F1.3)

Revision ID: r6f13trn001
Revises: rv6p1nodename001
Create Date: 2026-11-12 07:00:00.000000

Two new tables, nothing changed on existing ones (contract section 2: no foreign key to another part's tables, so the
F1 parts' migrations apply in any order; at merge time ``down_revision`` is re-chained to dev's head).
* ``cbomtransport``: a team's transport; secrets only as ``secret_encrypted``; soft-deleted (``deleted_at``).
* ``cbomzscollectrelease``: deployment-wide releases whose manifest signature was verified on import (no team FK).
"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa
import sqlmodel


# revision identifiers, used by Alembic.
revision: str = 'r6f13trn001'
down_revision: Union[str, Sequence[str], None] = 'rv6p1nodename001'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.create_table(
        'cbomtransport',
        sa.Column('id', sa.Integer(), nullable=False),
        sa.Column('team_id', sa.Integer(), nullable=False),
        sa.Column('kind', sqlmodel.sql.sqltypes.AutoString(length=16), nullable=False),
        sa.Column('name', sqlmodel.sql.sqltypes.AutoString(length=64), nullable=False),
        sa.Column('name_lower', sqlmodel.sql.sqltypes.AutoString(length=64), nullable=False),
        sa.Column('enabled', sa.Boolean(), nullable=False),
        sa.Column('config', sa.JSON(), nullable=True),
        sa.Column('secret_encrypted', sa.Text(), nullable=True),
        sa.Column('secret_fields', sa.JSON(), nullable=True),
        sa.Column('last_validated_at', sa.DateTime(), nullable=True),
        sa.Column('last_validation_status', sqlmodel.sql.sqltypes.AutoString(length=16), nullable=False),
        sa.Column('last_validation_summary', sqlmodel.sql.sqltypes.AutoString(length=512), nullable=True),
        sa.Column('owner_user_id', sa.Integer(), nullable=False),
        sa.Column('updated_by_user_id', sa.Integer(), nullable=True),
        sa.Column('row_version', sa.Integer(), nullable=False),
        sa.Column('created_at', sa.DateTime(), nullable=True),
        sa.Column('last_updated', sa.DateTime(), nullable=True),
        sa.Column('deleted_at', sa.DateTime(), nullable=True),
        sa.ForeignKeyConstraint(['team_id'], ['team.id'], ondelete='CASCADE'),
        sa.PrimaryKeyConstraint('id'),
    )
    op.create_index(op.f('ix_cbomtransport_team_id'), 'cbomtransport', ['team_id'], unique=False)
    op.create_table(
        'cbomzscollectrelease',
        sa.Column('id', sa.Integer(), nullable=False),
        sa.Column('team_id', sa.Integer(), nullable=True),
        sa.Column('version', sqlmodel.sql.sqltypes.AutoString(length=40), nullable=False),
        sa.Column('manifest', sa.JSON(), nullable=True),
        sa.Column('manifest_raw', sa.Text(), nullable=False),
        sa.Column('manifest_sig', sqlmodel.sql.sqltypes.AutoString(length=200), nullable=False),
        sa.Column('sha256_amd64', sqlmodel.sql.sqltypes.AutoString(length=64), nullable=True),
        sa.Column('sha256_arm64', sqlmodel.sql.sqltypes.AutoString(length=64), nullable=True),
        sa.Column('key_fingerprint', sqlmodel.sql.sqltypes.AutoString(length=80), nullable=False),
        sa.Column('verified_at', sa.DateTime(), nullable=True),
        sa.Column('active', sa.Boolean(), nullable=False),
        sa.Column('row_version', sa.Integer(), nullable=False),
        sa.Column('created_at', sa.DateTime(), nullable=True),
        sa.Column('last_updated', sa.DateTime(), nullable=True),
        sa.PrimaryKeyConstraint('id'),
        sa.UniqueConstraint('version', name='uq_cbomzscollectrelease_version'),
    )
    op.create_index(op.f('ix_cbomzscollectrelease_team_id'), 'cbomzscollectrelease', ['team_id'], unique=False)
    op.create_index(op.f('ix_cbomzscollectrelease_active'), 'cbomzscollectrelease', ['active'], unique=False)


def downgrade() -> None:
    op.drop_index(op.f('ix_cbomzscollectrelease_active'), table_name='cbomzscollectrelease')
    op.drop_index(op.f('ix_cbomzscollectrelease_team_id'), table_name='cbomzscollectrelease')
    op.drop_table('cbomzscollectrelease')
    op.drop_index(op.f('ix_cbomtransport_team_id'), table_name='cbomtransport')
    op.drop_table('cbomtransport')
