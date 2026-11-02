"""cbom scan nodes: deployment id, Ed25519 request signing, replay nonces, mTLS pin, require-signed team setting

Revision ID: wp5a0node001
Revises: wp1a0auth001
Create Date: 2026-11-02 12:00:00.000000

"""
import uuid
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa
import sqlmodel


# revision identifiers, used by Alembic.
revision: str = 'wp5a0node001'
down_revision: Union[str, Sequence[str], None] = 'wp1a0auth001'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    """Upgrade schema."""
    # One row: this deployment's id, created once here so every worker and replica stamps the same value.
    op.create_table('cbomdeployment',
    sa.Column('id', sa.Integer(), nullable=False),
    sa.Column('deployment_id', sqlmodel.sql.sqltypes.AutoString(length=36), nullable=False),
    sa.Column('created_at', sa.DateTime(), nullable=True),
    sa.PrimaryKeyConstraint('id')
    )
    op.execute(sa.text("INSERT INTO cbomdeployment (id, deployment_id, created_at) VALUES (1, :d, now())")
               .bindparams(d=str(uuid.uuid4())))
    op.create_table('cbomnodenonce',
    sa.Column('node_id', sa.Integer(), nullable=False),
    sa.Column('nonce', sqlmodel.sql.sqltypes.AutoString(length=64), nullable=False),
    sa.Column('expires_at', sa.DateTime(), nullable=False),
    sa.ForeignKeyConstraint(['node_id'], ['cbomscannode.id'], ondelete='CASCADE'),
    sa.PrimaryKeyConstraint('node_id', 'nonce')
    )
    op.create_index(op.f('ix_cbomnodenonce_expires_at'), 'cbomnodenonce', ['expires_at'], unique=False)
    # Nodes enrolled before this release have no key: they stay "legacy" (unsigned) until they enroll again.
    op.add_column('cbomscannode', sa.Column('signing_public_key', sqlmodel.sql.sqltypes.AutoString(length=64), nullable=True))
    op.add_column('cbomscannode', sa.Column('client_cert_sha256', sqlmodel.sql.sqltypes.AutoString(length=64), nullable=True))
    op.add_column('cbomcollectionsettings', sa.Column('require_signed_nodes', sa.Boolean(), server_default=sa.false(), nullable=False))


def downgrade() -> None:
    """Downgrade schema."""
    op.drop_column('cbomcollectionsettings', 'require_signed_nodes')
    op.drop_column('cbomscannode', 'client_cert_sha256')
    op.drop_column('cbomscannode', 'signing_public_key')
    op.drop_index(op.f('ix_cbomnodenonce_expires_at'), table_name='cbomnodenonce')
    op.drop_table('cbomnodenonce')
    op.drop_table('cbomdeployment')
