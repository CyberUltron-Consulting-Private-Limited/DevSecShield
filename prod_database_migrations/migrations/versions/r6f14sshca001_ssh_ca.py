"""cbom fleet (F1.4): SSH certificate authority and the issued-certificate audit

Revision ID: r6f14sshca001
Revises: rv6p1nodename001
Create Date: 2026-11-11 12:00:00.000000

* ``cbomsshca``: one row per CA key (builtin: the private key wrapped by AWS KMS or the deployment key; vault: the
  HashiCorp Vault SSH engine's public key and an encrypted token), its state (next / active / retired / revoked),
  its lineage (rotation) and the next serial.
* ``cbomsshcertissued``: one row per issued certificate (serial unique per CA, principals, source addresses,
  validity, node, job, source, revocation).  ``ca_id`` is a plain int so the audit outlives the CA row.

New tables only: no existing row changes, so the downgrade drops both.  At merge time ``down_revision`` is re-chained
to dev's head (F1 contract, section 2).
"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa
import sqlmodel


# revision identifiers, used by Alembic.
revision: str = 'r6f14sshca001'
down_revision: Union[str, Sequence[str], None] = 'rv6p1nodename001'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def _s(length: int):
    return sqlmodel.sql.sqltypes.AutoString(length=length)


def upgrade() -> None:
    """Upgrade schema."""
    op.create_table(
        'cbomsshca',
        sa.Column('id', sa.Integer(), nullable=False),
        sa.Column('team_id', sa.Integer(), nullable=False),
        sa.Column('owner_user_id', sa.Integer(), nullable=False),
        sa.Column('updated_by_user_id', sa.Integer(), nullable=True),
        sa.Column('name', _s(64), nullable=False),
        sa.Column('provider', _s(16), nullable=False),
        sa.Column('key_alg', _s(16), nullable=False),
        sa.Column('public_key', sa.Text(), nullable=False),
        sa.Column('fingerprint', _s(64), nullable=False),
        sa.Column('private_key_encrypted', sa.Text(), nullable=True),
        sa.Column('key_wrap', _s(16), nullable=True),
        sa.Column('kms_key_ref', _s(2048), nullable=True),
        sa.Column('vault_config', sa.JSON(), nullable=True),
        sa.Column('secret_encrypted', sa.Text(), nullable=True),
        sa.Column('secret_fields', sa.JSON(), nullable=True),
        sa.Column('state', _s(16), nullable=False),
        sa.Column('default_ttl_s', sa.Integer(), nullable=False),
        sa.Column('serial_next', sa.BigInteger(), nullable=False),
        sa.Column('rotated_from_id', sa.Integer(), nullable=True),
        sa.Column('lineage_id', sa.Integer(), nullable=True),
        sa.Column('retired_at', sa.DateTime(), nullable=True),
        sa.Column('revoked_at', sa.DateTime(), nullable=True),
        sa.Column('revoked_reason', _s(512), nullable=True),
        sa.Column('row_version', sa.Integer(), nullable=False),
        sa.Column('created_at', sa.DateTime(), nullable=True),
        sa.Column('last_updated', sa.DateTime(), nullable=True),
        sa.ForeignKeyConstraint(['team_id'], ['team.id'], ondelete='CASCADE'),
        sa.PrimaryKeyConstraint('id'),
    )
    op.create_index(op.f('ix_cbomsshca_team_id'), 'cbomsshca', ['team_id'], unique=False)
    op.create_index(op.f('ix_cbomsshca_lineage_id'), 'cbomsshca', ['lineage_id'], unique=False)
    op.create_table(
        'cbomsshcertissued',
        sa.Column('id', sa.Integer(), nullable=False),
        sa.Column('team_id', sa.Integer(), nullable=False),
        sa.Column('ca_id', sa.Integer(), nullable=False),
        sa.Column('serial', sa.BigInteger(), nullable=False),
        sa.Column('key_id', _s(255), nullable=False),
        sa.Column('principals', sa.JSON(), nullable=True),
        sa.Column('source_addresses', sa.JSON(), nullable=True),
        sa.Column('valid_after', sa.DateTime(), nullable=False),
        sa.Column('valid_before', sa.DateTime(), nullable=False),
        sa.Column('cert_public_key_sha256', _s(64), nullable=False),
        sa.Column('node_id', sa.Integer(), nullable=True),
        sa.Column('job_id', sa.Integer(), nullable=True),
        sa.Column('source_id', sa.Integer(), nullable=True),
        sa.Column('via', _s(16), nullable=False),
        sa.Column('issued_at', sa.DateTime(), nullable=False),
        sa.Column('revoked_at', sa.DateTime(), nullable=True),
        sa.Column('revoked_reason', _s(512), nullable=True),
        sa.Column('row_version', sa.Integer(), nullable=False),
        sa.Column('created_at', sa.DateTime(), nullable=True),
        sa.Column('last_updated', sa.DateTime(), nullable=True),
        sa.ForeignKeyConstraint(['team_id'], ['team.id'], ondelete='CASCADE'),
        sa.PrimaryKeyConstraint('id'),
        sa.UniqueConstraint('ca_id', 'serial', name='uq_cbomsshcertissued_ca_serial'),
    )
    op.create_index(op.f('ix_cbomsshcertissued_team_id'), 'cbomsshcertissued', ['team_id'], unique=False)
    op.create_index(op.f('ix_cbomsshcertissued_ca_id'), 'cbomsshcertissued', ['ca_id'], unique=False)
    op.create_index('ix_cbomsshcertissued_team_issued', 'cbomsshcertissued', ['team_id', 'issued_at'], unique=False)
    op.create_index('ix_cbomsshcertissued_team_job', 'cbomsshcertissued', ['team_id', 'job_id'], unique=False)


def downgrade() -> None:
    """Downgrade schema."""
    op.drop_index('ix_cbomsshcertissued_team_job', table_name='cbomsshcertissued')
    op.drop_index('ix_cbomsshcertissued_team_issued', table_name='cbomsshcertissued')
    op.drop_index(op.f('ix_cbomsshcertissued_ca_id'), table_name='cbomsshcertissued')
    op.drop_index(op.f('ix_cbomsshcertissued_team_id'), table_name='cbomsshcertissued')
    op.drop_table('cbomsshcertissued')
    op.drop_index(op.f('ix_cbomsshca_lineage_id'), table_name='cbomsshca')
    op.drop_index(op.f('ix_cbomsshca_team_id'), table_name='cbomsshca')
    op.drop_table('cbomsshca')
