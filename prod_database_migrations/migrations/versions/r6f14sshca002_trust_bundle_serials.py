"""cbom fleet (F1.4): serials from a sequence, audit indexes, trust bundle tables (PR #65 review round 7)

Revision ID: r6f14sshca002
Revises: r6f14sshca001
Create Date: 2026-11-12 10:00:00.000000

* ``cbomsshca_serial_seq``: serials of builtin CAs (``nextval`` never waits; the per-CA row lock of
  ``UPDATE … serial_next`` is gone).  Starts after the highest serial already issued, so no (ca, serial) repeats.
* ``cbomsshca.trust_generation``: the team's trust generation that added the key (promote readiness).
* ``cbomsshcertissued``: ``ix_…_ca_id`` (duplicate of ``uq_…_ca_serial``) and ``ix_…_team_id`` (superseded by
  ``(team_id, id)``) dropped; ``(team_id, id)``, ``(team_id, node_id, id)``, ``(team_id, ca_id, id)`` for the audit
  list, and the partial ``(team_id, valid_before) WHERE revoked_at IS NOT NULL`` for the KRL.
* ``cbomscannode.ssh_public_key``: a hash index for the key-reuse check (the column holds up to 8 KB, too long for a
  btree entry).
* ``cbomsshcatrust`` (generations per team), ``cbomsshcatrusttoken`` (read-only distribution tokens, SHA-256 only),
  ``cbomsshcatrustfetch`` (what each fetcher last received).

The downgrade reverses all of it (``serial_next`` is still there for SQLite and is advanced past the sequence, so
going back to r6f14sshca001 cannot reuse a serial).
"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa
import sqlmodel


# revision identifiers, used by Alembic.
revision: str = 'r6f14sshca002'
down_revision: Union[str, Sequence[str], None] = 'r6f14sshca001'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def _s(length: int):
    return sqlmodel.sql.sqltypes.AutoString(length=length)


def _pg() -> bool:
    return op.get_bind().dialect.name == "postgresql"


def upgrade() -> None:
    """Upgrade schema."""
    if _pg():
        start = op.get_bind().execute(sa.text(
            "SELECT GREATEST(COALESCE((SELECT max(serial) FROM cbomsshcertissued WHERE serial > 0), 0), "
            "COALESCE((SELECT max(serial_next) FROM cbomsshca), 1) - 1) + 1")).scalar()
        op.execute(sa.text(f"CREATE SEQUENCE cbomsshca_serial_seq START WITH {int(start)}"))
    op.add_column('cbomsshca', sa.Column('trust_generation', sa.BigInteger(), nullable=True))

    op.drop_index('ix_cbomsshcertissued_ca_id', table_name='cbomsshcertissued')
    op.drop_index('ix_cbomsshcertissued_team_id', table_name='cbomsshcertissued')
    op.create_index('ix_cbomsshcertissued_team_id_id', 'cbomsshcertissued', ['team_id', 'id'], unique=False)
    op.create_index('ix_cbomsshcertissued_team_node_id', 'cbomsshcertissued', ['team_id', 'node_id', 'id'],
                    unique=False)
    op.create_index('ix_cbomsshcertissued_team_ca_id', 'cbomsshcertissued', ['team_id', 'ca_id', 'id'], unique=False)
    op.create_index('ix_cbomsshcertissued_revoked', 'cbomsshcertissued', ['team_id', 'valid_before'], unique=False,
                    postgresql_where=sa.text('revoked_at IS NOT NULL'), sqlite_where=sa.text('revoked_at IS NOT NULL'))
    op.create_index('ix_cbomscannode_ssh_public_key', 'cbomscannode', ['ssh_public_key'], unique=False,
                    postgresql_using='hash')

    op.create_table(
        'cbomsshcatrust',
        sa.Column('id', sa.Integer(), nullable=False),
        sa.Column('team_id', sa.Integer(), nullable=False),
        sa.Column('trust_generation', sa.BigInteger(), nullable=False),
        sa.Column('revocation_generation', sa.BigInteger(), nullable=False),
        sa.Column('trust_changed_at', sa.DateTime(), nullable=True),
        sa.Column('revocation_changed_at', sa.DateTime(), nullable=True),
        sa.Column('row_version', sa.Integer(), nullable=False),
        sa.Column('created_at', sa.DateTime(), nullable=True),
        sa.Column('last_updated', sa.DateTime(), nullable=True),
        sa.ForeignKeyConstraint(['team_id'], ['team.id'], ondelete='CASCADE'),
        sa.PrimaryKeyConstraint('id'),
    )
    op.create_index(op.f('ix_cbomsshcatrust_team_id'), 'cbomsshcatrust', ['team_id'], unique=True)
    op.create_table(
        'cbomsshcatrusttoken',
        sa.Column('id', sa.Integer(), nullable=False),
        sa.Column('team_id', sa.Integer(), nullable=False),
        sa.Column('name', _s(64), nullable=False),
        sa.Column('token_hash', _s(64), nullable=False),
        sa.Column('prefix', _s(12), nullable=False),
        sa.Column('created_by_user_id', sa.Integer(), nullable=False),
        sa.Column('last_used_at', sa.DateTime(), nullable=True),
        sa.Column('revoked_at', sa.DateTime(), nullable=True),
        sa.Column('revoked_by_user_id', sa.Integer(), nullable=True),
        sa.Column('row_version', sa.Integer(), nullable=False),
        sa.Column('created_at', sa.DateTime(), nullable=True),
        sa.Column('last_updated', sa.DateTime(), nullable=True),
        sa.ForeignKeyConstraint(['team_id'], ['team.id'], ondelete='CASCADE'),
        sa.PrimaryKeyConstraint('id'),
    )
    op.create_index(op.f('ix_cbomsshcatrusttoken_team_id'), 'cbomsshcatrusttoken', ['team_id'], unique=False)
    op.create_index(op.f('ix_cbomsshcatrusttoken_token_hash'), 'cbomsshcatrusttoken', ['token_hash'], unique=True)
    op.create_table(
        'cbomsshcatrustfetch',
        sa.Column('id', sa.Integer(), nullable=False),
        sa.Column('team_id', sa.Integer(), nullable=False),
        sa.Column('token_id', sa.Integer(), nullable=False),
        sa.Column('fetcher', _s(128), nullable=False),
        sa.Column('trust_generation', sa.BigInteger(), nullable=True),
        sa.Column('revocation_generation', sa.BigInteger(), nullable=True),
        sa.Column('first_fetch_at', sa.DateTime(), nullable=False),
        sa.Column('last_fetch_at', sa.DateTime(), nullable=False),
        sa.Column('last_ip', _s(64), nullable=True),
        sa.Column('row_version', sa.Integer(), nullable=False),
        sa.Column('created_at', sa.DateTime(), nullable=True),
        sa.Column('last_updated', sa.DateTime(), nullable=True),
        sa.ForeignKeyConstraint(['team_id'], ['team.id'], ondelete='CASCADE'),
        sa.PrimaryKeyConstraint('id'),
        sa.UniqueConstraint('token_id', 'fetcher', name='uq_cbomsshcatrustfetch_token_fetcher'),
    )
    op.create_index('ix_cbomsshcatrustfetch_team_seen', 'cbomsshcatrustfetch', ['team_id', 'last_fetch_at'],
                    unique=False)


def downgrade() -> None:
    """Downgrade schema."""
    op.drop_index('ix_cbomsshcatrustfetch_team_seen', table_name='cbomsshcatrustfetch')
    op.drop_table('cbomsshcatrustfetch')
    op.drop_index(op.f('ix_cbomsshcatrusttoken_token_hash'), table_name='cbomsshcatrusttoken')
    op.drop_index(op.f('ix_cbomsshcatrusttoken_team_id'), table_name='cbomsshcatrusttoken')
    op.drop_table('cbomsshcatrusttoken')
    op.drop_index(op.f('ix_cbomsshcatrust_team_id'), table_name='cbomsshcatrust')
    op.drop_table('cbomsshcatrust')

    op.drop_index('ix_cbomscannode_ssh_public_key', table_name='cbomscannode')
    op.drop_index('ix_cbomsshcertissued_revoked', table_name='cbomsshcertissued')
    op.drop_index('ix_cbomsshcertissued_team_ca_id', table_name='cbomsshcertissued')
    op.drop_index('ix_cbomsshcertissued_team_node_id', table_name='cbomsshcertissued')
    op.drop_index('ix_cbomsshcertissued_team_id_id', table_name='cbomsshcertissued')
    op.create_index(op.f('ix_cbomsshcertissued_team_id'), 'cbomsshcertissued', ['team_id'], unique=False)
    op.create_index(op.f('ix_cbomsshcertissued_ca_id'), 'cbomsshcertissued', ['ca_id'], unique=False)

    op.drop_column('cbomsshca', 'trust_generation')
    if _pg():
        # r6f14sshca001 signs with serial_next again: move every CA past the serials the sequence handed out
        op.execute(sa.text("UPDATE cbomsshca SET serial_next = GREATEST(serial_next, "
                           "(SELECT COALESCE(max(serial), 0) + 1 FROM cbomsshcertissued WHERE serial > 0))"))
        op.execute(sa.text("DROP SEQUENCE IF EXISTS cbomsshca_serial_seq"))
