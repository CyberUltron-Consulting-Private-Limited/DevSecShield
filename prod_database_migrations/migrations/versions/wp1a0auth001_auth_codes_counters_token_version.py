"""auth: one live sign-in code per email with a wrong-attempt counter, shared auth counters, token versions

Revision ID: wp1a0auth001
Revises: e3b7c9a1cs03
Create Date: 2026-11-02 09:00:00.000000

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa
import sqlmodel


# revision identifiers, used by Alembic.
revision: str = 'wp1a0auth001'
down_revision: Union[str, Sequence[str], None] = 'e3b7c9a1cs03'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    """Upgrade schema."""
    # Sign-in codes live ten minutes. Dropping the current ones (a user mid sign-in asks for a new code) also
    # removes rows that held the retired fixed codes and the duplicates the unique index below would refuse.
    op.execute("DELETE FROM verificationcode")
    op.add_column('verificationcode', sa.Column('attempts', sa.Integer(), server_default='0', nullable=False))
    op.create_index(op.f('ix_verificationcode_email'), 'verificationcode', ['email'], unique=True)
    op.add_column('user', sa.Column('token_version', sa.Integer(), server_default='0', nullable=False))
    op.create_table('authcounter',
    sa.Column('key', sqlmodel.sql.sqltypes.AutoString(length=400), nullable=False),
    sa.Column('window_start', sa.DateTime(), nullable=False),
    sa.Column('hits', sa.Integer(), nullable=False),
    sa.PrimaryKeyConstraint('key')
    )


def downgrade() -> None:
    """Downgrade schema."""
    op.drop_table('authcounter')
    op.drop_column('user', 'token_version')
    op.drop_index(op.f('ix_verificationcode_email'), table_name='verificationcode')
    op.drop_column('verificationcode', 'attempts')
