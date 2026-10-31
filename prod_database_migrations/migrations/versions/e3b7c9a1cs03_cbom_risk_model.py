"""cbom settings: risk_model (Mosca X/Y/Z years) for the post-quantum posture of collection runs

Revision ID: e3b7c9a1cs03
Revises: e3b7c9a1cs02
Create Date: 2026-10-31 20:10:00.000000

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = 'e3b7c9a1cs03'
down_revision: Union[str, Sequence[str], None] = 'e3b7c9a1cs02'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    """Upgrade schema."""
    op.add_column('cbomcollectionsettings', sa.Column('risk_model', sa.JSON(), nullable=True))


def downgrade() -> None:
    """Downgrade schema."""
    op.drop_column('cbomcollectionsettings', 'risk_model')
