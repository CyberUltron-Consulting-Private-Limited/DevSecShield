"""merge the two heads that both revise r6f3repo001

Revision ID: r6mergeheads001
Revises: d44mcphdr001, r6t2ledger001
Create Date: 2026-11-18 12:40:00.000000

``d44mcphdr001`` and ``r6t2ledger001`` are both already applied on databases stamped with the two heads.
Joining them here leaves each head's ``down_revision`` unchanged (rewriting an applied revision is rejected:
"overlaps with other requested revisions"). This revision changes no schema.
"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = 'r6mergeheads001'
down_revision: Union[str, Sequence[str], None] = ('d44mcphdr001', 'r6t2ledger001')
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    """Upgrade schema."""
    pass


def downgrade() -> None:
    """Downgrade schema."""
    pass
