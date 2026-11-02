"""outputs: charged credits and the estimate digest on scans; KB / classifier / engine versions on collection runs

Revision ID: wp9a0outputs001
Revises: wp1a0auth001
Create Date: 2026-11-02 12:00:00.000000

* ``scan.credit_charged``: what /start took (``credit_consumed`` stays the estimate); a refund gives back exactly this.
* ``scan.credit_estimate``: what the estimate measured (input digest, formula version, minimum), so /start re-estimates
  when the input or the formula changed instead of charging a stale number.
* ``cbomcollectionrun.kb_version`` / ``classifier_version`` / ``engine_version``: what judged the run, recorded when it
  was created (the CycloneDX export names them; its serial number is derived from the run id and the KB version).

All columns are nullable: rows created before this revision read as "not recorded".
"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = 'wp9a0outputs001'
down_revision: Union[str, Sequence[str], None] = 'wp1a0auth001'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    """Upgrade schema."""
    op.add_column('scan', sa.Column('credit_charged', sa.Float(), nullable=True))
    op.add_column('scan', sa.Column('credit_estimate', sa.JSON(), nullable=True))
    op.add_column('cbomcollectionrun', sa.Column('kb_version', sa.String(length=32), nullable=True))
    op.add_column('cbomcollectionrun', sa.Column('classifier_version', sa.String(length=32), nullable=True))
    op.add_column('cbomcollectionrun', sa.Column('engine_version', sa.String(length=32), nullable=True))


def downgrade() -> None:
    """Downgrade schema."""
    op.drop_column('cbomcollectionrun', 'engine_version')
    op.drop_column('cbomcollectionrun', 'classifier_version')
    op.drop_column('cbomcollectionrun', 'kb_version')
    op.drop_column('scan', 'credit_estimate')
    op.drop_column('scan', 'credit_charged')
