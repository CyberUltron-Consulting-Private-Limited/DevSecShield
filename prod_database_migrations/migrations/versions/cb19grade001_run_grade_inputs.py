"""CB-19 PR-2: the grade model and grade inputs a collection run was started with

Revision ID: cb19grade001
Revises: cb18evconf001
Create Date: 2026-11-14 12:00:00.000000

* ``cbomcollectionrun.grade_model_version``: the quantum risk grade model version (``qg-1+<12 hex>``) at Start.
* ``cbomcollectionrun.grade_inputs``: the snapshot taken at Start (team Mosca X/Y/Z, settings row version, evidence
  levels and Q0 gaps with their reasons, a digest). Run views grade with it; the team's later edits are shown beside
  the record ("with current inputs"), never in place of it.

Both columns are nullable with no default (metadata-only on PostgreSQL >= 11): runs created before this revision read
NULL and are graded with the team's current inputs, labelled ``inputs_source: current``.
"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = 'cb19grade001'
down_revision: Union[str, Sequence[str], None] = 'cb18evconf001'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    """Upgrade schema."""
    op.add_column('cbomcollectionrun', sa.Column('grade_model_version', sa.String(length=32), nullable=True))
    op.add_column('cbomcollectionrun', sa.Column('grade_inputs', sa.JSON(), nullable=True))


def downgrade() -> None:
    """Downgrade schema."""
    op.drop_column('cbomcollectionrun', 'grade_inputs')
    op.drop_column('cbomcollectionrun', 'grade_model_version')
