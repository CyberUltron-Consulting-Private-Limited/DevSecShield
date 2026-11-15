"""cbom ops counters (CB-31, GAP-MATRIX X1): platform-wide operational counters for the admin metrics endpoint

Revision ID: cb31opsctr001
Revises: cbcorr001
Create Date: 2026-11-15 06:00:00.000000

* ``cbomopscounter``: one row per counter (``name`` is the key), its ``value`` (bigint, monotonic) and when it last
  moved. Incremented in the transaction of the event it counts: a job lease the reaper expired
  (``job_lease_expired_requeued`` / ``job_lease_expired_failed``) and assets the ingest refused
  (``ingest_rejected_assets``). ``GET /cbom/ops/metrics`` serves them as Prometheus counters.

A new, empty table: nothing is backfilled (the counters start at 0 on the deploy that adds them).
"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa
import sqlmodel


# revision identifiers, used by Alembic.
revision: str = 'cb31opsctr001'
down_revision: Union[str, Sequence[str], None] = 'cbcorr001'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    """Upgrade schema."""
    op.create_table(
        'cbomopscounter',
        sa.Column('name', sqlmodel.sql.sqltypes.AutoString(length=64), nullable=False),
        sa.Column('value', sa.BigInteger(), server_default='0', nullable=False),
        sa.Column('updated_at', sa.DateTime(), nullable=True),
        sa.PrimaryKeyConstraint('name'),
    )


def downgrade() -> None:
    """Downgrade schema."""
    op.drop_table('cbomopscounter')
