"""cbom cloud pool (F1): AWS collection split into one slice job per account x region

Revision ID: w9cloudpool001
Revises: r6f14sshca002
Create Date: 2026-11-14 12:00:00.000000

* ``cbomcollectionjob.parent_job_id``: a ``slice`` job (one AWS account x region, run by the cloud-worker pool) points
  at the source's ``collect`` job.  Nullable: every existing job, and every job that is not a slice, reads NULL.
  Indexed (the pool counts a parent's open slices and finalises the parent from them).  ``ON DELETE CASCADE``:
  slices are scaffolding of their parent and never outlive it.

PostgreSQL: runs with ``lock_timeout`` 5 s (``set_config(..., is_local)``), like r6f14sshca002: ``cbomcollectionjob``
is read and written by every scan-node poll, so a long transaction holding a conflicting lock makes the migration
fail fast (run it again later) instead of queueing every node request behind the ALTER.
"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = 'w9cloudpool001'
down_revision: Union[str, Sequence[str], None] = 'r6f14sshca002'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None

LOCK_TIMEOUT = "5s"
FK = "fk_cbomcollectionjob_parent_job_id"
IX = "ix_cbomcollectionjob_parent_job_id"


def _pg() -> bool:
    return op.get_bind().dialect.name == "postgresql"


def _lock_timeout(value: str) -> str:
    """Set this transaction's lock_timeout (PostgreSQL); returns the value it had."""
    bind = op.get_bind()
    before = bind.execute(sa.select(sa.func.current_setting("lock_timeout"))).scalar()
    bind.execute(sa.select(sa.func.set_config("lock_timeout", value, True)))
    return str(before)


def upgrade() -> None:
    """Upgrade schema."""
    before = _lock_timeout(LOCK_TIMEOUT) if _pg() else None
    with op.batch_alter_table('cbomcollectionjob') as batch:
        batch.add_column(sa.Column('parent_job_id', sa.Integer(), nullable=True))
        batch.create_foreign_key(FK, 'cbomcollectionjob', ['parent_job_id'], ['id'], ondelete='CASCADE')
        batch.create_index(IX, ['parent_job_id'], unique=False)
    if before is not None:
        _lock_timeout(before)


def downgrade() -> None:
    """Downgrade schema."""
    before = _lock_timeout(LOCK_TIMEOUT) if _pg() else None
    # slices hold no assets and no credits of their own; dropping them loses nothing a run shows
    op.execute(sa.text("DELETE FROM cbomcollectionjob WHERE parent_job_id IS NOT NULL"))
    with op.batch_alter_table('cbomcollectionjob') as batch:
        batch.drop_index(IX)
        batch.drop_constraint(FK, type_='foreignkey')
        batch.drop_column('parent_job_id')
    if before is not None:
        _lock_timeout(before)
