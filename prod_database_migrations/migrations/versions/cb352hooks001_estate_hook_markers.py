"""estate write hooks write only what changed (#352): source markers and a row content digest

Revision ID: cb352hooks001
Revises: cb32summary001
Create Date: 2026-11-15 06:00:00.000000

* ``cbomestatesource.fix_through_job_id`` / ``fix_through_attempt``: the job the agility hook has brought the
  source's present observations up to (an unchanged re-read no longer rewrites every observation's pointer);
  ``register_through_job_id`` / ``register_through_attempt``: the job the risk register's grades of the source's
  present observations were computed from.
* ``cbomcollectedasset.content_digest``: a digest of what the hooks read from the row, set on insert by the model's
  column default. Rows from before this revision keep NULL (compared column by column, as before).

The upgrade fills ``fix_through`` with the source's latest job where every judged present observation already
points at it (the hook's state before this revision), so nothing is re-judged; the register marker starts empty, so
each source's next write grades its keys the way it did before, once. The downgrade drops the columns.
"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa
import sqlmodel


revision: str = 'cb352hooks001'
down_revision: Union[str, Sequence[str], None] = 'cb32summary001'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    for name in ('fix_through_job_id', 'fix_through_attempt', 'register_through_job_id', 'register_through_attempt'):
        op.add_column('cbomestatesource', sa.Column(name, sa.Integer(), nullable=True))
    # nullable, no server default: a metadata-only change on PostgreSQL, whatever the table's size
    op.add_column('cbomcollectedasset', sa.Column('content_digest', sqlmodel.sql.sqltypes.AutoString(length=64),
                                                  nullable=True))
    op.execute(
        "UPDATE cbomestatesource SET fix_through_job_id = latest_job_id, fix_through_attempt = latest_attempt "
        "WHERE NOT EXISTS (SELECT 1 FROM cbomestateobservation o WHERE o.team_id = cbomestatesource.team_id "
        "AND o.source_ref = cbomestatesource.source_ref AND o.presence = 'present' AND o.fix_version IS NOT NULL "
        "AND (o.fix_job_id IS NULL OR o.fix_job_id <> cbomestatesource.latest_job_id OR o.fix_attempt IS NULL "
        "OR o.fix_attempt <> cbomestatesource.latest_attempt))")


def downgrade() -> None:
    with op.batch_alter_table('cbomcollectedasset') as batch:
        batch.drop_column('content_digest')
    with op.batch_alter_table('cbomestatesource') as batch:
        batch.drop_column('register_through_attempt')
        batch.drop_column('register_through_job_id')
        batch.drop_column('fix_through_attempt')
        batch.drop_column('fix_through_job_id')
