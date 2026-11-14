"""cbom run concurrency and billing (CB-14): credit ledger, refunded amount, one open collection per source

Revision ID: cb14credit001
Revises: cb32index001
Create Date: 2026-11-15 06:00:00.000000

* ``cbomcreditentry``: one row per credit movement (charge at Start, a job's one refund), unique ``idem_key``
  (``run:<id>:charge``, ``job:<id>:refund``), so a retried or racing refund never moves credits twice.  Backfilled
  from the current runs (their charge) and refunded jobs (their weight), reason ``backfill``.
* ``cbomcollectionjob.refunded_c``: the centi-credits given back (a job refunded before this is backfilled with its
  weight).
* ``uq_cbomcollectionjob_open_collect``: at most one pending or claimed ``collect`` job per source (partial unique
  index, PostgreSQL and SQLite).  Two Starts that raced before this release may have left a source with two open
  collections; the newer ones are cancelled and refunded first (reason ``migration_duplicate``, counts printed), so
  the index can be built.  The oldest one keeps running.

Downgrade drops the index, the ledger and the column (the refunds already made stay made).
"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa
import sqlmodel


# revision identifiers, used by Alembic.
revision: str = 'cb14credit001'
down_revision: Union[str, Sequence[str], None] = 'cb32index001'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None

OPEN_COLLECT = "kind = 'collect' AND status IN ('pending', 'claimed')"
DUPLICATE_NOTE = "Cancelled: a second open collection of this source (two Starts raced); refunded (CB-14 migration)"


def upgrade() -> None:
    """Upgrade schema."""
    bind = op.get_bind()
    with op.batch_alter_table('cbomcollectionjob') as batch:
        batch.add_column(sa.Column('refunded_c', sa.Integer(), nullable=False, server_default='0'))
    bind.execute(sa.text("UPDATE cbomcollectionjob SET refunded_c = weight_c WHERE refunded AND weight_c > 0"))

    op.create_table(
        'cbomcreditentry',
        sa.Column('id', sa.Integer(), nullable=False),
        sa.Column('team_id', sa.Integer(), nullable=False),
        sa.Column('run_id', sa.Integer(), nullable=True),
        sa.Column('job_id', sa.Integer(), nullable=True),
        sa.Column('kind', sqlmodel.sql.sqltypes.AutoString(length=8), nullable=False),
        sa.Column('reason', sqlmodel.sql.sqltypes.AutoString(length=32), nullable=False),
        sa.Column('amount_c', sa.Integer(), nullable=False),
        sa.Column('idem_key', sqlmodel.sql.sqltypes.AutoString(length=64), nullable=False),
        sa.Column('created_at', sa.DateTime(), nullable=True),
        sa.ForeignKeyConstraint(['team_id'], ['team.id']),
        sa.ForeignKeyConstraint(['run_id'], ['cbomcollectionrun.id']),
        sa.PrimaryKeyConstraint('id'),
        sa.UniqueConstraint('idem_key'),
    )
    op.create_index(op.f('ix_cbomcreditentry_team_id'), 'cbomcreditentry', ['team_id'], unique=False)
    op.create_index(op.f('ix_cbomcreditentry_run_id'), 'cbomcreditentry', ['run_id'], unique=False)
    op.create_index('ix_cbomcreditentry_team_created', 'cbomcreditentry', ['team_id', 'created_at'], unique=False)

    # the ledger as it stands: each run's charge, each refunded job's refund
    bind.execute(sa.text(
        "INSERT INTO cbomcreditentry (team_id, run_id, job_id, kind, reason, amount_c, idem_key, created_at) "
        "SELECT team_id, id, NULL, 'charge', 'backfill', credits_charged_c, 'run:' || id || ':' || 'charge', :now "
        "FROM cbomcollectionrun WHERE credits_charged_c > 0"), {"now": _now(bind)})
    bind.execute(sa.text(
        "INSERT INTO cbomcreditentry (team_id, run_id, job_id, kind, reason, amount_c, idem_key, created_at) "
        "SELECT team_id, run_id, id, 'refund', 'backfill', refunded_c, 'job:' || id || ':' || 'refund', :now "
        "FROM cbomcollectionjob WHERE refunded AND refunded_c > 0"), {"now": _now(bind)})

    # settle duplicate open collections (keep the oldest per source), then build the index
    rows = bind.execute(sa.text(
        "SELECT id, team_id, run_id, source_id, weight_c, refunded FROM cbomcollectionjob "
        "WHERE kind = 'collect' AND status IN ('pending', 'claimed') AND source_id IS NOT NULL "
        "ORDER BY source_id, id")).all()
    seen: set[int] = set()
    settled = refunded_c = 0
    for job_id, team_id, run_id, source_id, weight_c, refunded in rows:
        if source_id not in seen:
            seen.add(source_id)
            continue
        bind.execute(sa.text(
            "UPDATE cbomcollectionjob SET status = 'cancelled', finished_at = :now, error = :note, lease_id = NULL, "
            "lease_expires_at = NULL WHERE id = :id"), {"now": _now(bind), "note": DUPLICATE_NOTE, "id": job_id})
        settled += 1
        if refunded or not weight_c or weight_c <= 0:
            continue
        bind.execute(sa.text("UPDATE cbomcollectionjob SET refunded = :t, refunded_c = :w WHERE id = :id"),
                     {"t": True, "w": weight_c, "id": job_id})
        if run_id is not None:
            bind.execute(sa.text("UPDATE cbomcollectionrun SET credits_refunded_c = credits_refunded_c + :w "
                                 "WHERE id = :id"), {"w": weight_c, "id": run_id})
        bind.execute(sa.text("UPDATE team SET credit_balance = credit_balance + :c WHERE id = :id"),
                     {"c": weight_c / 100, "id": team_id})
        bind.execute(sa.text(
            "INSERT INTO cbomcreditentry (team_id, run_id, job_id, kind, reason, amount_c, idem_key, created_at) "
            "VALUES (:team, :run, :job, 'refund', 'migration_duplicate', :w, :key, :now)"),
            {"team": team_id, "run": run_id, "job": job_id, "w": weight_c, "key": f"job:{job_id}:refund",
             "now": _now(bind)})
        refunded_c += weight_c
    print(f"cb14credit001: settled {settled} duplicate open collection job(s), refunded {refunded_c / 100:.2f} credits")
    op.create_index('uq_cbomcollectionjob_open_collect', 'cbomcollectionjob', ['source_id'], unique=True,
                    postgresql_where=sa.text(OPEN_COLLECT), sqlite_where=sa.text(OPEN_COLLECT))


def _now(bind):
    return bind.execute(sa.select(sa.func.current_timestamp())).scalar()


def downgrade() -> None:
    """Downgrade schema."""
    op.drop_index('uq_cbomcollectionjob_open_collect', table_name='cbomcollectionjob')
    op.drop_index('ix_cbomcreditentry_team_created', table_name='cbomcreditentry')
    op.drop_index(op.f('ix_cbomcreditentry_run_id'), table_name='cbomcreditentry')
    op.drop_index(op.f('ix_cbomcreditentry_team_id'), table_name='cbomcreditentry')
    op.drop_table('cbomcreditentry')
    with op.batch_alter_table('cbomcollectionjob') as batch:
        batch.drop_column('refunded_c')
