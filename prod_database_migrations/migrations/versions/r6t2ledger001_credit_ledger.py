"""credits ledger: one line per movement of a team's credits, with its reason and a unique movement key (#33, #52)

Revision ID: r6t2ledger001
Revises: rv6p1nodename001
Create Date: 2026-11-11 15:00:00.000000

Table ``creditledger`` (backend/new_models.py CreditLedgerEntry; written by backend/utilities/team/credit_ledger.py):

* ``id`` int8 (never pruned); ``movement_key`` varchar(96) NOT NULL UNIQUE, so one movement can never be written twice;
  a generic reference ``ref_type`` + ``ref_id`` (scan lines also carry ``scan_id``);
* amounts in integer milli-credits, ``delta_mc`` / ``balance_after_mc`` (exact sums; 0.006 credits = 6);
* ``ix_creditledger_team_id_id (team_id, id) INCLUDE (delta_mc, created_at)`` for reconciliation and statements
  (index-only), ``ix_creditledger_scan_id`` partial on scan lines, ``ix_creditledger_ref`` partial on non-scan lines.

These columns exist from the first revision because the table cannot be backfilled later: it is append-only. UPDATE,
DELETE and TRUNCATE are refused by triggers calling ``zs_append_only()``, one function shared by every append-only
table (it names the table and raises SQLSTATE 42501 insufficient_privilege). That is not a control against the
database role itself: the table's owner or a superuser can disable or drop a trigger (least-privilege role: #85).
No foreign keys: a line outlives a deleted scan or team. Nothing is backfilled: movements before this revision have no
line. Other databases (SQLite in tests) get the table without the triggers.

Downgrade policy for append-only tables (financial and audit records are never dropped or made writable by a
downgrade): the table is renamed ``<table>_archive`` and keeps its triggers; ``zs_append_only()`` is kept (other
tables' triggers use it); the next upgrade renames the archive back.
"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa
import sqlmodel


# revision identifiers, used by Alembic.
revision: str = 'r6t2ledger001'
down_revision: Union[str, Sequence[str], None] = 'rv6p1nodename001'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None

TABLE = "creditledger"
ARCHIVE = "creditledger_archive"

# The shared append-only trigger function (also for auditevent, #42). Idempotent; no '%' in the text.
ZS_APPEND_ONLY = (
    "CREATE OR REPLACE FUNCTION zs_append_only() RETURNS trigger LANGUAGE plpgsql AS $$ "
    "BEGIN RAISE EXCEPTION USING "
    "MESSAGE = TG_TABLE_NAME || ' is append-only: ' || TG_OP || ' refused', "
    "ERRCODE = 'insufficient_privilege', "
    "HINT = 'Add a compensating row instead.'; "
    "END $$"
)
ROW_TRIGGER = "creditledger_no_update_delete"
TRUNCATE_TRIGGER = "creditledger_no_truncate"
# the pre-review shape of this revision (float delta, no movement key) used this function; never shipped
OLD_FUNCTION = "creditledger_append_only"


def _append_only() -> None:
    """PostgreSQL: refuse UPDATE/DELETE of any line and TRUNCATE of the table (idempotent)."""
    if op.get_bind().dialect.name != "postgresql":
        return
    op.execute(ZS_APPEND_ONLY)
    op.execute(f"DROP TRIGGER IF EXISTS {ROW_TRIGGER} ON {TABLE}")
    op.execute(f"CREATE TRIGGER {ROW_TRIGGER} BEFORE UPDATE OR DELETE ON {TABLE} "
               "FOR EACH ROW EXECUTE FUNCTION zs_append_only()")
    op.execute(f"DROP TRIGGER IF EXISTS {TRUNCATE_TRIGGER} ON {TABLE}")
    op.execute(f"CREATE TRIGGER {TRUNCATE_TRIGGER} BEFORE TRUNCATE ON {TABLE} "
               "FOR EACH STATEMENT EXECUTE FUNCTION zs_append_only()")
    op.execute(f"DROP FUNCTION IF EXISTS {OLD_FUNCTION}()")


def upgrade() -> None:
    """Upgrade schema."""
    inspector = sa.inspect(op.get_bind())
    if inspector.has_table(ARCHIVE):
        columns = {c["name"] for c in inspector.get_columns(ARCHIVE)}
        if "movement_key" not in columns:
            raise RuntimeError(
                f"{ARCHIVE} has the pre-review shape of r6t2ledger001 (no movement_key; only ever created on test "
                f"databases): drop it (DROP TABLE {ARCHIVE}) and upgrade again")
        op.rename_table(ARCHIVE, TABLE)
        _append_only()
        return
    op.create_table(
        TABLE,
        sa.Column('id', sa.BigInteger().with_variant(sa.Integer(), "sqlite"), autoincrement=True, nullable=False),
        sa.Column('movement_key', sqlmodel.sql.sqltypes.AutoString(length=96), nullable=False),
        sa.Column('team_id', sa.Integer(), nullable=False),
        sa.Column('ref_type', sqlmodel.sql.sqltypes.AutoString(length=32), nullable=False),
        sa.Column('ref_id', sqlmodel.sql.sqltypes.AutoString(length=64), nullable=False),
        sa.Column('scan_id', sa.Integer(), nullable=True),
        sa.Column('user_id', sa.Integer(), nullable=True),
        sa.Column('delta_mc', sa.BigInteger(), nullable=False),
        sa.Column('balance_after_mc', sa.BigInteger(), nullable=True),
        sa.Column('reason', sqlmodel.sql.sqltypes.AutoString(length=48), nullable=False),
        sa.Column('detail', sa.JSON(), nullable=True),
        sa.Column('created_at', sa.DateTime(), nullable=False),
        sa.PrimaryKeyConstraint('id'),
        sa.UniqueConstraint('movement_key', name='uq_creditledger_movement_key'),
    )
    op.create_index('ix_creditledger_team_id_id', TABLE, ['team_id', 'id'], unique=False,
                    postgresql_include=['delta_mc', 'created_at'])
    op.create_index('ix_creditledger_scan_id', TABLE, ['scan_id'], unique=False,
                    postgresql_where=sa.column('scan_id').isnot(None), sqlite_where=sa.column('scan_id').isnot(None))
    op.create_index('ix_creditledger_ref', TABLE, ['ref_type', 'ref_id'], unique=False,
                    postgresql_where=sa.column('ref_type') != 'scan', sqlite_where=sa.column('ref_type') != 'scan')
    _append_only()


def downgrade() -> None:
    """Downgrade schema: keep the lines (renamed, still append-only), never drop them; zs_append_only() stays."""
    op.rename_table(TABLE, ARCHIVE)
