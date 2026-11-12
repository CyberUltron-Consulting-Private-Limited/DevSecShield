"""credits ledger: one append-only line per movement of a team's credits, with its reason (#33)

Revision ID: r6t2ledger001
Revises: rv6p1nodename001
Create Date: 2026-11-11 15:00:00.000000

Table ``creditledger`` (backend/new_models.py CreditLedgerEntry). Written in the same transaction as the balance
change it records. No foreign keys: a line outlives a deleted scan or team. Nothing is backfilled: movements before
this revision have no line.

Append-only is enforced by PostgreSQL, not only by the code: a trigger refuses every UPDATE and DELETE of a line and
every TRUNCATE of the table (an operator who must correct the ledger adds a compensating line). Other databases
(SQLite in tests) get the table without the trigger.

Downgrade renames the table to ``creditledger_archive`` instead of dropping it (financial records are never dropped
by a downgrade); the trigger stays on it, and the next upgrade renames it back.
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
APPEND_ONLY_FUNCTION = "creditledger_append_only"
ROW_TRIGGER = "creditledger_no_update_delete"
TRUNCATE_TRIGGER = "creditledger_no_truncate"


def _append_only() -> None:
    """PostgreSQL: refuse UPDATE/DELETE of any line and TRUNCATE of the table (idempotent)."""
    if op.get_bind().dialect.name != "postgresql":
        return
    # no '%' in these statements: the driver would read it as a parameter marker
    op.execute(
        f"CREATE OR REPLACE FUNCTION {APPEND_ONLY_FUNCTION}() RETURNS trigger LANGUAGE plpgsql AS $$ "
        "BEGIN RAISE EXCEPTION 'creditledger is append-only' "
        "USING DETAIL = TG_OP || ' refused; add a compensating line instead'; END $$"
    )
    op.execute(f"DROP TRIGGER IF EXISTS {ROW_TRIGGER} ON {TABLE}")
    op.execute(f"CREATE TRIGGER {ROW_TRIGGER} BEFORE UPDATE OR DELETE ON {TABLE} "
               f"FOR EACH ROW EXECUTE FUNCTION {APPEND_ONLY_FUNCTION}()")
    op.execute(f"DROP TRIGGER IF EXISTS {TRUNCATE_TRIGGER} ON {TABLE}")
    op.execute(f"CREATE TRIGGER {TRUNCATE_TRIGGER} BEFORE TRUNCATE ON {TABLE} "
               f"FOR EACH STATEMENT EXECUTE FUNCTION {APPEND_ONLY_FUNCTION}()")


def upgrade() -> None:
    """Upgrade schema."""
    if sa.inspect(op.get_bind()).has_table(ARCHIVE):
        op.rename_table(ARCHIVE, TABLE)
        _append_only()
        return
    op.create_table(
        TABLE,
        sa.Column('id', sa.Integer(), nullable=False),
        sa.Column('team_id', sa.Integer(), nullable=False),
        sa.Column('scan_id', sa.Integer(), nullable=True),
        sa.Column('user_id', sa.Integer(), nullable=True),
        sa.Column('delta', sa.Float(), nullable=False),
        sa.Column('balance_after', sa.Float(), nullable=True),
        sa.Column('reason', sqlmodel.sql.sqltypes.AutoString(length=48), nullable=False),
        sa.Column('detail', sa.JSON(), nullable=True),
        sa.Column('created_at', sa.DateTime(), nullable=True),
        sa.PrimaryKeyConstraint('id'),
    )
    op.create_index(op.f('ix_creditledger_team_id'), TABLE, ['team_id'], unique=False)
    op.create_index(op.f('ix_creditledger_scan_id'), TABLE, ['scan_id'], unique=False)
    _append_only()


def downgrade() -> None:
    """Downgrade schema: keep the lines (renamed, still append-only), never drop them."""
    op.rename_table(TABLE, ARCHIVE)
