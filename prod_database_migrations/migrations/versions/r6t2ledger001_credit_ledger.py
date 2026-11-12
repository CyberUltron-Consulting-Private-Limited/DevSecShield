"""credits ledger: one append-only line per movement of a team's credits, with its reason (#33)

Revision ID: r6t2ledger001
Revises: rv6p1nodename001
Create Date: 2026-11-11 15:00:00.000000

Table ``creditledger`` (backend/new_models.py CreditLedgerEntry). Written in the same transaction as the balance
change it records. No foreign keys: a line outlives a deleted scan or team. Nothing is backfilled: movements before
this revision have no line.

Downgrade renames the table to ``creditledger_archive`` instead of dropping it (financial records are never dropped
by a downgrade); the next upgrade renames it back.
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


def upgrade() -> None:
    """Upgrade schema."""
    if sa.inspect(op.get_bind()).has_table(ARCHIVE):
        op.rename_table(ARCHIVE, TABLE)
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


def downgrade() -> None:
    """Downgrade schema: keep the lines (renamed), never drop them."""
    op.rename_table(TABLE, ARCHIVE)
