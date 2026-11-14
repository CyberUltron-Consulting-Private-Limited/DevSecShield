"""cbom evidence confidence: Q0..Q3 -> E0..E3 (CB-18)

Revision ID: cb18evconf001
Revises: r6f14sshca002
Create Date: 2026-11-14 12:00:00.000000

Evidence confidence used the symbols of the quantum risk grade (Q0..Q4). The levels are now E0 Unknown, E1
Self-attested, E2 Documented, E3 Verified (DA §2.3); an E0 item creates a "Q0 gap" in the risk register.

Pure data, no DDL: ``cbomevidencearea.confidence`` and ``cbomevidencevendor.confidence`` stay varchar(2) and "E3" fits.
Only the four old values are rewritten; any other value is left as it is (the read side maps it to E0, as it mapped it
to Q0 before). ``row_version`` and ``last_updated`` are not touched: a renamed level is not a user's edit (ST-F).
Running the upgrade twice changes nothing the second time. The downgrade maps E0..E3 back to Q0..Q3.

The read side (``evidence.level``) also accepts the old spelling, so a row an older process writes during a rolling
deploy, or any row after a code rollback, still reads at its level.

PostgreSQL: both directions run with ``lock_timeout`` 5 s (``SET LOCAL``; the value before is put back at the end):
the UPDATE takes row locks on two small tables that a user's edit can hold; it fails after 5 s instead of queueing
(run it again later) (CB-18 EC-17).
"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = 'cb18evconf001'
down_revision: Union[str, Sequence[str], None] = 'r6f14sshca002'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None

TABLES = ('cbomevidencearea', 'cbomevidencevendor')
LOCK_TIMEOUT = '5s'
UP = {'Q0': 'E0', 'Q1': 'E1', 'Q2': 'E2', 'Q3': 'E3'}
DOWN = {new: old for old, new in UP.items()}


def _pg() -> bool:
    return op.get_bind().dialect.name == "postgresql"


def _lock_timeout(value: str) -> str:
    """Set this transaction's lock_timeout (PostgreSQL); returns the value it had."""
    bind = op.get_bind()
    before = bind.execute(sa.select(sa.func.current_setting("lock_timeout"))).scalar()
    bind.execute(sa.select(sa.func.set_config("lock_timeout", value, True)))
    return str(before)


def _rewrite(mapping: dict[str, str]) -> None:
    bind = op.get_bind()
    before = _lock_timeout(LOCK_TIMEOUT) if _pg() else None
    try:
        for name in TABLES:
            table = sa.table(name, sa.column('confidence', sa.String(2)))
            col = table.c.confidence
            bind.execute(sa.update(table).where(col.in_(list(mapping))).values(confidence=sa.case(mapping, value=col)))
    finally:
        if before is not None:
            _lock_timeout(before)


def upgrade() -> None:
    """Upgrade schema."""
    _rewrite(UP)


def downgrade() -> None:
    """Downgrade schema."""
    _rewrite(DOWN)
