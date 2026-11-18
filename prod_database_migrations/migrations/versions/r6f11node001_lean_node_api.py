"""cbom lean node API (F1.1): per-node replay window, segment jobs, hot-path indexes

Revision ID: r6f11node001
Revises: d44mcphdr001, r6t2ledger001
Create Date: 2026-11-11 12:00:00.000000

* ``cbomscannode.replay_hwm`` / ``replay_bits`` (BIGINT, 0): the protocol-2 anti-replay window (highest request
  sequence accepted + a bitmap of the 63 below it), checked and advanced by one conditional UPDATE per request
  instead of a ``cbomnodenonce`` row (protocol-1 nodes keep using that table).
* ``cbomcollectionsource.node_segment`` / ``cbomcollectionjob.node_segment`` (varchar 64, NULL): a source with a
  segment and no node queues segment jobs that any agentless node of the team in that ``cbomscannode.segment``
  may claim; NULL everywhere for existing rows, so every existing source and job behaves as before.
* ``cbomcollectionjob.refund_due`` (bool, false): a job end marks its credits owed here (the amount in CB-14's
  ``refunded_c``); ``jobs.settle_refunds`` moves the money right after that commit, or in the reaper's pass, and sets
  ``refunded`` (partial index ``ix_cbomcollectionjob_refund_due``).
* Indexes for the claim, heartbeat, reaper and run-status paths; the partial ones cover only open jobs.
  ``(node_id, claimed_at)`` counts the claims a node made since a claim ticket was issued (stateless grants).
* Each node's replay window is seeded from the protocol-2 (``s2_``) nonces the previous code stored in
  ``cbomnodenonce`` (security review S5): the highest such sequence becomes ``replay_hwm`` with every window bit set,
  so a request the older code accepted is refused by this code.  Only well-formed values count (``s2_`` + 19 digits,
  below 2^63, at most 30 days of microseconds ahead of the migration's clock, the bound ``node_auth`` enforces); any
  other row is ignored.  Release rule: replace every backend replica at once (no mixed versions).

Dev has two heads, ``d44mcphdr001`` and ``r6t2ledger001``, both revising ``r6f3repo001``. This revision merges that
pair. ``r6t2ledger001`` stays on ``r6f3repo001``: rewriting it onto ``d44mcphdr001`` makes Alembic 1.17.2 raise
"overlaps with other requested revisions" on a database already stamped with both heads.
"""
import re
import time
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa
import sqlmodel


# revision identifiers, used by Alembic.
revision: str = 'r6f11node001'
down_revision: Union[str, Sequence[str], None] = ('d44mcphdr001', 'r6t2ledger001')
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None

PENDING = "status = 'pending'"
CLAIMED = "status = 'claimed'"
# (name, columns, partial predicate or None)
INDEXES = (
    ('ix_cbomcollectionjob_run_status', ['run_id', 'status'], None),
    ('ix_cbomcollectionjob_node_pending', ['node_id', 'id'], PENDING),
    ('ix_cbomcollectionjob_node_claimed', ['node_id'], CLAIMED),
    ('ix_cbomcollectionjob_claimed_lease', ['lease_expires_at'], CLAIMED),
    ('ix_cbomcollectionjob_pending_created', ['created_at'], PENDING),
    ('ix_cbomcollectionjob_team_status_segment', ['team_id', 'status', 'node_segment', 'id'], None),
    ('ix_cbomcollectionjob_refund_due', ['run_id'], "refund_due AND NOT refunded"),
    ('ix_cbomcollectionjob_node_claimed_at', ['node_id', 'claimed_at'], None),  # claim tickets' used claims
)
_S2 = re.compile(r"^s2_([0-9]{19})$")
_TOP = (1 << 63) - 1
_AHEAD_US = 30 * 86_400 * 1_000_000  # node_auth.SEQ_AHEAD_US
_WINDOW_ALL = (1 << 63) - 1  # bits 0..62: every sequence in the window counts as seen


def seed_replay_windows(bind, now_us: int | None = None) -> int:
    """Seed ``replay_hwm`` / ``replay_bits`` from the ``s2_`` nonces stored by the previous code.  Returns how many
    nodes were seeded.  Malformed or out-of-range values are ignored (a row like ``s2_9999999999999999999`` would
    otherwise abort the migration on the BIGINT cast)."""
    now_us = time.time_ns() // 1000 if now_us is None else now_us
    bound = min(_TOP, (now_us + _AHEAD_US) << 11)
    best: dict[int, int] = {}
    rows = bind.execute(sa.text("SELECT node_id, nonce FROM cbomnodenonce WHERE nonce LIKE 's2!_%' ESCAPE '!'"))
    for node_id, nonce in rows:
        m = _S2.match(nonce or "")
        if not m:
            continue
        value = int(m.group(1))
        if 0 < value <= bound and value > best.get(node_id, 0):
            best[node_id] = value
    for node_id, value in sorted(best.items()):
        bind.execute(sa.text("UPDATE cbomscannode SET replay_hwm = :h, replay_bits = :b WHERE id = :n AND replay_hwm < :h")
                     .bindparams(h=value, b=_WINDOW_ALL, n=node_id))
    return len(best)


def upgrade() -> None:
    """Upgrade schema."""
    op.add_column('cbomscannode', sa.Column('replay_hwm', sa.BigInteger(), nullable=False, server_default='0'))
    op.add_column('cbomscannode', sa.Column('replay_bits', sa.BigInteger(), nullable=False, server_default='0'))
    op.add_column('cbomcollectionsource',
                  sa.Column('node_segment', sqlmodel.sql.sqltypes.AutoString(length=64), nullable=True))
    op.add_column('cbomcollectionjob',
                  sa.Column('node_segment', sqlmodel.sql.sqltypes.AutoString(length=64), nullable=True))
    op.add_column('cbomcollectionjob', sa.Column('refund_due', sa.Boolean(), nullable=False, server_default=sa.false()))
    for name, columns, where in INDEXES:
        kwargs = {'postgresql_where': sa.text(where), 'sqlite_where': sa.text(where)} if where else {}
        op.create_index(name, 'cbomcollectionjob', columns, unique=False, **kwargs)
    seed_replay_windows(op.get_bind())


def downgrade() -> None:
    """Downgrade schema."""
    for name, _columns, _where in reversed(INDEXES):
        op.drop_index(name, table_name='cbomcollectionjob')
    op.drop_column('cbomcollectionjob', 'refund_due')
    op.drop_column('cbomcollectionjob', 'node_segment')
    op.drop_column('cbomcollectionsource', 'node_segment')
    op.drop_column('cbomscannode', 'replay_bits')
    op.drop_column('cbomscannode', 'replay_hwm')
