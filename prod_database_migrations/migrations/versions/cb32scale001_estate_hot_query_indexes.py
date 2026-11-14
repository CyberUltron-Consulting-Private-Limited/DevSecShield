"""cbom store at scale (CB-32): indexes for the estate store's hot queries at 1.5M assets per team

Revision ID: cb32scale001
Revises: w9cloudpool001
Create Date: 2026-11-15 10:00:00.000000

Measured on PostgreSQL 15 with 1.5M assets (``bench/cb32_store_scale/bench.py``):

* ``cbomestateobservation``:
  * ``(team_id, source_ref)`` becomes ``(team_id, source_ref, asset_key)``, so a source's observations are read in
    key order (``present_keys``, the estate list's source filter);
  * partial indexes for the live count and for agility ``heal``'s stale probes: version, recheck day, a present
    observation whose class was computed from another job, a not-read one whose pointer moved.
* ``cbomestateasset``:
  * ``(team_id, system_key, fix_class)`` becomes a covering partial index over the live classed assets, so the agility
    roll-up is one index-only GROUP BY;
  * class indexes for the roll-up pages, plus the fix-version and not-correlated partial indexes.
* ``cbomriskregister``: list-order indexes for the source, application, reason and not-present filters, a covering
  ``(team_id, q_grade, q_reason, family, presence)`` for the one summary GROUP BY, ``(team_id, model_version, inputs_digest)``
  for the re-grade's "graded with other rules" ranges, and live-row partial indexes (with the estate's) so "not graded
  yet" is two index-only counts instead of an anti-join.

Only indexes change. On PostgreSQL both directions run with ``lock_timeout`` 5 s: if a long transaction holds the
table, the build fails fast instead of queueing every estate write behind it; run the migration again later.
"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


revision: str = 'cb32scale001'
down_revision: Union[str, Sequence[str], None] = 'w9cloudpool001'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None

LOCK_TIMEOUT = "5s"
AGILITY_LIVE = "presence <> 'removed' AND fix_class IS NOT NULL"
NOT_REMOVED = "presence <> 'removed'"
NOT_CORRELATED_LIVE = "key_kind = 'not_correlated' AND presence <> 'removed'"
RECHECK = "presence <> 'removed' AND fix_recheck_on IS NOT NULL"
UNREAD_MOVED = "presence = 'not_read' AND (fix_job_id <> seen_job_id OR fix_attempt <> seen_attempt)"
NOT_PRESENT = "presence <> 'present'"
PRESENT = "presence = 'present'"

# (name, table, columns, partial predicate or None, include or None)
INDEXES = (
    ("ix_cbomestateobs_team_source_key", "cbomestateobservation", ["team_id", "source_ref", "asset_key"], None, None),
    ("ix_cbomestateobs_team_live", "cbomestateobservation", ["team_id"], NOT_REMOVED, None),
    ("ix_cbomestateobs_team_fix_version", "cbomestateobservation", ["team_id", "fix_version"], NOT_REMOVED, None),
    ("ix_cbomestateobs_team_recheck", "cbomestateobservation", ["team_id", "fix_recheck_on"], RECHECK, None),
    ("ix_cbomestateobs_present_fix", "cbomestateobservation", ["team_id", "source_ref", "fix_job_id", "fix_attempt"],
     PRESENT, None),
    ("ix_cbomestateobs_unread_fix_moved", "cbomestateobservation", ["team_id"], UNREAD_MOVED, None),
    ("ix_cbomestateasset_agility_groups", "cbomestateasset",
     ["team_id", "system_key", "fix_class", "fix_class_excl_pq", "fix_reasons"], AGILITY_LIVE,
     ["system_label", "system_kind"]),
    ("ix_cbomestateasset_agility_class", "cbomestateasset", ["team_id", "fix_class", "asset_key"], AGILITY_LIVE, None),
    ("ix_cbomestateasset_agility_class_excl", "cbomestateasset", ["team_id", "fix_class_excl_pq", "asset_key"],
     AGILITY_LIVE, None),
    ("ix_cbomestateasset_team_fix_version", "cbomestateasset", ["team_id", "fix_version"], NOT_REMOVED, None),
    ("ix_cbomestateasset_team_not_correlated", "cbomestateasset", ["team_id"], NOT_CORRELATED_LIVE, None),
    ("ix_cbomriskregister_team_source_rank", "cbomriskregister", ["team_id", "source_ref", "q_rank", "item_key"], None,
     None),
    ("ix_cbomriskregister_team_app_rank", "cbomriskregister", ["team_id", "application", "q_rank", "item_key"], None,
     None),
    ("ix_cbomriskregister_team_reason_rank", "cbomriskregister", ["team_id", "q_reason", "q_rank", "item_key"], None,
     None),
    ("ix_cbomriskregister_team_unpresent_rank", "cbomriskregister", ["team_id", "presence", "q_rank", "item_key"],
     NOT_PRESENT, None),
    ("ix_cbomriskregister_team_summary", "cbomriskregister", ["team_id", "q_grade", "q_reason", "family", "presence"],
     None, None),
    ("ix_cbomriskregister_team_model_inputs", "cbomriskregister", ["team_id", "model_version", "inputs_digest"], None,
     None),
    ("ix_cbomriskregister_team_live", "cbomriskregister", ["team_id"], NOT_REMOVED, None),
    ("ix_cbomestateasset_team_live", "cbomestateasset", ["team_id"], NOT_REMOVED, None),
)
# replaced by a wider index above (same leading columns)
REPLACED = (
    ("ix_cbomestateobs_team_source", "cbomestateobservation", ["team_id", "source_ref"]),
    ("ix_cbomestateasset_team_system_fix", "cbomestateasset", ["team_id", "system_key", "fix_class"]),
)


def _pg() -> bool:
    return op.get_bind().dialect.name == "postgresql"


def _lock_timeout(value: str) -> str:
    bind = op.get_bind()
    before = bind.execute(sa.select(sa.func.current_setting("lock_timeout"))).scalar()
    bind.execute(sa.select(sa.func.set_config("lock_timeout", value, True)))
    return str(before)


def upgrade() -> None:
    before = _lock_timeout(LOCK_TIMEOUT) if _pg() else None
    for name, table, columns, where, include in INDEXES:
        kw = {}
        if where:
            kw.update(postgresql_where=sa.text(where), sqlite_where=sa.text(where))
        if include:
            kw["postgresql_include"] = include
        op.create_index(name, table, columns, unique=False, **kw)
    for name, table, _columns in REPLACED:
        op.drop_index(name, table_name=table)
    if before is not None:
        _lock_timeout(before)


def downgrade() -> None:
    before = _lock_timeout(LOCK_TIMEOUT) if _pg() else None
    for name, table, columns in REPLACED:
        op.create_index(name, table, columns, unique=False)
    for name, table, _columns, _where, _include in reversed(INDEXES):
        op.drop_index(name, table_name=table)
    if before is not None:
        _lock_timeout(before)
