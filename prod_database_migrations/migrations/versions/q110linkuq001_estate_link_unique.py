"""cbomestatelink one link per (asset, scan, component); close Q0 items of assets q109 merged away (review 6060766322)

Revision ID: q110linkuq001
Revises: q109certkey001
Create Date: 2026-11-25 17:00:00.000000

Nit: ``q109certkey001`` merged two estate assets by renaming the old key's links to the new key, so a peer linked to
both kept two identical links. Upgrade: each (team, asset key, kind, scan, component) keeps its lowest-id link, then the
unique index ``uq_cbomestatelink_link`` holds it (the links builder emits one per key already: ``unique_links``; the
key move drops a link the new key holds instead of copying it). On PostgreSQL the index is built CONCURRENTLY, outside
the revision's transaction (as ``q102hist001``): a retry first drops an invalid index an interrupted build left, the
duplicates are removed again right before the build, and a build that a concurrent duplicate made fail is retried.

m2: an asset ``q109certkey001`` merged away (its estate row is gone) kept its open Q0 item until the team's next store
write. This release closes it inside the key move; a database that ran ``q109certkey001`` before this release closes
those items here: every open estate asset item (``detail.estate``) whose estate asset no longer exists closes, as
``model_change`` (recorded, not forwarded) when a key move merged it away, or as ``removed`` when the store removed the
asset in a write without hooks (its register row is still there: ``estate backfill`` without hooks, an operator path).
No ``q0_closed`` event is written by the migration.

Runbook: the CONCURRENTLY build waits for every transaction older than it; each step of an attempt (dropping an
INVALID index left before, building) waits at most ``LOCK_TIMEOUT`` (60 s), three attempts, then one cleanup drop:
4 x 60 s + 2 x 10 s = 260 s in the worst case. If the ``migrate`` one-shot fails on it, end the idle-in-transaction sessions
(``pg_stat_activity``) and run the deploy again (deploy/staging/README.md, "Migrations that build an index
CONCURRENTLY").

Downgrade: drops the unique index (CONCURRENTLY on PostgreSQL). The removed duplicate links and the closed items stay
as they are: a duplicate carried nothing its twin does not, and a closed item stays history (an open item for the old
key is opened again by the register if it is still Q0 after the downgrade's key move).
"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


revision: str = 'q110linkuq001'
down_revision: Union[str, Sequence[str], None] = 'q109certkey001'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None

NAME = 'uq_cbomestatelink_link'
COLUMNS = ['team_id', 'asset_key', 'kind', 'scan_id', 'component']
ATTEMPTS = 3
LOCK_TIMEOUT = '60s'  # per build attempt: how long it may wait for older transactions
RETRY_SECONDS = 10


def _pg() -> bool:
    return op.get_bind().dialect.name == 'postgresql'


def _links() -> sa.Table:
    return sa.table('cbomestatelink', sa.column('id', sa.Integer), *(sa.column(c) for c in COLUMNS))


def dedupe(bind) -> int:
    """Delete every link whose (team, asset key, kind, scan, component) a lower-id link already holds."""
    el = _links()
    el2 = el.alias('el2')
    twin = sa.exists(sa.select(el2.c.id).where(*(el2.c[c] == el.c[c] for c in COLUMNS), el2.c.id < el.c.id))
    return bind.execute(sa.delete(el).where(twin)).rowcount or 0


def close_orphan_q0(bind, now=None) -> dict[str, int]:
    """Open estate asset Q0 items whose estate asset no longer exists close (m2). The cause is what happened to the
    asset (#504 review 6062542062 info): its register row still there means the store removed the asset in a write
    that ran no hooks (``estate backfill`` without hooks, an operator path), so ``removed``; no register row means a
    key move merged it away (q109 deletes the merged key's register row), a re-identification, so ``model_change``
    (recorded, not forwarded). Returns the items closed per cause."""
    import datetime as _dt
    import json

    gq = sa.table('cbomq0gap', sa.column('id', sa.Integer), sa.column('team_id', sa.Integer),
                  sa.column('item_kind', sa.String), sa.column('item_key', sa.String), sa.column('detail'),
                  sa.column('closed_at', sa.DateTime), sa.column('close_cause', sa.String),
                  sa.column('closed_grade', sa.String))
    ea = sa.table('cbomestateasset', sa.column('team_id', sa.Integer), sa.column('asset_key', sa.String))
    rr = sa.table('cbomriskregister', sa.column('team_id', sa.Integer), sa.column('item_key', sa.String))
    key = sa.func.substr(gq.c.item_key, 7)
    gone = ~sa.exists(sa.select(sa.literal(1)).select_from(ea).where(
        ea.c.team_id == gq.c.team_id, ea.c.asset_key == key))
    graded = sa.exists(sa.select(sa.literal(1)).select_from(rr).where(rr.c.team_id == gq.c.team_id,
                                                                      rr.c.item_key == key))
    candidates = bind.execute(sa.select(gq.c.id, gq.c.detail, graded.label('graded')).where(
        gq.c.item_kind == 'asset', gq.c.closed_at.is_(None), gq.c.item_key.like('asset:%'), gone)).all()
    ids: dict[str, list[int]] = {'removed': [], 'model_change': []}
    for gid, detail, has_row in candidates:
        if isinstance(detail, str):
            try:
                detail = json.loads(detail)
            except ValueError:
                detail = None
        if isinstance(detail, dict) and detail.get('estate'):  # a pre-estate (per observation) item: the hook's
            ids['removed' if has_row else 'model_change'].append(int(gid))  # close_legacy_assets handles it
    now = now or _dt.datetime.now(_dt.timezone.utc).replace(tzinfo=None)
    closed = {'removed': 0, 'model_change': 0}
    for cause, todo in ids.items():
        for start in range(0, len(todo), 500):
            closed[cause] += bind.execute(sa.update(gq).where(
                gq.c.id.in_(todo[start:start + 500]), gq.c.closed_at.is_(None)).values(
                closed_at=now, close_cause=cause, closed_grade=None)).rowcount or 0
    return closed


def _valid(bind):
    return bind.execute(sa.text("SELECT i.indisvalid FROM pg_index i JOIN pg_class c ON c.oid = i.indexrelid "
                                "WHERE c.relname = :name"), {"name": NAME}).scalar()


def _drop_invalid(bind, *, concurrently: bool = True) -> None:
    """Drop the index if a failed build left it INVALID (under the same ``lock_timeout``: may raise)."""
    if _valid(bind) is False:
        op.drop_index(NAME, table_name='cbomestatelink', postgresql_concurrently=concurrently, if_exists=True)


def build_concurrently(bind) -> None:
    """PostgreSQL, in an autocommit block: build the unique index CONCURRENTLY (as ``q102hist001``), retry-safe. The
    build waits for every transaction older than it, so each attempt runs under ``lock_timeout`` (``LOCK_TIMEOUT``,
    #504 review 6062542062 nit): an idle-in-transaction connection makes it fail fast instead of holding the
    ``migrate`` one-shot.

    One attempt = drop the INVALID index an earlier attempt or run left, remove duplicates again, build. Any lock
    timeout or duplicate in ANY of those steps fails that attempt only (PR #499 review 6064356833 m2: the drop at the
    start of an attempt used to raise out of the loop, so a held transaction got one build attempt, not three), and
    the next one starts after ``RETRY_SECONDS``, ``ATTEMPTS`` times. After the last failure the INVALID index is
    dropped (non-concurrently, still under ``lock_timeout``: it succeeds as soon as nothing holds a lock on the table,
    so a transaction that only kept an old snapshot leaves no INVALID index) and the error is raised (runbook:
    deploy/staging/README.md "Migrations that build an index CONCURRENTLY").

    Worst case with a transaction that holds the table and stays open: attempt 1 waits ``LOCK_TIMEOUT`` (60 s) to
    build; attempts 2 and 3 each wait ``LOCK_TIMEOUT`` to drop the INVALID index it left; two ``RETRY_SECONDS`` (10 s)
    pauses; one final cleanup wait: 4 x 60 + 2 x 10 = 260 s, about 4.5 minutes."""
    import time

    bind.execute(sa.text("SELECT set_config('lock_timeout', :value, false)"), {"value": LOCK_TIMEOUT})
    failure: Exception | None = None
    try:
        for attempt in range(1, ATTEMPTS + 1):
            try:
                valid = _valid(bind)
                if valid is True:
                    return
                _drop_invalid(bind)  # an interrupted or failed build: drop it, build again
                dedupe(bind)  # a duplicate written since the transactional pass (an older worker's key move)
                op.create_index(NAME, 'cbomestatelink', COLUMNS, unique=True, postgresql_concurrently=True,
                                if_not_exists=True)
                return
            except (sa.exc.IntegrityError, sa.exc.OperationalError) as exc:
                failure = exc
                if attempt < ATTEMPTS:
                    time.sleep(RETRY_SECONDS)
        try:  # leave no INVALID index when the table is free to drop it
            _drop_invalid(bind, concurrently=False)
        except sa.exc.OperationalError:
            pass  # still held: the next run drops it first
        assert failure is not None
        raise failure
    finally:
        bind.execute(sa.text("RESET lock_timeout"))


def upgrade() -> None:
    """Upgrade schema and data."""
    bind = op.get_bind()
    close_orphan_q0(bind)
    dedupe(bind)
    if not _pg():
        op.create_index(NAME, 'cbomestatelink', COLUMNS, unique=True, if_not_exists=True)
        return
    with op.get_context().autocommit_block():
        build_concurrently(bind)


def downgrade() -> None:
    """Downgrade schema."""
    if _pg():
        with op.get_context().autocommit_block():
            op.drop_index(NAME, table_name='cbomestatelink', postgresql_concurrently=True, if_exists=True)
    else:
        op.drop_index(NAME, table_name='cbomestatelink', if_exists=True)
