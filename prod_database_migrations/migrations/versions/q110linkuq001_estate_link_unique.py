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
those items here: every open estate asset item (``detail.estate``) whose estate asset no longer exists closes as
``model_change`` (recorded, not forwarded), as the estate hook closes a moved key's item.

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


def close_orphan_q0(bind, now=None) -> int:
    """Open estate asset Q0 items whose estate asset no longer exists close as ``model_change`` (m2)."""
    import datetime as _dt
    import json

    gq = sa.table('cbomq0gap', sa.column('id', sa.Integer), sa.column('team_id', sa.Integer),
                  sa.column('item_kind', sa.String), sa.column('item_key', sa.String), sa.column('detail'),
                  sa.column('closed_at', sa.DateTime), sa.column('close_cause', sa.String),
                  sa.column('closed_grade', sa.String))
    ea = sa.table('cbomestateasset', sa.column('team_id', sa.Integer), sa.column('asset_key', sa.String))
    gone = ~sa.exists(sa.select(sa.literal(1)).select_from(ea).where(
        ea.c.team_id == gq.c.team_id, ea.c.asset_key == sa.func.substr(gq.c.item_key, 7)))
    candidates = bind.execute(sa.select(gq.c.id, gq.c.detail).where(
        gq.c.item_kind == 'asset', gq.c.closed_at.is_(None), gq.c.item_key.like('asset:%'), gone)).all()
    ids = []
    for gid, detail in candidates:
        if isinstance(detail, str):
            try:
                detail = json.loads(detail)
            except ValueError:
                detail = None
        if isinstance(detail, dict) and detail.get('estate'):  # a pre-estate (per observation) item: the hook's
            ids.append(int(gid))  # close_legacy_assets closes and re-opens it, untouched here
    now = now or _dt.datetime.now(_dt.timezone.utc).replace(tzinfo=None)
    closed = 0
    for start in range(0, len(ids), 500):
        closed += bind.execute(sa.update(gq).where(gq.c.id.in_(ids[start:start + 500]), gq.c.closed_at.is_(None))
                               .values(closed_at=now, close_cause='model_change', closed_grade=None)).rowcount or 0
    return closed


def upgrade() -> None:
    """Upgrade schema and data."""
    bind = op.get_bind()
    close_orphan_q0(bind)
    dedupe(bind)
    if not _pg():
        op.create_index(NAME, 'cbomestatelink', COLUMNS, unique=True, if_not_exists=True)
        return
    with op.get_context().autocommit_block():
        for attempt in range(1, ATTEMPTS + 1):
            valid = bind.execute(sa.text(
                "SELECT i.indisvalid FROM pg_index i JOIN pg_class c ON c.oid = i.indexrelid "
                "WHERE c.relname = :name"), {"name": NAME}).scalar()
            if valid is True:
                return
            if valid is False:  # an interrupted or failed build: drop it, build again
                op.drop_index(NAME, table_name='cbomestatelink', postgresql_concurrently=True, if_exists=True)
            dedupe(bind)  # a duplicate written since the transactional pass (an older worker's key move)
            try:
                op.create_index(NAME, 'cbomestatelink', COLUMNS, unique=True, postgresql_concurrently=True,
                                if_not_exists=True)
                return
            except sa.exc.IntegrityError:
                if attempt == ATTEMPTS:
                    raise


def downgrade() -> None:
    """Downgrade schema."""
    if _pg():
        with op.get_context().autocommit_block():
            op.drop_index(NAME, table_name='cbomestatelink', postgresql_concurrently=True, if_exists=True)
    else:
        op.drop_index(NAME, table_name='cbomestatelink', if_exists=True)
