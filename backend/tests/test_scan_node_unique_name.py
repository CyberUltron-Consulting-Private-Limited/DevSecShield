"""X1 B1 (Nov 11): creating a scan node checked for a node of the same name and then inserted, with no unique
constraint, so two concurrent requests both succeeded and the team had two nodes with one name (X1's 68a3977 only
guards the UI's double click). A unique index on (team_id, lower(name)) refuses the second; the API answers 409
"A scan node named <name> already exists". Migration rv6p1nodename001 renames older duplicates first (oldest keeps the
name, then -2, -3 ...).

The PostgreSQL tests need a throwaway database: P1_PG_URL=postgresql+psycopg2://postgres:pw@127.0.0.1:55433/p1
(skipped without it). The rename rules and the SQLite index run everywhere."""
from __future__ import annotations

import importlib.util
import os
import sys
import threading
import time
from pathlib import Path

import pytest

_REPO_ROOT = Path(__file__).resolve().parents[2]
if str(_REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(_REPO_ROOT))
os.environ.setdefault("JWT_SECRET_KEY", "p1-node-name-secret-not-for-production-use")

import sqlalchemy as sa  # noqa: E402
from fastapi import HTTPException  # noqa: E402
from sqlalchemy.exc import IntegrityError  # noqa: E402
from sqlmodel import Session, SQLModel, create_engine, select  # noqa: E402

from backend.new_models import SCAN_NODE_NAME_INDEX, CbomScanNode, Team, User  # noqa: E402

PG_URL = os.environ.get("P1_PG_URL")
needs_pg = pytest.mark.skipif(not PG_URL, reason="P1_PG_URL not set (throwaway PostgreSQL)")
MIGRATION = _REPO_ROOT / "prod_database_migrations/migrations/versions/rv6p1nodename001_scan_node_unique_name.py"


def _migration():
    spec = importlib.util.spec_from_file_location("rv6p1nodename001", MIGRATION)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)  # type: ignore[union-attr]
    return mod


def test_duplicates_are_renamed_deterministically():
    rows = [(1, 7, "edge"), (2, 7, "Edge"), (3, 7, "edge-2"), (4, 7, "EDGE"), (5, 8, "edge"), (6, 7, "x" * 64),
            (9, 7, "X" * 64)]
    assert _migration().renames(rows) == {2: "Edge-3", 4: "EDGE-4", 9: "X" * 62 + "-2"}
    assert _migration().renames(list(reversed(rows))) == _migration().renames(rows)  # order of the rows read


def test_migration_revises_the_current_head():
    mod = _migration()
    assert mod.revision == "rv6p1nodename001" and mod.down_revision == "rv6s2invite001"  # chained after S2 (one head)
    assert mod.INDEX == SCAN_NODE_NAME_INDEX


def _world(engine):
    SQLModel.metadata.drop_all(engine)
    SQLModel.metadata.create_all(engine)
    with Session(engine) as s:
        s.add(Team(id=1, name="t", credit_balance=10.0))
        s.add(User(id=1, email="p1@example.test", password="x", first_name="p", last_name="1", default_team_id=1))
        s.commit()


def _node(name: str, team_id: int = 1) -> CbomScanNode:
    return CbomScanNode(team_id=team_id, owner_user_id=1, name=name)


def test_the_index_refuses_a_second_name_in_any_case_sqlite(tmp_path):
    engine = create_engine(f"sqlite:///{tmp_path / 'n.db'}")
    _world(engine)
    with Session(engine) as s:
        s.add(_node("Edge-A"))
        s.commit()
        s.add(_node("edge-a"))
        with pytest.raises(IntegrityError) as info:
            s.commit()
    assert SCAN_NODE_NAME_INDEX in str(info.value.orig)


def _race(engine, monkeypatch, n: int = 6):
    """n requests create "Edge-A" in different cases at the same moment; the name check and the insert are held
    apart (as under load) by a pause in token generation, which runs between them."""
    from backend.routers import cbom_sources as routes
    from backend.utilities.cbom_sources.schemas import NodeCreate

    real = routes.new_token
    monkeypatch.setattr(routes, "new_token", lambda prefix: (time.sleep(0.3), real(prefix))[1])
    barrier = threading.Barrier(n)
    results: list = []

    def create(i):
        barrier.wait()
        try:
            results.append(routes._create_node(engine, 1, 1, NodeCreate(name="Edge-A" if i % 2 else "edge-a")))
        except HTTPException as exc:
            results.append(exc)

    threads = [threading.Thread(target=create, args=(i,)) for i in range(n)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    return results


@needs_pg
def test_concurrent_creates_make_one_node_and_409s_on_postgresql(monkeypatch):
    engine = create_engine(PG_URL, pool_size=10)
    _world(engine)
    try:
        results = _race(engine, monkeypatch)
        made = [r for r in results if isinstance(r, dict)]
        refused = [r for r in results if isinstance(r, HTTPException)]
        assert len(made) == 1, results  # before: every request made a node
        assert len(refused) == 5 and {r.status_code for r in refused} == {409}
        assert all("already exists" in r.detail for r in refused)
        with Session(engine) as s:
            assert len(s.exec(select(CbomScanNode).where(CbomScanNode.team_id == 1)).all()) == 1
    finally:
        SQLModel.metadata.drop_all(engine)
        engine.dispose()


@needs_pg
def test_the_migration_renames_duplicates_then_adds_the_index_on_postgresql():
    from alembic.migration import MigrationContext
    from alembic.operations import Operations

    engine = create_engine(PG_URL)
    with engine.begin() as conn:
        conn.execute(sa.text("DROP TABLE IF EXISTS cbomscannode CASCADE"))
        conn.execute(sa.text("CREATE TABLE cbomscannode (id serial PRIMARY KEY, team_id int NOT NULL, "
                             "name varchar(64) NOT NULL)"))
        conn.execute(sa.text("INSERT INTO cbomscannode (id, team_id, name) VALUES (1, 7, 'edge'), (2, 7, 'Edge'), "
                             "(3, 7, 'edge-2'), (4, 8, 'edge')"))
    try:
        with engine.begin() as conn:
            with Operations.context(MigrationContext.configure(conn)):
                _migration().upgrade()
        with engine.begin() as conn:
            names = dict(conn.execute(sa.text("SELECT id, name FROM cbomscannode ORDER BY id")).all())
        assert names == {1: "edge", 2: "Edge-3", 3: "edge-2", 4: "edge"}
        with pytest.raises(IntegrityError), engine.begin() as conn:
            conn.execute(sa.text("INSERT INTO cbomscannode (id, team_id, name) VALUES (10, 7, 'EDGE')"))
        with engine.begin() as conn:
            with Operations.context(MigrationContext.configure(conn)):
                _migration().downgrade()
            conn.execute(sa.text("INSERT INTO cbomscannode (id, team_id, name) VALUES (10, 7, 'EDGE')"))
    finally:
        with engine.begin() as conn:
            conn.execute(sa.text("DROP TABLE IF EXISTS cbomscannode CASCADE"))
        engine.dispose()
