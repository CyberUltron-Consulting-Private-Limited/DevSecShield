"""CB-32 follow-up: the summary tables (agility groups, register summary, team counters) always equal the GROUP BYs
they replace, because database triggers keep them in the writing transaction.

* Product paths (estate writes with the CB-23 register and CB-25 agility hooks, presence changes, rekeys, prune,
  team deletion) leave every team's summaries equal to its base tables after each step.
* Raw writes (random inserts, updates of every summarised column, deletes; also batched ``executemany`` and
  ``INSERT … ON CONFLICT``) do too; a rolled-back savepoint rolls the deltas back.
* ``rebuild`` repairs a corrupted summary; ``check_due`` finds and rebuilds it.
* The migration builds the tables and fills them from existing rows (up / down / up).

PostgreSQL: CBOM_TEST_PG_URL=postgresql+psycopg2://postgres@127.0.0.1:55499/cb32test (skipped without it).
"""
from __future__ import annotations

import importlib.util
import os
import random
import sys
from pathlib import Path

import pytest

_REPO_ROOT = Path(__file__).resolve().parents[2]
if str(_REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(_REPO_ROOT))
sys.path.insert(0, str(Path(__file__).resolve().parent))

import sqlalchemy as sa
from backend.new_models import (
    CbomEstateAsset,
    CbomEstateObservation,
    CbomRiskRegister,
)
from backend.utilities.cbom_sources import (
    cleanup as _cleanup,  # noqa: F401  (registers every table it deletes)
)
from backend.utilities.cbom_sources import estate_summary_ddl as S
from sqlmodel import Session, SQLModel, create_engine
from test_cbom_cb20_estate import (
    NOT_AFTER,
    NOW,
    SERIAL,
    World,
    cert,
    endpoint,
)

PG = os.environ.get("CBOM_TEST_PG_URL")
needs_pg = pytest.mark.skipif(not PG, reason="set CBOM_TEST_PG_URL to run against PostgreSQL")
MIGRATION = _REPO_ROOT / "prod_database_migrations/migrations/versions/cb32summary001_estate_summary_tables.py"


@pytest.fixture(params=["sqlite", pytest.param("postgresql", marks=needs_pg)])
def engine(request, tmp_path):
    eng = create_engine(f"sqlite:///{tmp_path / 's.db'}", connect_args={"check_same_thread": False}) \
        if request.param == "sqlite" else create_engine(PG)
    SQLModel.metadata.drop_all(eng)
    SQLModel.metadata.create_all(eng)
    yield eng
    if request.param != "sqlite":
        SQLModel.metadata.drop_all(eng)
    eng.dispose()


def _agree(engine, teams=(1, 2)) -> None:
    with engine.connect() as conn:
        for team in teams:
            assert S.compare(conn, team) == [], team


def test_product_writes_keep_the_summaries_equal_to_the_group_bys(engine):
    w = World(engine)
    p, lin, other = w.source("network", "prober"), w.source("linux_servers", "linux"), w.source("network", "b", 2)
    rnd = random.Random(32)
    for r in range(6):
        hosts = [f"52.95.{r % 2}.{i}" for i in range(rnd.randint(3, 9))]
        jobs = {p: {"rows": [endpoint(h) for h in hosts]
                    + [cert(hosts[0], f"{hosts[0]}:443#chain[0]", serial=SERIAL, not_after=NOT_AFTER)]},
                lin: {"rows": [{"type": "crypto_library", "target": "app", "location": f"/usr/lib/l{i}",
                                "facts": {"name": "openssl"}} for i in range(rnd.randint(0, 4))]}}
        if r == 3:
            jobs[p] = {"status": "failed", "outcome": "failed", "rows": []}  # everything not read
        w.finalise(w.run(jobs))
        w.finalise(w.run({other: {"rows": [endpoint(f"10.9.0.{i}") for i in range(r + 1)]}}, team_id=2))
        _agree(engine)
    with engine.connect() as conn:
        assert S.count(Session(bind=conn), 1, "assets_live") > 0
    from backend.utilities.cbom_sources import estate as E

    with Session(engine) as s:  # prune purges long-removed rows
        E.prune_collected_assets(s, 1, keep_runs=2)
        s.commit()
    _agree(engine)
    from backend.utilities.cbom_sources.cleanup import delete_cbom_sources_for_team

    delete_cbom_sources_for_team(engine, 1)
    _agree(engine)
    with engine.connect() as conn:
        assert conn.execute(sa.text("SELECT coalesce(sum(n), 0) FROM cbomagilitygroup WHERE team_id = 1")).scalar() == 0


def _seed_raw(engine, n: int, rnd: random.Random) -> None:
    from backend.new_models import Team

    with Session(engine) as s:
        s.add(Team(id=1, name="T1", credit_balance=0.0))
        s.add(Team(id=2, name="T2", credit_balance=0.0))
        s.commit()
        s.execute(sa.insert(CbomEstateAsset.__table__), [_asset(i, rnd) for i in range(n)])
        s.execute(sa.insert(CbomEstateObservation.__table__), [_obs(i, rnd) for i in range(n)])
        s.execute(sa.insert(CbomRiskRegister.__table__), [_reg(i, rnd) for i in range(n)])
        s.commit()


def _asset(i: int, rnd: random.Random) -> dict:
    return {"team_id": 1 + i % 2, "asset_key": f"k{i}", "key_kind": rnd.choice(["cross", "source", "not_correlated"]),
            "asset_type": "certificate", "presence": rnd.choice(["present", "present", "not_read", "removed"]),
            "updated_run_id": 1, "fix_class": rnd.choice([None, "none", "configurable", "unknown"]),
            "fix_class_excl_pq": rnd.choice([None, "none", "unknown"]), "fix_reasons": rnd.choice([None, "a", "a,b"]),
            "system_key": rnd.choice([None, "s1", "s2"]), "system_label": "S", "system_kind": "host"}


def _obs(i: int, rnd: random.Random) -> dict:
    return {"team_id": 1 + i % 2, "asset_key": f"k{i}", "source_ref": "src", "observation_key": "o" * 40,
            "row_key": f"r{i}", "asset_type": "certificate", "occurrences": 1,
            "presence": rnd.choice(["present", "not_read", "removed"]), "seen_job_id": 1, "state_run_id": 1}


def _reg(i: int, rnd: random.Random) -> dict:
    return {"team_id": 1 + i % 2, "item_key": f"k{i}", "item_kind": "asset", "q_grade": rnd.choice(["Q1", "Q0", None]),
            "q_rank": 1, "q_reason": rnd.choice(["graded", "not_correlated"]), "family": rnd.choice(["RSA", None]),
            "presence": rnd.choice(["present", "removed"]), "sources": 1, "model_version": "m", "inputs_digest": "i",
            "grade_digest": "g"}


def test_raw_writes_and_rollbacks_keep_the_summaries_exact(engine):
    rnd = random.Random(7)
    _seed_raw(engine, 300, rnd)
    _agree(engine)
    ea, eo, rt = CbomEstateAsset.__table__, CbomEstateObservation.__table__, CbomRiskRegister.__table__
    for step in range(25):
        with Session(engine) as s:
            keys = [f"k{rnd.randrange(300)}" for _ in range(rnd.randint(1, 30))]
            pick = rnd.randrange(7)
            if pick == 0:
                s.execute(sa.update(ea).where(ea.c.asset_key.in_(keys)).values(
                    presence=rnd.choice(["present", "removed", "not_read"])))
            elif pick == 1:
                s.execute(sa.update(ea).where(ea.c.asset_key.in_(keys)).values(
                    fix_class=rnd.choice([None, "code", "unknown"]), fix_reasons=rnd.choice([None, "z"]),
                    system_key=rnd.choice([None, "s3"]), key_kind=rnd.choice(["cross", "not_correlated"])))
            elif pick == 2:
                s.execute(sa.delete(ea).where(ea.c.asset_key.in_(keys)))
            elif pick == 3:  # batched executemany, as agility_store writes
                stmt = sa.update(ea).where(ea.c.asset_key == sa.bindparam("b")).values(fix_class=sa.bindparam("c"))
                s.execute(stmt, [{"b": k, "c": rnd.choice(["none", "hardware-fixed"])} for k in keys])
            elif pick == 4:
                s.execute(sa.update(eo).where(eo.c.asset_key.in_(keys)).values(
                    presence=rnd.choice(["present", "removed"])))
            elif pick == 5:
                s.execute(sa.update(rt).where(rt.c.item_key.in_(keys)).values(
                    q_grade=rnd.choice(["Q2", None]), presence=rnd.choice(["present", "removed"])))
            else:  # INSERT … ON CONFLICT DO UPDATE, as estate and the register upsert
                if engine.dialect.name == "postgresql":
                    from sqlalchemy.dialects.postgresql import insert
                else:
                    from sqlalchemy.dialects.sqlite import insert
                rows = [_reg(int(k[1:]), rnd) | {"item_key": k, "team_id": 1 + int(k[1:]) % 2} for k in set(keys)]
                rows += [_reg(1000 + step * 50 + j, rnd) for j in range(3)]
                stmt = insert(rt).values(rows)
                s.execute(stmt.on_conflict_do_update(index_elements=["team_id", "item_key"], set_={
                    "q_grade": stmt.excluded.q_grade, "family": stmt.excluded.family}))
            if step % 5 == 4:  # a savepoint rolled back leaves nothing behind
                with s.begin_nested() as nested:
                    s.execute(sa.update(ea).values(presence="removed"))
                    s.execute(sa.delete(rt))
                    nested.rollback()
            s.commit()
        _agree(engine)


def test_rebuild_and_the_daily_check_repair_a_corrupted_summary(engine, monkeypatch, caplog):
    _seed_raw(engine, 120, random.Random(3))
    with engine.begin() as conn:
        conn.execute(sa.text("UPDATE cbomagilitygroup SET n = n + 5 WHERE team_id = 1"))
        conn.execute(sa.text("DELETE FROM cbomestatecount WHERE team_id = 2"))
    with engine.connect() as conn:
        assert S.compare(conn, 1) == ["cbomagilitygroup"] and S.compare(conn, 2)
    monkeypatch.setattr(S, "_last_check", [])
    with caplog.at_level("ERROR"):
        out = S.check_due(engine)
    assert out == {"teams": 2, "rebuilt": 2} and "disagreed" in caplog.text
    _agree(engine)
    assert S.check_due(engine) is None  # once a day
    with engine.begin() as conn:
        conn.execute(sa.text("DELETE FROM cbomregistersummary"))
        S.rebuild(conn, 1)
        S.rebuild(conn, 2)
    _agree(engine)


def _migration():
    spec = importlib.util.spec_from_file_location("cb32summary001", MIGRATION)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)  # type: ignore[union-attr]
    return mod


def test_migration_builds_and_fills_the_summaries(engine):
    from alembic.migration import MigrationContext
    from alembic.operations import Operations

    def step(name):
        with engine.begin() as conn, Operations.context(MigrationContext.configure(conn)):
            getattr(_migration(), name)()

    step("downgrade")  # no summary tables, no triggers
    assert not set(S.SUMMARIES) & set(sa.inspect(engine).get_table_names())
    _seed_raw(engine, 200, random.Random(11))  # rows written before the migration
    step("upgrade")
    _agree(engine)
    step("downgrade")
    step("upgrade")
    _agree(engine)
    with Session(engine) as s:  # the triggers are live after the upgrade
        s.execute(sa.update(CbomEstateAsset.__table__).values(presence="removed"))
        s.commit()
    _agree(engine)


def test_one_head():
    import re

    revs, downs = set(), set()
    for path in MIGRATION.parent.glob("*.py"):
        text = path.read_text()
        revs.add(re.search(r"^revision(?::\s*str)?\s*=\s*['\"]([^'\"]+)['\"]", text, re.MULTILINE).group(1))
        down = re.search(r"^down_revision[^=]*=\s*(.+)$", text, re.MULTILINE)
        if down:
            downs.update(re.findall(r"""['"]([^'"]+)['"]""", down.group(1)))
    assert len(revs - downs) == 1 and _migration().down_revision in revs


assert NOW  # imported for the World helpers' clock
