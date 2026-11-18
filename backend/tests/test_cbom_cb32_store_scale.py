"""CB-32: the estate store's hot queries at scale keep their answers.

The 1.5M-asset timings are in ``bench/cb32_store_scale/bench.py`` (PostgreSQL). These tests pin that each rewritten
query returns what the query it replaced returned:
* agility ``heal``: ``stale_ids`` (index probes) selects exactly what ``_stale_condition`` (a join of every
  observation with its source) selects, over random combinations, and falls back to the scan past its cap;
* the register list: the row-value keyset pages give the same rows as one ordered read, ``total`` on the first page;
* the register summary: one GROUP BY gives the three tallies the three GROUP BYs gave;
* the estate list's source filter (a join now): same assets and pages as the semi-join;
* the migration: up / down / up, and its indexes equal the models' (one head).

PostgreSQL variants: CBOM_TEST_PG_URL=postgresql+psycopg2://postgres@127.0.0.1:55499/cb32 (skipped without it).
"""
from __future__ import annotations

import datetime as dt
import importlib.util
import os
import random
import re
import sys
from pathlib import Path

import pytest

_REPO_ROOT = Path(__file__).resolve().parents[2]
if str(_REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(_REPO_ROOT))
sys.path.insert(0, str(Path(__file__).resolve().parent))

import sqlalchemy as sa  # noqa: E402
from sqlmodel import Session, SQLModel, create_engine  # noqa: E402

from backend.new_models import (  # noqa: E402
    CbomEstateObservation,
    CbomEstateSource,
    CbomRiskRegister,
    Team,
)
from backend.utilities.cbom_sources import agility as AG  # noqa: E402
from backend.utilities.cbom_sources import agility_store as AS  # noqa: E402
from backend.utilities.cbom_sources import estate as E  # noqa: E402
from backend.utilities.cbom_sources import risk_register as RR  # noqa: E402
from test_cbom_cb20_estate import World, endpoint  # noqa: E402

NOW = dt.datetime(2026, 11, 15, 9, 0)
PG = os.environ.get("CBOM_TEST_PG_URL")
needs_pg = pytest.mark.skipif(not PG, reason="set CBOM_TEST_PG_URL to run against PostgreSQL")
MIGRATION = _REPO_ROOT / "prod_database_migrations/migrations/versions/cb32scale001_estate_hot_query_indexes.py"


@pytest.fixture(params=["sqlite", pytest.param("postgresql", marks=needs_pg)])
def engine(request, tmp_path):
    eng = create_engine(f"sqlite:///{tmp_path / 's.db'}") if request.param == "sqlite" else create_engine(PG)
    SQLModel.metadata.drop_all(eng)
    SQLModel.metadata.create_all(eng)
    with Session(eng) as s:
        s.add(Team(id=1, name="T1", credit_balance=0.0))
        s.add(Team(id=2, name="T2", credit_balance=0.0))
        s.commit()
    yield eng
    if request.param != "sqlite":
        SQLModel.metadata.drop_all(eng)
    eng.dispose()


# ----------------------------------------------------------------------------- agility heal
def _observation_world(engine, n: int, rnd: random.Random) -> None:
    today = NOW.date()
    with Session(engine) as s:
        for team in (1, 2):
            for i in range(4):
                s.add(CbomEstateSource(team_id=team, source_ref=f"src{i}", latest_job_id=100 + i, latest_attempt=1 + i % 2,
                                       latest_status="success", latest_comparable=True))
        s.commit()
        rows = []
        for i in range(n):
            team = 1 if i % 5 else 2
            src = rnd.randrange(4)
            presence = rnd.choice(["present", "present", "present", "not_read", "removed"])
            seen_job, seen_attempt = rnd.choice([(100 + src, 1 + src % 2), (90, 1), (100 + src, 3)])
            fix_job, fix_attempt = rnd.choice([(100 + src, 1 + src % 2), (seen_job, seen_attempt), (90, 1), (None, None),
                                               (100 + src, 2 + src % 2)])
            rows.append({
                "team_id": team, "asset_key": f"k{i}", "source_ref": f"src{src}", "observation_key": "o" * 40,
                "row_key": f"r{i}", "asset_type": "certificate", "occurrences": 1, "presence": presence,
                "seen_job_id": seen_job, "seen_attempt": seen_attempt, "state_run_id": 1,
                "fix_version": rnd.choice([AG.version(), AG.version(), "old-1", None]),
                "fix_recheck_on": rnd.choice([None, None, today, today - dt.timedelta(days=3),
                                              today + dt.timedelta(days=9)]),
                "fix_job_id": fix_job, "fix_attempt": fix_attempt})
        s.execute(sa.insert(CbomEstateObservation.__table__), rows)
        s.commit()


def _old_stale(session, team_id: int) -> set[int]:
    eo, es, _ea, _row = AS._tables()
    return set(session.execute(sa.select(eo.c.id).select_from(eo.join(es, sa.and_(
        es.c.team_id == eo.c.team_id, es.c.source_ref == eo.c.source_ref))).where(
        eo.c.team_id == team_id, eo.c.presence != "removed", AS._stale_condition(NOW))).scalars())


def test_heal_finds_exactly_the_stale_observations_through_indexes(engine):
    _observation_world(engine, 3000, random.Random(32))
    with Session(engine) as s:
        for team in (1, 2):
            old = _old_stale(s, team)
            assert 0 < len(old) < 3000
            assert set(AS.stale_ids(s, team, NOW)) == old


def test_heal_scans_once_past_the_cap(engine, monkeypatch):
    _observation_world(engine, 400, random.Random(5))
    monkeypatch.setattr(AS, "STALE_IDS_MAX", 10)
    with Session(engine) as s:
        assert AS.stale_ids(s, 1, NOW) is None


# ----------------------------------------------------------------------------- the register
def _register(engine, n: int) -> None:
    rnd = random.Random(9)
    rows = []
    for i in range(n):
        grade = rnd.choice(["Q1", "Q2", "Q3", "Q4", "Q0", None])
        rows.append({"team_id": 1 if i % 7 else 2, "item_key": f"cert:{i:040x}", "item_kind": "asset", "q_grade": grade,
                     "q_rank": RR.RANK[grade], "q_reason": "graded" if grade not in ("Q0", None) else
                     rnd.choice(["unknown_verdict", "not_correlated"]), "family": rnd.choice(["RSA", "ECC", None]),
                     "source_ref": f"src{i % 3}", "application": f"app-{i % 4}", "presence":
                     rnd.choice(["present", "present", "removed", "not_read"]), "sources": 1, "model_version": "m",
                     "inputs_digest": "i", "grade_digest": "g", "asset_type": "certificate"})
    with Session(engine) as s:
        s.execute(sa.insert(CbomRiskRegister.__table__), rows)
        s.commit()


@pytest.mark.parametrize("filters", [{}, {"grade": "Q2"}, {"source": "src1"}, {"application": "app-2"},
                                     {"presence": "removed"}, {"reason": "not_correlated"}])
def test_register_pages_walk_the_same_rows_as_one_ordered_read(engine, filters):
    _register(engine, 900)
    rt = CbomRiskRegister.__table__
    with Session(engine) as s:
        expect = [k for k, in s.execute(sa.select(rt.c.item_key).where(*RR._where(1, filters))
                                        .order_by(rt.c.q_rank, rt.c.item_key)).all()]
        got, after, totals = [], None, []
        while True:
            page = RR.list_register(s, 1, filters, after=after, limit=37)
            got += [r["item_key"] for r in page["items"]]
            totals.append(page["total"])
            if not page["next_after"]:
                break
            after = RR.decode_after(page["next_after"])
    assert got == expect and totals[0] == len(expect) and all(t is None for t in totals[1:])


def test_register_summary_tallies_equal_the_three_group_bys(engine):
    _register(engine, 900)
    rt = CbomRiskRegister.__table__
    with Session(engine) as s:
        out = RR.summary(s, 1, NOW)
        grades = dict(s.execute(sa.select(rt.c.q_grade, sa.func.count()).where(rt.c.team_id == 1)
                                .group_by(rt.c.q_grade)).all())
        reasons = dict(s.execute(sa.select(rt.c.q_reason, sa.func.count()).where(
            rt.c.team_id == 1, rt.c.q_grade == "Q0").group_by(rt.c.q_reason)).all())
        families: dict = {}
        for fam, grade, n in s.execute(sa.select(rt.c.family, rt.c.q_grade, sa.func.count()).where(
                rt.c.team_id == 1).group_by(rt.c.family, rt.c.q_grade)).all():
            families.setdefault(fam or "Other", {})[grade or "none"] = int(n)
    assert out["total"] == sum(grades.values())
    assert out["q_grades"] == {g or "none": int(grades.get(g, 0)) for g in ("Q1", "Q2", "Q3", "Q4", "Q0", None)}
    assert out["q0_reasons"] == {k: int(v) for k, v in sorted(reasons.items())}
    assert out["families"] == dict(sorted(families.items()))


def test_pending_counts_equal_the_exact_queries_while_the_register_follows_the_store(engine, monkeypatch):
    from backend.new_models import CbomEstateAsset
    from backend.utilities.cbom_sources import qgrade as QG

    _register(engine, 600)
    rt, ea = CbomRiskRegister.__table__, CbomEstateAsset.__table__
    rnd = random.Random(3)
    with Session(engine) as s:
        rows = s.execute(sa.select(rt.c.team_id, rt.c.item_key, rt.c.presence)).all()
        assets = [{"team_id": t, "asset_key": k, "key_kind": "cross", "asset_type": "certificate", "presence": p,
                   "updated_run_id": 1} for t, k, p in rows]
        assets += [{"team_id": 1, "asset_key": f"new:{i:040x}", "key_kind": "cross", "asset_type": "certificate",
                    "presence": rnd.choice(["present", "removed", "not_read"]), "updated_run_id": 1} for i in range(40)]
        s.execute(sa.insert(ea), assets)
        s.execute(sa.update(rt).where(rt.c.item_key.in_([r[1] for r in rows[::9]])).values(model_version="old"))
        s.execute(sa.update(rt).where(rt.c.item_key.in_([r[1] for r in rows[::11]])).values(inputs_digest="zzz"))
        s.commit()
        monkeypatch.setattr(QG, "GRADE_MODEL_VERSION", "m")
        monkeypatch.setattr(RR, "team_inputs", lambda _s, _t: RR.TeamInputs(mosca={}, risk_model={}, by_source={},
                                                                             digest="i"))
        for team in (1, 2):
            stale = s.execute(sa.select(sa.func.count()).select_from(rt).where(
                rt.c.team_id == team, sa.or_(rt.c.model_version != "m", rt.c.inputs_digest != "i"))).scalar_one()
            missing = s.execute(sa.select(sa.func.count()).select_from(ea.outerjoin(rt, sa.and_(
                rt.c.team_id == ea.c.team_id, rt.c.item_key == ea.c.asset_key))).where(
                ea.c.team_id == team, ea.c.presence != "removed", rt.c.id.is_(None))).scalar_one()
            assert RR.missing_count(s, team) == missing
            assert RR.pending(s, team) == stale + missing
            by_model, by_inputs, absent = RR._mismatched(s, team, RR.team_inputs(s, team), "m", 10_000)
            assert set(by_model) == set(s.execute(sa.select(rt.c.item_key).where(
                rt.c.team_id == team, rt.c.model_version != "m")).scalars())
            assert set(by_inputs) == set(s.execute(sa.select(rt.c.item_key).where(
                rt.c.team_id == team, rt.c.model_version == "m", rt.c.inputs_digest != "i")).scalars())
            assert len(absent) == missing


# ----------------------------------------------------------------------------- the estate list
def test_estate_list_source_filter_pages_like_the_semi_join(tmp_path):
    from test_cbom_cb20_estate import _sqlite

    w = World(_sqlite(tmp_path / "e.db"))
    a, b = w.source("network", "a"), w.source("network", "b")
    w.finalise(w.run({a: {"rows": [endpoint(f"52.95.0.{i}") for i in range(1, 40)]},
                      b: {"rows": [endpoint(f"52.95.0.{i}") for i in range(30, 70)]}}))
    eo = CbomEstateObservation.__table__
    with Session(w.engine) as s:
        ref = s.execute(sa.select(eo.c.source_ref).where(eo.c.team_id == 1).order_by(eo.c.source_ref)).scalars().first()
        expect = sorted(s.execute(sa.select(eo.c.asset_key).where(eo.c.team_id == 1, eo.c.source_ref == ref)).scalars())
        got, after = [], None
        while True:
            page = E.list_estate(s, 1, after=after, limit=7, source=ref)
            got += [i["asset_key"] for i in page["items"]]
            if not page["next"]:
                break
            after = page["next"]
        assert got == expect
        assert [i["asset_key"] for i in E.list_estate(s, 1, limit=500, source=ref, presence="present")["items"]] == expect


# ----------------------------------------------------------------------------- migration
def _migration():
    spec = importlib.util.spec_from_file_location("cb32scale001", MIGRATION)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)  # type: ignore[union-attr]
    return mod


def test_one_head():
    revs, downs = set(), set()
    for path in MIGRATION.parent.glob("*.py"):
        text = path.read_text()
        revs.add(re.search(r"^revision(?::\s*str)?\s*=\s*['\"]([^'\"]+)['\"]", text, re.M).group(1))
        down = re.search(r"^down_revision[^=]*=\s*(.+)$", text, re.M)
        if down:
            downs.update(re.findall(r"""['"]([^'"]+)['"]""", down.group(1)))
    assert len(revs - downs) == 1 and _migration().down_revision in revs


def _indexes(eng) -> dict:
    insp = sa.inspect(eng)
    return {t: {i["name"]: tuple(i["column_names"]) for i in insp.get_indexes(t)}
            for t in ("cbomestateobservation", "cbomestateasset", "cbomriskregister")}


def test_migration_up_down_up_gives_the_models_indexes(engine):
    from alembic.migration import MigrationContext
    from alembic.operations import Operations

    want = _indexes(engine)
    for step in ("downgrade", "upgrade", "downgrade"):
        with engine.begin() as conn, Operations.context(MigrationContext.configure(conn)):
            getattr(_migration(), step)()
    before = _indexes(engine)
    assert "ix_cbomestateobs_team_source" in before["cbomestateobservation"]
    assert "ix_cbomestateasset_agility_groups" not in before["cbomestateasset"]
    with engine.begin() as conn, Operations.context(MigrationContext.configure(conn)):
        _migration().upgrade()
    assert _indexes(engine) == want
