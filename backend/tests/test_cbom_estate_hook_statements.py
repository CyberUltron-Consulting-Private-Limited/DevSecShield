"""#352: the estate write's hooks do set-based work, whatever the number of sources, jobs and keys.

* agility ``carry_unchanged``: one UPDATE per run (it was one correlated UPDATE ... WHERE EXISTS per source and old
  job, which PostgreSQL could answer by reading a whole job's rows for every observation), with the same result: the
  observations whose re-read row is unchanged move to their source's latest job, a changed row is judged alone;
* ``estate.latest_rows`` (the register refresh's reader): one lookup of the collected rows per (job, attempt), by the
  unique (job_id, attempt, asset_key) index (it was an OR of 300 (job, attempt, key) triples per query).

SQLite always; PostgreSQL with CBOM_TEST_PG_URL (a throwaway database: the schema is dropped and created).
"""
from __future__ import annotations

import contextlib
import copy
import hashlib
import os
import re
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent))

import sqlalchemy as sa  # noqa: E402
from sqlmodel import Session, SQLModel, create_engine, select  # noqa: E402

from backend.new_models import CbomCollectedAsset, CbomCollectionSource, CbomEstateSource  # noqa: E402
from backend.utilities.cbom_sources import agility_store as AS  # noqa: E402
from backend.utilities.cbom_sources import estate as E  # noqa: E402
from test_cbom_cb20_estate import World, endpoint  # noqa: E402

PG = os.environ.get("CBOM_TEST_PG_URL")
needs_pg = pytest.mark.skipif(not PG, reason="set CBOM_TEST_PG_URL to run against PostgreSQL")
CARRY = re.compile(r"UPDATE cbomestateobservation SET fix_job_id")


@pytest.fixture(params=["sqlite", pytest.param("postgresql", marks=needs_pg)])
def world(request, tmp_path):
    engine = create_engine(f"sqlite:///{tmp_path / 'h.db'}") if request.param == "sqlite" else create_engine(PG)
    SQLModel.metadata.drop_all(engine)
    SQLModel.metadata.create_all(engine)
    yield World(engine)
    if request.param == "postgresql":
        SQLModel.metadata.drop_all(engine)
    engine.dispose()


@contextlib.contextmanager
def statements(engine):
    seen: list[str] = []

    def record(_conn, _cursor, statement, *_a):
        seen.append(" ".join(statement.split()))

    sa.event.listen(engine, "before_cursor_execute", record)
    try:
        yield seen
    finally:
        sa.event.remove(engine, "before_cursor_execute", record)


@pytest.fixture()
def judged(monkeypatch):
    keys: list[str] = []
    original = AS.judge_observations

    def spy(*a, **k):
        out = original(*a, **k)
        keys.extend(out)
        return out

    monkeypatch.setattr(AS, "judge_observations", spy)
    return keys


def _key(world, r: dict) -> str:
    """The estate key of the observation of row ``r`` (World's row key -> the store's correlation key)."""
    row_key = hashlib.sha256(f"{r['type']}|{r['target']}|{r['location']}".encode()).hexdigest()
    (key,) = {o.asset_key for o in world.observations() if o.row_key == row_key}
    return key


def _latest(world) -> dict[str, int]:
    with Session(world.engine) as s:
        return {r.source_ref: r.latest_job_id for r in s.exec(select(CbomEstateSource)).all()}


def test_carrying_is_one_statement_per_run_with_the_same_result(world, judged):
    kinds = ["network", "linux_servers", "windows_servers", "aws_account"]
    sources = [world.source(kind, f"src-{i}") for i, kind in enumerate(kinds)]
    rows = {sid: [endpoint(f"10.{i}.0.{h}") for h in range(1, 6)] for i, sid in enumerate(sources)}
    world.finalise(world.run({sid: {"rows": rows[sid]} for sid in sources}))
    assert len(judged) == 20  # the first write judges every observation
    judged.clear()

    second = copy.deepcopy(rows)
    second[sources[1]][0]["facts"] = {"protocols": ["TLSv1.0", "TLSv1.2"], "port": 443}  # one row changed
    with statements(world.engine) as seen:
        world.finalise(world.run({sid: {"rows": second[sid]} for sid in sources}))
    assert len([s for s in seen if CARRY.search(s)]) == 1  # 4 sources: one statement (was one per source)

    assert judged == [_key(world, second[sources[1]][0])]  # the changed row alone is judged
    latest = _latest(world)
    present = [o for o in world.observations() if o.presence == "present"]
    assert len(present) == 20 and all(o.fix_job_id == latest[o.source_ref] for o in present)

    judged.clear()
    with statements(world.engine) as seen:  # nothing changed: everything is carried, nothing judged
        world.finalise(world.run({sid: {"rows": second[sid]} for sid in sources}))
    assert len([s for s in seen if CARRY.search(s)]) == 1 and judged == []
    latest = _latest(world)
    assert all(o.fix_job_id == latest[o.source_ref] for o in world.observations() if o.presence == "present")


def test_a_changed_job_context_carries_nothing_of_that_source(world, judged):
    a, b = world.source("network", "a"), world.source("linux_servers", "b")
    rows = {a: [endpoint("10.1.0.1"), endpoint("10.1.0.2")], b: [endpoint("10.2.0.1")]}
    world.finalise(world.run({a: {"rows": rows[a]}, b: {"rows": rows[b]}}))
    with Session(world.engine) as s:  # source a now belongs to another application: a new system for its assets
        src = s.get(CbomCollectionSource, a)
        src.config = {**(src.config or {}), "application": "Cards"}
        s.add(src)
        s.commit()
    judged.clear()
    with statements(world.engine) as seen:
        world.finalise(world.run({a: {"rows": rows[a]}, b: {"rows": rows[b]}}))
    assert len([q for q in seen if CARRY.search(q)]) == 1  # b's row carried in one statement
    assert sorted(judged) == sorted(_key(world, r) for r in rows[a])  # a's two rows judged again, b's not
    latest = _latest(world)
    assert all(o.fix_job_id == latest[o.source_ref] for o in world.observations() if o.presence == "present")


def test_latest_rows_looks_up_each_job_once(world):
    a, b = world.source("network", "a"), world.source("linux_servers", "b")
    world.finalise(world.run({a: {"rows": [endpoint(f"10.1.{h // 250}.{h % 250}") for h in range(301)]},
                              b: {"rows": [endpoint("10.2.0.1")]}}))
    with Session(world.engine) as s:
        keys = sorted({o.asset_key for o in world.observations()})
        assert len(keys) == 302
        with statements(world.engine) as seen:
            out = E.latest_rows(s, 1, keys)
        lookups = [q for q in seen if q.startswith("SELECT cbomcollectedasset.id")]
        assert len(lookups) == 2  # one per job (was one per 300 triples: 2 for a alone, plus b)
        assert not any("IN ((" in q or "IN (VALUES" in q for q in lookups)  # no row-value list
        rows = {r.id: r for r in s.exec(select(CbomCollectedAsset)).all()}
        row_key = {(o.asset_key, o.source_ref): o.row_key for o in world.observations()}
        found = [(key, ref, obs) for key in keys for ref, obs in out[key]["observations"].items()]
        assert {obs["asset_id"] for _k, _r, obs in found} == set(rows)  # every observation found its row
        for key, ref, obs in found:
            row = rows[obs["asset_id"]]
            assert (row.job_id, row.attempt, row.asset_key) == (obs["job_id"], obs["attempt"], row_key[(key, ref)])
