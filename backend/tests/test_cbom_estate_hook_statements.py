"""#352: the estate write's hooks write and read only what a run changed, with the same answers.

* agility (``agility_store.advance``): a source brought up to date for the job it pointed at before (``fix_through``)
  compares the new job's rows with that job's by ``content_digest``; an observation whose row is the same is not
  written at all (it was one UPDATE per observation, then one per run that rewrote every pointer); a changed row is
  judged alone; ``fix_through`` marks the source up to date;
* register (``risk_register.write_keys``): only the keys whose observations changed are read and re-digested;
* ``estate.latest_rows``: one lookup of the collected rows per (job, attempt), by the unique index;
* the same answers: a randomized history (row changes the agility class reads, changes only the register reads, new and
  vanished rows, incomplete collections, a job-context change, a run written without hooks) gives the same observation
  classes, asset classes and register rows as the reference path (``USE_DIGESTS = False``: every observation compared
  row by row and every key re-digested, as before #352);
* the digest is set on every insert path (bulk VALUES, executemany, ORM) and differs whenever a stored value does.

SQLite always; PostgreSQL with CBOM_TEST_PG_URL (a throwaway database: the schema is dropped and created).
"""
from __future__ import annotations

import contextlib
import copy
import hashlib
import os
import random
import re
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent))

import sqlalchemy as sa  # noqa: E402
from sqlmodel import Session, SQLModel, create_engine, select  # noqa: E402

from backend.new_models import (  # noqa: E402
    CbomCollectedAsset,
    CbomCollectionSource,
    CbomEstateAsset,
    CbomEstateObservation,
    CbomEstateSource,
    CbomRiskRegister,
    content_digest,
)
from backend.utilities.cbom_sources import agility_store as AS  # noqa: E402
from backend.utilities.cbom_sources import estate as E  # noqa: E402
from backend.utilities.cbom_sources import q0register  # noqa: E402,F401  (registers the risk register's hook)
from backend.utilities.cbom_sources import risk_register as RR  # noqa: E402
from test_cbom_cb20_estate import NOW, World, endpoint  # noqa: E402

PG = os.environ.get("CBOM_TEST_PG_URL")
needs_pg = pytest.mark.skipif(not PG, reason="set CBOM_TEST_PG_URL to run against PostgreSQL")
AGILITY_WRITE = re.compile(r"^(WITH carry AS MATERIALIZED .*)?UPDATE cbomestateobservation SET fix_")


def _engine(kind: str, tmp_path: Path, name: str):
    engine = create_engine(f"sqlite:///{tmp_path / name}") if kind == "sqlite" else create_engine(PG)
    SQLModel.metadata.drop_all(engine)
    SQLModel.metadata.create_all(engine)
    return engine


@pytest.fixture(params=["sqlite", pytest.param("postgresql", marks=needs_pg)])
def kind(request):
    return request.param


@pytest.fixture()
def world(kind, tmp_path):
    engine = _engine(kind, tmp_path, "h.db")
    yield World(engine)
    if kind == "postgresql":
        SQLModel.metadata.drop_all(engine)
    engine.dispose()


@contextlib.contextmanager
def statements(engine):
    """(statement, rows it changed) for every statement executed inside the block."""
    seen: list[tuple[str, int]] = []

    def record(_conn, cursor, statement, *_a):
        seen.append((" ".join(statement.split()), int(getattr(cursor, "rowcount", -1) or 0)))

    sa.event.listen(engine, "after_cursor_execute", record)
    try:
        yield seen
    finally:
        sa.event.remove(engine, "after_cursor_execute", record)


def agility_rows_written(seen) -> int:
    return sum(max(n, 0) for q, n in seen if AGILITY_WRITE.search(q))


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


def _up_to_date(world) -> bool:
    with Session(world.engine) as s:
        srcs = s.exec(select(CbomEstateSource)).all()
        fresh = all((r.fix_through_job_id, r.fix_through_attempt) == (r.latest_job_id, r.latest_attempt)
                    for r in srcs)
        return fresh and AS.stale_ids(s, 1, NOW) == []


# ---------------------------------------------------------------------------------------------- agility
def test_an_unchanged_re_read_writes_no_observation(world, judged):
    kinds = ["network", "linux_servers", "windows_servers", "aws_account"]
    sources = [world.source(k, f"src-{i}") for i, k in enumerate(kinds)]
    rows = {sid: [endpoint(f"10.{i}.0.{h}") for h in range(1, 6)] for i, sid in enumerate(sources)}
    world.finalise(world.run({sid: {"rows": rows[sid]} for sid in sources}))
    assert len(judged) == 20 and _up_to_date(world)  # the first write judges every observation
    judged.clear()

    second = copy.deepcopy(rows)
    second[sources[1]][0]["facts"] = {"protocols": ["TLSv1.0", "TLSv1.2"], "port": 443}  # one row changed
    with statements(world.engine) as seen:
        world.finalise(world.run({sid: {"rows": second[sid]} for sid in sources}))
    assert judged == [_key(world, second[sources[1]][0])]  # the changed row alone is judged ...
    assert agility_rows_written(seen) == 1  # ... and written: the 19 unchanged ones are not touched
    assert _up_to_date(world)

    judged.clear()
    with statements(world.engine) as seen:  # nothing changed: nothing judged, no observation written
        world.finalise(world.run({sid: {"rows": second[sid]} for sid in sources}))
    assert judged == [] and agility_rows_written(seen) == 0 and _up_to_date(world)


def test_a_changed_job_context_judges_that_source_alone(world, judged):
    a, b = world.source("network", "a"), world.source("linux_servers", "b")
    rows = {a: [endpoint("10.1.0.1"), endpoint("10.1.0.2")], b: [endpoint("10.2.0.1")]}
    world.finalise(world.run({a: {"rows": rows[a]}, b: {"rows": rows[b]}}))
    with Session(world.engine) as s:  # source a now belongs to another application: a new system for its assets
        src = s.get(CbomCollectionSource, a)
        src.config = {**(src.config or {}), "application": "Cards"}
        s.add(src)
        s.commit()
    judged.clear()
    world.finalise(world.run({a: {"rows": rows[a]}, b: {"rows": rows[b]}}))
    assert sorted(judged) == sorted(_key(world, r) for r in rows[a])  # a's two rows judged again, b's not
    assert _up_to_date(world)


def test_a_run_written_without_hooks_is_caught_up_by_the_next_one(world, judged, monkeypatch):
    a = world.source("network", "a")
    rows = [endpoint(f"10.1.0.{h}") for h in range(1, 4)]
    world.finalise(world.run({a: {"rows": rows}}))
    changed = copy.deepcopy(rows)
    changed[0]["facts"] = {"protocols": ["TLSv1.0"], "port": 443}
    with monkeypatch.context() as m:  # a backfill without hooks: the store moves on, the markers do not
        m.setattr(E, "HOOKS", [])
        world.finalise(world.run({a: {"rows": changed}}))
    with Session(world.engine) as s:
        assert len(AS.stale_ids(s, 1, NOW) or []) == 3  # behind: every present observation of the source is stale
    world.finalise(world.run({a: {"rows": changed}}))  # the marker is not the previous job: compared row by row
    assert _up_to_date(world)


# ---------------------------------------------------------------------------------------------- register reader
def test_latest_rows_looks_up_each_job_once(world):
    a, b = world.source("network", "a"), world.source("linux_servers", "b")
    world.finalise(world.run({a: {"rows": [endpoint(f"10.1.{h // 250}.{h % 250}") for h in range(301)]},
                              b: {"rows": [endpoint("10.2.0.1")]}}))
    with Session(world.engine) as s:
        keys = sorted({o.asset_key for o in world.observations()})
        assert len(keys) == 302
        with statements(world.engine) as seen:
            out = E.latest_rows(s, 1, keys)
        lookups = [q for q, _n in seen if q.startswith("SELECT cbomcollectedasset.id")]
        assert len(lookups) == 2  # one per job (was one per 300 triples: 2 for a alone, plus b)
        assert not any("IN ((" in q or "IN (VALUES" in q for q in lookups)  # no row-value list
        rows = {r.id: r for r in s.exec(select(CbomCollectedAsset)).all()}
        row_key = {(o.asset_key, o.source_ref): o.row_key for o in world.observations()}
        found = [(key, ref, obs) for key in keys for ref, obs in out[key]["observations"].items()]
        assert {obs["asset_id"] for _k, _r, obs in found} == set(rows)  # every observation found its row
        for key, ref, obs in found:
            row = rows[obs["asset_id"]]
            assert (row.job_id, row.attempt, row.asset_key) == (obs["job_id"], obs["attempt"], row_key[(key, ref)])


def test_the_register_reads_only_the_changed_keys(world, monkeypatch):
    a = world.source("network", "a")
    rows = [endpoint(f"10.1.0.{h}") for h in range(1, 21)]
    world.finalise(world.run({a: {"rows": rows}}))
    asked: list[int] = []
    original = RR.refresh

    def spy(session, team_id, keys, *a, **k):
        keys = sorted(set(keys))
        asked.append(len(keys))
        return original(session, team_id, keys, *a, **k)

    monkeypatch.setattr(RR, "refresh", spy)
    changed = copy.deepcopy(rows)
    changed[3]["qv"] = True  # a grade input the agility class does not read
    world.finalise(world.run({a: {"rows": changed}}))
    assert asked == [1]  # one key read and re-digested (was 20)
    world.finalise(world.run({a: {"rows": changed}}))
    assert asked == [1, 0]


# ---------------------------------------------------------------------------------------------- the digest
def test_the_content_digest_is_set_on_every_insert_path_and_follows_the_stored_values(world):
    t = CbomCollectedAsset.__table__
    a = world.source("network", "a")
    run = world.run({a: {"rows": [endpoint("10.1.0.1")]}})
    with Session(world.engine) as s:
        job = s.exec(select(CbomCollectedAsset)).one()
        base = dict(team_id=1, run_id=run, job_id=job.job_id, source_id=a, asset_type="kms_key", cdx_type="c",
                    location="vault:k", facts={"key_spec": "AES"}, finding_codes=[])
        s.execute(sa.insert(t).values([{**base, "attempt": 2, "asset_key": f"v{i}"} for i in range(2)]))
        s.execute(sa.insert(t), [{**base, "attempt": 3, "asset_key": f"m{i}"} for i in range(2)])
        s.commit()
        digests = {r.asset_key: r.content_digest for r in s.exec(select(CbomCollectedAsset)).all()}
    assert all(digests.values())  # the ORM row (World), multi-VALUES and executemany inserts
    assert digests["v0"] == digests["v1"] == digests["m0"]  # same stored values, same digest
    assert digests["v0"] == content_digest(base)
    variants = [{"facts": {"key_spec": "RSA"}}, {"facts": {"key_spec": "AES", "x": 1}}, {"target": "h"},
                {"quantum_vulnerable": True}, {"impact": "high"}, {"finding_codes": ["C1"]}, {"key_size": 256},
                {"facts": None}]
    seen = {content_digest(base)} | {content_digest({**base, **v}) for v in variants}
    assert len(seen) == len(variants) + 1  # every stored difference is a different digest
    without = {k: v for k, v in base.items() if k != "facts"}
    assert content_digest(without) != content_digest({**base, "facts": None})  # SQL NULL vs JSON null
    assert content_digest({**base, "facts": {"a": 1, "b": 2}}) != content_digest({**base, "facts": {"b": 2, "a": 1}})


# ---------------------------------------------------------------------------------------------- same answers
OBS_FIELDS = ("presence", "fix_class", "fix_class_excl_pq", "fix_floor", "fix_reasons", "fix_codes", "fix_version",
              "fix_recheck_on", "system_key", "system_label", "system_kind", "cert_cnb_key", "cert_cn_key")
ASSET_FIELDS = ("presence", "fix_class", "fix_class_excl_pq", "fix_floor", "fix_reasons", "fix_codes", "fix_version",
                "system_key", "system_label", "system_kind", "fix_observations")
REGISTER_FIELDS = ("item_key", "q_grade", "q_rank", "q_reason", "label", "asset_type", "family", "source_ref",
                   "source_name", "application", "exposure", "presence", "sources", "last_run_id",
                   "model_version", "inputs_digest", "grade_digest")  # last_observed_at: the wall clock


def _snapshot(engine) -> tuple:
    with Session(engine) as s:
        obs = sorted(tuple([o.asset_key, o.source_ref] + [getattr(o, f) for f in OBS_FIELDS])
                     for o in s.exec(select(CbomEstateObservation)).all())
        assets = sorted(tuple([a.asset_key] + [getattr(a, f) for f in ASSET_FIELDS])
                        for a in s.exec(select(CbomEstateAsset)).all())
        register = sorted(tuple(getattr(r, f) for f in REGISTER_FIELDS)
                          for r in s.exec(select(CbomRiskRegister)).all())
        return obs, assets, register


def _history(world, seed: int, monkeypatch) -> list:
    rnd = random.Random(seed)
    kinds = ["network", "linux_servers", "windows_servers"]
    sources = [world.source(k, f"s{i}") for i, k in enumerate(kinds)]
    rows = {sid: [endpoint(f"10.{i}.0.{h}") for h in range(1, 13)] for i, sid in enumerate(sources)}
    snaps: list = []
    for step in range(8):
        jobs = {}
        for i, sid in enumerate(sources):
            if rnd.random() < 0.15:
                continue  # not in this run
            mine = rows[sid]
            for r in rnd.sample(mine, 3):
                pick = rnd.random()
                if pick < 0.35:  # what the agility class reads
                    r["facts"] = {"protocols": rnd.choice([["TLSv1.0", "TLSv1.2"], ["TLSv1.2"], ["TLSv1.3"]]),
                                  "port": 443}
                elif pick < 0.6:  # only the register reads it
                    r["qv"] = rnd.choice([None, True, False])
                elif pick < 0.75:
                    r["codes"] = rnd.choice([[], ["TLS_LEGACY_PROTOCOL"]])
                elif pick < 0.9 and len(mine) > 4:
                    mine.remove(r)  # gone (removed in a complete collection, not read in an incomplete one)
                else:
                    mine.append(endpoint(f"10.{i}.1.{step * 10 + len(mine)}"))
            spec: dict = {"rows": copy.deepcopy(mine)}
            if rnd.random() < 0.2:
                spec.update(outcome="partial", counts={"ok": 1, "partial": 1})
            jobs[sid] = spec
        if step == 4:  # a job context change: source 0 moves to another application
            with Session(world.engine) as s:
                src = s.get(CbomCollectionSource, sources[0])
                src.config = {**(src.config or {}), "application": "Cards"}
                s.add(src)
                s.commit()
        if not jobs:
            continue
        run = world.run(jobs)
        if step == 2:  # written without hooks (a backfill): the next run catches up
            with monkeypatch.context() as m:
                m.setattr(E, "HOOKS", [])
                world.finalise(run)
            snaps.append(("no hooks", step))
            continue
        world.finalise(run)
        snaps.append(_snapshot(world.engine))
    return snaps


@pytest.mark.parametrize("seed", [1, 2, 3])
def test_a_random_history_gives_the_answers_of_the_reference_path(kind, tmp_path, monkeypatch, seed):
    fast = World(_engine(kind, tmp_path, "fast.db"))
    got = _history(fast, seed, monkeypatch)
    fast.engine.dispose()
    with monkeypatch.context() as m:
        m.setattr(AS, "USE_DIGESTS", False)
        m.setattr(RR, "USE_DIGESTS", False)
        reference = World(_engine(kind, tmp_path, "ref.db"))
        want = _history(reference, seed, monkeypatch)
    if kind == "postgresql":
        SQLModel.metadata.drop_all(reference.engine)
    reference.engine.dispose()
    assert len(got) == len(want)
    for step, (a, b) in enumerate(zip(got, want)):
        assert a == b, f"run {step} differs"
    assert got[-1][2], "the history graded something"
