"""CB-20 PR-1: the per-team estate store (one row per cross-source asset key, latest observation per source).

Failing-first on dev (no ``estate`` module, no tables): one row per key across collectors, presence transitions
(present -> not read under a gap -> removed -> present), a failed collection is "not read", retention keeps the latest
comparable job per source, the CB-23 hook runs in the drift transaction exactly once per run, concurrent / out-of-order
finalisations end in the newer run's state, backfill is idempotent, migration up/down/up, the read API.

PostgreSQL variants need a throwaway database: CBOM_TEST_PG_URL=postgresql+psycopg2://postgres:pw@127.0.0.1:55499/cb20
(skipped without it).
"""
from __future__ import annotations

import datetime as dt
import hashlib
import importlib.util
import os
import re
import sys
import threading
from pathlib import Path

import pytest

_REPO_ROOT = Path(__file__).resolve().parents[2]
if str(_REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(_REPO_ROOT))
sys.path.insert(0, str(Path(__file__).resolve().parent))

import sqlalchemy as sa  # noqa: E402
from sqlmodel import Session, SQLModel, create_engine, select  # noqa: E402

from backend.new_models import (  # noqa: E402
    CbomCollectedAsset,
    CbomCollectionJob,
    CbomCollectionRun,
    CbomCollectionSource,
    CbomDriftEvent,
    CbomEstateAsset,
    CbomEstateObservation,
    CbomEstateSource,
    CbomEstateTeam,
    Team,
)
from backend.utilities.cbom_sources import drift as D  # noqa: E402
from backend.utilities.cbom_sources import estate as E  # noqa: E402

NOW = dt.datetime(2026, 11, 14, 9, 0)
PG = os.environ.get("CBOM_TEST_PG_URL")
needs_pg = pytest.mark.skipif(not PG, reason="set CBOM_TEST_PG_URL to run against PostgreSQL")
MIGRATION = _REPO_ROOT / "prod_database_migrations/migrations/versions/cb20estate001_estate_store.py"

# one certificate: serial >= 64 bits, the notAfter, its DER fingerprints
SERIAL = "4F:A1:9C:00:12:7B:3E:55:90:AB:CD:EF:01:23"
NOT_AFTER = "2027-06-30T12:00:00Z"
SHA256 = "ab" * 32
SHA1 = "cd" * 20
SUBJECT = "CN=pay.example.com,O=Example Corp,C=US"
ISSUER = "CN=Example Issuing CA 2,O=Example Corp,C=US"


# ----------------------------------------------------------------------------- a small world
class World:
    def __init__(self, engine):
        self.engine = engine
        self.clock = 0
        with Session(engine) as s:
            s.add(Team(id=1, name="T1", credit_balance=0.0))
            s.add(Team(id=2, name="T2", credit_balance=0.0))
            s.commit()

    def source(self, kind: str, name: str, team_id: int = 1) -> int:
        with Session(self.engine) as s:
            src = CbomCollectionSource(team_id=team_id, owner_user_id=1, kind=kind, name=name, name_lower=name.lower(),
                                       source_uid=hashlib.sha256(f"{team_id}{kind}{name}".encode()).hexdigest()[:32])
            s.add(src)
            s.commit()
            return int(src.id)  # type: ignore[arg-type]

    def run(self, jobs: dict[int, dict], *, team_id: int = 1, drift: bool = False) -> int:
        """``jobs``: source id -> {"rows": [...], "status", "outcome", "counts"}. The run is finished."""
        self.clock += 1
        when = NOW + dt.timedelta(hours=self.clock)
        with Session(self.engine) as s:
            run = CbomCollectionRun(team_id=team_id, owner_user_id=1, client_request_id=f"r{self.clock}",
                                    status="done", finished_at=when, kb_version="kb", classifier_version="c",
                                    drift_at=when if drift else None)
            s.add(run)
            s.commit()
            for source_id, spec in jobs.items():
                src = s.get(CbomCollectionSource, source_id)
                counts = {"ok": 1, "partial": 0, "failed": 0, "skipped": 0, **spec.get("counts", {})}
                job = CbomCollectionJob(team_id=team_id, run_id=run.id, source_id=source_id, kind="collect",
                                        status=spec.get("status", "success"), outcome=spec.get("outcome", "ok"),
                                        attempts=1, params={"source_uid": src.source_uid, "kind": src.kind},
                                        result={"counts": counts})
                s.add(job)
                s.commit()
                for r in spec.get("rows", []):
                    s.add(CbomCollectedAsset(
                        team_id=team_id, run_id=run.id, job_id=job.id, source_id=source_id, attempt=1,
                        asset_key=hashlib.sha256(f"{r['type']}|{r['target']}|{r['location']}".encode()).hexdigest(),
                        asset_type=r["type"], cdx_type=r.get("cdx_type", "cryptographic-asset"), target=r["target"],
                        location=r["location"], name=r.get("name"), algorithm=r.get("algorithm"),
                        quantum_vulnerable=r.get("qv"), impact=r.get("impact"), finding_codes=r.get("codes", []),
                        facts=r.get("facts", {}), created_at=when))
                s.commit()
            return int(run.id)  # type: ignore[arg-type]

    def finalise(self, run_id: int):
        with Session(self.engine) as s:
            run = s.get(CbomCollectionRun, run_id)
            out = D.record_run_drift(s, run, NOW)
            s.commit()
            return out

    def assets(self, team_id: int = 1) -> dict[str, CbomEstateAsset]:
        with Session(self.engine) as s:
            return {a.asset_key: a for a in s.exec(select(CbomEstateAsset).where(CbomEstateAsset.team_id == team_id))}

    def observations(self, team_id: int = 1) -> list[CbomEstateObservation]:
        with Session(self.engine) as s:
            return list(s.exec(select(CbomEstateObservation).where(CbomEstateObservation.team_id == team_id)
                               .order_by(CbomEstateObservation.asset_key, CbomEstateObservation.source_ref)))

    def latest(self, team_id: int = 1) -> dict[str, dict]:
        with Session(self.engine) as s:
            return E.latest_rows(s, team_id, sorted(self.assets(team_id)))

    def dump(self, pointers: bool = True) -> list[tuple]:
        """The store's content without row ids / write times (to compare two worlds)."""
        out: list[tuple] = []
        for team in (1, 2):
            latest = self.latest(team)
            for a in self.assets(team).values():
                ptr = latest.get(a.asset_key, {}).get("latest") or {}
                out.append((team, a.asset_key, a.key_kind, a.asset_type, a.presence, a.presence_reason,
                            a.first_seen_run_id) + ((ptr.get("asset_id"), ptr.get("job_id"), ptr.get("run_id"),
                                                     ptr.get("source_ref")) if pointers else ()))
            for o in self.observations(team):
                out.append((team, o.asset_key, o.source_ref, o.observation_key, o.row_key, o.presence,
                            o.presence_reason, o.first_seen_run_id))
        return sorted(out, key=repr)


def _sqlite(path: Path):
    engine = create_engine(f"sqlite:///{path}", connect_args={"check_same_thread": False, "timeout": 30})
    SQLModel.metadata.create_all(engine)
    return engine


@pytest.fixture(params=["sqlite", pytest.param("postgresql", marks=needs_pg)])
def world(request, tmp_path):
    if request.param == "sqlite":
        engine = _sqlite(tmp_path / "estate.db")
    else:
        engine = create_engine(PG, pool_size=8)
        SQLModel.metadata.drop_all(engine)
        SQLModel.metadata.create_all(engine)
    yield World(engine)
    if request.param != "sqlite":
        SQLModel.metadata.drop_all(engine)
    engine.dispose()


def endpoint(host: str, port: int = 443) -> dict:
    return {"type": "tls_endpoint", "target": host, "location": f"{host}:{port}", "name": "TLS",
            "facts": {"protocols": ["TLSv1.2"], "port": port}}


def cert(target: str, location: str, **facts) -> dict:
    return {"type": "certificate", "cdx_type": "certificate", "target": target, "location": location,
            "algorithm": "RSA", "name": "pay.example.com", "facts": facts}


def gap(target: str, detail: str) -> dict:
    return {"type": "coverage", "target": target, "location": f"{target}#coverage",
            "facts": {"check": "no answer", "status": "unreachable", "detail": detail}}


PARTIAL = {"outcome": "partial", "counts": {"ok": 1, "partial": 1}}


# ----------------------------------------------------------------------------- one row per key across sources
def test_one_certificate_seen_by_four_collectors_is_one_row_with_four_observations(world):
    """Every collector reports the fingerprint: one estate asset, one observation per source."""
    src = [world.source(k, n) for k, n in (("network", "prober"), ("linux_servers", "linux"),
                                           ("windows_servers", "win"), ("aws_account", "aws"))]
    facts = {"serial": SERIAL, "not_after": NOT_AFTER, "fingerprint_sha256": SHA256, "subject": SUBJECT,
             "issuer": ISSUER}
    rows = [cert("10.0.0.5", "10.0.0.5:443#chain[0]", **facts), cert("app-01", "/etc/ssl/pay.pem", **facts),
            cert("win-01", "LocalMachine\\My\\" + SHA1, **facts), cert("aws", "arn:aws:acm:eu-west-1:1:certificate/x",
                                                                      **facts)]
    run = world.run({s: {"rows": [r]} for s, r in zip(src, rows)})
    assert world.finalise(run) is not None
    assets = world.assets()
    assert len(assets) == 1
    (key, asset), = assets.items()
    assert re.fullmatch(r"cert:[0-9a-f]{40}", key) and asset.key_kind == "cross" and asset.presence == "present"
    obs = world.observations()
    assert len(obs) == 4 and {o.asset_key for o in obs} == {key} and {o.seen_run_id for o in obs} == {run}
    latest = world.latest()[key]
    assert asset.first_seen_run_id == run and len(latest["observations"]) == 4
    assert {o["run_id"] for o in latest["observations"].values()} == {run}
    with Session(world.engine) as s:  # the latest stored row is where the grade inputs are re-read
        row = s.get(CbomCollectedAsset, latest["latest"]["asset_id"])
        assert row.asset_type == "certificate" and row.job_id == latest["latest"]["job_id"]
        assert s.get(CbomCollectionJob, row.job_id).run_id == run
        assert {s.get(CbomCollectedAsset, o["asset_id"]).source_id
                for o in latest["observations"].values()} == set(src)


def test_cb21_keys_join_the_windows_thumbprint_and_the_acm_amazon_issuer(world):
    """The DA-P3 case: ACM says Issuer "Amazon", Windows has only a thumbprint; CB-21 correlates all four."""
    src = [world.source(k, n) for k, n in (("network", "prober"), ("linux_servers", "linux"),
                                           ("windows_servers", "win"), ("aws_account", "aws"))]
    full = {"serial": SERIAL, "not_after": NOT_AFTER, "fingerprint_sha256": SHA256, "fingerprint_sha1": SHA1,
            "subject": SUBJECT, "issuer": ISSUER}
    rows = [cert("10.0.0.5", "10.0.0.5:443#chain[0]", **full),
            cert("app-01", "/etc/ssl/pay.pem", serial=SERIAL.replace(":", "").lower(), not_after=NOT_AFTER,
                 subject=SUBJECT, issuer=ISSUER),
            cert("win-01", "LocalMachine\\My", thumbprint=SHA1.upper(), subject=SUBJECT, issuer=ISSUER,
                 not_after=NOT_AFTER),
            cert("aws", "arn:aws:acm:eu-west-1:1:certificate/x", serial=SERIAL, not_after=NOT_AFTER, issuer="Amazon",
                 subject="CN=pay.example.com")]
    world.finalise(world.run({s: {"rows": [r]} for s, r in zip(src, rows)}))
    assert len(world.assets()) == 1
    assert len({o.asset_key for o in world.observations()}) == 1 and len(world.observations()) == 4


def test_an_observation_whose_key_got_stronger_moves_and_is_never_removed(world):
    """Run 1: the Windows store alone (thumbprint key). Run 2: a Linux file with serial + SHA-1 joins it under the
    serial key: the Windows observation moves to that key; nothing reads "removed"."""
    win, linux = world.source("windows_servers", "win"), world.source("linux_servers", "linux")
    w = cert("win-01", "LocalMachine\\My", thumbprint=SHA1, subject=SUBJECT, issuer=ISSUER, not_after=NOT_AFTER)
    world.finalise(world.run({win: {"rows": [w]}}))
    (old,) = world.assets()
    f = cert("app-01", "/etc/ssl/pay.pem", serial=SERIAL, fingerprint_sha1=SHA1, not_after=NOT_AFTER,
             subject=SUBJECT, issuer=ISSUER)
    seen = []
    E.register_hook(hook := (lambda s, write: seen.append(write)))
    try:
        world.finalise(world.run({win: {"rows": [w]}, linux: {"rows": [f]}}))
    finally:
        E.unregister_hook(hook)
    assets = world.assets()
    assert old not in assets and len(assets) == 1
    (new,) = assets
    assert [o.presence for o in world.observations()] == ["present", "present"]
    assert seen[0].rekeyed == [(old, new, D.ID.job_source_ref(_job(world, win), None))]
    assert seen[0].removed_keys == [old] and seen[0].counts["removed"] == 0


def _job(world, source_id):
    with Session(world.engine) as s:
        return s.exec(select(CbomCollectionJob).where(CbomCollectionJob.source_id == source_id)).first()


def test_assets_without_a_cross_source_identity_get_a_per_source_key(world):
    net = world.source("linux_servers", "linux")
    lib = {"type": "crypto_library", "target": "app-01", "location": "/usr/lib/libssl.so.3",
           "facts": {"name": "openssl", "version": "3.0.2"}}
    bare = cert("app-01", "/etc/ssl/x.pem", subject="CN=x")  # nothing identifying: correlation missing
    world.finalise(world.run({net: {"rows": [lib, bare, endpoint("10.0.0.9")]}}))
    kinds = sorted((a.key_kind, a.asset_type) for a in world.assets().values())
    assert kinds == [("cross", "tls_endpoint"), ("not_correlated", "certificate"), ("source", "crypto_library")]
    assert all(re.fullmatch(r"(obs|ep):[0-9a-f]{40}", k) for k in world.assets())


# ----------------------------------------------------------------------------- presence transitions
def test_presence_present_then_not_read_under_a_gap_then_removed_then_present_again(world):
    net = world.source("network", "lab")
    a, b = endpoint("10.0.0.1"), endpoint("10.0.0.2")
    r1 = world.run({net: {"rows": [a, b]}})
    world.finalise(r1)
    kb = next(o.asset_key for o in world.observations() if o.target == "10.0.0.2")
    assert {x.presence for x in world.assets().values()} == {"present"}

    r2 = world.run({net: {"rows": [a, gap("10.0.0.2", "10.0.0.2 did not answer on any listed port"),
                                   ], **PARTIAL}})
    assert D.job_comparable(_job_of_run(world, r2))[0]
    world.finalise(r2)
    b2 = world.assets()[kb]
    assert (b2.presence, b2.presence_reason) == ("not_read", "lab: 10.0.0.2 did not answer on any listed port")
    latest = world.latest()[kb]["latest"]
    assert latest["run_id"] == r1 and latest["asset_id"] is not None  # the last known observation is kept
    (ob,) = [o for o in world.observations() if o.asset_key == kb]
    assert (ob.presence, ob.presence_reason) == ("not_read", "10.0.0.2 did not answer on any listed port")
    ka = next(k for k in world.assets() if k != kb)
    assert world.latest()[ka]["latest"]["run_id"] == r2  # re-read: the latest row is run 2's (no rewrite needed)

    r3 = world.run({net: {"rows": [a]}})  # complete, no gap: really gone
    world.finalise(r3)
    assert world.assets()[kb].presence == "removed" and world.assets()[kb].presence_reason is None
    assert [o.presence for o in world.observations() if o.asset_key == kb] == ["removed"]

    r4 = world.run({net: {"rows": [a, b]}})
    world.finalise(r4)
    back = world.assets()[kb]
    assert (back.presence, back.first_seen_run_id, world.latest()[kb]["latest"]["run_id"]) == ("present", r1, r4)
    assert {x.presence for x in world.assets().values()} == {"present"}


def _job_of_run(world, run_id):
    with Session(world.engine) as s:
        return s.exec(select(CbomCollectionJob).where(CbomCollectionJob.run_id == run_id)).first()


def test_a_failed_or_incomplete_collection_makes_the_unseen_not_read_never_removed(world):
    net, other = world.source("network", "lab"), world.source("network", "dmz")
    world.finalise(world.run({net: {"rows": [endpoint("10.0.0.1")]}, other: {"rows": [endpoint("10.9.0.1")]}}))
    world.finalise(world.run({net: {"status": "failed", "outcome": "failed", "rows": []},
                              other: {"outcome": "partial", "counts": {"ok": 0, "failed": 1}, "rows": []}}))
    reasons = sorted((a.presence, a.presence_reason) for a in world.assets().values())
    assert reasons == [("not_read", "dmz: collection partial (some targets were not read)"),
                       ("not_read", "lab: collection failed")]


def test_an_asset_still_seen_by_another_source_stays_present(world):
    p, w = world.source("network", "prober"), world.source("linux_servers", "linux")
    c = cert("10.0.0.5", "10.0.0.5:443#chain[0]", serial=SERIAL, not_after=NOT_AFTER, fingerprint_sha256=SHA256)
    f = cert("app", "/etc/ssl/pay.pem", serial=SERIAL, not_after=NOT_AFTER, fingerprint_sha256=SHA256)
    world.finalise(world.run({p: {"rows": [c]}, w: {"rows": [f]}}))
    world.finalise(world.run({w: {"rows": []}}))  # the file is gone; the prober still saw it last time
    (asset,) = world.assets().values()
    assert asset.presence == "present"
    assert sorted(o.presence for o in world.observations()) == ["present", "removed"]


def test_other_teams_never_mix(world):
    mine, theirs = world.source("network", "lab"), world.source("network", "lab", team_id=2)
    world.finalise(world.run({mine: {"rows": [endpoint("52.95.0.1")]}}))
    world.finalise(world.run({theirs: {"rows": [endpoint("52.95.0.1")]}}, team_id=2))
    world.finalise(world.run({mine: {"rows": []}}))
    assert [a.presence for a in world.assets(1).values()] == ["removed"]
    assert [a.presence for a in world.assets(2).values()] == ["present"]
    assert set(world.assets(1)) == set(world.assets(2))  # same (public) endpoint key, one row per team


# ----------------------------------------------------------------------------- hook, transaction, exactly once
def test_the_hook_runs_in_the_drift_transaction_exactly_once_per_run(world):
    net = world.source("network", "lab")
    run = world.run({net: {"rows": [endpoint("10.0.0.1"), endpoint("10.0.0.2")]}})
    calls = []

    def hook(session, write):
        assert session.in_transaction()
        drift_at = session.execute(sa.select(CbomCollectionRun.drift_at).where(CbomCollectionRun.id == run)).scalar()
        stored = list(E.present_keys(session, write.team_id, write.source_refs))  # the write is visible here
        calls.append((write.run_id, drift_at, len(stored), len(write.changed)))

    E.register_hook(hook)
    try:
        assert world.finalise(run) is not None
        assert world.finalise(run) is None  # already recorded: no second write, no second call
        assert D.record_pending_drift(world.engine, NOW) == 0
    finally:
        E.unregister_hook(hook)
    assert calls == [(run, NOW, 2, 2)]


def _stale(world, team_id: int = 1):
    with Session(world.engine) as s:
        row = s.exec(select(CbomEstateTeam).where(CbomEstateTeam.team_id == team_id)).first()
        return None if row is None else (row.stale, row.stale_run_id)


def test_a_failing_plain_hook_is_isolated_and_the_store_write_stands(world, caplog):
    net = world.source("network", "lab")
    run = world.run({net: {"rows": [endpoint("10.0.0.1")]}})
    calls = []

    def boom(session, _write):
        session.add(CbomEstateTeam(team_id=2, stale=True))  # its own writes are undone with it
        session.flush()
        raise RuntimeError("register down")

    E.register_hook(boom)
    E.register_hook(ok := (lambda _s, w: calls.append(w.run_id)))
    try:
        with caplog.at_level("ERROR"):
            assert world.finalise(run) is not None
    finally:
        E.unregister_hook(boom)
        E.unregister_hook(ok)
    assert calls == [run] and len(world.assets()) == 1 and _stale(world) is None and _stale(world, 2) is None
    assert any(r.levelname == "ERROR" and "hook" in r.getMessage() for r in caplog.records)


def test_a_failing_atomic_hook_rolls_back_store_and_register_only_drift_commits(world, caplog):
    net = world.source("network", "lab")
    run = world.run({net: {"rows": [endpoint("10.0.0.1")]}})

    def boom(_session, _write):
        raise RuntimeError("register down")

    E.register_hook(boom, atomic=True)
    try:
        with caplog.at_level("ERROR"):
            assert D.record_pending_drift(world.engine, NOW) == 1  # drift recorded all the same
    finally:
        E.unregister_hook(boom)
    with Session(world.engine) as s:
        assert s.get(CbomCollectionRun, run).drift_at == NOW
    assert world.assets() == {} and _stale(world) == (True, run)
    assert any(r.levelname == "ERROR" and "estate write failed" in r.getMessage() for r in caplog.records)
    assert E.backfill(world.engine, NOW)["repaired_teams"] == 1
    assert len(world.assets()) == 1 and _stale(world) == (False, run)


def test_a_store_error_never_blocks_drift_other_teams_or_changes_and_backfill_repairs_it(world, monkeypatch):
    mine, theirs = world.source("network", "lab"), world.source("network", "lab", team_id=2)
    first = world.run({mine: {"rows": [endpoint("10.0.0.1"), endpoint("10.0.0.2")]}})
    world.finalise(first)
    broken = world.run({mine: {"rows": [endpoint("10.0.0.1")]}})  # 10.0.0.2 removed: a drift event
    other = world.run({theirs: {"rows": [endpoint("10.0.0.1")]}}, team_id=2)
    real = E._lock_source

    def lock(session, sql, team_id, ref):
        if team_id == 1:
            raise RuntimeError("store broken for team 1")
        return real(session, sql, team_id, ref)

    monkeypatch.setattr(E, "_lock_source", lock)
    assert D.record_pending_drift(world.engine, NOW) == 2  # neither run is stuck
    monkeypatch.setattr(E, "_lock_source", real)
    with Session(world.engine) as s:
        assert s.get(CbomCollectionRun, broken).drift_at == NOW and s.get(CbomCollectionRun, other).drift_at == NOW
        kinds = {e.kind for e in s.exec(select(CbomDriftEvent).where(CbomDriftEvent.run_id == broken))}
        assert "removed_asset" in kinds
    assert _stale(world) == (True, broken) and _stale(world, 2) is None
    assert {a.presence for a in world.assets(1).values()} == {"present"}  # still run 1's state: stale
    assert [a.presence for a in world.assets(2).values()] == ["present"]
    E.backfill(world.engine, NOW)
    assert sorted(a.presence for a in world.assets(1).values()) == ["present", "removed"]
    assert _stale(world) == (False, broken)


def test_a_deleted_sources_assets_are_not_read_source_deleted(world):
    lab, dmz = world.source("network", "lab"), world.source("network", "dmz")
    world.finalise(world.run({lab: {"rows": [endpoint("10.0.0.1")]}, dmz: {"rows": [endpoint("10.9.0.1")]}}))
    with Session(world.engine) as s:  # what removal.py does: jobs and rows detached, the source row deleted
        s.execute(sa.update(CbomCollectionJob).where(CbomCollectionJob.source_id == dmz).values(source_id=None))
        s.execute(sa.update(CbomCollectedAsset).where(CbomCollectedAsset.source_id == dmz).values(source_id=None))
        s.execute(sa.delete(CbomCollectionSource).where(CbomCollectionSource.id == dmz))
        s.commit()
    world.finalise(world.run({lab: {"rows": [endpoint("10.0.0.1")]}}))
    reasons = sorted((a.presence, a.presence_reason) for a in world.assets().values())
    assert reasons == [("not_read", "dmz: source deleted"), ("present", None)]
    gone = next(k for k, a in world.assets().items() if a.presence == "not_read")
    assert world.latest()[gone]["latest"]["asset_id"] is not None  # its last reading is still there


def test_prune_purges_long_removed_rows(world):
    net = world.source("network", "lab")
    runs = [world.run({net: {"rows": [endpoint("10.0.0.1"), endpoint("10.0.0.2")]}})]
    runs += [world.run({net: {"rows": [endpoint("10.0.0.1")]}}) for _ in range(3)]
    for r in runs:
        world.finalise(r)
    assert sorted(a.presence for a in world.assets().values()) == ["present", "removed"]
    with Session(world.engine) as s:
        E.prune_collected_assets(s, 1, keep_runs=2)  # removed in run 2, before the 2 newest runs
        s.commit()
    assert [a.presence for a in world.assets().values()] == ["present"] and len(world.observations()) == 1


def test_concurrent_finalisations_of_one_run_write_once(world):
    net = world.source("network", "lab")
    run = world.run({net: {"rows": [endpoint(f"10.0.0.{i}") for i in range(1, 40)]}})
    calls: list[int] = []
    E.register_hook(hook := (lambda _s, w: calls.append(w.run_id)))
    barrier = threading.Barrier(4)
    results: list = []

    def go():
        barrier.wait()
        results.append(world.finalise(run))

    try:
        threads = [threading.Thread(target=go) for _ in range(4)]
        [t.start() for t in threads]
        [t.join(60) for t in threads]
    finally:
        E.unregister_hook(hook)
    assert calls == [run] and sum(1 for r in results if r is not None) == 1 and len(results) == 4
    assert len(world.assets()) == 39 and len(world.observations()) == 39


def _three_runs(world):
    net, dmz = world.source("network", "lab"), world.source("network", "dmz")
    a, b, c = endpoint("10.0.0.1"), endpoint("10.0.0.2"), endpoint("10.9.0.3")
    r1 = world.run({net: {"rows": [a, b]}, dmz: {"rows": [c]}})
    r2 = world.run({net: {"rows": [a, b]}, dmz: {"rows": [gap("10.9.0.3", "silent")], **PARTIAL}})
    r3 = world.run({net: {"rows": [a]}})
    return r1, r2, r3


def test_runs_finalised_out_of_order_end_in_the_newer_runs_state(tmp_path):
    in_order, reversed_ = World(_sqlite(tmp_path / "a.db")), World(_sqlite(tmp_path / "b.db"))
    for w, order in ((in_order, (0, 1, 2)), (reversed_, (0, 2, 1))):
        runs = _three_runs(w)
        for i in order:
            w.finalise(runs[i])
    # the newer run decides: same keys, presence and reasons; only the "last read" of the endpoint the newer run
    # removed stays run 1's (run 2's reading of that source came after run 3's and is skipped: newest job wins)
    assert reversed_.dump(pointers=False) == in_order.dump(pointers=False)
    for w in (in_order, reversed_):
        present = [k for k, a in w.assets().items() if a.presence == "present"]
        assert [w.latest()[k]["latest"]["run_id"] for k in present] == [3]
    presence = sorted((a.asset_type, a.presence) for a in in_order.assets().values())
    assert presence == [("tls_endpoint", "not_read"), ("tls_endpoint", "present"), ("tls_endpoint", "removed")]


@needs_pg
def test_concurrent_finalisations_of_two_runs_on_postgresql():
    engine = create_engine(PG, pool_size=8)
    SQLModel.metadata.drop_all(engine)
    SQLModel.metadata.create_all(engine)
    try:
        w = World(engine)
        r1, r2, r3 = _three_runs(w)
        w.finalise(r1)
        barrier = threading.Barrier(2)
        errors: list = []

        def go(run_id):
            try:
                barrier.wait()
                w.finalise(run_id)
            except Exception as exc:  # a deadlock would land here
                errors.append(exc)

        threads = [threading.Thread(target=go, args=(r,)) for r in (r3, r2)]
        [t.start() for t in threads]
        [t.join(60) for t in threads]
        assert errors == []
        presence = sorted((a.asset_type, a.presence) for a in w.assets().values())
        assert presence == [("tls_endpoint", "not_read"), ("tls_endpoint", "present"), ("tls_endpoint", "removed")]
    finally:
        SQLModel.metadata.drop_all(engine)
        engine.dispose()


# ----------------------------------------------------------------------------- backfill
def test_backfill_writes_recorded_runs_and_is_idempotent(tmp_path):
    live, old = World(_sqlite(tmp_path / "live.db")), World(_sqlite(tmp_path / "old.db"))
    for r in _three_runs(live):
        live.finalise(r)
    _three_runs(old)
    with Session(old.engine) as s:  # runs recorded before the store existed
        s.execute(sa.update(CbomCollectionRun).values(drift_at=NOW))
        s.commit()
    assert old.assets() == {}
    assert E.backfill(old.engine, NOW)["runs"] == 3
    first = old.dump()
    assert first == live.dump()
    E.backfill(old.engine, NOW)
    assert old.dump() == first


# ----------------------------------------------------------------------------- retention
def test_retention_keeps_the_latest_comparable_job_per_source_and_what_the_store_points_at(world):
    net, dmz = world.source("network", "lab"), world.source("network", "dmz")
    runs = [world.run({net: {"rows": [endpoint("10.0.0.1")]}, dmz: {"rows": [endpoint("10.9.0.1")]}})]
    for _ in range(3):  # dmz fails from now on: its last comparable job stays the first one
        runs.append(world.run({net: {"rows": [endpoint("10.0.0.1")]}, dmz: {"status": "failed", "outcome": "failed"}}))
    for r in runs:
        world.finalise(r)
    with Session(world.engine) as s:
        jobs = {(j.run_id, j.source_id): j.id for j in s.exec(select(CbomCollectionJob))}
        keep = E.protected_job_ids(s, 1)
        assert jobs[(runs[0], dmz)] in keep and jobs[(runs[3], net)] in keep
        assert jobs[(runs[0], net)] not in keep
        deleted = E.prune_collected_assets(s, 1, keep_runs=2)
        s.commit()
        left = {(r.run_id, r.source_id) for r in s.exec(select(CbomCollectedAsset))}
    assert deleted == 2  # lab's rows of runs 1 and 2
    assert left == {(runs[0], dmz), (runs[2], net), (runs[3], net)}
    with Session(world.engine) as s:  # every row the store points at is still there
        for item in world.latest().values():
            for o in item["observations"].values():
                assert o["asset_id"] is not None and s.get(CbomCollectedAsset, o["asset_id"]) is not None
    with pytest.raises(ValueError):
        with Session(world.engine) as s:
            E.prune_collected_assets(s, 1, keep_runs=0)


# ----------------------------------------------------------------------------- migration
def _migration():
    spec = importlib.util.spec_from_file_location("cb20estate001", MIGRATION)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)  # type: ignore[union-attr]
    return mod


def test_the_migration_is_the_one_head():
    versions = MIGRATION.parent
    revs, downs = set(), set()
    for path in versions.glob("*.py"):
        text = path.read_text()
        rev = re.search(r"^revision(?::\s*str)?\s*=\s*['\"]([^'\"]+)['\"]", text, re.M)
        down = re.search(r"^down_revision(?:[^=]*)=\s*['\"]([^'\"]+)['\"]", text, re.M)
        revs.add(rev.group(1))
        if down:
            downs.add(down.group(1))
    assert revs - downs == {"cb20estate001"}
    assert _migration().down_revision in revs


def _schema(engine) -> dict:
    insp = sa.inspect(engine)
    out = {}
    for table in TABLES:
        cols = {c["name"]: c["nullable"] for c in insp.get_columns(table)}
        idx = {i["name"]: tuple(i["column_names"]) for i in insp.get_indexes(table)}
        uq = {u["name"]: tuple(u["column_names"]) for u in insp.get_unique_constraints(table)}
        out[table] = (cols, idx, uq)
    return out


def _migrate(engine, *steps: str) -> None:
    from alembic.migration import MigrationContext
    from alembic.operations import Operations

    for step in steps:
        with engine.begin() as conn:
            with Operations.context(MigrationContext.configure(conn)):
                getattr(_migration(), step)()


TABLES = ("cbomestatesource", "cbomestateasset", "cbomestateobservation", "cbomestateteam")


def _up_down_up(engine) -> None:
    with engine.begin() as conn:
        Team.__table__.create(conn, checkfirst=True)
    _migrate(engine, "upgrade")
    assert set(TABLES) <= set(sa.inspect(engine).get_table_names())
    _migrate(engine, "downgrade")
    assert not set(TABLES) & set(sa.inspect(engine).get_table_names())
    _migrate(engine, "upgrade")


def test_migration_up_down_up_matches_the_models_sqlite(tmp_path):
    migrated = create_engine(f"sqlite:///{tmp_path / 'm.db'}")
    _up_down_up(migrated)
    modelled = create_engine(f"sqlite:///{tmp_path / 'n.db'}")
    with modelled.begin() as conn:
        for t in (Team.__table__, CbomEstateSource.__table__, CbomEstateAsset.__table__,
                  CbomEstateObservation.__table__, CbomEstateTeam.__table__):
            t.create(conn)
    assert _schema(migrated) == _schema(modelled)


@needs_pg
def test_migration_up_down_up_on_postgresql():
    engine = create_engine(PG)
    SQLModel.metadata.drop_all(engine)
    try:
        _up_down_up(engine)
        cols = {c["name"] for c in sa.inspect(engine).get_columns("cbomestateobservation")}
        assert set(CbomEstateObservation.__table__.columns.keys()) == cols
    finally:
        with engine.begin() as conn:
            conn.execute(sa.text("DROP TABLE IF EXISTS cbomestateobservation, cbomestateasset, cbomestatesource, "
                                 "cbomestateteam, team CASCADE"))
        engine.dispose()
