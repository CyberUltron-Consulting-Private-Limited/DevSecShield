"""CB-20 PR-1 bench: what the estate-store write adds to run finalisation (``drift.record_run_drift``).

Seeds one team with 4 sources (prober, Linux, Windows, AWS kinds) and two finished runs of N assets each (40 %
certificates, a quarter of them seen by 2-4 sources; 20 % TLS endpoints; 40 % libraries, keys and settings; run 2
moves 1 % of the assets and adds a coverage gap), finalises run 1 (store written: the steady state), then times the
finalisation of run 2, interleaved REPS times, each inside a transaction that is rolled back:

* ``drift_only``  ``record_run_drift`` with the estate write replaced by a no-op (dev's work);
* ``with_store``  ``record_run_drift`` as shipped (drift + ``estate.record_run``);
* ``store_only``  the estate write's own time inside ``with_store``;
* ``store_cold``  the same once with an empty key index (a restarted process), when the tree has one (CB-21 #205
  ``CorrelationIndex`` in ``estate._keys_for_run``). Before each warm repetition the index is put back to run 1's
  observations (what the previous run left), so every repetition re-keys exactly run 2's changes.

Run this file against two trees (PYTHONPATH) to compare them: it works with or without the index.

Wall-clock seconds (``perf_counter``: PostgreSQL work happens in the server process). Runs on SQLite (a temp file)
and, with ``--pg URL``, on a throwaway PostgreSQL.

    cd <repo> && PYTHONPATH=. python bench/cb20_estate/bench.py --n 50000 --reps 5 [--pg postgresql+psycopg2://...]
"""
from __future__ import annotations

import argparse
import datetime as dt
import hashlib
import json
import statistics
import sys
import tempfile
import time
from pathlib import Path

from sqlalchemy import insert
from sqlmodel import Session, SQLModel, create_engine

from backend.new_models import (CbomCollectedAsset, CbomCollectionJob, CbomCollectionRun, CbomCollectionSource, Team)
from backend.utilities.cbom_sources import crypto_kb
from backend.utilities.cbom_sources import drift as D
from backend.utilities.cbom_sources import estate as E
from backend.utilities.cbom_sources.classify import CLASSIFIER_VERSION, classify

NOW = dt.datetime(2026, 11, 14, 9, 0)
KINDS = ["network", "linux_servers", "windows_servers", "aws_account"]


def _cert(c: int) -> dict:
    return {"serial": format(0x9F00000000000000000000 + c * 7919, "x"), "not_after": "2027-06-30T12:00:00Z",
            "fingerprint_sha256": hashlib.sha256(str(c).encode()).hexdigest(),
            "subject": f"CN=host-{c}.example.com,O=Example", "issuer": "CN=Example CA 2,O=Example",
            "key_alg": "RSA", "key_size": 2048, "sig_alg": "sha256WithRSAEncryption"}


def _assets(n: int, run: int) -> dict[int, list[dict]]:
    """source index -> assets of that source in run ``run`` (1 or 2)."""
    out: dict[int, list[dict]] = {i: [] for i in range(4)}
    for i in range(n):
        j = i + (n if run == 2 and i % 100 == 0 else 0)  # 1 % moved: gone in run 2, a new one instead
        src = i % 4
        host = f"10.{(j >> 16) & 255}.{(j >> 8) & 255}.{j & 255}"
        bucket = i % 10
        if bucket < 4:
            c = j // 2 if bucket < 1 else j  # a quarter of the certificates is shared with another source
            out[src].append({"type": "certificate", "target": host, "location": f"{host}:443#chain[0]",
                             "algorithm": "RSA", "key_size": 2048, "facts": _cert(c), "cdx": "certificate"})
        elif bucket < 6:
            out[src].append({"type": "tls_endpoint", "target": host, "location": f"{host}:443",
                             "facts": {"protocols": ["TLSv1.2", "TLSv1.3"], "group": "x25519", "port": 443}})
        elif bucket < 8:
            out[src].append({"type": "crypto_library", "target": host, "location": f"{host}/usr/lib/libssl.so.{j}",
                             "facts": {"name": "openssl", "version": "3.0.2-0ubuntu1.15", "source": "package"}})
        else:
            out[src].append({"type": "kms_key", "target": "aws", "location": f"arn:aws:kms:eu-west-1:1:key/{j}",
                             "algorithm": "SYMMETRIC_DEFAULT", "facts": {"key_spec": "SYMMETRIC_DEFAULT",
                                                                         "identity": f"arn:aws:kms:eu-west-1:1:key/{j}"}})
    if run == 2:
        out[0].append({"type": "coverage", "target": "10.0.0.7", "location": "10.0.0.7#coverage",
                       "facts": {"check": "no answer", "status": "unreachable", "detail": "10.0.0.7 did not answer"}})
    return out


def seed(engine, n: int) -> tuple[int, int]:
    verdicts: dict[tuple, dict] = {}
    with Session(engine) as s:
        s.add(Team(id=1, name="bench", credit_balance=0.0))
        s.commit()
        srcs = [CbomCollectionSource(team_id=1, owner_user_id=1, kind=k, name=k, name_lower=k) for k in KINDS]
        s.add_all(srcs)
        s.commit()
        runs = []
        for r in (1, 2):
            run = CbomCollectionRun(team_id=1, owner_user_id=1, client_request_id=f"b{r}", status="done",
                                    finished_at=NOW + dt.timedelta(hours=r), kb_version=crypto_kb.version(),
                                    classifier_version=CLASSIFIER_VERSION)
            s.add(run)
            s.commit()
            runs.append(run.id)
            for idx, assets in _assets(n, r).items():
                partial = r == 2 and idx == 0
                job = CbomCollectionJob(team_id=1, run_id=run.id, source_id=srcs[idx].id, kind="collect",
                                        status="success", outcome="partial" if partial else "ok", attempts=1,
                                        params={"source_uid": srcs[idx].source_uid},
                                        result={"counts": {"ok": 1, "partial": 1 if partial else 0, "failed": 0,
                                                           "skipped": 0}})
                s.add(job)
                s.commit()
                rows = []
                for a in assets:
                    vk = (a["type"], a.get("algorithm"), a.get("key_size"))
                    if vk not in verdicts:
                        verdicts[vk] = classify(a["type"], a.get("algorithm"), a.get("key_size"), None, a["facts"], NOW)
                    v = verdicts[vk]
                    rows.append({"team_id": 1, "run_id": run.id, "job_id": job.id, "source_id": srcs[idx].id,
                                 "attempt": 1, "asset_key": hashlib.sha256(a["location"].encode()).hexdigest(),
                                 "asset_type": a["type"], "cdx_type": a.get("cdx") or v["cdx_type"],
                                 "target": a["target"], "location": a["location"], "name": None,
                                 "algorithm": a.get("algorithm"), "key_size": a.get("key_size"), "protocol": None,
                                 "quantum_vulnerable": v["quantum_vulnerable"], "impact": v["impact"],
                                 "finding_codes": v["finding_codes"], "finding": v["finding"], "facts": a["facts"],
                                 "created_at": NOW + dt.timedelta(hours=r)})
                for k in range(0, len(rows), 2000):
                    s.execute(insert(CbomCollectedAsset), rows[k:k + 2000])
                s.commit()
        return runs[0], runs[1]


def bench(engine, n: int, reps: int) -> dict:
    r1, r2 = seed(engine, n)
    with Session(engine) as s:
        D.record_run_drift(s, s.get(CbomCollectionRun, r1), NOW)
        s.commit()
    real_write = D.record_estate
    store_times: list[float] = []

    def timed_write(*a, **k):
        t0 = time.perf_counter()
        real_write(*a, **k)
        store_times.append(time.perf_counter() - t0)

    with Session(engine) as s:
        srcs = D._sources(s, 1)
        run1_rows = [(r, D.ID.job_source_ref(j, srcs.get(j.source_id or 0)))
                     for j in D._run_jobs(s, s.get(CbomCollectionRun, r1)) for r in E._rows(s, j)
                     if r.asset_type != "coverage"]
    indexed = hasattr(E, "_keys_for_run")

    def finalise(with_store: bool, cold: bool = False) -> float:
        if with_store and indexed:
            if cold:
                E._INDEXES.clear()
            else:
                E._keys_for_run(1, run1_rows)  # the index as the previous run left it
        D.record_estate = timed_write if with_store else (lambda *a, **k: None)  # type: ignore[assignment]
        try:
            with Session(engine) as s:
                run = s.get(CbomCollectionRun, r2)
                t0 = time.perf_counter()
                assert D.record_run_drift(s, run, NOW) is not None
                took = time.perf_counter() - t0
                s.rollback()
                return took
        finally:
            D.record_estate = real_write  # type: ignore[assignment]

    finalise(True)  # warm caches (knowledge base, query plans)
    store_times.clear()
    without, with_ = [], []
    for _ in range(reps):
        without.append(finalise(False))
        with_.append(finalise(True))
    out = {"assets_per_run": n, "drift_only": {"p50": round(statistics.median(without), 3), "max": round(max(without), 3)},
           "with_store": {"p50": round(statistics.median(with_), 3), "max": round(max(with_), 3)},
           "store_only": {"p50": round(statistics.median(store_times), 3), "max": round(max(store_times), 3)}}
    if indexed:
        store_times.clear()
        finalise(True, cold=True)
        out["store_cold"] = round(store_times[0], 3)
    out["delta_pct"] = round(100 * (out["with_store"]["p50"] / out["drift_only"]["p50"] - 1), 1)
    out["store_share_pct"] = round(100 * out["store_only"]["p50"] / out["drift_only"]["p50"], 1)
    with Session(engine) as s:
        out["store_rows_after_run1"] = {"assets": s.exec(E.select(E.CbomEstateAsset.id)).all().__len__(),
                                        "observations": s.exec(E.select(E.CbomEstateObservation.id)).all().__len__()}
    return out


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--n", type=int, default=50_000)
    ap.add_argument("--reps", type=int, default=5)
    ap.add_argument("--pg", default=None)
    args = ap.parse_args()
    with tempfile.TemporaryDirectory() as tmp:
        engine = create_engine(f"sqlite:///{Path(tmp) / 'b.db'}")
        SQLModel.metadata.create_all(engine)
        print(json.dumps({"db": "sqlite", **bench(engine, args.n, args.reps)}), flush=True)
        engine.dispose()
    if args.pg:
        engine = create_engine(args.pg)
        SQLModel.metadata.drop_all(engine)
        SQLModel.metadata.create_all(engine)
        try:
            print(json.dumps({"db": "postgresql", **bench(engine, args.n, args.reps)}), flush=True)
        finally:
            SQLModel.metadata.drop_all(engine)
            engine.dispose()
    return 0


if __name__ == "__main__":
    sys.exit(main())
