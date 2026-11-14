"""CB-19 PR-1 bench: what the quantum risk grade (qg-1) costs inside the run posture, at 5,000 and 50,000 assets.

Seeds one run into a throwaway SQLite file (a mix of endpoints on private / public IPs and host names, CA and leaf
certificates, hybrid endpoints, KMS keys, database settings, crypto libraries, coverage rows), then times, per size:
* ``posture``: ``posture.run_posture`` as the route calls it (the grade accumulator included);
* ``posture_no_grade``: the same with the accumulator replaced by a no-op (dev's work);
* ``grade_only``: ``qgrade.RunGrades`` over the run's rows (context load, one ``add`` per row, ``result``);
* ``list_page``: one 200-row page of ``inventory.list_assets`` (grades included), and the grading part of it alone.
The knowledge-base caches are warmed once before timing. Times are CPU seconds of this process (``process_time``), so
other load on a shared machine does not land in one variant only; the two posture variants are interleaved.

    cd <repo> && PYTHONPATH=. backend/.venv/bin/python bench/cb19_grade/bench.py --sizes 5000 50000 --reps 5 \
        --per-host 1 8
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
from sqlmodel import Session, SQLModel, create_engine, select

from backend.new_models import (CbomCollectedAsset, CbomCollectionJob, CbomCollectionRun, CbomCollectionSettings,
                                CbomCollectionSource, Team)
from backend.utilities.cbom_sources import inventory as INV
from backend.utilities.cbom_sources import posture as P
from backend.utilities.cbom_sources import qgrade as QG
from backend.utilities.cbom_sources.classify import classify

NOW = dt.datetime(2026, 11, 14, 9, 0)
MOSCA = {"data_shelf_life_years": 10, "migration_years": 5, "threat_years": 12}
CA = {"is_ca": True, "key_alg": "RSA", "key_size": 2048, "not_after": "2034-01-01T00:00:00Z", "subject": "CN=ca",
      "issuer": "CN=ca", "sig_alg": "sha256WithRSAEncryption"}
LEAF = {**CA, "is_ca": False, "subject": "CN=leaf"}
# (weight, type, algorithm, key_size, facts, target pattern)
SHAPES = [
    (30, "tls_endpoint", None, None, {"protocols": ["TLSv1.2", "TLSv1.3"], "group": "x25519"}, "10.{a}.{b}.{c}"),
    (10, "tls_endpoint", None, None, {"protocols": ["TLSv1.2", "TLSv1.3"], "group": "x25519"}, "52.95.{b}.{c}"),
    (5, "tls_endpoint", None, None, {"protocols": ["TLSv1.2", "TLSv1.3"], "group": "x25519"}, "h{a}-{b}-{c}.corp"),
    (8, "tls_endpoint", None, None, {"versions": {"TLSv1.2": True, "TLSv1.3": True}, "pq_hybrid": True},
     "10.{a}.{b}.{c}"),
    (15, "certificate", "RSA", 2048, LEAF, "10.{a}.{b}.{c}"),
    (3, "certificate", "RSA", 2048, CA, "10.{a}.{b}.{c}"),
    (8, "kms_key", "SYMMETRIC_DEFAULT", None, {"key_spec": "SYMMETRIC_DEFAULT"}, "aws"),
    (8, "database_config", None, None, {"password_encryption": "scram-sha-256"}, "10.{a}.{b}.{c}"),
    (5, "crypto_library", None, None, {"name": "openssl", "version": "3.0.2-0ubuntu1.15", "source": "package"},
     "10.{a}.{b}.{c}"),
    (5, "coverage", None, None, {"check": "package list", "status": "error", "detail": "no answer"}, "10.{a}.{b}.{c}"),
    (3, "coverage", None, None, {"check": "no answer", "status": "unreachable", "detail": "silent"}, "10.{a}.{b}.{c}"),
]


def seed(engine, n: int, per_host: int = 1) -> int:
    """``per_host``: assets per target address (1 = every asset on its own host, the worst case for the exposure
    memo; real estates hold several certificates, keys, libraries and endpoints per host)."""
    templates = []
    for weight, type_, alg, size, facts, pattern in SHAPES:
        v = classify(type_, alg, size, None, facts, NOW)
        templates += [(type_, alg, size, facts, pattern, v)] * weight
    with Session(engine) as s:
        s.add(Team(id=1, name="bench", credit_balance=0.0))
        s.add(CbomCollectionSettings(team_id=1, aws_external_id="bench", risk_model=MOSCA))
        src = CbomCollectionSource(team_id=1, owner_user_id=1, kind="linux_servers", name="bench", name_lower="bench")
        run = CbomCollectionRun(team_id=1, owner_user_id=1, client_request_id="bench", status="finished")
        s.add(src)
        s.add(run)
        s.commit()
        job = CbomCollectionJob(team_id=1, run_id=run.id, source_id=src.id, kind="collect", status="success",
                                outcome="ok", params={"source_uid": src.source_uid, "metadata": {}})
        s.add(job)
        s.commit()
        rows = []
        for i in range(n):
            type_, alg, size, facts, pattern, v = templates[i % len(templates)]
            h = i // per_host
            target = pattern.format(a=(h >> 16) & 255, b=(h >> 8) & 255, c=h & 255)
            rows.append({"team_id": 1, "run_id": run.id, "job_id": job.id, "source_id": src.id, "attempt": 1,
                         "asset_key": hashlib.sha256(str(i).encode()).hexdigest(), "asset_type": type_,
                         "cdx_type": v["cdx_type"], "target": target, "location": f"{target}:{i}", "name": None,
                         "algorithm": alg, "key_size": size, "protocol": None,
                         "quantum_vulnerable": v["quantum_vulnerable"], "impact": v["impact"],
                         "finding_codes": v["finding_codes"], "finding": v["finding"], "facts": facts,
                         "created_at": NOW})
        for k in range(0, n, 5000):
            s.execute(insert(CbomCollectedAsset), rows[k:k + 5000])
        s.commit()
        return run.id  # type: ignore[return-value]


class _NoGrades:
    def __init__(self, *a, **k):
        pass

    def add(self, *a, **k):
        return None

    def result(self):
        return {}


def timed(fn, reps: int) -> dict:
    times = []
    for _ in range(reps):
        t0 = time.process_time()
        fn()
        times.append(time.process_time() - t0)
    return {"p50": round(statistics.median(times), 3), "max": round(max(times), 3)}


def bench(n: int, reps: int, per_host: int = 1) -> dict:
    with tempfile.TemporaryDirectory() as tmp:
        engine = create_engine(f"sqlite:///{Path(tmp) / 'b.db'}")
        SQLModel.metadata.create_all(engine)
        run_id = seed(engine, n, per_host)

        def posture():
            with Session(engine) as s:
                P.run_posture(s, team_id=1, run_id=run_id, risk_model=MOSCA)

        def posture_no_grade():
            real = QG.RunGrades
            QG.RunGrades = _NoGrades  # type: ignore[misc,assignment]
            try:
                posture()
            finally:
                QG.RunGrades = real  # type: ignore[misc]

        def grade_only():
            with Session(engine) as s:
                rows = s.exec(select(CbomCollectedAsset).where(CbomCollectedAsset.run_id == run_id)).all()
                t0 = time.process_time()
                g = QG.RunGrades(s, team_id=1, run_id=run_id, risk_model=MOSCA)
                for row in rows:
                    g.add(row, row.finding_codes)
                g.result()
                return time.process_time() - t0

        def list_page():
            with Session(engine) as s:
                INV.list_assets(s, team_id=1, run_id=run_id, page=1, page_size=200)

        def list_grade_only():
            with Session(engine) as s:
                rows = s.exec(select(CbomCollectedAsset).where(CbomCollectedAsset.run_id == run_id).limit(200)).all()
                t0 = time.process_time()
                ctx = QG.load_context(s, team_id=1, run_id=run_id)
                for row in rows:
                    ctx.grade_row(row, row.finding_codes)
                return time.process_time() - t0

        posture()  # warm the knowledge-base caches once, so neither variant pays for them
        grade_times = []
        for _ in range(reps):
            grade_times.append(grade_only())
        with_g, without = [], []
        for _ in range(reps):  # interleaved, so load from other processes hits both variants alike
            with_g.append(timed(posture, 1)["p50"])
            without.append(timed(posture_no_grade, 1)["p50"])
        out = {"assets": n, "assets_per_host": per_host,
               "posture": {"p50": round(statistics.median(with_g), 3), "max": round(max(with_g), 3)},
               "posture_no_grade": {"p50": round(statistics.median(without), 3), "max": round(max(without), 3)},
               "grade_only": {"p50": round(statistics.median(grade_times), 3), "max": round(max(grade_times), 3)},
               "list_page_200": timed(list_page, reps),
               "list_page_grade_only": round(statistics.median([list_grade_only() for _ in range(reps)]), 4)}
        out["grade_share_of_posture_pct"] = round(100 * out["grade_only"]["p50"] / out["posture"]["p50"], 1)
        out["posture_delta_pct"] = round(100 * (out["posture"]["p50"] / out["posture_no_grade"]["p50"] - 1), 1)
        out["list_grade_share_pct"] = round(100 * out["list_page_grade_only"] / out["list_page_200"]["p50"], 1)
        return out


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--sizes", type=int, nargs="+", default=[5000, 50000])
    ap.add_argument("--reps", type=int, default=3)
    ap.add_argument("--per-host", type=int, nargs="+", default=[1, 8])
    args = ap.parse_args()
    for n in args.sizes:
        for per_host in args.per_host:
            print(json.dumps(bench(n, args.reps, per_host)), flush=True)
    return 0


if __name__ == "__main__":
    sys.exit(main())
