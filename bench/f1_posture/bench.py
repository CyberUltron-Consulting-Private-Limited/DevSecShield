"""F-1 bench: what ``posture.run_posture`` (and the views that call ``classify.shown``) cost at 5,000 and 50,000 assets.

The same script runs against any checkout (dev, this branch, a trial merge): put that checkout first on PYTHONPATH.

* ``seed --db FILE --n N --mix cb19|estate``: one run in a SQLite file. ``cb19`` is the CB-19 bench's asset mix
  (``bench/cb19_grade/bench.py`` on #114: 5 % crypto libraries, all one version, collected on the bench day);
  ``estate`` adds the dated cases: 20 % library rows over 14 package versions (OpenSSL 1.0-3.6 branches, OpenSSH,
  GnuTLS, process libraries), certificates that expire around the run and today, and collection dates spread over
  the last 400 days, so many rows are judged differently today than on their run day (``shown()['as_of_run']``).
* ``time --db FILE --run R``: one ``run_posture`` call in a fresh process (knowledge base loaded, memo cold), CPU
  and wall seconds, plus a 200-row ``inventory.list_assets`` page and 200 ``asset_detail`` calls on library rows.
* ``verdicts --db FILE --run R --out F``: every row's ``shown()`` (at a fixed time and at the real now), the whole
  ``run_posture`` result, every list page and the library rows' ``asset_detail``, as one JSON line per item, so two
  checkouts can be compared byte for byte.
* ``count --db FILE --run R``: calls of ``crypto_kb.library_status`` and of its CVE-range check during one
  ``run_posture``.

    PYTHONPATH=<checkout> /home/claude/venv-backend/bin/python bench/f1_posture/bench.py seed --db /tmp/b.db --n 50000
"""
from __future__ import annotations

import argparse
import datetime as dt
import hashlib
import json
import sys
import time

from sqlalchemy import insert
from sqlmodel import Session, SQLModel, create_engine, select

from backend.new_models import (CbomCollectedAsset, CbomCollectionJob, CbomCollectionRun, CbomCollectionSettings,
                                CbomCollectionSource, Team)
from backend.utilities.cbom_sources import crypto_kb
from backend.utilities.cbom_sources import inventory as INV
from backend.utilities.cbom_sources import posture as P
from backend.utilities.cbom_sources.classify import classify, shown

NOW = dt.datetime(2026, 11, 14, 9, 0)
MOSCA = {"data_shelf_life_years": 10, "migration_years": 5, "threat_years": 12}
CA = {"is_ca": True, "key_alg": "RSA", "key_size": 2048, "not_after": "2034-01-01T00:00:00Z", "subject": "CN=ca",
      "issuer": "CN=ca", "sig_alg": "sha256WithRSAEncryption"}
LEAF = {**CA, "is_ca": False, "subject": "CN=leaf"}
TLS = {"protocols": ["TLSv1.2", "TLSv1.3"], "group": "x25519"}
# (weight, type, algorithm, key_size, facts, target pattern): the CB-19 bench's mix, unchanged
CB19 = [
    (30, "tls_endpoint", None, None, TLS, "10.{a}.{b}.{c}"),
    (10, "tls_endpoint", None, None, TLS, "52.95.{b}.{c}"),
    (5, "tls_endpoint", None, None, TLS, "h{a}-{b}-{c}.corp"),
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
_LIBS = [("openssl", "3.0.2-0ubuntu1.15"), ("libssl3", "3.0.13-0ubuntu3.4"), ("openssl-libs", "1:3.2.2-6.el9"),
         ("openssl", "3.4.0"), ("openssl", "3.5.4"), ("libssl3t64", "3.6.0-1"), ("openssl", "3.3.1"),
         ("libssl1.1", "1.1.1f-1ubuntu2.23"), ("openssl", "1.0.2k-fips"), ("openssh-server", "1:9.6p1-3ubuntu13.5"),
         ("openssh-clients", "8.7p1-38.el9"), ("libgnutls30", "3.7.3-4ubuntu1.5"), ("libgcrypt20", "1.10.1-3"),
         ("zlib1g", "1.2.13")]
ESTATE = [(w, t, a, k, f, p) for w, t, a, k, f, p in CB19 if t != "crypto_library"]
ESTATE += [(1, "crypto_library", None, None, {"name": n, "version": v, "source": "package"}, "10.{a}.{b}.{c}")
           for n, v in _LIBS]
ESTATE += [(1, "process_library", None, None, {"name": n, "version": v, "pid": 1}, "10.{a}.{b}.{c}")
           for n, v in _LIBS[:6]]
ESTATE += [(2, "certificate", "RSA", 2048, {**LEAF, "not_after": d}, "10.{a}.{b}.{c}")
           for d in ("2026-11-20T00:00:00Z", "2026-10-01T00:00:00Z", "2026-06-01T00:00:00Z", "2027-01-05T00:00:00Z")]
MIXES = {"cb19": CB19, "estate": ESTATE}


def seed(path: str, n: int, mix: str) -> int:
    engine = create_engine(f"sqlite:///{path}")
    SQLModel.metadata.create_all(engine)
    shapes = MIXES[mix]
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
        templates = [shape for shape in shapes for _ in range(shape[0])]
        verdicts: dict[tuple[int, int], dict] = {}
        rows = []
        for i in range(n):
            _, type_, alg, size, facts, pattern = templates[i % len(templates)]
            # cb19: everything collected on the bench day; estate: spread over 400 days (the run's own verdict is
            # the one on its collection day, as jobs.add_assets stores it)
            when = NOW if mix == "cb19" else NOW - dt.timedelta(days=(i * 7919) % 400)
            key = (i % len(templates), when.toordinal())
            v = verdicts.get(key) or verdicts.setdefault(key, classify(type_, alg, size, None, facts, when))
            target = pattern.format(a=(i >> 16) & 255, b=(i >> 8) & 255, c=i & 255)
            rows.append({"team_id": 1, "run_id": run.id, "job_id": job.id, "source_id": src.id, "attempt": 1,
                         "asset_key": hashlib.sha256(str(i).encode()).hexdigest(), "asset_type": type_,
                         "cdx_type": v["cdx_type"], "target": target, "location": f"{target}:{i}", "name": None,
                         "algorithm": alg, "key_size": size, "protocol": None,
                         "quantum_vulnerable": v["quantum_vulnerable"], "impact": v["impact"],
                         "finding_codes": v["finding_codes"], "finding": v["finding"], "facts": facts,
                         "created_at": when})
        for k in range(0, n, 5000):
            s.execute(insert(CbomCollectedAsset), rows[k:k + 5000])
        s.commit()
        return run.id  # type: ignore[return-value]


def _engine(path: str):
    return create_engine(f"sqlite:///{path}")


def _library_rows(s: Session, run_id: int, limit: int) -> list[CbomCollectedAsset]:
    return list(s.exec(select(CbomCollectedAsset).where(
        CbomCollectedAsset.run_id == run_id,
        CbomCollectedAsset.asset_type.in_(["crypto_library", "process_library"]))  # type: ignore[union-attr]
        .order_by(CbomCollectedAsset.id).limit(limit)).all())


def time_once(path: str, run_id: int) -> dict:
    crypto_kb.load()  # the knowledge base is loaded once per process in the product too
    engine = _engine(path)
    out = {}
    with Session(engine) as s:
        c0, w0 = time.process_time(), time.perf_counter()
        P.run_posture(s, team_id=1, run_id=run_id, risk_model=MOSCA)
        out["posture_cpu"], out["posture_wall"] = time.process_time() - c0, time.perf_counter() - w0
    with Session(engine) as s:
        c0 = time.process_time()
        INV.list_assets(s, team_id=1, run_id=run_id, page=1, page_size=200)
        out["list_page_cpu"] = time.process_time() - c0
    with Session(engine) as s:
        libs = _library_rows(s, run_id, 200)
        c0 = time.process_time()
        for row in libs:
            P.asset_detail(row, None)
        out["detail_200_cpu"] = time.process_time() - c0
    return {k: round(v, 3) for k, v in out.items()}


def _line(fh, kind: str, key, value) -> None:
    fh.write(json.dumps([kind, key, value], sort_keys=True, default=str) + "\n")


def verdicts(path: str, run_id: int, out: str) -> dict:
    engine = _engine(path)
    real_now = dt.datetime.utcnow()  # noqa: DTZ003  (naive UTC, as the stored collection times)
    n = changed = 0
    with Session(engine) as s, open(out, "w", encoding="utf-8") as fh:
        rows = s.exec(select(CbomCollectedAsset).where(CbomCollectedAsset.run_id == run_id)
                      .order_by(CbomCollectedAsset.id)).all()
        for row in rows:
            fixed, today = shown(row, NOW), shown(row, real_now)
            _line(fh, "shown_fixed", row.asset_key, fixed)
            _line(fh, "shown_today", row.asset_key, today)
            n += 1
            changed += bool(today["as_of_run"])
        result = P.run_posture(s, team_id=1, run_id=run_id, risk_model=MOSCA)
        _line(fh, "posture", run_id, {k: v for k, v in result.items() if k not in ("qgrade", "grades", "agility")})
        for page in range(1, len(rows) // 5000 + 2):
            listed = INV.list_assets(s, team_id=1, run_id=run_id, page=page, page_size=5000, now=real_now)
            _line(fh, "list", page, {"total": listed["total"], "facets": listed["facets"],
                                     "items": [[i["id"], i["impact"], i["finding_codes"], i["finding"],
                                                i["as_of_run"]] for i in listed["items"]]})
        for row in _library_rows(s, run_id, 10_000):
            _line(fh, "detail", row.asset_key, P.asset_detail(row, None, today=real_now.date()))
    return {"rows": n, "changed_today": changed, "out": out}


def count(path: str, run_id: int) -> dict:
    calls = {"library_status": 0, "_in_range": 0}
    real_status, real_range = crypto_kb.library_status, crypto_kb._in_range

    def status(*a, **k):
        calls["library_status"] += 1
        return real_status(*a, **k)

    def in_range(*a, **k):
        calls["_in_range"] += 1
        return real_range(*a, **k)

    crypto_kb.library_status, crypto_kb._in_range = status, in_range  # type: ignore[assignment]
    try:
        with Session(_engine(path)) as s:
            libs = len(_library_rows(s, run_id, 10**9))
            P.run_posture(s, team_id=1, run_id=run_id, risk_model=MOSCA)
    finally:
        crypto_kb.library_status, crypto_kb._in_range = real_status, real_range  # type: ignore[assignment]
    return {"library_rows": libs, **calls}


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("mode", choices=["seed", "time", "verdicts", "count"])
    ap.add_argument("--db", required=True)
    ap.add_argument("--n", type=int, default=5000)
    ap.add_argument("--mix", choices=sorted(MIXES), default="cb19")
    ap.add_argument("--run", type=int, default=1)
    ap.add_argument("--out")
    args = ap.parse_args()
    if args.mode == "seed":
        result: dict = {"run": seed(args.db, args.n, args.mix), "n": args.n, "mix": args.mix}
    elif args.mode == "time":
        result = time_once(args.db, args.run)
    elif args.mode == "verdicts":
        result = verdicts(args.db, args.run, args.out)
    else:
        result = count(args.db, args.run)
    print(json.dumps(result), flush=True)
    return 0


if __name__ == "__main__":
    sys.exit(main())
