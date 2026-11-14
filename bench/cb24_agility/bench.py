"""CB-24 PR-1 bench: view-time cost of the crypto-agility fix class at N assets (default 5,000), SQLite.

One run, 20 sources (four kinds, two vendor-operated, half with an application), N assets of 14 templates (TLS,
SSH, certificates incl. Windows-store ones, PKCS#11 and AWS KMS keys, libraries, disks, an OT endpoint, coverage),
each classified by the real classifier at insert. Measured, p50 / max of REPS repetitions, each in a fresh process
state (agility memo cleared); with/without pairs are interleaved:

* ``run_posture``          the run posture (CB-24 adds RunAgility: one accumulator call per asset);
* ``run_posture_no_agil``  the same with RunAgility replaced by a no-op (what dev computes);
* ``list_assets_200``      one 200-row asset list page (CB-24 adds annotate_assets);
* ``list_assets_200_no_agil``;
* ``run_agility_accumulator`` what run_posture adds, alone: RunAgility over every row (jobs query included);
* ``evaluate_unmemoised``  the rules over every asset without the memo (the pure cost, worst case);
* ``evaluate_cold``        agility.evaluate over every asset, memo emptied first;
* ``evaluate_warm``        the same again (memoised on the deciding facts).

Usage (repo root): PYTHONPATH=. python bench/cb24_agility/bench.py [N] [REPS]
"""
from __future__ import annotations

import datetime as dt
import json
import statistics
import sys
import tempfile
import time
from pathlib import Path

from sqlmodel import Session, SQLModel, create_engine, select

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))

from backend.new_models import (  # noqa: E402
    CbomCollectedAsset,
    CbomCollectionJob,
    CbomCollectionRun,
    CbomCollectionSource,
    Team,
)
from backend.utilities.cbom_sources import agility as AG  # noqa: E402
from backend.utilities.cbom_sources import inventory as INV  # noqa: E402
from backend.utilities.cbom_sources import posture as POSTURE  # noqa: E402
from backend.utilities.cbom_sources.classify import CDX_TYPE, classify  # noqa: E402

TEMPLATES = [
    ("tls_endpoint", None, None, {"protocols": ["TLSv1.0", "TLSv1.2", "TLSv1.3"], "pq_group_supported": True}),
    ("tls_endpoint", None, None, {"protocols": ["TLSv1.2", "TLSv1.3"], "group": "x25519"}),
    ("ssh_endpoint", None, None, {"banner": "SSH-2.0-OpenSSH_9.6p1", "kex": ["curve25519-sha256"]}),
    ("ssh_endpoint", None, None, {"banner": "SSH-2.0-OpenSSH_8.7", "kex": ["diffie-hellman-group14-sha1"]}),
    ("certificate", "RSA", 2048, {"subject": "CN=a", "issuer": "CN=ca", "not_after": "2030-01-01T00:00:00Z",
                                  "key_alg": "RSA", "key_size": 2048, "sig_alg": "sha256WithRSAEncryption"}),
    ("certificate", "RSA", 2048, {"subject": "CN=w", "issuer": "CN=ca", "not_after": "2030-01-01T00:00:00Z",
                                  "key_alg": "RSA", "key_size": 2048, "source": "windows-store",
                                  "has_private_key": True}),
    ("certificate", "RSA", 1024, {"subject": "CN=o", "issuer": "CN=o", "not_after": "2030-01-01T00:00:00Z",
                                  "key_alg": "RSA", "key_size": 1024, "sig_alg": "sha1WithRSAEncryption",
                                  "self_signed": True}),
    ("managed_key", "RSA", 2048, {"store": "pkcs11", "key_class": "private", "key_type": "RSA", "key_size": 2048}),
    ("kms_key", "RSA", 2048, {"key_spec": "RSA_2048", "arn": "arn:aws:kms:eu-west-1:1:key/x"}),
    ("kms_key", "AES", 256, {"key_spec": "SYMMETRIC_DEFAULT", "rotation_enabled": False}),
    ("crypto_library", None, None, {"name": "openssl", "version": "3.0.2", "source": "package"}),
    ("disk_encryption", None, None, {"encrypted": False}),
    ("ot_endpoint", None, None, {"service": "modbus", "port": 502}),
    ("coverage", None, None, {"reason": "denied"}),
]
KINDS = ("linux_servers", "windows_servers", "network_range", "aws_account")


def seed(path: str, n: int) -> tuple:
    engine = create_engine(f"sqlite:///{path}")
    SQLModel.metadata.create_all(engine)
    now = dt.datetime.utcnow()
    with Session(engine) as s:
        s.add(Team(id=1, name="bench", credit_balance=0.0))
        run = CbomCollectionRun(team_id=1, owner_user_id=1, status="done", client_request_id="cb24-bench")
        s.add(run)
        s.commit()
        s.refresh(run)
        jobs = []
        for i in range(20):
            src = CbomCollectionSource(team_id=1, owner_user_id=1, kind=KINDS[i % 4], name=f"s{i}", name_lower=f"s{i}",
                                       config={"application": f"app{i % 5}" if i % 2 else None,
                                               "operated_by": "vendor" if i in (3, 7) else None})
            s.add(src)
            s.commit()
            s.refresh(src)
            job = CbomCollectionJob(team_id=1, run_id=run.id, source_id=src.id, kind="collect", status="success",
                                    params={"metadata": {"application": src.config["application"],
                                                         "operated_by": src.config["operated_by"]}})
            s.add(job)
            s.commit()
            s.refresh(job)
            jobs.append(job)
        verdicts = [classify(t, a, k, None, f, now) for t, a, k, f in TEMPLATES]
        for i in range(n):
            t, a, k, f = TEMPLATES[i % len(TEMPLATES)]
            v = verdicts[i % len(TEMPLATES)]
            job = jobs[i % len(jobs)]
            s.add(CbomCollectedAsset(team_id=1, run_id=run.id, job_id=job.id, source_id=job.source_id,
                                     asset_key=f"k{i}", asset_type=t, cdx_type=CDX_TYPE.get(t, "algorithm"),
                                     target=f"10.0.{i // 250}.{i % 250}", location=f"10.0.{i // 250}.{i % 250}:{i}",
                                     algorithm=a, key_size=k, quantum_vulnerable=v["quantum_vulnerable"],
                                     impact=v["impact"], finding_codes=v["finding_codes"], finding=v["finding"],
                                     facts=f, created_at=now))
        s.commit()
        return engine, run.id


class _NoAgility:
    def __init__(self, *a, **k):
        pass

    def add(self, *a, **k):
        pass

    def result(self):
        return {}


def _stats(out: list[float]) -> dict:
    return {"p50_s": round(statistics.median(out), 4), "max_s": round(max(out), 4)}


def timed(fn, reps: int) -> dict:
    out = []
    for _ in range(reps):
        AG._evaluate.cache_clear()
        t0 = time.perf_counter()
        fn()
        out.append(time.perf_counter() - t0)
    return _stats(out)


def ab(fn, reps: int) -> tuple[dict, dict]:
    """``fn`` with and without the agility hooks, interleaved (with, without, with, ...) so machine noise hits both
    the same way; the memo is cleared before every timed call."""
    real_acc, real_annotate = AG.RunAgility, AG.annotate_assets
    with_, without = [], []
    for _ in range(reps):
        for bucket, patched in ((with_, False), (without, True)):
            if patched:
                AG.RunAgility, AG.annotate_assets = _NoAgility, lambda _s, _t, _j, items: items
            AG._evaluate.cache_clear()
            try:
                t0 = time.perf_counter()
                fn()
                bucket.append(time.perf_counter() - t0)
            finally:
                AG.RunAgility, AG.annotate_assets = real_acc, real_annotate
    return _stats(with_), _stats(without)


def main() -> None:
    n = int(sys.argv[1]) if len(sys.argv) > 1 else 5000
    reps = int(sys.argv[2]) if len(sys.argv) > 2 else 5
    with tempfile.TemporaryDirectory() as tmp:
        engine, run_id = seed(str(Path(tmp) / "b.db"), n)
        res: dict = {"assets": n, "reps": reps}

        def posture():
            with Session(engine) as s:
                POSTURE.run_posture(s, team_id=1, run_id=run_id, risk_model=None)

        def page():
            with Session(engine) as s:
                INV.list_assets(s, team_id=1, run_id=run_id, page=1, page_size=200)

        posture()  # warm the KB, classifier and SQLite caches once before timing
        res["run_posture"], res["run_posture_no_agil"] = ab(posture, reps)
        res["list_assets_200"], res["list_assets_200_no_agil"] = ab(page, reps)
        with Session(engine) as s:
            rows = s.exec(select(CbomCollectedAsset).where(CbomCollectedAsset.run_id == run_id)).all()
        ctx = AG.node_context(None, None)

        def evaluate():
            for r in rows:
                AG.evaluate("node", r.asset_type, r.finding_codes, r.facts, ctx, r.location)

        def unmemoised():  # every asset through the rules, no memo (the worst case: all deciding facts distinct)
            kb = AG.crypto_kb.version()
            for r in rows:
                facts = r.facts or {}
                AG._evaluate.__wrapped__(kb, "node", r.asset_type, AG._codes(r.finding_codes),
                                         AG._deciding(r.asset_type, facts, r.location), AG._ctx_key(ctx))

        res["evaluate_unmemoised"] = timed(unmemoised, reps)

        def accumulate():  # what run_posture adds: RunAgility over every row (its own jobs query included)
            with Session(engine) as s:
                acc = AG.RunAgility(s, 1, run_id, {})
                for r in rows:
                    acc.add(r, list(r.finding_codes or []))
                acc.result()

        res["run_agility_accumulator"] = timed(accumulate, reps)
        res["evaluate_cold"] = timed(evaluate, reps)
        t0 = time.perf_counter()
        evaluate()
        res["evaluate_warm_s"] = round(time.perf_counter() - t0, 4)
        for key in ("run_posture", "list_assets_200"):
            base = res[f"{key}_no_agil"]["p50_s"]
            res[f"{key}_overhead_pct"] = round(100 * (res[key]["p50_s"] - base) / base, 1) if base else None
        with Session(engine) as s:
            res["fix_classes"] = POSTURE.run_posture(s, team_id=1, run_id=run_id, risk_model=None)["fix_classes"]
        print(json.dumps(res, indent=1))


if __name__ == "__main__":
    main()
