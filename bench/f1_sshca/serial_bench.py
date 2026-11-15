"""F1.4 bench: do the certificates of ONE CA serialise?  8 threads, 1 CA vs 8 CAs, on PostgreSQL (review 5871815439).

Each mint is the real ``issue.issue_for_job`` in its own transaction (claim-like: the caller may do more work after the
mint, ``--hold-ms``, before it commits).  Before review round 7 every mint of a CA took the CA row's lock
(``UPDATE cbomsshca SET serial_next …``) until its caller committed, so 1 CA was much slower than 8.  Now serials come
from a SEQUENCE and the CA row is only share-locked: the two should be within 10 %.

    PYTHONPATH=<repo> backend/.venv/bin/python bench/f1_sshca/serial_bench.py \\
        --pg-url postgresql+psycopg2://user:pass@127.0.0.1:5432/bench --out serial-bench.json

The database is dropped and re-created (``SQLModel.metadata``): use a throw-away one.  Rounds alternate 1 CA and 8 CAs
so a busy machine slows both alike; the report has every round and the medians.
"""
from __future__ import annotations

import argparse
import concurrent.futures as cf
import datetime as dt
import json
import os
import statistics
import threading
import time

os.environ.setdefault("JWT_SECRET_KEY", "bench-only")
os.environ.setdefault("JWT_REFRESH_SECRET_KEY", "bench-only")
os.environ["CBOM_SSH_CA"] = "1"
if not os.environ.get("ENCRYPTION_KEY"):
    from cryptography.fernet import Fernet

    os.environ["ENCRYPTION_KEY"] = Fernet.generate_key().decode()  # generated per run, never stored

from cryptography.hazmat.primitives.asymmetric import ed25519  # noqa: E402
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat  # noqa: E402
from sqlalchemy import create_engine, text  # noqa: E402
from sqlmodel import Session, SQLModel  # noqa: E402

from backend.new_models import CbomCollectionJob, CbomCollectionSource, CbomScanNode, Team, TeamMembership, User  # noqa: E402
from backend.utilities.cbom_sources.sshca import keywrap as KW  # noqa: E402
from backend.utilities.cbom_sources.sshca import registry as R  # noqa: E402
from backend.utilities.cbom_sources.sshca.issue import issue_for_job  # noqa: E402


def utcnow() -> dt.datetime:
    return dt.datetime.now(dt.timezone.utc).replace(tzinfo=None)


class Body:
    provider, key_alg, key_wrap, kms_key_ref, kms_key = "builtin", "ed25519", None, None, None
    vault_config, secrets, default_ttl_s = None, None, 300

    def __init__(self, name: str):
        self.name = name


def seed(engine, cas: int) -> list[dict]:
    with engine.begin() as c:  # a throw-away database: start from an empty schema every round
        c.execute(text("DROP SCHEMA public CASCADE"))
        c.execute(text("CREATE SCHEMA public"))
    SQLModel.metadata.create_all(engine)
    now = utcnow()
    out = []
    with Session(engine) as s:
        s.add(Team(id=1, name="bench", credit_balance=10.0))
        s.commit()
        user = User(email="admin@bench.test", password="x", first_name="a", last_name="b", profile_photo=None,
                    default_team_id=1)
        s.add(user)
        s.commit()
        s.add(TeamMembership(team_id=1, user_id=user.id, role="admin"))
        for i in range(cas):
            line = ed25519.Ed25519PrivateKey.generate().public_key().public_bytes(Encoding.OpenSSH,
                                                                                  PublicFormat.OpenSSH).decode()
            node = CbomScanNode(team_id=1, owner_user_id=user.id, name=f"n{i}", node_token_hash=f"{i:064d}",
                                ssh_public_key=line, source_ips=["10.0.0.5"], enrolled_at=now)
            s.add(node)
            s.flush()
            ca = R.create_ca(s, 1, user.id, Body(f"ca{i}"), now)
            src = CbomCollectionSource(team_id=1, owner_user_id=user.id, updated_by_user_id=user.id,
                                       kind="linux_servers", name=f"s{i}", name_lower=f"s{i}", node_id=node.id,
                                       config={"targets": ["10.20.0.5"], "credential_type": "ssh_ca",
                                               "ssh_ca_id": ca.id, "ssh_principals": ["zs-1-prod"]})
            s.add(src)
            s.flush()
            job = CbomCollectionJob(team_id=1, source_id=src.id, node_id=node.id, kind="collect", status="claimed",
                                    lease_id=f"lease-{i:08d}", claimed_at=now)
            s.add(job)
            s.commit()
            out.append({"node": node.id, "job": job.id, "source": src.id})
    return out


def mint(engine, ids: dict, hold_s: float) -> float:
    t = time.perf_counter()
    with Session(engine) as s:
        issue_for_job(s, s.get(CbomScanNode, ids["node"]), s.get(CbomCollectionJob, ids["job"]),
                      s.get(CbomCollectionSource, ids["source"]), utcnow(), via="claim")
        if hold_s:
            time.sleep(hold_s)
        s.commit()
    return time.perf_counter() - t


def run(engine, targets: list[dict], n: int, threads: int, hold_s: float, waits: list[int]) -> dict:
    stop = threading.Event()

    def sample():
        with engine.connect() as c:
            while not stop.is_set():
                waits.append(int(c.execute(text(
                    "SELECT count(*) FROM pg_stat_activity WHERE wait_event_type = 'Lock' AND query ILIKE "
                    "'%cbomsshca%'")).scalar()))
                time.sleep(0.02)

    sampler = threading.Thread(target=sample)
    sampler.start()
    t = time.perf_counter()
    try:
        with cf.ThreadPoolExecutor(threads) as pool:
            lat = sorted(pool.map(lambda i: mint(engine, targets[i % len(targets)], hold_s), range(n)))
    finally:
        stop.set()
        sampler.join()
    took = time.perf_counter() - t
    return {"n": n, "per_s": round(n / took, 1), "p50_ms": round(lat[len(lat) // 2] * 1000, 1),
            "p99_ms": round(lat[min(len(lat) - 1, int(len(lat) * 0.99))] * 1000, 1)}


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--pg-url", required=True)
    parser.add_argument("--out", required=True)
    parser.add_argument("--n", type=int, default=400)
    parser.add_argument("--threads", type=int, default=8)
    parser.add_argument("--rounds", type=int, default=3)
    parser.add_argument("--hold-ms", type=float, nargs="+", default=[0.0, 5.0])
    args = parser.parse_args()
    engine = create_engine(args.pg_url, pool_size=args.threads + 4, max_overflow=4)
    report: dict = {"threads": args.threads, "n": args.n, "load_avg_start": os.getloadavg(), "cases": {}}
    for hold_ms in args.hold_ms:
        rounds: dict[str, list[dict]] = {"1ca": [], "8ca": []}
        waits: dict[str, list[int]] = {"1ca": [], "8ca": []}
        for _ in range(args.rounds):
            for label, cas in (("1ca", 1), ("8ca", 8)):
                targets = seed(engine, cas)
                KW.forget()
                for ids in targets:
                    mint(engine, ids, 0.0)  # warm each CA's key in this worker (the bench measures the database)
                rounds[label].append(run(engine, targets, args.n, args.threads, hold_ms / 1000, waits[label]))
        one = statistics.median(r["per_s"] for r in rounds["1ca"])
        eight = statistics.median(r["per_s"] for r in rounds["8ca"])
        report["cases"][f"hold_{hold_ms:g}ms"] = {
            "rounds": rounds, "median_per_s": {"1ca": one, "8ca": eight},
            "difference_pct": round(abs(eight - one) / max(one, eight) * 100, 1),
            "lock_waiters_max": {k: max(v or [0]) for k, v in waits.items()},
            "lock_waiters_mean": {k: round(sum(v) / max(1, len(v)), 3) for k, v in waits.items()}}
    report["load_avg_end"] = os.getloadavg()
    with open(args.out, "w") as fh:
        json.dump(report, fh, indent=2)
    print(json.dumps({k: (v["median_per_s"], v["difference_pct"], v["lock_waiters_max"])
                      for k, v in report["cases"].items()}))


if __name__ == "__main__":
    main()
