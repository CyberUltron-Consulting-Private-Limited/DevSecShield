"""F1.4 scale: issue N certificates through the real issuing path and time them.

Each certificate goes through ``sshca.issue.issue_for_job`` (checks, guarded serial UPDATE ... RETURNING, signature,
audit row) and is committed on its own, as the node route does.  Reports p50/p95/p99 per certificate, the total, the
audit row count and serial uniqueness, the KRL size and build time for ``--revoke`` revoked certificates, and the
same with several threads issuing at once (serials must stay unique).

    cd backend && uv run --frozen python ../bench/f1_sshca/issue_bench.py --n 10000 [--pg-url postgresql+psycopg2://...]

Run it under ``flock $L/heavy-tests.lock``.  Output: JSON on stdout (and ``--out``).
"""
from __future__ import annotations

import argparse
import concurrent.futures as cf
import datetime as dt
import json
import os
import statistics
import sys
import tempfile
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))
os.environ.setdefault("JWT_SECRET_KEY", "bench")
os.environ.setdefault("JWT_REFRESH_SECRET_KEY", "bench")
os.environ["CBOM_SSH_CA"] = "1"
if not os.environ.get("ENCRYPTION_KEY"):
    from cryptography.fernet import Fernet

    os.environ["ENCRYPTION_KEY"] = Fernet.generate_key().decode()

from cryptography.hazmat.primitives.asymmetric import ed25519  # noqa: E402
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat  # noqa: E402
from sqlmodel import Session, SQLModel, create_engine, func, select  # noqa: E402

from backend.new_models import CbomCollectionJob, CbomCollectionSource, CbomScanNode, Team, TeamMembership, User  # noqa: E402
from backend.utilities.cbom_sources.sshca import keywrap as KW  # noqa: E402
from backend.utilities.cbom_sources.sshca import registry as R  # noqa: E402
from backend.utilities.cbom_sources.sshca.issue import issue_for_job  # noqa: E402
from backend.utilities.cbom_sources.sshca.models import CbomSshCertIssued  # noqa: E402


def _now() -> dt.datetime:
    return dt.datetime.now(dt.timezone.utc).replace(tzinfo=None)


class _Body:
    name = "bench-ca"
    provider = "builtin"
    key_alg = "ed25519"
    key_wrap = None
    kms_key_ref = None
    vault_config = None
    secrets = None
    default_ttl_s = 300


def seed(engine) -> dict:
    SQLModel.metadata.create_all(engine)
    now = _now()
    with Session(engine) as s:
        s.add(Team(id=1, name="bench", credit_balance=1000.0))
        s.commit()
        user = User(email="admin@bench.test", password="x", first_name="a", last_name="b", profile_photo=None,
                    session_active=True, default_team_id=1)
        s.add(user)
        s.commit()
        s.refresh(user)
        s.add(TeamMembership(team_id=1, user_id=user.id, role="admin"))
        line = ed25519.Ed25519PrivateKey.generate().public_key().public_bytes(Encoding.OpenSSH, PublicFormat.OpenSSH).decode()
        node = CbomScanNode(team_id=1, owner_user_id=user.id, name="bench-node", ssh_public_key=line,
                            source_ips=["10.0.0.5"], enrolled_at=now)
        s.add(node)
        s.flush()
        ca = R.create_ca(s, 1, user.id, _Body(), now)
        source = CbomCollectionSource(team_id=1, owner_user_id=user.id, updated_by_user_id=user.id,
                                      kind="linux_servers", name="bench", name_lower="bench", node_id=node.id,
                                      config={"targets": ["10.0.0.9"], "credential_type": "ssh_ca", "ssh_ca_id": ca.id,
                                              "ssh_principals": ["zs-1-prod"]})
        s.add(source)
        s.flush()
        job = CbomCollectionJob(team_id=1, source_id=source.id, node_id=node.id, kind="collect", status="claimed",
                                lease_id="bench-lease", claimed_at=now)
        s.add(job)
        s.commit()
        return {"node": node.id, "job": job.id, "source": source.id, "ca": ca.id}


def issue_one(engine, ids) -> float:
    started = time.perf_counter()
    with Session(engine) as s:
        node, job, source = s.get(CbomScanNode, ids["node"]), s.get(CbomCollectionJob, ids["job"]), \
            s.get(CbomCollectionSource, ids["source"])
        issue_for_job(s, node, job, source, _now(), via="claim")
        s.commit()
    return time.perf_counter() - started


def pct(values: list[float], q: float) -> float:
    ordered = sorted(values)
    return ordered[min(len(ordered) - 1, int(round(q * (len(ordered) - 1))))] * 1000


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--n", type=int, default=10_000)
    ap.add_argument("--threads", type=int, default=4)
    ap.add_argument("--revoke", type=int, default=1000)
    ap.add_argument("--pg-url", default=None)
    ap.add_argument("--out", default=None)
    args = ap.parse_args()
    if args.pg_url:
        engine = create_engine(args.pg_url, pool_size=args.threads + 2)
        SQLModel.metadata.drop_all(engine)
        backend = "postgresql"
    else:
        path = Path(tempfile.mkdtemp()) / "bench.db"
        engine = create_engine(f"sqlite:///{path}", connect_args={"check_same_thread": False, "timeout": 30})
        backend = "sqlite"
    ids = seed(engine)
    KW.forget()
    issue_one(engine, ids)  # warm: unwrap once (cached afterwards, as in a worker)
    times = []
    started = time.perf_counter()
    for _ in range(args.n):
        times.append(issue_one(engine, ids))
    total = time.perf_counter() - started
    conc_n = max(args.n // 10, 100)
    c_started = time.perf_counter()
    with cf.ThreadPoolExecutor(args.threads) as pool:
        conc = list(pool.map(lambda _i: issue_one(engine, ids), range(conc_n)))
    c_total = time.perf_counter() - c_started
    now = _now()
    with Session(engine) as s:
        rows = s.exec(select(func.count()).select_from(CbomSshCertIssued)).one()
        distinct = s.exec(select(func.count(func.distinct(CbomSshCertIssued.serial)))).one()
        certs = s.exec(select(CbomSshCertIssued).order_by(CbomSshCertIssued.id).limit(args.revoke)).all()
        for cert in certs:
            cert.revoked_at = now
            s.add(cert)
        s.commit()
        k_started = time.perf_counter()
        krl = R.krl_bytes(s, 1, now)
        k_time = time.perf_counter() - k_started
    report = {
        "backend": backend, "n": args.n, "total_s": round(total, 2), "per_s": round(args.n / total, 1),
        "p50_ms": round(pct(times, 0.50), 2), "p95_ms": round(pct(times, 0.95), 2), "p99_ms": round(pct(times, 0.99), 2),
        "max_ms": round(max(times) * 1000, 2), "mean_ms": round(statistics.mean(times) * 1000, 2),
        "concurrent": {"threads": args.threads, "n": conc_n, "total_s": round(c_total, 2),
                       "p99_ms": round(pct(conc, 0.99), 2)},
        "audit_rows": int(rows), "issued": args.n + 1 + conc_n, "distinct_serials": int(distinct),
        "krl": {"revoked_certs": len(certs), "bytes": len(krl), "build_ms": round(k_time * 1000, 2)},
    }
    assert report["audit_rows"] == report["issued"] == report["distinct_serials"], report
    text = json.dumps(report, indent=2)
    print(text)
    if args.out:
        Path(args.out).write_text(text + "\n")


if __name__ == "__main__":
    main()
