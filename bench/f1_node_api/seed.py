"""Seed a throwaway PostgreSQL for the F1.1 node-API bench: one team, one admin, N enrolled scan nodes, M sources.

    PYTHONPATH=<src root> python bench/f1_node_api/seed.py --db postgresql://... --nodes 10000 --sources 10000 \\
        --assign pinned|segment --creds /scratch/creds.json

The schema comes from the models of the code under test (``SQLModel.metadata.create_all`` after ``drop_all``), so
the same script seeds the dev baseline and the branch. Nodes are enrolled directly in the database (enrollment is
not the hot path under test): token hash, Ed25519 public key, ``enrolled_at``. Sources are ``linux_servers`` with
one target each and ``window: any`` (claimable at any hour), stored exactly as the API stores them
(the kind's model ``model_dump(mode="json")``). ``--assign pinned`` gives source i to node i mod N (today's model);
``--assign segment`` puts every node in one segment and gives every source that segment and no node, so any node
claims any job (F1.1 segment jobs; the code under test must have ``node_segment``).
DESTRUCTIVE: drops every table of the target database. Use only a throwaway database.
"""
from __future__ import annotations

import argparse
import datetime as dt
import hashlib
import json
import secrets
import sys
import time
from pathlib import Path

from sqlalchemy import insert
from sqlmodel import Session, SQLModel, create_engine

sys.path.insert(0, str(Path(__file__).resolve().parent))
from common import node_key, node_token, public_b64  # noqa: E402

CHUNK = 1000
SEGMENT = "bench-seg"


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--db", required=True)
    ap.add_argument("--nodes", type=int, default=10_000)
    ap.add_argument("--sources", type=int, default=0)
    ap.add_argument("--assign", choices=("pinned", "segment"), default="pinned")
    ap.add_argument("--creds", required=True, help="where to write the derivation secret (JSON)")
    ap.add_argument("--yes-drop-everything", action="store_true", required=True)
    args = ap.parse_args()

    from backend import new_models as M  # the code under test
    from backend.utilities.cbom_sources.kinds import KINDS
    from backend.utilities.cbom_sources.settings import get_or_create_settings

    secret = secrets.token_hex(16)
    engine = create_engine(args.db)
    t0 = time.monotonic()
    SQLModel.metadata.drop_all(engine)
    SQLModel.metadata.create_all(engine)
    now = dt.datetime.utcnow()
    with Session(engine) as s:
        s.add(M.Team(id=1, name="Bench Bank", credit_balance=1e9))
        s.commit()
        s.add(M.User(id=1, email="bench@f1.test", password="x", first_name="b", last_name="b", profile_photo=None,
                     session_active=True, default_team_id=1))
        s.commit()
        s.add(M.TeamMembership(team_id=1, user_id=1, role="admin"))
        s.commit()
        get_or_create_settings(s, 1)
    has_segments = "node_segment" in M.CbomCollectionSource.__table__.c
    if args.assign == "segment" and not has_segments:
        raise SystemExit("--assign segment: the code under test has no segment jobs")
    rows = []
    for i in range(args.nodes):
        row = {"team_id": 1, "owner_user_id": 1, "updated_by_user_id": 1, "name": f"sim-{i:05d}", "segment": SEGMENT,
               "timezone": "UTC", "deployment": "docker", "proxy_tls_inspect": False, "enrolled_at": now,
               "node_token_hash": hashlib.sha256(node_token(secret, i).encode()).hexdigest(), "hostname": f"sim-{i}",
               "node_version": "bench", "source_ips": [], "capabilities": {}, "last_heartbeat_at": now,
               "signing_public_key": public_b64(node_key(secret, i)), "mode": "agentless", "row_version": 1,
               "created_at": now, "last_updated": now}
        rows.append(row)
    with engine.begin() as conn:
        for start in range(0, len(rows), CHUNK):
            conn.execute(insert(M.CbomScanNode.__table__), rows[start:start + CHUNK])
    with engine.connect() as conn:
        ids = [r[0] for r in conn.exec_driver_sql("SELECT id FROM cbomscannode ORDER BY name")]
    spec = KINDS["linux_servers"]
    src_rows = []
    for j in range(args.sources):
        cfg = spec.model.model_validate({"targets": [f"10.{(j >> 16) & 255}.{(j >> 8) & 255}.{j & 255}"],
                                         "credential_type": "node_key", "host_key_policy": "tofu",
                                         "window": "any"}).model_dump(mode="json")
        row = {"team_id": 1, "owner_user_id": 1, "updated_by_user_id": 1, "kind": "linux_servers",
               "name": f"src-{j:05d}", "name_lower": f"src-{j:05d}", "enabled": True, "config": cfg,
               "secret_encrypted": None, "secret_fields": [], "last_test_status": "passed", "last_test_result": {},
               "row_version": 1, "created_at": now, "last_updated": now, "source_uid": secrets.token_hex(16),
               "node_id": None if args.assign == "segment" else ids[j % len(ids)]}
        if has_segments:
            row["node_segment"] = SEGMENT if args.assign == "segment" else None
        src_rows.append(row)
    with engine.begin() as conn:
        for start in range(0, len(src_rows), CHUNK):
            conn.execute(insert(M.CbomCollectionSource.__table__), src_rows[start:start + CHUNK])
        conn.exec_driver_sql("ANALYZE")
    Path(args.creds).write_text(json.dumps({"secret": secret, "nodes": args.nodes, "node_ids": ids,
                                            "sources": args.sources, "assign": args.assign, "segment": SEGMENT}))
    print(json.dumps({"seeded_nodes": len(ids), "seeded_sources": len(src_rows), "assign": args.assign,
                      "seconds": round(time.monotonic() - t0, 1)}))


if __name__ == "__main__":
    main()
