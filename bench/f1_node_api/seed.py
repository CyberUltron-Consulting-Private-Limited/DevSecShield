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
Round 7 (DA section 5): ``--big-frac`` of the sources carry ``--big-targets`` targets (default 10% x 100); a second
team (``--team-b-nodes``, ``--team-b-sources``; nodes numbered after team A's, their own admin ``bench2@f1.test``);
``--closed-window-team T``: team T's scan window is closed every hour and its sources follow the team window.
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
    ap.add_argument("--big-frac", type=float, default=0.1)
    ap.add_argument("--big-targets", type=int, default=100)
    ap.add_argument("--team-b-nodes", type=int, default=0)
    ap.add_argument("--team-b-sources", type=int, default=0)
    ap.add_argument("--closed-window-team", type=int, action="append", default=[])
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
    teams = [(1, "Bench Bank", "bench@f1.test", args.nodes, args.sources)]
    if args.team_b_nodes or args.team_b_sources:
        teams.append((2, "Bench Two", "bench2@f1.test", args.team_b_nodes, args.team_b_sources))
    with Session(engine) as s:
        for team_id, name, email, _n, _src in teams:
            s.add(M.Team(id=team_id, name=name, credit_balance=1e9))
            s.commit()
            s.add(M.User(id=team_id, email=email, password="x", first_name="b", last_name="b", profile_photo=None,
                         session_active=True, default_team_id=team_id))
            s.commit()
            s.add(M.TeamMembership(team_id=team_id, user_id=team_id, role="admin"))
            s.commit()
            settings = get_or_create_settings(s, team_id)
            if team_id in args.closed_window_team:
                settings.scan_window = [[False] * 24 for _ in range(7)]
                s.add(settings)
                s.commit()
    has_segments = "node_segment" in M.CbomCollectionSource.__table__.c
    if args.assign == "segment" and not has_segments:
        raise SystemExit("--assign segment: the code under test has no segment jobs")
    spec = KINDS["linux_servers"]
    ids: list[int] = []
    index = 0
    rnd = __import__("random").Random(3)
    total_sources = 0
    for team_id, _name, _email, n_nodes, n_sources in teams:
        rows = []
        for i in range(index, index + n_nodes):
            rows.append({"team_id": team_id, "owner_user_id": team_id, "updated_by_user_id": team_id,
                         "name": f"sim-{i:05d}", "segment": SEGMENT, "timezone": "UTC", "deployment": "docker",
                         "proxy_tls_inspect": False, "enrolled_at": now,
                         "node_token_hash": hashlib.sha256(node_token(secret, i).encode()).hexdigest(),
                         "hostname": f"sim-{i}", "node_version": "bench", "source_ips": [], "capabilities": {},
                         "last_heartbeat_at": now, "signing_public_key": public_b64(node_key(secret, i)),
                         "mode": "agentless", "row_version": 1, "created_at": now, "last_updated": now})
        with engine.begin() as conn:
            for start in range(0, len(rows), CHUNK):
                conn.execute(insert(M.CbomScanNode.__table__), rows[start:start + CHUNK])
        with engine.connect() as conn:
            team_ids = [r[0] for r in conn.exec_driver_sql(
                f"SELECT id FROM cbomscannode WHERE team_id = {int(team_id)} ORDER BY name")]
        ids += team_ids
        window = "network" if team_id in args.closed_window_team else "any"  # "network": the team's window
        src_rows = []
        for j in range(total_sources, total_sources + n_sources):
            width = args.big_targets if rnd.random() < args.big_frac else 1
            targets = [f"10.{(j >> 8) & 255}.{j & 255}.0/24"] if width > 1 else \
                [f"10.{(j >> 16) & 255}.{(j >> 8) & 255}.{j & 255}"]
            if width > 1:
                targets = [f"10.{(j >> 8) & 255}.{j & 255}.{k + 1}" for k in range(min(width, 250))]
            cfg = spec.model.model_validate({"targets": targets, "credential_type": "node_key",
                                             "host_key_policy": "tofu", "window": window}).model_dump(mode="json")
            row = {"team_id": team_id, "owner_user_id": team_id, "updated_by_user_id": team_id, "kind": "linux_servers",
                   "name": f"src-{j:05d}", "name_lower": f"src-{j:05d}", "enabled": True, "config": cfg,
                   "secret_encrypted": None, "secret_fields": [], "last_test_status": "passed", "last_test_result": {},
                   "row_version": 1, "created_at": now, "last_updated": now, "source_uid": secrets.token_hex(16),
                   "node_id": None if args.assign == "segment" else team_ids[j % len(team_ids)]}
            if has_segments:
                row["node_segment"] = SEGMENT if args.assign == "segment" else None
            src_rows.append(row)
        total_sources += n_sources
        with engine.begin() as conn:
            for start in range(0, len(src_rows), CHUNK):
                conn.execute(insert(M.CbomCollectionSource.__table__), src_rows[start:start + CHUNK])
        index += n_nodes
    with engine.begin() as conn:
        conn.exec_driver_sql("ANALYZE")
    nodes_total = args.nodes + args.team_b_nodes
    Path(args.creds).write_text(json.dumps({"secret": secret, "nodes": nodes_total, "node_ids": ids,
                                            "team_a_nodes": args.nodes, "sources": total_sources,
                                            "assign": args.assign, "segment": SEGMENT}))
    print(json.dumps({"seeded_nodes": len(ids), "seeded_sources": total_sources, "assign": args.assign,
                      "seconds": round(time.monotonic() - t0, 1)}))


if __name__ == "__main__":
    main()
