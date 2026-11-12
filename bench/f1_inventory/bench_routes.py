"""F1.2 request-path bench (PR #80 review 5874269505, after the reviewer's ``bench_routes.py``): the routes that used to
evaluate every target of a team, called through the PR's own functions on SQLite in memory (the cost measured is
Python evaluation; PostgreSQL adds I/O).  Random selectors of 1-3 leaves; a quarter of the policies never-scan.

    PYTHONPATH=<root> python bench/f1_inventory/bench_routes.py <targets> <policies>

Prints one JSON line: the request paths (GET /policies, a targets page with and without filters, preview of a narrow
and of a catch-all draft, a policy write), the evaluation the fleet worker runs after a write, and the import; ``cpu_s`` has the CPU time of each.
"""
from __future__ import annotations

import datetime as dt
import json
import os
import random
import resource
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))
os.environ.setdefault("CBOM_FLEET_INVENTORY", "1")
os.environ.setdefault("CBOM_FLEET_POLICIES", "1")

from sqlalchemy.pool import StaticPool  # noqa: E402
from sqlmodel import Session, SQLModel, create_engine  # noqa: E402

import backend.new_models  # noqa: E402,F401
from backend.new_models import Team, TeamMembership, User  # noqa: E402
from backend.routers import cbom_fleet_inventory as INV  # noqa: E402
from backend.routers import cbom_fleet_policies as POL  # noqa: E402
from backend.utilities.cbom_sources.fleet import evaluate as EVAL  # noqa: E402
from backend.utilities.cbom_sources.fleet import store  # noqa: E402
from backend.utilities.cbom_sources.fleet.inventory_sources import normalize  # noqa: E402
from backend.utilities.cbom_sources.fleet.models import CbomCredential, CbomFleetPolicy, CbomInventorySource  # noqa: E402
from backend.utilities.cbom_sources.fleet.schemas import PolicyCreate, PolicyUpdate, PreviewBody  # noqa: E402

N, P = int(sys.argv[1]), int(sys.argv[2])
rng = random.Random(7)
keys = ["env", "team", "app", "owner", "tier", "zone", "os", "cost", "role", "svc"]
vals = [f"v{i}" for i in range(20)]


def sel():
    leaves = []
    for _ in range(rng.randint(1, 3)):
        op = rng.choice(["eq", "in", "exists", "prefix", "ne"])
        leaf = {"tag": rng.choice(keys), "op": op}
        if op == "in":
            leaf["value"] = rng.sample(vals, 3)
        elif op != "exists":
            leaf["value"] = rng.choice(vals)
        leaves.append(leaf)
    return {"all": leaves} if len(leaves) > 1 else leaves[0]


db = create_engine("sqlite://", poolclass=StaticPool, connect_args={"check_same_thread": False})
SQLModel.metadata.create_all(db)
now = dt.datetime.now(dt.timezone.utc).replace(tzinfo=None)
out: dict = {"targets": N, "policies": P}
with Session(db) as s:
    s.add(Team(id=1, name="bench", credit_balance=0.0))
    s.commit()
    user = User(email="bench@f12.test", password="x", first_name="b", last_name="a", profile_photo=None,
                session_active=True, default_team_id=1)
    s.add(user)
    s.commit()
    s.refresh(user)
    s.add(TeamMembership(team_id=1, user_id=user.id, role="admin"))
    s.add(CbomCredential(id=1, team_id=1, name="k", credential_type="node_key", config={}, secret_fields=[]))
    for i in range(1, P + 1):
        action = {"never_scan": True} if i % 4 == 0 else {"transport": "ssh", "credential_id": 1, "node_id": 1}
        s.add(CbomFleetPolicy(id=i, team_id=1, name=f"p{i}", priority=rng.randint(0, 100), selector=sel(),
                              action=action, created_at=now, last_updated=now))
    src = CbomInventorySource(team_id=1, kind="csv", name="CSV import", config={}, created_at=now, last_updated=now)
    s.add(src)
    s.commit()
    s.refresh(src)
    uid = user.id
    targets = [normalize({"external_id": f"h{n}", "address": f"10.{n // 65536}.{(n // 256) % 256}.{n % 256}",
                          "tags": {k: rng.choice(vals) for k in rng.sample(keys, 6)}}) for n in range(N)]
    t0 = time.perf_counter()
    engine = EVAL.inputs(s, 1, now).engine
    store.upsert(s, 1, src, targets, now, engine=engine, snapshot=True)
    s.commit()
    out["import_with_policies_s"] = round(time.perf_counter() - t0, 2)


def timed(name, fn, *args, repeat=1):
    """The slowest of ``repeat`` calls, wall clock; ``cpu_s`` keeps the process CPU time of that call, which a busy
    machine inflates far less than the wall clock."""
    worst = cpu = None
    for _ in range(repeat):
        t0, c0 = time.perf_counter(), time.process_time()
        res = fn(*args)
        took = time.perf_counter() - t0
        if worst is None or took > worst:
            worst, cpu = took, time.process_time() - c0
    out[name] = round(worst, 3)
    out.setdefault("cpu_s", {})[name] = round(cpu, 3)
    return res


def _evaluate():
    with Session(db) as s:
        EVAL.evaluate_team(s, 1, now)
        s.commit()


_evaluate()  # the stored decisions and counts the reads serve
timed("GET_policies_s", POL._list_policies, db, 1)
timed("GET_targets_page_no_filter_s", INV._list_targets, db, 1, None, None, None, None, None, None, None, 0, 100)
timed("GET_targets_page_tag_filter_s", INV._list_targets, db, 1, None, "env", "v3", None, None, None, None, 0, 100)
timed("GET_targets_page_decision_filter_s", INV._list_targets, db, 1, None, None, None, None, None, None, "collect", 0, 100)
narrow = PreviewBody(policy=PolicyCreate(name="draft", priority=50, selector={"tag": "env", "op": "eq", "value": "v1"},
                                         action={"never_scan": True}))
timed("POST_preview_narrow_s", POL._preview, db, 1, narrow, repeat=3)
wide = PreviewBody(policy=PolicyCreate(name="all", priority=50, selector={}, action={"never_scan": True}))
timed("POST_preview_catch_all_s", POL._preview, db, 1, wide)
body = PolicyUpdate(priority=77)
timed("policy_write_s", POL._update_policy, db, 1, uid, 1, body, repeat=3)  # PATCH: save + ask the worker
t0, c0 = time.perf_counter(), time.process_time()
ran = EVAL.run_requested(db, now + dt.timedelta(seconds=1))
out["worker_evaluation_s"] = round(time.perf_counter() - t0, 2)
out["cpu_s"]["worker_evaluation_s"] = round(time.process_time() - c0, 2)
out["worker_runs"] = [r.get("status") for r in ran]
out["max_rss_mb"] = round(resource.getrusage(resource.RUSAGE_SELF).ru_maxrss / 1024)
print(json.dumps(out))
