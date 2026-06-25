#!/usr/bin/env python3
"""Persist real CBOM scan results (/tmp/cbom_runs/*.json) into the local DB,
exactly like the worker->backend flow: Scan row (success) + scan_findings docs.
Run from backend dir: uv run python persist_cbom_runs.py
"""
import json, glob, datetime, os
from datetime import timezone
from sqlmodel import Session, select
import new_models
from new_models import Scan
from get_db import get_db, get_mongo_client_db

TEAM_ID = int(os.getenv("SEED_TEAM_ID", "1"))
USER_ID = int(os.getenv("SEED_USER_ID", "1"))
RUNS = sorted(glob.glob("/tmp/cbom_runs/*.json"))
RUNS = [p for p in RUNS if os.path.basename(p) not in ("summary.json",)]

eng = get_db()
mdb = get_mongo_client_db()
col = mdb["scan_findings"]
now = datetime.datetime.now(timezone.utc)
created = []

for path in RUNS:
    data = json.load(open(path))
    results = data.get("results") or []
    if not results:
        print(f"skip {path}: 0 findings"); continue
    name = data.get("name") or os.path.basename(path).replace(".json", "")
    scan = Scan(
        team_id=TEAM_ID, owner_user_id=USER_ID, scan_type="cbom",
        title=f"CBOM: {name} (real scan)", scan_status="success",
        created_at=now, last_updated=now,
        credit_consumed=round(float(data.get("duration_of_scan", 0)) / 30.0, 2),
        task_id=None,
        scan_metadata={
            "repo_url": data.get("repo_url"), "branch": data.get("branch"),
            "zip_file_used": False, "cbom_file_used": False, "scan_binaries": False,
            "cbom_json": data.get("cbom_json"),
        },
        scan_data={"results": results, "cbom_json": data.get("cbom_json"),
                   "duration_of_scan": data.get("duration_of_scan")},
    )
    with Session(eng) as s:
        s.add(scan); s.commit(); s.refresh(scan); sid = scan.id
    col.delete_many({"scan_id": sid})
    docs = [{"scan_id": sid, "created_at": now, "finding_data": r,
             "finding_status": "not_started", "fixed_at": None, "ignored_at": None, "info": None}
            for r in results]
    col.insert_many(docs)
    created.append((sid, name, len(results)))
    print(f"persisted scan {sid}: {name} -> {len(results)} findings")

print("\nSUMMARY:")
for sid, name, n in created:
    print(f"  scan_id={sid}  {name}  findings={n}")
print(f"team_id={TEAM_ID} total_new_scans={len(created)}")
