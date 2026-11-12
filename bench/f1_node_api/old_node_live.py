"""Live check (AC 4a, DA L7): the current scan-node image (scan node 1.0.0, protocol 1) against this branch's backend.

    PYTHONPATH=<src root> python bench/f1_node_api/old_node_live.py --api http://127.0.0.1:18082 --db <url> \\
        --image <scan node 1.0 image> --out result.json

Uses a database seeded by seed.py (team 1, user bench@f1.test). Creates a node through the API, starts the image with
its registration token (``--network host``, plain HTTP allowed for this lab only), then: a connection test of a
pinned network_range source (127.0.0.1/32), and a run with one *segment* job (a linux_servers source on the node's
segment, no node) that the old node claims although it knows nothing of segments. Passes when the node enrolled
signed, heartbeated, both jobs reached a terminal state through the node's own result calls, its requests went
through the protocol-1 nonce table (no replay-window use), and it logged no warning or error while it polled claims
that were answered 204 (whatever the reason: no job, or no dispatch permit; both are the same 204 to the node, and
test_cbom_f1_node_api proves the empty-bucket case with the verbatim 1.0 client).
"""
from __future__ import annotations

import argparse
import json
import subprocess
import sys
import time
import uuid

import httpx
import psycopg2


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--api", required=True)
    ap.add_argument("--db", required=True)
    ap.add_argument("--image", required=True)
    ap.add_argument("--out", required=True)
    args = ap.parse_args()
    from backend.utilities.auth.auth_utils import create_access_token
    from backend.utilities.cbom_sources.kinds import KINDS

    h = {"Authorization": f"Bearer {create_access_token('bench@f1.test')}"}
    c = httpx.Client(base_url=args.api, headers=h, timeout=60)
    out: dict = {"image": args.image}
    r = c.post("/1/cbom/sources/nodes", json={"name": "old-image-node", "segment": "lab"})
    r.raise_for_status()
    node_id, reg = r.json()["node"]["id"], r.json()["registration_token"]
    r = c.post("/1/cbom/sources/items", json={"kind": "network_range", "name": "lab-loopback", "node_id": node_id,
                                              "config": {"cidr": "127.0.0.1/32", "mode": "fragile"}})
    r.raise_for_status()
    rng = r.json()["source"]
    name = f"f1-1-oldnode-{uuid.uuid4().hex[:6]}"
    subprocess.run(["docker", "run", "-d", "--name", name, "--label", "zs-owner=f1-1", "--network", "host",
                    "-e", f"ZS_API_URL={args.api}", "-e", "ZS_ALLOW_INSECURE_HTTP=1", "-e", f"ZS_REGISTRATION_TOKEN={reg}",
                    args.image], check=True, capture_output=True)
    try:
        deadline = time.time() + 120
        node = {}
        while time.time() < deadline:
            node = c.get(f"/1/cbom/sources/nodes/{node_id}").json()["node"]
            if node.get("status") == "online":
                break
            time.sleep(2)
        out["node"] = {k: node.get(k) for k in ("status", "signing", "node_version", "mode", "segment")}
        test = c.post(f"/1/cbom/sources/items/{rng['id']}/test").json()
        out["test_job"] = test.get("job", {}).get("id")
        deadline = time.time() + 180
        while time.time() < deadline:
            src = c.get(f"/1/cbom/sources/items/{rng['id']}").json()["source"]
            if src["last_test_status"] not in ("pending", "never"):
                break
            time.sleep(3)
        out["test"] = {"status": src["last_test_status"], "summary": src.get("last_test_summary")}
        # a segment job: inserted like a policy-managed source would be (F1.2), then a normal run
        cfg = KINDS["linux_servers"].model.model_validate({"targets": ["127.0.0.2"], "window": "any",
                                                          "timeout_s": 10}).model_dump(mode="json")
        conn = psycopg2.connect(args.db)
        conn.autocommit = True
        with conn.cursor() as cur:
            cur.execute("INSERT INTO cbomcollectionsource (team_id, owner_user_id, kind, name, name_lower, node_id,"
                        " node_segment, enabled, config, secret_fields, last_test_status, last_test_result, row_version,"
                        " created_at, last_updated, source_uid) VALUES (1, 1, 'linux_servers', 'seg-src', 'seg-src',"
                        " NULL, 'lab', true, %s, '[]', 'passed', '{}', 1, now(), now(), %s) RETURNING id",
                        (json.dumps(cfg), uuid.uuid4().hex))
            seg_source = cur.fetchone()[0]
        run = c.post("/1/cbom/sources/runs", json={"include": {"servers": True, "network": False},
                                                   "source_ids": [seg_source],
                                                   "client_request_id": "old-node-" + uuid.uuid4().hex[:8]})
        out["run_create"] = run.status_code
        run_id = run.json()["run"]["id"]
        deadline = time.time() + 240
        while time.time() < deadline:
            with conn.cursor() as cur:
                cur.execute("SELECT status FROM cbomcollectionrun WHERE id = %s", (run_id,))
                status = cur.fetchone()[0]
                cur.execute("SELECT status, node_id, node_segment, attempts, error FROM cbomcollectionjob WHERE "
                            "run_id = %s", (run_id,))
                jobs = cur.fetchall()
            if status in ("done", "partial", "failed", "cancelled"):
                break
            time.sleep(3)
        out["segment_run"] = {"status": status, "jobs": [{"status": j[0], "claimed_by_node": j[1], "segment": j[2],
                                                          "attempts": j[3], "error": j[4]} for j in jobs]}
        with conn.cursor() as cur:
            cur.execute("SELECT count(*) FROM cbomnodenonce WHERE node_id = %s", (node_id,))
            nonces = cur.fetchone()[0]
            cur.execute("SELECT replay_hwm, last_heartbeat_at, node_version FROM cbomscannode WHERE id = %s",
                        (node_id,))
            hwm, seen, version = cur.fetchone()
        out["protocol1"] = {"nonce_rows": nonces, "replay_hwm": hwm, "last_heartbeat_at": str(seen),
                            "node_version": version}
        time.sleep(15)  # a few more 204 polls with nothing to do
        logs = subprocess.run(["docker", "logs", name], capture_output=True, text=True)
        lines = (logs.stdout + logs.stderr).splitlines()
        out["node_log_tail"] = lines[-40:]
        out["node_warnings"] = [line for line in lines if (" warn " in line or " error " in line)
                                and "ZS_ALLOW_INSECURE_HTTP" not in line]
    finally:
        subprocess.run(["docker", "rm", "-f", name], capture_output=True)
    ok = (out["node"].get("signing") == "required" and out["test"]["status"] not in ("pending", "never")
          and out["segment_run"]["status"] in ("done", "partial", "failed")
          and all(j["claimed_by_node"] == node_id for j in out["segment_run"]["jobs"])
          and out["protocol1"]["nonce_rows"] > 0 and out["protocol1"]["replay_hwm"] == 0
          and out["protocol1"]["node_version"] == "1.0.0" and not out["node_warnings"])
    out["passed"] = ok
    text = json.dumps(out, indent=2, default=str)
    open(args.out, "w").write(text)
    print(text)
    sys.exit(0 if ok else 1)


if __name__ == "__main__":
    main()
