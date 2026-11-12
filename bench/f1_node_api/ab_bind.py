"""L8 (DA E3 gate): server CPU per heartbeat with one connection per request vs the plain Session.

    bench/f1_node_api/ab_bind.sh <src-root> <workdir>          # wraps this: PG, seed 1 node, gunicorn 1 worker x 4

    PYTHONPATH=<src root> python bench/f1_node_api/ab_bind.py --api http://127.0.0.1:18081 --creds creds.json \\
        --worker-pid <pid> --n 2000

Sends ``--n`` sequential signed protocol-2 heartbeats from one node and reports the worker's CPU seconds (utime +
stime from /proc) per heartbeat, and the pool checkouts the server counted (``Server-Timing`` is not needed here).
E3 lands only if the bound connection saves at least 3% CPU per heartbeat.
"""
from __future__ import annotations

import argparse
import json
import os
import sys
import time
from pathlib import Path

import httpx

sys.path.insert(0, str(Path(__file__).resolve().parent))
from common import Signer, dumps, load_creds, node_key, node_token  # noqa: E402


def cpu_s(pid: int) -> float:
    fields = Path(f"/proc/{pid}/stat").read_text().rsplit(")", 1)[1].split()
    return (int(fields[11]) + int(fields[12])) / os.sysconf("SC_CLK_TCK")


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--api", required=True)
    ap.add_argument("--creds", required=True)
    ap.add_argument("--worker-pid", type=int, required=True)
    ap.add_argument("--n", type=int, default=2000)
    args = ap.parse_args()
    creds = load_creds(args.creds)
    nodes = [(node_token(creds["secret"], i), Signer(node_key(creds["secret"], i), 2)) for i in range(creds["nodes"])]
    body = dumps({"hostname": "ab", "version": "1.2", "capabilities": {"protocol": 2, "max_jobs": 2}, "running": []})
    with httpx.Client(base_url=args.api, timeout=30) as client:
        def beat(k):  # round-robin over the nodes: each stays far below its 120-a-minute budget
            token, signer = nodes[k % len(nodes)]
            return client.post("/cbom/node/heartbeat", content=body, headers={
                "X-ZS-Node-Token": token, "Content-Type": "application/json",
                **signer.headers("POST", "/cbom/node/heartbeat", body)})

        for k in range(len(nodes)):  # warm-up: caches, connections, first-use paths
            beat(k)
        c0, t0 = cpu_s(args.worker_pid), time.perf_counter()
        bad = 0
        for k in range(args.n):
            bad += beat(k).status_code != 200
        c1, t1 = cpu_s(args.worker_pid), time.perf_counter()
    print(json.dumps({"n": args.n, "errors": bad, "cpu_ms_per_hb": round((c1 - c0) * 1000 / args.n, 4),
                      "wall_ms_per_hb": round((t1 - t0) * 1000 / args.n, 3)}))


if __name__ == "__main__":
    main()
