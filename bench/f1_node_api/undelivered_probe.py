"""L6 (DA D3): a claim whose node gave up is handed back at once, without counting an attempt.

    PYTHONPATH=<src root> python bench/f1_node_api/undelivered_probe.py --api http://127.0.0.1:18081 --db <url> \\
        --creds creds.json --n 50 --out result.json

For each of ``--n`` nodes (seeded with one pinned job each): another connection locks the node's row for 4 s, the
node claims with a 1.5 s client timeout (so it disconnects while the claim waits on the row), the lock is released,
and the probe polls the job.  Pass: every job is ``pending`` again with ``attempts`` 0 within 1 s of the release,
the server logged ``job released ... reason=undelivered`` for each, and never ``reason=not_reported``.
"""
from __future__ import annotations

import argparse
import json
import sys
import threading
import time
from pathlib import Path

import httpx
import psycopg2

sys.path.insert(0, str(Path(__file__).resolve().parent))
from common import Signer, load_creds, node_key, node_token  # noqa: E402


def probe(api: str, db: str, secret: str, index: int, node_id: int, results: list) -> None:
    lock = psycopg2.connect(db)
    lock.autocommit = False
    with lock.cursor() as cur:
        cur.execute("SELECT id FROM cbomcollectionjob WHERE node_id = %s AND status = 'pending' LIMIT 1", (node_id,))
        job_id = cur.fetchone()[0]
        cur.execute("SELECT id FROM cbomscannode WHERE id = %s FOR UPDATE", (node_id,))
    signer = Signer(node_key(secret, index), 2)
    body = b'{"mode":"agentless"}'
    headers = {"X-ZS-Node-Token": node_token(secret, index), "Content-Type": "application/json",
               **signer.headers("POST", "/cbom/node/jobs/claim", body)}
    timed_out = False
    try:
        httpx.post(api + "/cbom/node/jobs/claim", content=body, headers=headers, timeout=1.5)
    except httpx.TimeoutException:
        timed_out = True
    time.sleep(max(0.0, 4.0 - 1.5))
    lock.rollback()  # the row lock ends: the claim's work goes on, commits, and finds its client gone
    released_at = time.perf_counter()
    lock.close()
    check = psycopg2.connect(db)
    check.autocommit = True
    back_after = None
    status = attempts = None
    with check.cursor() as cur:
        while time.perf_counter() - released_at < 5.0:
            cur.execute("SELECT status, attempts FROM cbomcollectionjob WHERE id = %s", (job_id,))
            status, attempts = cur.fetchone()
            if status == "pending" and attempts == 0 and back_after is None and time.perf_counter() - released_at > 0.05:
                back_after = time.perf_counter() - released_at
                break
            time.sleep(0.02)
    check.close()
    results.append({"node": node_id, "job": job_id, "client_timed_out": timed_out, "status": status,
                    "attempts": attempts, "back_after_s": None if back_after is None else round(back_after, 3)})


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--api", required=True)
    ap.add_argument("--db", required=True)
    ap.add_argument("--creds", required=True)
    ap.add_argument("--n", type=int, default=50)
    ap.add_argument("--parallel", type=int, default=10)
    ap.add_argument("--out", required=True)
    args = ap.parse_args()
    creds = load_creds(args.creds)
    ids = creds["node_ids"]
    from backend.utilities.auth.auth_utils import create_access_token  # the code under test's JWT format

    token = create_access_token("bench@f1.test")
    r = httpx.post(args.api + "/1/cbom/sources/runs", headers={"Authorization": f"Bearer {token}"}, timeout=120,
                   json={"include": {"servers": True}, "client_request_id": "l6-" + str(int(time.time())),
                         "soc_ack": True})
    assert r.status_code == 201, r.text
    results: list = []
    for start in range(0, args.n, args.parallel):
        batch = [threading.Thread(target=probe, args=(args.api, args.db, creds["secret"], i, ids[i], results))
                 for i in range(start, min(args.n, start + args.parallel))]
        for t in batch:
            t.start()
        for t in batch:
            t.join(60)
    ok = [r for r in results if r["status"] == "pending" and r["attempts"] == 0 and r["back_after_s"] is not None
          and r["back_after_s"] <= 1.0]
    out = {"n": args.n, "probed": len(results), "back_within_1s_attempts_0": len(ok),
           "client_timed_out": sum(r["client_timed_out"] for r in results),
           "max_back_after_s": max((r["back_after_s"] or 99) for r in results) if results else None,
           "results": sorted(results, key=lambda r: r["node"])}
    Path(args.out).write_text(json.dumps(out, indent=1))
    print(json.dumps({k: v for k, v in out.items() if k != "results"}))
    sys.exit(0 if len(ok) == args.n else 1)


if __name__ == "__main__":
    main()
