"""Database facts after a bench scenario (run status, money, job attempts), for report.py.

    PYTHONPATH=<src root> python bench/f1_node_api/facts.py --db postgresql://... > db.json

Money check (DA L5/E2a): every run's ``credits_refunded_c`` must equal the sum of the weights of its refund-due jobs,
every refund-due job must be settled, and each team's balance must equal its start (1e9, seed.py) minus what its
runs were charged plus what they refunded.
"""
from __future__ import annotations

import argparse
import json

import psycopg2

START_BALANCE = 1e9


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--db", required=True)
    args = ap.parse_args()
    conn = psycopg2.connect(args.db)
    conn.autocommit = True
    out: dict = {"runs": [], "teams": {}}
    with conn.cursor() as cur:
        cur.execute("SELECT id, team_id, status, credits_charged_c, credits_refunded_c, created_at, finished_at "
                    "FROM cbomcollectionrun ORDER BY id")
        for rid, team, status, charged, refunded, created, finished in cur.fetchall():
            cur.execute("SELECT status, count(*) FROM cbomcollectionjob WHERE run_id = %s GROUP BY status", (rid,))
            statuses = dict(cur.fetchall())
            cur.execute("SELECT attempts, count(*) FROM cbomcollectionjob WHERE run_id = %s GROUP BY attempts", (rid,))
            attempts = {int(a): int(n) for a, n in cur.fetchall()}
            cur.execute("SELECT count(*) FILTER (WHERE status = 'failure'), count(*) FILTER (WHERE (id::bigint * "
                        "2654435761) %% 100 BETWEEN 60 AND 89) FROM cbomcollectionjob WHERE run_id = %s", (rid,))
            failures, injected_failures = cur.fetchone()
            cur.execute("SELECT coalesce(sum(weight_c) FILTER (WHERE refund_due), 0), "
                        "coalesce(sum(weight_c) FILTER (WHERE refunded), 0), "
                        "count(*) FILTER (WHERE refund_due AND NOT refunded), "
                        "count(*) FILTER (WHERE refunded AND NOT refund_due), coalesce(sum(attempts), 0) "
                        "FROM cbomcollectionjob WHERE run_id = %s", (rid,))
            due_c, refunded_jobs_c, unsettled, refunded_not_due, attempts_total = cur.fetchone()
            out["runs"].append({
                "id": rid, "team": team, "status": status, "charged_c": charged, "refunded_c": refunded,
                "due_c": int(due_c), "refunded_jobs_c": int(refunded_jobs_c), "unsettled_due_jobs": int(unsettled),
                "refunded_but_not_due": int(refunded_not_due), "attempts_total": int(attempts_total),
                "statuses": statuses, "attempts": attempts, "failures": int(failures),
                "injected_failures": int(injected_failures),
                "created": created.isoformat() if created else None, "finished": finished.isoformat() if finished else None,
                "money_exact": int(due_c) == int(refunded) == int(refunded_jobs_c) and not unsettled})
        cur.execute("SELECT id, credit_balance FROM team ORDER BY id")
        for team, balance in cur.fetchall():
            cur.execute("SELECT coalesce(sum(credits_charged_c),0), coalesce(sum(credits_refunded_c),0) "
                        "FROM cbomcollectionrun WHERE team_id = %s", (team,))
            charged, refunded = cur.fetchone()
            expected = START_BALANCE - int(charged) / 100 + int(refunded) / 100
            jobs = sum(sum(r["statuses"].values()) for r in out["runs"] if r["team"] == team) or 1
            out["teams"][team] = {"balance": balance, "expected": expected, "diff": balance - expected,
                                  "within_tolerance": abs(balance - expected) <= 1e-6 * jobs + 1e-6}
        cur.execute("SELECT count(*) FROM cbomscannode WHERE last_heartbeat_at < now() AT TIME ZONE 'UTC' - "
                    "interval '120 seconds'")
        out["nodes_silent_over_120s"] = int(cur.fetchone()[0])
        cur.execute("SELECT count(*) FROM cbomnodenonce")
        out["nonce_rows"] = int(cur.fetchone()[0])
    conn.close()
    print(json.dumps(out, indent=1, default=str))


if __name__ == "__main__":
    main()
