"""Evaluate one F1.1 bench scenario against the devil's-advocate thresholds (f1-1/DEVILS-ADVOCATE.md section 5).

    python bench/f1_node_api/report.py --name E2a --dir <workdir>/E2a > gates.json

Reads sim.json, server.log, pg.log, db.json and reaper.log from ``--dir``.  Every gate is listed with its value and
threshold; ``valid`` is the validity gates (V1-V8), ``pass`` the scenario's thresholds.  A run that is not valid is
re-run once and never quoted (DA 5.1).
"""
from __future__ import annotations

import argparse
import json
import math
import re
from pathlib import Path

STATS_RE = re.compile(r"cbom sources cbom node stats (.*)$")
FIELD_RE = re.compile(r"(\w+)=(\S+)")


def load(path: Path, default=None):
    try:
        return json.loads(path.read_text())
    except (OSError, ValueError):
        return default


def server_facts(log: str, since: float, workers: int) -> dict:
    stats, sums, peaks = [], {}, {}
    for line in log.splitlines():
        m = STATS_RE.search(line)
        if not m:
            continue
        fields = dict(FIELD_RE.findall(m.group(1)))
        if float(fields.get("at", 0)) < since:
            continue
        stats.append(fields)
        for key in ("claims_committed", "results_committed", "undelivered", "shed_429", "limiter_miss",
                    "limiter_lookups", "pool_checkouts", "requests", "dispatch_granted", "dispatch_taken",
                    "dispatch_returned", "dispatch_denied", "dispatch_204_after_grant"):
            if key in fields and fields[key].lstrip("-").isdigit():
                sums[key] = sums.get(key, 0) + int(fields[key])
        for key in ("inflight_max", "tp_waiting_max", "pool_out_max", "pool_overflow_max", "loop_lag_max_ms"):
            if key in fields and fields[key].isdigit():
                peaks[key] = max(peaks.get(key, 0), int(fields[key]))
    count = lambda pattern: len(re.findall(pattern, log))  # noqa: E731
    return {
        "stats_lines": len(stats), "sums": sums, "peaks": peaks,
        "worker_timeouts": count(r"WORKER TIMEOUT"), "worker_boots": count(r"Booting worker"),
        "tracebacks": count(r"Traceback"), "undelivered_lines": count(r"node response undelivered"),
        "released_undelivered": count(r"job released .*reason=undelivered"),
        "released_not_reported": count(r"job released .*reason=not_reported"),
        "released_lease_expired": count(r"job released .*reason=lease_expired"),
        "released_any": count(r"cbom sources job released "),
        "slow_lines": count(r"node request slow"), "failed_lines": count(r" FAILED"),
        "deadlocks": count(r"[Dd]eadlock"), "claimed_lines": count(r"cbom sources job claimed "),
    }


def pg_facts(log: str) -> dict:
    lines = log.splitlines()
    waits_run = waits_team = waits = 0
    for i, line in enumerate(lines):
        if "still waiting for" in line:
            waits += 1
            near = " ".join(lines[i:i + 4])
            waits_run += "cbomcollectionrun" in near
            waits_team += bool(re.search(r'relation "team"|UPDATE team\b', near))
    return {"lock_waits": waits, "lock_waits_run": waits_run, "lock_waits_team": waits_team,
            "deadlocks": sum("deadlock detected" in line for line in lines)}


def gate(out: list, name: str, value, ok: bool | None, threshold: str) -> None:
    out.append({"gate": name, "value": value, "threshold": threshold, "pass": ok})


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--name", required=True)
    ap.add_argument("--dir", required=True)
    ap.add_argument("--rate", type=float, default=None, help="deployment claims/s (default 25 x workers)")
    ap.add_argument("--workers", type=int, default=3)
    ap.add_argument("--ideal-s", type=float, default=None)
    args = ap.parse_args()
    d = Path(args.dir)
    sim = load(d / "sim.json", {}) or {}
    db = load(d / "db.json", {}) or {}
    log = (d / "server.log").read_text(errors="replace") if (d / "server.log").exists() else ""
    pg = pg_facts((d / "pg.log").read_text(errors="replace") if (d / "pg.log").exists() else "")
    srv = server_facts(log, float(sim.get("wall_measure_start") or 0), args.workers)
    name = args.name
    cfg = sim.get("config") or {}
    rate = args.rate or 25.0 * args.workers
    lat = sim.get("latency") or {}
    worst = sim.get("worst_10s_window") or {}
    run = sim.get("run") or {}
    runs = run.get("runs") or ([run] if run else [])
    db_runs = {r["id"]: r for r in db.get("runs") or []}
    gates: list = []

    # ---- validity (V1-V8)
    valid = list(sim.get("invalid_because") or [])
    v = sim.get("validity") or {}
    if srv["worker_timeouts"]:
        valid.append("V3 WORKER TIMEOUT in the server log")
    if not name.startswith("E7") and srv["worker_boots"] > args.workers:
        valid.append(f"V3 {srv['worker_boots'] - args.workers} worker re-spawn(s)")
    if not name.startswith("E7"):
        if srv["sums"].get("undelivered", 0):
            valid.append("V4 server undelivered responses > 0")
        committed = srv["sums"].get("claims_committed")
        received = (sim.get("claims") or {}).get("received")
        if committed is not None and received is not None and abs(committed - received) > max(2, 0.001 * received):
            valid.append(f"V4 server-committed claims {committed} != client-received {received}")
    for f in ("sim.json", "server.log", "pg.log", "db.json"):
        if not (d / f).exists():
            valid.append(f"V7 artefact missing: {f}")

    hb = lat.get("heartbeat") or {}
    hb_worst = (worst.get("heartbeat") or {}).get("p99")
    errors = sim.get("attempt_errors")
    stm = sim.get("db") or {}

    def overhead(r: dict) -> float | None:
        if r.get("done_s") is None:
            return None
        return round(r["done_s"] + (r.get("create_ms") or 0) / 1000.0, 1)

    def money(r: dict) -> tuple[bool, dict]:
        f = db_runs.get(r.get("run_id"))
        team_ok = all(t.get("within_tolerance") for t in (db.get("teams") or {}).values())
        return bool(f and f.get("money_exact") and team_ok), {"run": f and {k: f[k] for k in (
            "charged_c", "refunded_c", "due_c", "refunded_jobs_c", "unsettled_due_jobs")}, "teams": db.get("teams")}

    if name.startswith("E1") or name.startswith("E9"):
        gate(gates, "heartbeat p99 (ms)", hb.get("p99"), hb.get("p99") is not None and hb["p99"] < 300, "< 300")
        gate(gates, "heartbeat p99 worst 10 s window (ms)", hb_worst, hb_worst is not None and hb_worst < 300, "< 300")
        gate(gates, "attempt errors", errors, errors == 0, "0")
        gate(gates, "nonce INSERTs", stm.get("nonce_inserts"), stm.get("nonce_inserts") == 0, "0")
        gate(gates, "nodes silent > 120 s", db.get("nodes_silent_over_120s"), db.get("nodes_silent_over_120s") == 0, "0")
        hbs = hb.get("n") or 0
        sel = stm.get("limiter_token_selects")
        gate(gates, "limiter token SELECTs / heartbeats", None if sel is None or not hbs else round(sel / hbs, 4),
             sel is not None and hbs and sel / hbs <= 0.02, "<= 2%")
        req, chk = srv["sums"].get("requests"), srv["sums"].get("pool_checkouts")
        gate(gates, "pool checkouts per request", round(chk / req, 3) if req else None,
             bool(req) and chk / req <= 2.05, "<= 2.05 (no E3)")
    if name.startswith(("E2", "E4a", "E5", "E6", "E7", "L5")):
        r = runs[0] if runs else {}
        o = overhead(r)
        if name.startswith(("E2", "E4a", "E6")):
            gate(gates, "scheduling overhead POST->done (s)", o, o is not None and o < 300, "< 300")
        if not name.startswith(("E6", "E7")):
            gate(gates, "attempt errors", errors, errors == 0, "0")
        if name.startswith("E6"):
            p2_err = sum(n for k, n in (sim.get("attempt_error_kinds") or {}).items() if "_p1" not in k.split(":")[0])
            gate(gates, "protocol-2 attempt errors", p2_err, p2_err == 0, "0")
        if name.startswith(("E2", "E6", "E7")):
            gate(gates, "heartbeat p99 worst 10 s window (ms)", hb_worst,
                 hb_worst is not None and hb_worst < 300, "< 300")
        if name.startswith("E2"):
            for kind in ("claim", "result"):
                p99 = (lat.get(kind) or {}).get("p99")
                gate(gates, f"{kind} p99 (ms)", p99, p99 is not None and p99 < 1000, "< 1000")
            gate(gates, "job released lines", srv["released_any"], srv["released_any"] == 0, "0")
            f = db_runs.get(r.get("run_id")) or {}
            multi = sum(n for a, n in (f.get("attempts") or {}).items() if int(a) > 1)
            gate(gates, "jobs with attempts > 1", multi, multi == 0, "0")
            gate(gates, "failures = injected failures", [f.get("failures"), f.get("injected_failures")],
                 f.get("failures") == f.get("injected_failures"), "equal")
            gate(gates, "dispatch 204 after grant / claims", srv["sums"].get("dispatch_204_after_grant"),
                 srv["sums"].get("dispatch_204_after_grant", 0) <= 0.1 * max(1, srv["sums"].get("dispatch_taken", 1)),
                 "<= 10%")
            gate(gates, "admission 429s", srv["sums"].get("shed_429", 0), srv["sums"].get("shed_429", 0) == 0, "0")
            cpu = (sim.get("cpu_pct_of_one_cpu") or {}).get("server_p95")
            gate(gates, "server CPU p95 (% of the server vCPUs)", None if cpu is None else round(cpu / args.workers, 1),
                 cpu is not None and cpu / args.workers <= 85, "<= 85%")
        if name.startswith(("E2", "E4a", "E6")):
            per10 = (sim.get("claims") or {}).get("max_per_10s")
            gate(gates, "claims per 10 s (max)", per10, per10 is not None and per10 <= 1.1 * 10 * rate,
                 f"<= {1.1 * 10 * rate:.0f}")
        if name.startswith(("E2", "E7", "L5")):
            gate(gates, "lock waits on run/team (pg log)", [pg["lock_waits_run"], pg["lock_waits_team"]],
                 pg["lock_waits_run"] == 0 and pg["lock_waits_team"] == 0, "0")
            gate(gates, "deadlocks", pg["deadlocks"] + srv["deadlocks"], pg["deadlocks"] + srv["deadlocks"] == 0, "0")
            gate(gates, "blocking FOR UPDATE on cbomcollectionrun", stm.get("run_row_for_update"),
                 stm.get("run_row_for_update") == 0, "0")
            ok, detail = money(r)
            gate(gates, "money exact", detail, ok, "run refunded = sum of due weights; team delta = sum / 100")
    if name.startswith("E4b"):
        r = runs[0] if runs else {}
        o = overhead(r)
        ideal = args.ideal_s or 300.0
        gate(gates, "done - ideal (s)", None if o is None else round(o - ideal, 1), o is not None and o - ideal <= 120,
             "<= 120")
        gate(gates, "attempt errors", errors, errors == 0, "0")
        gate(gates, "heartbeat p99 (ms)", hb.get("p99"), hb.get("p99") is not None and hb["p99"] < 300, "< 300")
    if name.startswith("E5") or name.startswith("L4"):
        p1 = sim.get("phase1_by_team") or sim.get("by_team") or {}
        a = p1.get("A") or {}
        gate(gates, "phase 1: claim requests from blocked team A", a.get("claim_requests", 0),
             a.get("claim_requests", 0) == 0, "0")
        gate(gates, "phase 1: A answers with claim > 0", a.get("heartbeats_granting", 0),
             a.get("heartbeats_granting", 0) == 0, "0 of " + str(a.get("heartbeats", 0)))
        b_run = next((x for x in runs if x.get("team") == 2), None)
        b_o = overhead(b_run) if b_run else None
        limit = 300 if name.startswith("E5") else None
        gate(gates, "capable node completes every X job (s)", b_o, b_o is not None and (limit is None or b_o <= limit),
             f"<= {limit}" if limit else "done")
        gate(gates, "heartbeat p99 worst 10 s window (ms)", hb_worst, hb_worst is not None and hb_worst < 300, "< 300")
        gate(gates, "attempt errors", errors, errors == 0, "0")
        if name.startswith("E5"):
            a_run = next((x for x in runs if x.get("team") == 1), None)
            opened = next((e["wall"] for e in sim.get("events") or [] if e["cmd"].startswith("open window")), None)
            done_wall = (a_run["posted_wall"] + (a_run.get("create_ms") or 0) / 1000 + a_run["done_s"]) \
                if a_run and a_run.get("done_s") is not None else None
            after = None if done_wall is None or opened is None else round(done_wall - opened, 1)
            gate(gates, "phase 2: A's run done after the window opened (s)", after, after is not None and after <= 372,
                 "<= 372")
    if name.startswith("E6"):
        p1 = {k: v for k, v in lat.items() if k.endswith("_p1")}
        gate(gates, "protocol-1 latency (reported)", p1, None, "report")
        p1_err = sum(n for k, n in (sim.get("attempt_error_kinds") or {}).items() if "_p1" in k.split(":")[0])
        gate(gates, "protocol-1 attempt errors (reported)", p1_err, None, "report")
    if name.startswith("E7"):
        r = runs[0] if runs else {}
        f = db_runs.get(r.get("run_id")) or {}
        k = r.get("killed_jobs", 0)
        attempts = {int(a): n for a, n in (f.get("attempts") or {}).items()}
        gate(gates, "killed jobs re-run by others", [k, r.get("killed_jobs_finished_by_others")],
             k > 0 and r.get("killed_jobs_finished_by_others") == k, "all")
        gate(gates, "attempts: 2 for killed, 1 for all others", attempts,
             attempts.get(2, 0) == k and sum(n for a, n in attempts.items() if a > 2) == 0, f"{{2: {k}}}")
        gate(gates, "lease expiries = killed jobs", srv["released_lease_expired"], srv["released_lease_expired"] == k,
             str(k))
        by10 = {int(w): n for w, n in (sim.get("attempt_errors_by_10s") or {}).items()}
        hup = sum(by10.get(w, 0) for w in (9, 10, 11))
        gate(gates, "HUP: attempt errors t=90-120 s", hup, hup == 0, "0")
        outside = sum(n for w, n in by10.items() if not (18 <= w <= 29) and w not in (9, 10, 11))
        gate(gates, "outage: errors outside 180-300 s", outside, outside == 0, "0")
        gate(gates, "undelivered = undelivered releases", [srv["sums"].get("undelivered", 0), srv["released_undelivered"]],
             srv["sums"].get("undelivered", 0) >= srv["released_undelivered"], "releases <= undelivered")
        gate(gates, "not_reported releases", srv["released_not_reported"], srv["released_not_reported"] == 0, "0")
        o = overhead(r)
        gate(gates, "run done (s)", o, o is not None and o <= 852, "<= 852")
        gate(gates, "live nodes all heartbeating", db.get("nodes_silent_over_120s"),
             db.get("nodes_silent_over_120s") == r.get("killed_nodes"), f"silent = killed ({r.get('killed_nodes')})")
    if name.startswith(("L1", "L2")):
        r = runs[0] if runs else {}
        o = overhead(r)
        ideal = args.ideal_s
        gate(gates, "done / ideal", None if o is None or not ideal else round(o / ideal, 3),
             o is not None and ideal and o <= 1.15 * ideal, "<= 1.15")
        if name.startswith("L2"):
            per1 = (sim.get("claims") or {}).get("max_per_1s")
            gate(gates, "claims per 1 s (max)", per1, per1 is not None and per1 <= 1.1 * rate, f"<= {1.1 * rate:.0f}")
    if name.startswith("L3"):
        b_run = next((x for x in runs if x.get("team") == 2), None)
        b_o = overhead(b_run) if b_run else None
        gate(gates, "team B's 50 jobs done after queueing (s)", b_o, b_o is not None and b_o <= 150, "<= 150")
        gate(gates, "attempt errors", errors, errors == 0, "0")

    out = {"scenario": name, "valid": not valid, "invalid_because": valid, "pass": all(g["pass"] is not False for g in gates),
           "gates": gates, "validity": v, "server": srv, "pg": pg,
           "served_per_s": sim.get("served_per_s"), "cpu": sim.get("cpu_pct_of_one_cpu"),
           "latency": lat, "worst_10s_window": worst, "claims": sim.get("claims"), "by_team": sim.get("by_team")}
    print(json.dumps(out, indent=1, default=str))


if __name__ == "__main__":
    main()
