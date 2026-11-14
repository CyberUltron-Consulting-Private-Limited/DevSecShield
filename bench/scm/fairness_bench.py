"""F3 scale proof: a 1,000-repository scheduled run, with per-team fairness measured.

Three teams share one dispatcher (global cap 8; no per-team limit unless --team-cap is given):

* team A: a scheduled policy over 1,000 repositories fires at tick 0;
* team B: a manual bulk run of 50 repositories, started at tick 20;
* team C: 10 push webhooks (scan on push), arriving at tick 40.

Everything is real except Celery and the clock: the policy really fires (``policies.fire_due``), runs are really
created and charged, the real dispatcher claims and sends requests (to a fake launcher that records them), the real
``poll_tick`` closes them (a fake worker finishes each scan after a seeded 3-12 ticks with a few findings drawn from a
shared pool, so the roll-up de-duplicates across all repositories). One tick is 5 virtual seconds (the queue loop's
period). The same workload is replayed with a FIFO dispatcher (oldest request first, no team cap) as the baseline.

    PYTHONPATH=. python bench/scm/fairness_bench.py --db postgresql://user@127.0.0.1:5432/bench --out result.json
"""
from __future__ import annotations

import argparse
import datetime as dt
import json
import os
import random
import statistics
import sys
import time
from collections import Counter, defaultdict
from pathlib import Path

REPO = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO))
os.environ.setdefault("JWT_SECRET_KEY", "bench-only")
os.environ.setdefault("JWT_REFRESH_SECRET_KEY", "bench-only")
if not os.environ.get("ENCRYPTION_KEY"):
    from cryptography.fernet import Fernet

    os.environ["ENCRYPTION_KEY"] = Fernet.generate_key().decode()

from sqlalchemy import create_engine, func, insert  # noqa: E402
from sqlmodel import Session, SQLModel, select  # noqa: E402

from backend.new_models import Scan, Team, TeamMembership, User  # noqa: E402
from backend.utilities.cbom_sources.crypto import encrypt_secrets  # noqa: E402
from backend.utilities.scm import policies as P  # noqa: E402
from backend.utilities.scm import queue as Q  # noqa: E402
from backend.utilities.scm.models import (  # noqa: E402
    ScmConnection,
    ScmFinding,
    ScmRepository,
    ScmScanPolicy,
    ScmScanRequest,
)

T0 = dt.datetime(2026, 11, 12, 2, 0)
TICK = dt.timedelta(seconds=5)
POOL = [{"dependency": f"lib{i}@1.{i}.0", "title": f"Advisory {i}", "impact": ["low", "medium", "high", "critical"][i % 4],
         "cves": [f"CVE-2026-{1000 + i}"]} for i in range(40)]


def pct(values, q):
    if not values:
        return None
    values = sorted(values)
    return values[min(len(values) - 1, int(round(q / 100 * (len(values) - 1))))]


class Sim:
    """The fake Celery: a launched scan finishes ``duration`` ticks later with a few findings."""

    def __init__(self, engine, seed):
        self.engine, self.rng = engine, random.Random(seed)
        self.finish_at: dict[int, int] = {}
        self.tick = 0
        self.sent = 0

    def launcher(self, engine, scan_type, scan_id, team_id, payload):
        self.finish_at[scan_id] = self.tick + self.rng.randint(3, 12)
        self.sent += 1
        with Session(engine) as s:
            scan = s.get(Scan, scan_id)
            scan.task_id, scan.scan_status = f"sim-{scan_id}", "pending"
            s.add(scan)
            s.commit()
        return f"sim-{scan_id}"

    def status_reader(self, engine, scan):
        if self.finish_at.get(scan.id, 10**9) <= self.tick:
            rows = self.rng.sample(POOL, self.rng.randint(1, 4))
            with Session(engine) as s:
                row = s.get(Scan, scan.id)
                row.scan_status, row.scan_data = "success", {"results": rows}
                s.add(row)
                s.commit()


def token_for(_connection):
    return "ghp_bench"


def fifo_dispatch(engine, now, *, launcher, token_for, max_inflight, team_max):  # noqa: ARG001 (same signature)
    """Baseline: oldest queued request first across all teams, global cap only."""
    with Session(engine) as s:
        inflight = s.exec(select(func.count()).select_from(ScmScanRequest).where(
            ScmScanRequest.status.in_(("dispatching", "dispatched")))).one()
        ids = list(s.exec(select(ScmScanRequest.id).where(ScmScanRequest.status == "queued")
                          .order_by(ScmScanRequest.id).limit(max(0, max_inflight - inflight))).all())
    return [i for i in ids if Q._dispatch_one(engine, i, now, launcher, token_for) == "dispatched"]


def build(engine, n_a, n_b, n_c):
    SQLModel.metadata.drop_all(engine)
    SQLModel.metadata.create_all(engine)
    users, repos = {}, defaultdict(list)
    with Session(engine) as s:
        for team, size in (("A", n_a), ("B", n_b), ("C", n_c)):
            tid = {"A": 1, "B": 2, "C": 3}[team]
            s.add(Team(id=tid, name=f"team {team}", credit_balance=1e6))
            s.commit()
            u = User(email=f"{team}@bench.test", password="x", first_name=team, last_name="b", profile_photo=None,
                     default_team_id=tid)
            s.add(u)
            s.commit()
            s.add(TeamMembership(team_id=tid, user_id=u.id, role="admin"))
            users[tid] = u.id
            c = ScmConnection(team_id=tid, owner_user_id=u.id, provider="github", auth_kind="token", name=team,
                              name_lower=team.lower(), api_base="https://api.github.com", scope_kind="org",
                              scope_name=f"org{team}", secret_encrypted=encrypt_secrets({"token": "t"}),
                              secret_fields=["token"], webhook_uid=os.urandom(16).hex())
            s.add(c)
            s.commit()
            rows = [{"team_id": tid, "connection_id": c.id, "external_id": f"{team}{i}",
                     "full_name": f"org{team}/repo-{i:05d}", "name": f"repo-{i:05d}", "owner": f"org{team}",
                     "web_url": f"https://github.com/org{team}/repo-{i:05d}",
                     "clone_url": f"https://github.com/org{team}/repo-{i:05d}", "default_branch": "main",
                     "visibility": "private", "archived": False, "fork": False, "language": "Python", "topics": [],
                     "size_kb": 300 + i % 700, "in_scope": True, "scope_reason": "matched", "row_version": 1,
                     "first_seen_at": T0, "last_seen_at": T0, "last_scan_summary": {}, "manual_state": None}
                    for i in range(size)]
            s.exec(insert(ScmRepository), params=rows)
            s.commit()
            repos[tid] = list(s.exec(select(ScmRepository.id).where(ScmRepository.team_id == tid)
                                     .order_by(ScmRepository.id)).all())
        s.add(ScmScanPolicy(team_id=1, owner_user_id=users[1], name="nightly", name_lower="nightly", selector={},
                            products=["sbom_sca"], schedule={"frequency": "daily", "time_of_day": "02:00",
                                                             "timezone": "UTC"}, next_run_at=T0))
        s.add(ScmScanPolicy(team_id=3, owner_user_id=users[3], name="push", name_lower="push", selector={},
                            products=["sbom_sca"], on_push=True))
        s.commit()
    return users, repos


def simulate(engine, mode, *, n_a, n_b, n_c, cap, team_cap, seed, max_ticks):
    users, repos = build(engine, n_a, n_b, n_c)
    sim = Sim(engine, seed)
    dispatch = Q.dispatch_tick if mode == "fair" else fifo_dispatch
    tick_ms, inflight_trace = [], []
    fire_s = None
    for tick in range(max_ticks):
        sim.tick = tick
        now = T0 + tick * TICK
        t0 = time.perf_counter()
        fired = P.fire_due(engine, now)
        if fired and fire_s is None:
            fire_s = round(time.perf_counter() - t0, 3)
        if tick == 20:
            with Session(engine) as s:
                est = Q.estimate(s, 2, repo_ids=repos[2], products=["sbom_sca"])
            Q.create_run(engine, 2, users[2], trigger="manual", repo_ids=repos[2], products=["sbom_sca"],
                         expected_credits=est["credits"], client_request_id="bench-b", now=now)
        if tick == 40:
            with Session(engine) as s:
                for rid in repos[3]:
                    Q.enqueue_push(s, s.get(ScmRepository, rid), products=["sbom_sca"], branch="main",
                                   commit_sha=f"{rid:040x}", owner_user_id=users[3], now=now)
                s.commit()
        t1 = time.perf_counter()
        Q.poll_tick(engine, now, status_reader=sim.status_reader)
        dispatch(engine, now, launcher=sim.launcher, token_for=token_for, max_inflight=cap, team_max=team_cap)
        tick_ms.append((time.perf_counter() - t1) * 1000)
        with Session(engine) as s:
            per_team = Counter(dict(s.exec(select(ScmScanRequest.team_id, func.count()).where(
                ScmScanRequest.status.in_(("dispatching", "dispatched"))).group_by(ScmScanRequest.team_id)).all()))
            waiting = set(s.exec(select(ScmScanRequest.team_id).where(ScmScanRequest.status == "queued")
                                 .group_by(ScmScanRequest.team_id)).all())
            open_left = s.exec(select(func.count()).select_from(ScmScanRequest).where(
                ScmScanRequest.status.in_(Q.ACTIVE))).one()
        inflight_trace.append((tick, dict(per_team), waiting))
        if tick > 40 and open_left == 0:
            break
    with Session(engine) as s:
        reqs = s.exec(select(ScmScanRequest)).all()
        findings = s.exec(select(func.count()).select_from(ScmFinding)).one()
        occurrences = s.exec(select(func.sum(ScmFinding.occurrence_count))).one()
    names = {1: "A (1,000 scheduled)", 2: "B (50 manual)", 3: "C (10 push)"}
    teams = {}
    for tid in (1, 2, 3):
        mine = [r for r in reqs if r.team_id == tid]
        waits = [(r.dispatched_at - r.enqueued_at).total_seconds() / TICK.total_seconds() for r in mine if r.dispatched_at]
        ends = [(r.finished_at - T0).total_seconds() / TICK.total_seconds() for r in mine if r.finished_at]
        arrival = {1: 0, 2: 20, 3: 40}[tid]
        firsts = [(r.dispatched_at - T0).total_seconds() / TICK.total_seconds() for r in mine if r.dispatched_at]
        teams[names[tid]] = {"scans": len(mine), "done": sum(1 for r in mine if r.status == "done"),
                             "first_slot_after_ticks": (min(firsts) - arrival) if firsts else None,
                             "wait_ticks_p50": pct(waits, 50), "wait_ticks_p95": pct(waits, 95),
                             "wait_ticks_max": max(waits) if waits else None,
                             "last_finished_tick": max(ends) if ends else None}
    # fairness while two or more teams were waiting: Jain's index over the in-flight counts of the waiting teams
    jain, shares = [], defaultdict(list)
    for _tick, per_team, waiting in inflight_trace:
        backlogged = sorted(waiting)
        if len(backlogged) < 2:
            continue
        xs = [per_team.get(t, 0) for t in backlogged]
        if sum(xs):
            jain.append(sum(xs) ** 2 / (len(xs) * sum(x * x for x in xs)))
            for t in backlogged:
                shares[names[t]].append(per_team.get(t, 0) / sum(xs))
    max_total = max(sum(p.values()) for _t, p, _w in inflight_trace)
    max_team = max(max(p.values(), default=0) for _t, p, _w in inflight_trace)
    return {"mode": mode, "ticks": len(inflight_trace), "virtual_minutes": round(len(inflight_trace) * 5 / 60, 1),
            "schedule_fire_s": fire_s, "dispatch_tick_ms": {"p50": round(pct(tick_ms, 50), 1),
                                                            "p95": round(pct(tick_ms, 95), 1),
                                                            "max": round(max(tick_ms), 1)},
            "max_inflight_total": max_total, "max_inflight_one_team": max_team,
            "jain_fairness_while_contended": round(statistics.mean(jain), 3) if jain else None,
            "mean_slot_share_while_contended": {k: round(statistics.mean(v), 3) for k, v in shares.items()},
            "teams": teams, "rollup": {"findings": findings, "occurrences": int(occurrences or 0)}}


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--db", required=True, help="SQLAlchemy URL of a throwaway database (tables are dropped)")
    ap.add_argument("--repos", type=int, default=1000)
    ap.add_argument("--cap", type=int, default=8)
    ap.add_argument("--team-cap", type=int, default=0, help="optional per-team limit (0: none, the default)")
    ap.add_argument("--seed", type=int, default=11)
    ap.add_argument("--max-ticks", type=int, default=3000)
    ap.add_argument("--out", default="")
    args = ap.parse_args()
    engine = create_engine(args.db)
    started = time.monotonic()
    fair = simulate(engine, "fair", n_a=args.repos, n_b=50, n_c=10, cap=args.cap, team_cap=args.team_cap,
                    seed=args.seed, max_ticks=args.max_ticks)
    fifo = simulate(engine, "fifo", n_a=args.repos, n_b=50, n_c=10, cap=args.cap, team_cap=0,
                    seed=args.seed, max_ticks=args.max_ticks)
    SQLModel.metadata.drop_all(engine)
    out = {"db": engine.dialect.name, "cap": args.cap, "team_cap": args.team_cap, "fair": fair, "fifo_baseline": fifo,
           "wall_s": round(time.monotonic() - started, 1)}
    b, c = fair["teams"]["B (50 manual)"], fair["teams"]["C (10 push)"]
    a = fair["teams"]["A (1,000 scheduled)"]
    out["pass"] = (a["done"] == args.repos and b["done"] == 50 and c["done"] == 10
                   and fair["max_inflight_total"] <= args.cap
                   and (args.team_cap <= 0 or fair["max_inflight_one_team"] <= args.team_cap)
                   and b["wait_ticks_max"] < fifo["teams"]["B (50 manual)"]["wait_ticks_max"]
                   and c["wait_ticks_max"] < fifo["teams"]["C (10 push)"]["wait_ticks_max"])
    text = json.dumps(out, indent=2, default=str)
    print(text)
    if args.out:
        Path(args.out).write_text(text)
    return 0 if out["pass"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
