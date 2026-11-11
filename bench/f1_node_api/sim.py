"""Asyncio simulator of a scan-node fleet against the real node API (heartbeat, claim, complete), with latency, error,
CPU and database-QPS measurement.

    python bench/f1_node_api/sim.py --api http://127.0.0.1:18080 --creds creds.json --db postgresql://... \\
        --protocol 2 --nodes 10000 --duration 660 --warmup 60 --out result.json            # steady fleet
    ... --run --run-timeout 900 --kill-frac 0.05 --work-s 0                                  # plus a run of every source

Protocols (what each simulated node does, mirroring scan_node/zs_scan_node/agent.py):
  1  scan node 1.0 (dev today): heartbeat at the server's ``heartbeat_interval_s`` clamped to [5, 60] s, a claim
     every 5 s whatever happens, random request nonces.
  2  this branch's node: heartbeat at the server's interval (clamped to [5, 600] s), a claim only when the heartbeat
     answer says ``claim: true`` (then claims until 204), sequence nonces (``s2_<seq>``). Against a server that does
     not send ``claim`` it polls like protocol 1.
``--hb-override S`` ignores the server's interval (to offer a protocol-1 server the 60 s target profile).

Measured: client-side latency per call type (p50/p95/p99/max), errors (any non-2xx other than claim's 204, timeouts,
connection errors), achieved request rate, event-loop lag of the simulator itself (if large, latencies are inflated
by the simulator, not the server), CPU of the server processes (``--server-pids``) and of the PostgreSQL container
(cgroup ``cpu.stat``), and PostgreSQL work: transactions/s (pg_stat_database) and statements/s by statement
(pg_stat_statements, reset at the start of the measured window). Run mode: queue a run of every source through
``POST /1/cbom/sources/runs`` after the warm-up and record the time until the run is finished ("scheduling
overhead" when ``--work-s 0``), plus re-queues after lease expiry when ``--kill-frac`` nodes die holding a job.
"""
from __future__ import annotations

import argparse
import asyncio
import json
import os
import random
import socket
import sys
import threading
import time
import uuid
from collections import Counter, defaultdict
from pathlib import Path

import aiohttp

sys.path.insert(0, str(Path(__file__).resolve().parent))
from common import Signer, dumps, load_creds, node_key, node_token, percentile  # noqa: E402

CAPS_COLLECTORS = ["linux_servers", "windows_servers", "active_directory", "kubernetes", "database", "network_range",
                   "ca_connector", "key_manager", "appliance", "container_images"]


class Stats:
    def __init__(self) -> None:
        self.lat: dict[str, list[float]] = defaultdict(list)
        self.codes: Counter = Counter()
        self.errors: Counter = Counter()
        self.samples: list[str] = []
        self.measuring = False
        self.t_start = 0.0
        self.count_all = 0

    def record(self, kind: str, ms: float, code: int | str, ok: bool) -> None:
        self.count_all += 1
        if not self.measuring:
            return
        self.lat[kind].append(ms)
        self.codes[f"{kind}:{code}"] += 1
        if not ok:
            self.errors[f"{kind}:{code}"] += 1

    def summary(self) -> dict:
        out: dict = {}
        for kind, values in sorted(self.lat.items()):
            v = sorted(values)
            out[kind] = {"n": len(v), "p50_ms": _r(percentile(v, 50)), "p95_ms": _r(percentile(v, 95)),
                         "p99_ms": _r(percentile(v, 99)), "max_ms": _r(v[-1] if v else None)}
        every = sorted(x for values in self.lat.values() for x in values)
        out["all"] = {"n": len(every), "p50_ms": _r(percentile(every, 50)), "p95_ms": _r(percentile(every, 95)),
                      "p99_ms": _r(percentile(every, 99)), "max_ms": _r(every[-1] if every else None)}
        return out


def _r(v):
    return None if v is None else round(v, 1)


class Node:
    def __init__(self, sim: "Sim", i: int) -> None:
        self.sim, self.i = sim, i
        self.token = node_token(sim.secret, i)
        self.signer = Signer(node_key(sim.secret, i), sim.args.protocol)
        self.interval = 30.0 if sim.args.protocol == 1 else 60.0
        self.running: dict[int, str] = {}
        self.claim_event = asyncio.Event()
        self.dead = False
        self.saw_claim_key = False

    async def call(self, kind: str, path: str, body) -> tuple[int, dict | None]:
        raw = b"" if body is None else dumps(body)
        headers = {"X-ZS-Node-Token": self.token, "Content-Type": "application/json",
                   "User-Agent": "zs-scan-node/bench"}
        headers.update(self.signer.headers("POST", path, raw))
        t = time.perf_counter()
        try:
            async with self.sim.http.post(self.sim.api + path, data=raw, headers=headers) as r:
                data = None
                if r.status != 204:
                    try:
                        data = await r.json(content_type=None)
                    except Exception:
                        data = None
                ms = (time.perf_counter() - t) * 1000
                ok = 200 <= r.status < 300
                code = r.status
        except asyncio.TimeoutError:
            ms, ok, code, data = (time.perf_counter() - t) * 1000, False, "timeout", None
        except aiohttp.ClientError as exc:
            ms, ok, code, data = (time.perf_counter() - t) * 1000, False, type(exc).__name__, None
        self.sim.stats.record(kind, ms, code, ok)
        if not ok and len(self.sim.stats.samples) < 30 and self.sim.stats.measuring:
            self.sim.stats.samples.append(f"{kind} node={self.i} {code} {json.dumps(data)[:200] if data else ''}")
        return (code if isinstance(code, int) else 0), data

    def hb_body(self) -> dict:
        caps = {"collectors": CAPS_COLLECTORS, "openssl": True, "ipv6": False, "max_jobs": 2, "vault": False,
                "mode": "agentless"}
        if self.sim.args.protocol >= 2:
            caps["protocol"] = 2
        return {"hostname": f"sim-{self.i}", "version": "bench", "source_ips": ["10.99.0.1"], "capabilities": caps,
                "clock": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
                "running": [{"job_id": j, "lease_id": lease} for j, lease in self.running.items()]}

    async def heartbeat_loop(self) -> None:
        await asyncio.sleep(random.uniform(0, self.sim.spread))
        while not self.sim.stopping and not self.dead:
            code, data = await self.call("heartbeat", "/cbom/node/heartbeat", self.hb_body())
            if code == 200 and isinstance(data, dict):
                hb = self.sim.args.hb_override or data.get("heartbeat_interval_s") or self.interval
                lo, hi = (5, 60) if self.sim.args.protocol == 1 else (5, 600)
                self.interval = max(lo, min(float(hb), hi))
                if "claim" in data:
                    self.saw_claim_key = True
                    if data.get("claim"):
                        self.claim_event.set()
            await self.sim.sleep(self.interval)

    async def claim_loop(self) -> None:
        """Protocol 1: claim every 5 s. Protocol 2: claim when the heartbeat said so (or poll if the server never
        sends the key), then drain."""
        await asyncio.sleep(random.uniform(0, 5))
        while not self.sim.stopping and not self.dead:
            if self.sim.args.protocol >= 2 and (self.saw_claim_key or not self.sim.args.p2_poll_fallback):
                try:
                    await asyncio.wait_for(self.claim_event.wait(), timeout=5)
                except asyncio.TimeoutError:
                    continue
                self.claim_event.clear()
            elif not self.sim.args.claims:
                await self.sim.sleep(5)
                continue
            while not self.sim.stopping and not self.dead:
                code, data = await self.call("claim", "/cbom/node/jobs/claim", {"mode": "agentless"})
                if code != 200 or not data:
                    break
                await self.run_job(data)
            if self.sim.args.protocol == 1 or not self.saw_claim_key:
                await self.sim.sleep(5)

    async def run_job(self, payload: dict) -> None:
        job = payload.get("job") or {}
        job_id, lease = int(job["id"]), str(job["lease_id"])
        self.sim.claimed.add(job_id)
        if self.sim.kill_set and self.i in self.sim.kill_set and not self.dead:
            self.dead = True  # the node dies holding the job: no result, no more heartbeats
            self.sim.killed_jobs.append(job_id)
            return
        self.running[job_id] = lease
        if self.sim.args.work_s:
            await asyncio.sleep(self.sim.args.work_s)
        body = {"lease_id": lease, "status": "success",
                "result": {"counts": {"ok": 1, "failed": 0, "skipped": 0}, "asset_count": 0, "node_version": "bench"},
                "error": None}
        code, _ = await self.call("result", f"/cbom/node/jobs/{job_id}/result", body)
        self.running.pop(job_id, None)
        if code == 200:
            self.sim.finished.add(job_id)


class Sampler(threading.Thread):
    """Every 5 s: PostgreSQL transactions and the CPU of the server processes and the database container."""

    def __init__(self, db: str | None, pids: list[int], pg_container: str | None) -> None:
        super().__init__(daemon=True)
        self.db, self.pids, self.container = db, pids, pg_container
        self.stop = threading.Event()
        self.points: list[dict] = []
        self.cg = _cgroup_cpu_path(pg_container) if pg_container else None

    def _xacts(self, cur) -> int:
        cur.execute("SELECT xact_commit + xact_rollback FROM pg_stat_database WHERE datname = current_database()")
        return int(cur.fetchone()[0])

    def run(self) -> None:
        import psycopg2

        conn = psycopg2.connect(self.db) if self.db else None
        if conn:
            conn.autocommit = True
        last = None
        while not self.stop.is_set():
            point = {"t": time.time(), "server_cpu_s": _proc_cpu(self.pids), "pg_cpu_s": _cg_cpu(self.cg),
                     "host_cpu": _host_cpu()}
            if conn:
                with conn.cursor() as cur:
                    point["xacts"] = self._xacts(cur)
            if last is not None:
                self.points.append({"t": point["t"], **_rates(last, point)})
            last = point
            self.stop.wait(5)
        if conn:
            conn.close()


def _rates(a: dict, b: dict) -> dict:
    dt = b["t"] - a["t"]
    out = {}
    if a.get("server_cpu_s") is not None and b.get("server_cpu_s") is not None:
        out["server_cpu_pct"] = round(100 * (b["server_cpu_s"] - a["server_cpu_s"]) / dt, 1)
    if a.get("pg_cpu_s") is not None and b.get("pg_cpu_s") is not None:
        out["pg_cpu_pct"] = round(100 * (b["pg_cpu_s"] - a["pg_cpu_s"]) / dt, 1)
    if a.get("xacts") is not None:
        out["db_tps"] = round((b["xacts"] - a["xacts"]) / dt, 1)
    if a.get("host_cpu") and b.get("host_cpu"):
        busy = (b["host_cpu"][0] - a["host_cpu"][0])
        total = (b["host_cpu"][1] - a["host_cpu"][1]) or 1
        out["host_cpu_pct"] = round(100 * busy / total * os.cpu_count(), 1)  # of one CPU, like the others
    return out


def _proc_cpu(pids: list[int]) -> float | None:
    if not pids:
        return None
    tck = os.sysconf("SC_CLK_TCK")
    total = 0.0
    for pid in pids:
        try:
            fields = Path(f"/proc/{pid}/stat").read_text().rsplit(")", 1)[1].split()
            total += (int(fields[11]) + int(fields[12])) / tck  # utime + stime
        except (OSError, IndexError, ValueError):
            continue
    return total


def _host_cpu() -> tuple[int, int] | None:
    try:
        parts = [int(x) for x in Path("/proc/stat").read_text().splitlines()[0].split()[1:]]
    except OSError:
        return None
    idle = parts[3] + (parts[4] if len(parts) > 4 else 0)
    return sum(parts) - idle, sum(parts)


def _cgroup_cpu_path(container: str) -> Path | None:
    import subprocess

    try:
        cid = subprocess.run(["docker", "inspect", "-f", "{{.Id}}", container], capture_output=True, text=True,
                             check=True).stdout.strip()
    except Exception:
        return None
    for cand in (f"/sys/fs/cgroup/system.slice/docker-{cid}.scope/cpu.stat", f"/sys/fs/cgroup/docker/{cid}/cpu.stat",
                 f"/sys/fs/cgroup/cpuacct/docker/{cid}/cpuacct.usage"):  # cgroup v2, v2 (cgroupfs), v1
        if Path(cand).exists():
            return Path(cand)
    return None


def _cg_cpu(path: Path | None) -> float | None:
    """CPU seconds the container used: cgroup v2 ``cpu.stat`` usage_usec, or cgroup v1 ``cpuacct.usage`` (ns)."""
    if path is None:
        return None
    try:
        text = path.read_text()
    except OSError:
        return None
    if path.name == "cpuacct.usage":
        return int(text.strip()) / 1e9
    for line in text.splitlines():
        if line.startswith("usage_usec"):
            return int(line.split()[1]) / 1e6
    return None


def pg_statements(db: str, reset: bool = False, top: int = 20) -> dict:
    import psycopg2

    conn = psycopg2.connect(db)
    conn.autocommit = True
    out: dict = {}
    with conn.cursor() as cur:
        try:
            if reset:
                cur.execute("SELECT pg_stat_statements_reset()")
                return {}
            cur.execute("SELECT coalesce(sum(calls),0), coalesce(sum(total_exec_time),0) FROM pg_stat_statements "
                        "WHERE dbid = (SELECT oid FROM pg_database WHERE datname = current_database())")
            calls, ms = cur.fetchone()
            out["calls"], out["exec_ms"] = int(calls), round(float(ms), 1)
            cur.execute("SELECT calls, round(total_exec_time::numeric,1), left(regexp_replace(query, '\\s+', ' ', 'g'),"
                        " 140) FROM pg_stat_statements WHERE dbid = (SELECT oid FROM pg_database WHERE datname = "
                        "current_database()) ORDER BY calls DESC LIMIT %s", (top,))
            out["top"] = [{"calls": int(c), "ms": float(t), "query": q} for c, t, q in cur.fetchall()]
            cur.execute("SELECT coalesce(sum(calls),0) FROM pg_stat_statements WHERE query ILIKE 'INSERT INTO "
                        "cbomnodenonce%%'")
            out["nonce_inserts"] = int(cur.fetchone()[0])
            cur.execute("SELECT count(*) FROM cbomnodenonce")
            out["nonce_rows"] = int(cur.fetchone()[0])
        except psycopg2.Error as exc:
            out["error"] = str(exc).splitlines()[0]
    conn.close()
    return out


class Sim:
    def __init__(self, args) -> None:
        self.args = args
        creds = load_creds(args.creds)
        self.secret = creds["secret"]
        self.n = min(args.nodes or creds["nodes"], creds["nodes"])
        self.api = args.api.rstrip("/")
        self.stats = Stats()
        self.stopping = False
        self.spread = args.spread if args.spread is not None else (5.0 if args.protocol == 1 and not args.hb_override
                                                                     else float(args.hb_override or 60))
        self.claimed: set[int] = set()
        self.finished: set[int] = set()
        self.killed_jobs: list[int] = []
        rnd = random.Random(7)
        self.kill_set = set(rnd.sample(range(self.n), int(self.n * args.kill_frac))) if args.kill_frac else set()
        self.lag: list[float] = []
        self.user_token = None
        if args.run:  # imported and signed before the event loop starts: an import inside it stalls every node
            from backend.utilities.auth.auth_utils import create_access_token  # the code under test's JWT format

            self.user_token = create_access_token("bench@f1.test", expires_delta=__import__("datetime").timedelta(hours=3))

    async def sleep(self, seconds: float) -> None:
        await asyncio.sleep(seconds)

    async def lag_monitor(self) -> None:
        while not self.stopping:
            t = time.perf_counter()
            await asyncio.sleep(0.1)
            if self.stats.measuring:
                self.lag.append((time.perf_counter() - t - 0.1) * 1000)

    async def start_run(self) -> dict:
        token = self.user_token
        body = {"include": {"servers": True, "kubernetes": False, "databases": False, "cloud": False,
                            "network": False}, "client_request_id": "bench-" + uuid.uuid4().hex[:16]}
        t = time.perf_counter()
        async with self.http.post(self.api + "/1/cbom/sources/runs", json=body,
                                  headers={"Authorization": f"Bearer {token}"},
                                  timeout=aiohttp.ClientTimeout(total=600)) as r:
            data = await r.json(content_type=None)
            ms = (time.perf_counter() - t) * 1000
        if r.status not in (200, 201):
            raise SystemExit(f"run not created: HTTP {r.status} {json.dumps(data)[:300]}")
        return {"run_id": data["run"]["id"], "create_ms": round(ms, 1)}

    async def watch_run(self, run_id: int, t0: float) -> dict:
        import psycopg2

        conn = psycopg2.connect(self.args.db)
        conn.autocommit = True
        progress = []
        status = None
        jobs_done_s = None  # every job ended (whatever the run row says: dev can leave it "running", P6)
        deadline = time.monotonic() + self.args.run_timeout
        try:
            while time.monotonic() < deadline:
                with conn.cursor() as cur:
                    cur.execute("SELECT status FROM cbomcollectionrun WHERE id = %s", (run_id,))
                    status = cur.fetchone()[0]
                    cur.execute("SELECT status, count(*) FROM cbomcollectionjob WHERE run_id = %s GROUP BY status",
                                (run_id,))
                    counts = dict(cur.fetchall())
                now = round(time.monotonic() - t0, 1)
                progress.append({"t": now, "run": status, **counts})
                if jobs_done_s is None and counts and not (counts.get("pending") or counts.get("claimed")):
                    jobs_done_s = now
                if status in ("done", "partial", "failed", "cancelled"):
                    break
                if jobs_done_s is not None and now - jobs_done_s > 60:
                    break  # every job ended a minute ago and the run is still open: it is stuck
                await asyncio.sleep(1)
        finally:
            conn.close()
        final = status in ("done", "partial", "failed", "cancelled")
        return {"status": status, "seconds_to_finish": round(time.monotonic() - t0, 1) if final else None,
                "jobs_done_s": jobs_done_s, "run_stuck_open": bool(jobs_done_s is not None and not final),
                "progress": progress[-1:], "timeline": progress[:: max(1, len(progress) // 40)]}

    async def main(self) -> dict:
        timeout = aiohttp.ClientTimeout(total=30)
        conn = aiohttp.TCPConnector(limit=self.args.conns, keepalive_timeout=4)
        sampler = Sampler(self.args.db, self.args.server_pids, self.args.pg_container)
        self.http = aiohttp.ClientSession(connector=conn, timeout=timeout)
        nodes = [Node(self, i) for i in range(self.n)]
        tasks = [asyncio.create_task(n.heartbeat_loop()) for n in nodes]
        tasks += [asyncio.create_task(n.claim_loop()) for n in nodes]
        tasks.append(asyncio.create_task(self.lag_monitor()))
        t_begin = time.monotonic()
        await asyncio.sleep(self.args.warmup)
        if self.args.db:
            pg_statements(self.args.db, reset=True)
        sampler.start()
        self.stats.measuring = True
        t_measure = time.monotonic()
        count0 = self.stats.count_all
        run_info: dict = {}
        if self.args.run:
            info = await self.start_run()
            run_info.update(info)
            run_info.update(await self.watch_run(info["run_id"], t_measure))
            run_info["claimed_jobs"] = len(self.claimed)
            run_info["finished_by_sim"] = len(self.finished)
            run_info["killed_nodes"] = len(self.kill_set)
            run_info["jobs_held_by_killed_nodes"] = len(self.killed_jobs)
            run_info["killed_jobs_finished_by_others"] = sum(1 for j in self.killed_jobs if j in self.finished)
        remaining = self.args.duration - (time.monotonic() - t_measure)
        if remaining > 0:
            await asyncio.sleep(remaining)
        measured_s = time.monotonic() - t_measure
        self.stats.measuring = False
        requests = self.stats.count_all - count0
        statements = pg_statements(self.args.db) if self.args.db else {}
        sampler.stop.set()
        sampler.join(timeout=10)
        self.stopping = True
        for t in tasks:
            t.cancel()
        await asyncio.gather(*tasks, return_exceptions=True)
        await self.http.close()
        pts = sampler.points

        def avg(key):
            vals = [p[key] for p in pts if p.get(key) is not None]
            return round(sum(vals) / len(vals), 1) if vals else None

        def peak(key):
            vals = [p[key] for p in pts if p.get(key) is not None]
            return max(vals) if vals else None

        lag = sorted(self.lag)
        summary = self.stats.summary()
        errors = sum(self.stats.errors.values())
        return {
            "config": {k: v for k, v in vars(self.args).items() if k not in ("db",)} | {"nodes": self.n,
                                                                                     "host": socket.gethostname()},
            "measured_s": round(measured_s, 1), "total_s": round(time.monotonic() - t_begin, 1),
            "requests": requests, "req_per_s": round(requests / measured_s, 1),
            "latency": summary, "errors": errors,
            "error_rate": round(errors / max(1, summary["all"]["n"]), 6), "error_kinds": dict(self.stats.errors),
            "error_samples": self.stats.samples, "codes": dict(self.stats.codes),
            "sim_loop_lag_ms": {"p50": _r(percentile(lag, 50)), "p99": _r(percentile(lag, 99)),
                                "max": _r(lag[-1] if lag else None)},
            "cpu_pct_of_one_cpu": {"server_avg": avg("server_cpu_pct"), "server_peak": peak("server_cpu_pct"),
                                   "postgres_avg": avg("pg_cpu_pct"), "postgres_peak": peak("pg_cpu_pct"),
                                   "host_avg": avg("host_cpu_pct"), "host_cpus": os.cpu_count()},
            "db": {"tps_avg": avg("db_tps"), "tps_peak": peak("db_tps"),
                   "statements_per_s": round(statements.get("calls", 0) / measured_s, 1) if statements else None,
                   **statements},
            "run": run_info,
        }


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--api", required=True)
    ap.add_argument("--creds", required=True)
    ap.add_argument("--db", default=None, help="PostgreSQL URL of the server under test (stats only)")
    ap.add_argument("--pg-container", default=None)
    ap.add_argument("--server-pids", type=lambda s: [int(x) for x in s.split(",") if x], default=[])
    ap.add_argument("--protocol", type=int, choices=(1, 2), default=2)
    ap.add_argument("--nodes", type=int, default=0)
    ap.add_argument("--duration", type=float, default=600, help="measured seconds (after the warm-up)")
    ap.add_argument("--warmup", type=float, default=60)
    ap.add_argument("--spread", type=float, default=None, help="first heartbeat spread (default: one interval)")
    ap.add_argument("--hb-override", type=float, default=None)
    ap.add_argument("--no-claims", dest="claims", action="store_false", help="protocol 1: never claim")
    ap.add_argument("--p2-poll-fallback", action="store_true",
                    help="protocol 2: poll like protocol 1 until the server has sent a claim key")
    ap.add_argument("--conns", type=int, default=256)
    ap.add_argument("--run", action="store_true")
    ap.add_argument("--run-timeout", type=float, default=900)
    ap.add_argument("--work-s", type=float, default=0.0)
    ap.add_argument("--kill-frac", type=float, default=0.0)
    ap.add_argument("--out", default=None)
    args = ap.parse_args()
    try:
        import uvloop

        uvloop.install()
    except ImportError:
        pass
    result = asyncio.run(Sim(args).main())
    text = json.dumps(result, indent=2)
    if args.out:
        Path(args.out).write_text(text)
    print(text)


if __name__ == "__main__":
    main()
