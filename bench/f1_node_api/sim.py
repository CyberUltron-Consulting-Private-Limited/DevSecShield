"""Asyncio simulator of a scan-node fleet against the real node API, built to the validity gates of the F1.1
devil's-advocate review (f1-1/DEVILS-ADVOCATE.md section 5).

    python bench/f1_node_api/sim.py --api http://127.0.0.1:18080 --creds creds.json --db postgresql://... \\
        --nodes 10000 --duration 600 --warmup 60 --out result.json                       # steady fleet (E1)
    ... --run --work-s 0 --mix                                                            # plus a 10k-job run (E2)

What each simulated node does mirrors scan_node/zs_scan_node/agent.py (protocol 2) or scan node 1.0 (protocol 1):

* protocol 2: heartbeat at the server's ``heartbeat_interval_s`` (clamped to 5-600 s); claims only within the grant
  (``claim: n``) the last heartbeat, claim or result answer carried, at most ``max_jobs`` (2) at once, re-checking a
  full node every 2 s; a 204 ends the grant; sequence nonces.  Retries as the node: heartbeat 1, claim 1, assets and
  result 6, each re-signed, with exponential backoff (2 s doubling, capped at 60 s) and ``Retry-After`` honoured.
* protocol 1 (``--p1-frac``): heartbeat at most every 60 s, a claim every 5 s while a slot is free, random nonces.

Measurement (DA gates V1-V8):

* every attempt is traced: request id (sent as ``X-ZS-Request-Id``), node, kind, attempt, the wall clock, the FIRST
  time it queued for a client connection, when it got one, when the answer ended, the status, and the server's
  ``Server-Timing app`` (``--trace`` writes them as TSV);
* latency is measured from the intended send time (a heartbeat's schedule, or the moment a grant or a free slot let
  the node claim), per 10 s window; a timeout is an error, never a latency;
* attempt errors (any timeout, connection error, 5xx, 429, unexpected 4xx) are counted apart from operation errors
  (the node gave up after its retries);
* the simulator's own CPU and event-loop lag, the listen socket's accept queue (``ss``) and the client-minus-server
  residual per kind, so a run whose numbers the client inflated is marked invalid (``validity``);
* run mode (``--run``): queue a run through ``POST /1/cbom/sources/runs``, watch it to its end in the database, and
  report scheduling overhead (POST to ``done``) against the ideal makespan; ``--mix`` posts the DA request mix (60%
  success: 80% one batch of 50 assets, 20% one of 500; 30% failure; 10% success with every target skipped).
"""
from __future__ import annotations

import argparse
import asyncio
import json
import os
import random
import re
import resource
import socket
import subprocess
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
TIMING_RE = re.compile(r"app;dur=([0-9.]+)")
KINDS = ("heartbeat", "claim", "assets", "result", "enroll")
WINDOW_S = 10


def _r(v, nd=1):
    return None if v is None else round(v, nd)


def pct_summary(values: list[float]) -> dict:
    s = sorted(values)
    return {"n": len(s), "p50": _r(percentile(s, 50)), "p95": _r(percentile(s, 95)), "p99": _r(percentile(s, 99)),
            "max": _r(s[-1] if s else None)}


# ----------------------------------------------------------------------------- measurement
class Metrics:
    """Everything counted while ``measuring`` is set (warm-up excluded)."""

    def __init__(self) -> None:
        self.measuring = False
        self.t0 = time.monotonic()
        self.lat: dict[str, list[float]] = defaultdict(list)  # from the intended send time, successes only
        self.windows: dict[str, dict[int, list[float]]] = defaultdict(lambda: defaultdict(list))
        self.attempt_errors: Counter = Counter()
        self.op_errors: Counter = Counter()
        self.codes: Counter = Counter()
        self.residual: dict[str, list[float]] = defaultdict(list)  # client attempt time - Server-Timing app
        self.by_team: dict[str, Counter] = defaultdict(Counter)  # per team: heartbeats, grants > 0, claim requests
        self.timing_missing: Counter = Counter()
        self.claims_by_s: Counter = Counter()  # successful claims per wall second (since t0)
        self.results_ok = 0
        self.assets_ok = 0
        self.received_claims = 0
        self.attempt_errors_by_window: Counter = Counter()
        self.samples: list[str] = []

    def window(self) -> int:
        return int((time.monotonic() - self.t0) // WINDOW_S)

    def attempt(self, kind: str, status: int | None, client_ms: float, app_ms: float | None, error: str | None) -> None:
        if not self.measuring:
            return
        self.codes[f"{kind}:{status if status is not None else error}"] += 1
        if error is not None:
            self.attempt_errors[f"{kind}:{error}"] += 1
            self.attempt_errors_by_window[self.window()] += 1
            if len(self.samples) < 30:
                self.samples.append(f"{kind}:{error}")
        if status is not None:
            if app_ms is None:
                self.timing_missing[kind] += 1
            else:
                self.residual[kind].append(client_ms - app_ms)

    def op_done(self, kind: str, ms_from_intended: float) -> None:
        if self.measuring:
            self.lat[kind].append(ms_from_intended)
            self.windows[kind][self.window()].append(ms_from_intended)

    def op_failed(self, kind: str, why: str) -> None:
        if self.measuring:
            self.op_errors[f"{kind}:{why}"] += 1


class Trace:
    """aiohttp tracing: per request, the first time it queued for a connection and the time it got one (DA A2,
    cx4 O2: the old trace kept only the last queue interval and under-reported a 2 s wait as 22 ms)."""

    def __init__(self) -> None:
        self.config = aiohttp.TraceConfig()
        self.config.on_request_start.append(self._start)
        self.config.on_connection_queued_start.append(self._queued)
        self.config.on_connection_create_end.append(self._ready)
        self.config.on_connection_reuseconn.append(self._ready)

    @staticmethod
    async def _start(_session, ctx, _params) -> None:
        rec = ctx.trace_request_ctx
        if isinstance(rec, dict):
            rec.setdefault("t_start", time.perf_counter())

    @staticmethod
    async def _queued(_session, ctx, _params) -> None:
        rec = ctx.trace_request_ctx
        if isinstance(rec, dict):
            rec.setdefault("t_queued", time.perf_counter())  # the FIRST queue start, never overwritten

    @staticmethod
    async def _ready(_session, ctx, _params) -> None:
        rec = ctx.trace_request_ctx
        if isinstance(rec, dict):
            rec["t_conn"] = time.perf_counter()


class Client:
    """One HTTP client for the whole fleet (``conns`` 0 = no client-side cap) with the node's retry rules."""

    def __init__(self, api: str, metrics: Metrics, conns: int = 0, timeout_s: float = 30.0, trace_path: str | None = None,
                 force_close: bool = False) -> None:
        self.api = api.rstrip("/")
        self.metrics = metrics
        self.conns, self.timeout_s, self.force_close = conns, timeout_s, force_close
        self.trace = Trace()
        self.trace_rows: list[tuple] = []
        self.trace_path = trace_path
        self.http: aiohttp.ClientSession | None = None
        self.sleep = asyncio.sleep  # tests replace it

    async def open(self) -> None:
        connector = aiohttp.TCPConnector(limit=self.conns, limit_per_host=0, keepalive_timeout=4,
                                         force_close=self.force_close)
        self.http = aiohttp.ClientSession(connector=connector, timeout=aiohttp.ClientTimeout(total=self.timeout_s),
                                          trace_configs=[self.trace.config])

    async def close(self) -> None:
        if self.http is not None:
            await self.http.close()
        if self.trace_path and self.trace_rows:
            with open(self.trace_path, "w") as f:
                f.write("rid\tnode\tkind\tattempt\twall\tqueue_ms\tclient_ms\tstatus\tapp_ms\terror\n")
                for row in self.trace_rows:
                    f.write("\t".join("" if v is None else str(v) for v in row) + "\n")

    async def call(self, node: "Node | None", kind: str, path: str, body=None, *, retries: int,
                   intended: float | None = None, lease_sensitive: bool = False) -> tuple[int | None, dict | None]:
        """POST like the scan node: re-signed retries, 2 s doubling backoff (60 s cap), Retry-After honoured.
        Returns (status, json) of the final answer, or (None, None) when the node gave up."""
        raw = b"" if body is None else dumps(body)
        intended = time.perf_counter() if intended is None else intended
        delay, attempt = 2.0, 0
        rebased = False
        while True:
            rid = uuid.uuid4().hex[:16]
            headers = {"X-ZS-Request-Id": rid}
            if node is not None:
                headers.update(node.headers("POST", path, raw))
            if body is not None:
                headers["Content-Type"] = "application/json"
            rec: dict = {}
            t0 = time.perf_counter()
            status, data, app_ms, error, wait_hint = None, None, None, None, None
            refused = seq_next = None
            try:
                async with self.http.post(self.api + path, data=raw, headers=headers, trace_request_ctx=rec) as r:
                    status = r.status
                    m = TIMING_RE.search(r.headers.get("Server-Timing", ""))
                    app_ms = float(m.group(1)) if m else None
                    refused, seq_next = r.headers.get("X-ZS-Refused"), r.headers.get("X-ZS-Seq-Next")
                    wait_hint = r.headers.get("Retry-After")
                    payload = await r.read()
                if payload:
                    try:
                        data = json.loads(payload)
                    except ValueError:
                        data = None
            except asyncio.TimeoutError:
                error = "timeout"
            except aiohttp.ClientError as exc:
                error = type(exc).__name__
            t1 = time.perf_counter()
            client_ms = (t1 - rec.get("t_start", t0)) * 1000
            queue_ms = ((rec.get("t_conn", t1) - rec.get("t_queued", rec.get("t_start", t0))) * 1000
                        if "t_queued" in rec else 0.0)
            if status is not None and (status >= 500 or status == 429):
                error = f"http_{status}"
            elif status is not None and status >= 400 and not (lease_sensitive and status in (404, 409)):
                error = f"http_{status}" + (f"_{refused}" if refused else "")
            self.metrics.attempt(kind, status, client_ms, app_ms, error)
            if error is not None and node is not None and self.metrics.measuring:
                self.metrics.by_team[node.team]["attempt_errors"] += 1
            if self.trace_path is not None and self.metrics.measuring:
                self.trace_rows.append((rid, node.i if node else "", kind, attempt, round(time.time(), 3),
                                        round(queue_ms, 2), round(client_ms, 2), status, app_ms, error))
            if error is None:
                if status in (200, 201, 204):
                    self.metrics.op_done(kind, (t1 - intended) * 1000)
                return status, data
            if status in (404, 409) and lease_sensitive:
                return status, data
            if status == 403 and refused in ("replay_window", "seq_out_of_range") and node and seq_next and not rebased:
                node.signer.rebase(int(seq_next))
                rebased = True
                continue
            if status is not None and 400 <= status < 500 and status != 429:
                self.metrics.op_failed(kind, error)
                return status, data
            if attempt >= retries:
                self.metrics.op_failed(kind, error)
                return None, None
            wait = delay
            if status == 429 and wait_hint:
                try:
                    wait = max(wait, float(wait_hint))
                except ValueError:
                    pass
            await self.sleep(min(wait, 60.0) + random.random())
            delay = min(delay * 2, 60.0)
            attempt += 1


# ----------------------------------------------------------------------------- the fleet
def outcome_of(job_id: int) -> tuple[str, int]:
    """DA section 5.2 mix, deterministic per job: (status, assets to post)."""
    h = (job_id * 2654435761) % 100
    if h < 60:
        return "success", (500 if h % 5 == 0 else 50)
    if h < 90:
        return "failure", 0
    return "skipped", 0


def assets_for(job_id: int, n: int) -> list[dict]:
    return [{"type": "certificate", "target": f"10.{job_id % 250}.{i // 250}.{i % 250}", "location": f"/etc/ssl/c{i}.pem",
             "name": f"c{i}", "algorithm": "RSA", "key_size": 2048,
             "facts": {"fingerprint_sha256": f"{job_id:016x}{i:048x}", "not_after": "2030-01-01T00:00:00Z"}}
            for i in range(n)]


class Node:
    def __init__(self, sim: "Sim", i: int, protocol: int) -> None:
        self.sim, self.i, self.protocol = sim, i, protocol
        self.token = node_token(sim.secret, i)
        self.signer = Signer(node_key(sim.secret, i), protocol)
        self.grants = 0
        self.grant_sent = 0.0
        self.running: dict[int, str] = {}
        self.interval = 60.0
        self.wake = asyncio.Event()
        self.alive = True
        self.max_jobs = sim.args.max_jobs

    def headers(self, method: str, path: str, raw: bytes) -> dict:
        return {"X-ZS-Node-Token": self.token, **self.signer.headers(method, path, raw)}

    def body(self) -> dict:
        collectors = CAPS_COLLECTORS + ([self.sim.args.cap_x] if self.i in self.sim.cap_nodes else [])
        return {"hostname": f"bench-{self.i}", "version": "1.2" if self.protocol >= 2 else "1.0.0",
                "running": [{"job_id": j, "lease_id": lease} for j, lease in self.running.items()],
                "capabilities": {"collectors": collectors, "max_jobs": self.max_jobs,
                                 **({"protocol": 2} if self.protocol >= 2 else {})}}

    @property
    def team(self) -> str:
        return "A" if self.i < self.sim.team_a_nodes else "B"

    def count(self, what: str) -> None:
        if self.sim.metrics.measuring:
            self.sim.metrics.by_team[self.team][what] += 1

    def kind(self, kind: str) -> str:
        return kind if self.protocol >= 2 else f"{kind}_p1"  # protocol-1 nodes are reported apart (E6)

    def grant(self, data: dict | None, sent: float) -> None:
        """As the node: an answer to a request sent before the one that set the current grant is ignored."""
        if self.protocol < 2 or not isinstance(data, dict) or "claim" not in data or sent < self.grant_sent:
            return
        self.grant_sent = sent
        value = data.get("claim")
        self.grants = max(0, min(8, 1 if value is True else int(value or 0)))
        if self.grants:
            self.wake.set()

    async def heartbeat_loop(self, first: float) -> None:
        intended = first
        while self.alive and not self.sim.stopping:
            await self.sim.sleep_until(intended)
            if not self.alive:
                return
            sent = time.perf_counter()
            status, data = await self.sim.client.call(self, self.kind("heartbeat"), "/cbom/node/heartbeat", self.body(),
                                                      retries=1, intended=intended)
            if status == 200 and data:
                self.count("heartbeats")
                if data.get("claim"):
                    self.count("heartbeats_granting")
                self.interval = float(data.get("heartbeat_interval_s") or self.interval)
                self.grant(data, sent)
                for job_id in data.get("cancel_job_ids") or []:
                    self.running.pop(int(job_id), None)
            cap = 600.0 if self.protocol >= 2 else 60.0
            intended += max(5.0, min(self.interval, cap))

    async def claim_loop(self) -> None:
        while self.alive and not self.sim.stopping:
            if len(self.running) >= self.max_jobs:
                self.wake.clear()  # as the node: wait for a slot to free, re-checking at least every 2 s
                try:
                    await asyncio.wait_for(self.wake.wait(), 2.0)
                except asyncio.TimeoutError:
                    pass
                continue
            if self.protocol >= 2:
                if self.grants <= 0:
                    self.wake.clear()
                    await self.wake.wait()
                    continue
                self.grants -= 1
            intended = time.perf_counter()
            self.count("claim_requests")
            status, data = await self.sim.client.call(self, self.kind("claim"), "/cbom/node/jobs/claim",
                                                      {"mode": "agentless"} if self.protocol >= 2 else None,
                                                      retries=1, intended=intended)
            if status != 200 or not data:
                self.grants = 0
                if self.protocol < 2:
                    await asyncio.sleep(5.0 if status == 204 else 15.0)
                continue
            self.sim.metrics.received_claims += 1 if self.sim.metrics.measuring else 0
            self.count("claims")
            self.sim.on_claimed(self, data)
            if not self.alive:
                return
            self.grant(data, intended)
            job = data["job"]
            self.running[int(job["id"])] = job["lease_id"]
            asyncio.create_task(self.run_job(job))

    async def run_job(self, job: dict) -> None:
        job_id, lease = int(job["id"]), job["lease_id"]
        if self.sim.args.work_s:
            await asyncio.sleep(self.sim.args.work_s)
        status, assets = outcome_of(job_id) if self.sim.args.mix else ("success", 0)
        if self.alive and assets:
            st, _ = await self.sim.client.call(self, self.kind("assets"), f"/cbom/node/jobs/{job_id}/assets",
                                               {"lease_id": lease, "batch_id": "b1", "assets": assets_for(job_id, assets)},
                                               retries=6, lease_sensitive=True)
            if st == 200:
                self.sim.metrics.assets_ok += 1 if self.sim.metrics.measuring else 0
        if not self.alive:
            return
        if status == "success":
            result = {"counts": {"total": 1, "ok": 1}, "asset_count": assets}
        elif status == "skipped":
            status, result = "success", {"counts": {"total": 1, "skipped": 1}, "asset_count": 0}
        else:
            result = {"counts": {"total": 1, "failed": 1}}
        sent = time.perf_counter()
        st, data = await self.sim.client.call(self, self.kind("result"), f"/cbom/node/jobs/{job_id}/result",
                                              {"lease_id": lease, "status": status, "result": result,
                                               "error": None if status == "success" else "unreachable"},
                                              retries=6, lease_sensitive=True)
        self.running.pop(job_id, None)
        if st == 200:
            self.sim.metrics.results_ok += 1 if self.sim.metrics.measuring else 0
            self.count("results")
            self.sim.finished.add(job_id)
            self.grant(data, sent)
        self.wake.set()  # a slot is free (the claim loop re-checks its grants)


# ----------------------------------------------------------------------------- samplers
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


def _children(pid: int) -> list[int]:
    try:
        out = subprocess.run(["pgrep", "-P", str(pid)], capture_output=True, text=True).stdout.split()
        return [pid] + [int(x) for x in out]
    except Exception:
        return [pid]


def _recv_q(port: int | None) -> int | None:
    """Accept-queue length of the listening socket (ss Recv-Q on a LISTEN socket)."""
    if not port:
        return None
    try:
        out = subprocess.run(["ss", "-ltnH", f"sport = :{port}"], capture_output=True, text=True, timeout=2).stdout
        return max((int(line.split()[1]) for line in out.splitlines() if line.split()), default=0)
    except Exception:
        return None


class Sampler(threading.Thread):
    """Every second: the simulator's own CPU, the server processes' CPU (``--server-pid`` and its children), the
    accept queue of the API port, PostgreSQL transactions."""

    def __init__(self, db: str | None, server_pid: int | None, port: int | None) -> None:
        super().__init__(daemon=True)
        self.db, self.server_pid, self.port = db, server_pid, port
        self.stop = threading.Event()
        self.points: list[dict] = []

    def run(self) -> None:
        conn = None
        if self.db:
            import psycopg2

            conn = psycopg2.connect(self.db)
            conn.autocommit = True
        last = None
        while not self.stop.is_set():
            pids = _children(self.server_pid) if self.server_pid else []
            point = {"t": time.time(), "sim": _proc_cpu([os.getpid()]), "server": _proc_cpu(pids),
                     "recv_q": _recv_q(self.port)}
            if conn:
                with conn.cursor() as cur:
                    cur.execute("SELECT xact_commit + xact_rollback FROM pg_stat_database "
                                "WHERE datname = current_database()")
                    point["xacts"] = int(cur.fetchone()[0])
            if last is not None:
                dt = point["t"] - last["t"] or 1.0
                out = {"t": point["t"], "recv_q": point["recv_q"]}
                for key in ("sim", "server"):
                    if point[key] is not None and last[key] is not None:
                        out[f"{key}_cpu_pct"] = round(100 * (point[key] - last[key]) / dt, 1)
                if "xacts" in point and "xacts" in last:
                    out["db_tps"] = round((point["xacts"] - last["xacts"]) / dt, 1)
                self.points.append(out)
            last = point
            self.stop.wait(1.0)
        if conn:
            conn.close()


def pg_statements(db: str, reset: bool = False, top: int = 20) -> dict:
    """pg_stat_statements by TOTAL time (DA V5): the top ``top`` must cover >= 95% of the total."""
    import psycopg2

    conn = psycopg2.connect(db)
    conn.autocommit = True
    out: dict = {}
    with conn.cursor() as cur:
        try:
            if reset:
                cur.execute("SELECT pg_stat_statements_reset()")
                return {}
            scope = "dbid = (SELECT oid FROM pg_database WHERE datname = current_database())"
            cur.execute(f"SELECT coalesce(sum(calls),0), coalesce(sum(total_exec_time),0) FROM pg_stat_statements "
                        f"WHERE {scope}")
            calls, ms = cur.fetchone()
            out["calls"], out["exec_ms"] = int(calls), round(float(ms), 1)
            cur.execute(f"SELECT calls, round(total_exec_time::numeric,1), round(mean_exec_time::numeric,3), "
                        f"left(regexp_replace(query, '\\s+', ' ', 'g'), 160) FROM pg_stat_statements WHERE {scope} "
                        f"ORDER BY total_exec_time DESC LIMIT %s", (top,))
            out["top"] = [{"calls": int(c), "ms": float(t), "mean_ms": float(m), "query": q} for c, t, m, q in cur.fetchall()]
            covered = sum(row["ms"] for row in out["top"])
            out["top_coverage"] = round(covered / out["exec_ms"], 4) if out["exec_ms"] else 1.0
            cur.execute(f"SELECT coalesce(sum(calls),0) FROM pg_stat_statements WHERE {scope} AND query ILIKE "
                        "'INSERT INTO cbomnodenonce%%'")
            out["nonce_inserts"] = int(cur.fetchone()[0])
            cur.execute(f"SELECT coalesce(sum(calls),0) FROM pg_stat_statements WHERE {scope} AND query ILIKE "
                        "'%%FROM cbomcollectionrun%%FOR UPDATE%%' AND query NOT ILIKE '%%SKIP LOCKED%%'")
            out["run_row_for_update"] = int(cur.fetchone()[0])
            cur.execute(f"SELECT coalesce(sum(calls),0) FROM pg_stat_statements WHERE {scope} AND query ILIKE "
                        "'SELECT cbomscannode.id%%node_token_hash%%'")
            out["limiter_token_selects"] = int(cur.fetchone()[0])
        except psycopg2.Error as exc:
            out["error"] = str(exc).splitlines()[0]
    conn.close()
    return out


# ----------------------------------------------------------------------------- the simulation
class Sim:
    def __init__(self, args) -> None:
        self.args = args
        creds = load_creds(args.creds)
        self.secret = creds["secret"]
        lo, hi = args.node_range or (0, creds["nodes"])
        self.indexes = list(range(lo, min(hi, creds["nodes"])))[: args.nodes or None]
        self.team_a_nodes = int(creds.get("team_a_nodes") or creds["nodes"])
        self.cap_nodes: set[int] = set()
        for part in (args.cap_x_ranges or "").split(","):
            if ":" in part:
                a, b = (int(x) for x in part.split(":"))
                self.cap_nodes.update(range(a, b))
        self.metrics = Metrics()
        self.client = Client(args.api, self.metrics, conns=args.conns, trace_path=args.trace,
                             force_close=args.force_close)
        self.stopping = False
        self.finished: set[int] = set()
        self.claimed_jobs: set[int] = set()
        self.killed_jobs: list[int] = []
        self.kill_after: float | None = None
        rnd = random.Random(7)
        p1 = set(rnd.sample(self.indexes, int(len(self.indexes) * args.p1_frac))) if args.p1_frac else set()
        self.nodes = [Node(self, i, 1 if i in p1 else 2) for i in self.indexes]
        self.kill_set = set(rnd.sample([n.i for n in self.nodes], int(len(self.nodes) * args.kill_frac))) \
            if args.kill_frac else set()
        self.lag: list[tuple[float, float]] = []
        self.events: list[dict] = []
        self.phase1: dict | None = None
        # --runs "SECONDS:TEAM,...": runs queued that long after the measured window starts (default one run, team 1)
        self.runs = [(float(a), int(b)) for a, b in (x.split(":") for x in (args.runs or "0:1").split(","))]
        self.user_tokens: dict[int, str] = {}
        if args.run:  # imported and signed before the event loop starts: an import inside it stalls every node
            from backend.utilities.auth.auth_utils import create_access_token  # the code under test's JWT format

            for _t, team in self.runs:
                email = "bench@f1.test" if team == 1 else f"bench{team}@f1.test"
                self.user_tokens[team] = create_access_token(email, expires_delta=__import__("datetime").timedelta(hours=3))

    async def sleep_until(self, t: float) -> None:
        delay = t - time.perf_counter()
        if delay > 0:
            await asyncio.sleep(delay)

    def on_claimed(self, node: Node, data: dict) -> None:
        job_id = int(data["job"]["id"])
        self.claimed_jobs.add(job_id)
        if self.kill_after is not None and node.i in self.kill_set and time.monotonic() >= self.kill_after:
            node.alive = False  # dies right after a claim: no result, no heartbeat ever again
            self.killed_jobs.append(job_id)

    async def lag_monitor(self) -> None:
        while not self.stopping:
            t = time.perf_counter()
            await asyncio.sleep(0.05)
            if self.metrics.measuring:
                self.lag.append((time.monotonic(), (time.perf_counter() - t - 0.05) * 1000))

    async def start_run(self, team: int = 1) -> dict:
        body = {"include": {"servers": True, "kubernetes": False, "databases": False, "cloud": False,
                            "network": False}, "client_request_id": "bench-" + uuid.uuid4().hex[:16], "soc_ack": True}
        t = time.perf_counter()
        async with self.client.http.post(self.client.api + f"/{team}/cbom/sources/runs", json=body,
                                         headers={"Authorization": f"Bearer {self.user_tokens[team]}"},
                                         timeout=aiohttp.ClientTimeout(total=900)) as r:
            data = await r.json(content_type=None)
        if r.status not in (200, 201):
            raise SystemExit(f"run not created: HTTP {r.status} {json.dumps(data)[:300]}")
        return {"run_id": data["run"]["id"], "team": team, "create_ms": round((time.perf_counter() - t) * 1000, 1),
                "posted_wall": time.time()}

    async def watch_run(self, run_id: int, t0: float) -> dict:
        import psycopg2

        conn = psycopg2.connect(self.args.db)
        conn.autocommit = True
        timeline, status, jobs_done_s = [], None, None
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
                timeline.append({"t": now, "run": status, **counts})
                if jobs_done_s is None and counts and not (counts.get("pending") or counts.get("claimed")):
                    jobs_done_s = now
                if status in ("done", "partial", "failed", "cancelled"):
                    break
                if jobs_done_s is not None and now - jobs_done_s > 60:
                    break
                await asyncio.sleep(1)
        finally:
            conn.close()
        final = status in ("done", "partial", "failed", "cancelled")
        return {"status": status, "done_s": round(time.monotonic() - t0, 1) if final else None,
                "jobs_done_s": jobs_done_s, "run_stuck_open": bool(jobs_done_s is not None and not final),
                "timeline": timeline[:: max(1, len(timeline) // 60)]}

    async def open_window(self, t0: float) -> None:
        """``--open-window SECONDS:TEAM``: the team's scan window opens (every hour allowed), as a settings change."""
        if not self.args.open_window:
            return
        when, team = self.args.open_window.split(":")
        await self.sleep_until(t0 + float(when))
        import psycopg2

        self.phase1 = {team: dict(c) for team, c in self.metrics.by_team.items()}
        conn = psycopg2.connect(self.args.db)
        conn.autocommit = True
        with conn.cursor() as cur:
            cur.execute("UPDATE cbomcollectionsettings SET scan_window = %s, row_version = row_version + 1 "
                        "WHERE team_id = %s", (json.dumps([[True] * 24 for _ in range(7)]), int(team)))
        conn.close()
        self.events.append({"t": float(when), "cmd": f"open window team {team}", "rc": 0, "wall": time.time()})

    async def one_run(self, delay: float, team: int, t0: float) -> dict:
        await self.sleep_until(t0 + delay)
        info = await self.start_run(team)
        info.update(await self.watch_run(info["run_id"], time.monotonic()))
        info["queued_at_s"] = delay
        return info

    async def at_events(self, t0: float) -> None:
        """``--at SECONDS=COMMAND``: shell commands at times after the run starts (a HUP, an outage)."""
        for spec in sorted(self.args.at or [], key=lambda s: float(s.split("=", 1)[0])):
            when, cmd = spec.split("=", 1)
            await self.sleep_until(t0 + float(when))
            proc = await asyncio.create_subprocess_shell(cmd, stdout=asyncio.subprocess.DEVNULL,
                                                         stderr=asyncio.subprocess.DEVNULL)
            rc = await proc.wait()
            self.events.append({"t": float(when), "cmd": cmd, "rc": rc, "wall": time.time()})

    async def main(self) -> dict:
        await self.client.open()
        sampler = Sampler(self.args.db, self.args.server_pid, self.args.port)
        early: dict | None = None
        if self.args.run_before_nodes:  # a deep queue: the run exists before any node starts (L1, L2)
            early = await self.start_run(self.runs[0][1])
            early["t0"] = time.monotonic()
        spread = self.args.spread if self.args.spread is not None else 60.0
        start = time.perf_counter()
        rnd = random.Random(11)
        tasks = []
        for node in self.nodes:
            tasks.append(asyncio.create_task(node.heartbeat_loop(start + rnd.uniform(0, spread))))
            tasks.append(asyncio.create_task(node.claim_loop()))
        tasks.append(asyncio.create_task(self.lag_monitor()))
        t_begin = time.monotonic()
        await asyncio.sleep(self.args.warmup)
        if self.args.db:
            pg_statements(self.args.db, reset=True)
        sampler.start()
        self.metrics.measuring = True
        self.metrics.t0 = time.monotonic()
        t_measure = time.monotonic()
        wall_measure = time.time()
        run_info: dict = {}
        if self.args.run:
            if self.args.kill_frac:
                self.kill_after = time.monotonic() + self.args.kill_at
            t_run = time.perf_counter()
            events = asyncio.create_task(self.at_events(t_run))
            opener = asyncio.create_task(self.open_window(t_run))
            if early is not None:
                info = dict(early)
                info.update(await self.watch_run(info["run_id"], info.pop("t0")))
                runs = [info]
            else:
                runs = await asyncio.gather(*(self.one_run(d, team, t_run) for d, team in self.runs))
            await opener
            run_info.update(runs[0])
            run_info["runs"] = runs
            run_info.update({"claimed_jobs": len(self.claimed_jobs), "finished_by_sim": len(self.finished),
                             "killed_nodes": sum(1 for n in self.nodes if not n.alive),
                             "killed_jobs": len(self.killed_jobs),
                             "killed_jobs_finished_by_others": sum(1 for j in self.killed_jobs if j in self.finished)})
            await events
        remaining = self.args.duration - (time.monotonic() - t_measure)
        if remaining > 0:
            await asyncio.sleep(remaining)
        measured_s = time.monotonic() - t_measure
        self.metrics.measuring = False
        statements = pg_statements(self.args.db) if self.args.db else {}
        sampler.stop.set()
        sampler.join(timeout=10)
        self.stopping = True
        for t in tasks:
            t.cancel()
        await asyncio.gather(*tasks, return_exceptions=True)
        await self.client.close()
        return self.report(measured_s, time.monotonic() - t_begin, wall_measure, sampler.points, statements, run_info)

    def report(self, measured_s, total_s, wall_measure, points, statements, run_info) -> dict:
        m = self.metrics
        lag = sorted(v for _t, v in self.lag)
        lat = {k: pct_summary(v) for k, v in m.lat.items()}
        worst = {}
        for kind, windows in m.windows.items():
            p99s = [(w, percentile(sorted(v), 99)) for w, v in windows.items() if len(v) >= 20]
            if p99s:
                w, p = max(p99s, key=lambda x: x[1])
                worst[kind] = {"window": w, "p99": _r(p), "windows": len(p99s)}
        residual = {k: pct_summary(v) for k, v in m.residual.items()}
        sim_cpu = sorted(p["sim_cpu_pct"] for p in points if "sim_cpu_pct" in p)
        server_cpu = sorted(p["server_cpu_pct"] for p in points if "server_cpu_pct" in p)
        recv = [p["recv_q"] for p in points if p.get("recv_q") is not None]
        by_s = m.claims_by_s
        claims_1s = max(by_s.values()) if by_s else 0
        claims_10s = Counter()
        for sec, n in by_s.items():
            claims_10s[sec // 10] += n
        ops = sum(len(v) for v in m.lat.values())
        attempts = sum(m.codes.values())
        validity = {
            "V1_sim_cpu_p95_pct": _r(percentile(sim_cpu, 95)),
            "V1_loop_lag_p99_ms": _r(percentile(lag, 99)),
            "V2_residual_p99_ms": {k: v["p99"] for k, v in residual.items()},
            "V2_recv_q_max": max(recv) if recv else None,
            "V2_server_timing_missing": dict(m.timing_missing),
            "V5_top20_coverage": statements.get("top_coverage"),
            "V8_nofile": resource.getrlimit(resource.RLIMIT_NOFILE)[0],
        }
        fails = []
        if validity["V1_sim_cpu_p95_pct"] is not None and validity["V1_sim_cpu_p95_pct"] > 70:
            fails.append("V1 simulator CPU p95 > 70%")
        if validity["V1_loop_lag_p99_ms"] is not None and validity["V1_loop_lag_p99_ms"] >= 50:
            fails.append("V1 loop lag p99 >= 50 ms")
        for kind, p99 in validity["V2_residual_p99_ms"].items():
            if p99 is not None and p99 > self.args.residual_ms:
                fails.append(f"V2 {kind} client-server residual p99 {p99} > {self.args.residual_ms} ms")
        if validity["V2_recv_q_max"] is not None and validity["V2_recv_q_max"] > 64:
            fails.append("V2 accept queue > 64")
        if sum(m.timing_missing.values()):
            fails.append("V2 Server-Timing missing on some responses")
        if validity["V5_top20_coverage"] is not None and validity["V5_top20_coverage"] < 0.95:
            fails.append("V5 top-20 statements cover < 95% of DB time")
        if validity["V8_nofile"] < 65536 and self.args.conns == 0 and len(self.nodes) > 1000:
            fails.append("V8 ulimit -n < 65536")
        return {
            "config": {k: v for k, v in vars(self.args).items() if k not in ("db",)} | {
                "nodes": len(self.nodes), "p1_nodes": sum(1 for n in self.nodes if n.protocol < 2),
                "host": socket.gethostname()},
            "measured_s": round(measured_s, 1), "total_s": round(total_s, 1), "wall_measure_start": wall_measure,
            "served_per_s": round(ops / measured_s, 1) if measured_s else None,
            "attempts": attempts, "latency": lat, "worst_10s_window": worst,
            "attempt_errors": sum(m.attempt_errors.values()), "attempt_error_kinds": dict(m.attempt_errors),
            "attempt_errors_by_10s": dict(m.attempt_errors_by_window),
            "op_errors": sum(m.op_errors.values()), "op_error_kinds": dict(m.op_errors), "error_samples": m.samples,
            "codes": dict(m.codes),
            "by_team": {team: dict(c) for team, c in m.by_team.items()}, "phase1_by_team": self.phase1,
            "claims": {"received": m.received_claims, "max_per_1s": claims_1s,
                       "max_per_10s": max(claims_10s.values()) if claims_10s else 0, "results_ok": m.results_ok,
                       "assets_ok": m.assets_ok},
            "residual_ms": residual,
            "sim_loop_lag_ms": {"p50": _r(percentile(lag, 50)), "p99": _r(percentile(lag, 99)),
                                "max": _r(lag[-1] if lag else None)},
            "cpu_pct_of_one_cpu": {"sim_p95": _r(percentile(sim_cpu, 95)), "server_avg": _r(
                sum(server_cpu) / len(server_cpu)) if server_cpu else None, "server_p95": _r(percentile(server_cpu, 95))},
            "db": {"tps_avg": _r(sum(p.get("db_tps", 0) for p in points) / max(1, len(points))), **statements},
            "validity": validity, "valid": not fails, "invalid_because": fails,
            "events": self.events, "run": run_info,
        }


def _install_claim_counter(sim: Sim) -> None:
    """Count successful claims per wall second of the measured window (the dispatch-rate gates)."""
    real = sim.client.call

    async def call(node, kind, path, body=None, **kw):
        status, data = await real(node, kind, path, body, **kw)
        if kind.startswith("claim") and status == 200 and sim.metrics.measuring:
            sim.metrics.claims_by_s[int(time.monotonic() - sim.metrics.t0)] += 1
        return status, data

    sim.client.call = call  # type: ignore[method-assign]


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--api", required=True)
    ap.add_argument("--creds", required=True)
    ap.add_argument("--db", default=None, help="PostgreSQL URL of the server under test (stats and run watch)")
    ap.add_argument("--server-pid", type=int, default=None, help="gunicorn master pid (CPU of it and its workers)")
    ap.add_argument("--port", type=int, default=None, help="API port, for the accept-queue sampler")
    ap.add_argument("--nodes", type=int, default=0, help="at most this many nodes (default: every node in --node-range)")
    ap.add_argument("--node-range", type=lambda s: tuple(int(x) for x in s.split(":")), default=None)
    ap.add_argument("--p1-frac", type=float, default=0.0, help="share of nodes that behave as scan node 1.0")
    ap.add_argument("--max-jobs", type=int, default=2)
    ap.add_argument("--duration", type=float, default=600, help="measured seconds (after the warm-up)")
    ap.add_argument("--warmup", type=float, default=60)
    ap.add_argument("--spread", type=float, default=None, help="first heartbeat spread (default 60 s)")
    ap.add_argument("--conns", type=int, default=0, help="client connection cap (0: none, like a real fleet)")
    ap.add_argument("--force-close", action="store_true", help="a new TCP (and TLS) connection per request")
    ap.add_argument("--run", action="store_true")
    ap.add_argument("--run-timeout", type=float, default=900)
    ap.add_argument("--runs", default=None, help='"SECONDS:TEAM,...": runs to queue (default "0:1")')
    ap.add_argument("--run-before-nodes", action="store_true", help="queue the run before any node starts")
    ap.add_argument("--open-window", default=None, help="SECONDS:TEAM: open the team's scan window then")
    ap.add_argument("--cap-x", default="bench_x", help="the capability the --cap-x-ranges nodes report")
    ap.add_argument("--cap-x-ranges", default=None, help='"a:b,c:d": node indexes that have --cap-x')
    ap.add_argument("--work-s", type=float, default=0.0)
    ap.add_argument("--mix", action="store_true", help="the DA request mix (failures, assets, skipped)")
    ap.add_argument("--kill-frac", type=float, default=0.0)
    ap.add_argument("--kill-at", type=float, default=30.0, help="seconds after the run starts")
    ap.add_argument("--at", action="append", help="SECONDS=COMMAND after the run starts (repeatable)")
    ap.add_argument("--residual-ms", type=float, default=20.0)
    ap.add_argument("--trace", default=None, help="write every attempt as TSV here")
    ap.add_argument("--out", default=None)
    args = ap.parse_args()
    try:
        soft, hard = resource.getrlimit(resource.RLIMIT_NOFILE)
        resource.setrlimit(resource.RLIMIT_NOFILE, (min(65536, hard), hard))
    except (ValueError, OSError):
        pass
    sim = Sim(args)
    _install_claim_counter(sim)
    out = asyncio.run(sim.main())
    text = json.dumps(out, indent=1, default=str)
    if args.out:
        Path(args.out).write_text(text)
    print(json.dumps({"valid": out["valid"], "invalid_because": out["invalid_because"],
                      "attempt_errors": out["attempt_errors"], "latency": out["latency"].get("heartbeat"),
                      "run": {k: v for k, v in out["run"].items() if k != "timeline"}}, default=str))


if __name__ == "__main__":
    main()
