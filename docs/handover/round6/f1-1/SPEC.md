# F1.1 Lean node API: spec (builder, Nov 11)

Branch `feat/f1-node-api` from `origin/dev` 3399452. Contract: $R6/f1/CONTRACT.md (architect, in progress: align ids/paths when it lands).

## Verified current behaviour on dev (evidence: file:line on 3399452)

| # | Problem | Where | Effect at 10k nodes |
|---|---|---|---|
| P1 | Node polls claim every 5 s, heartbeat every 30 s (5 s while busy) | `scan_node/zs_scan_node/agent.py:48,110,266,322`; `backend/routers/cbom_node.py:53-54,350` | ~2,333 req/s idle |
| P2 | Nonce INSERT + COMMIT on every signed request, sweep DELETE once a minute per worker | `backend/utilities/cbom_sources/node_auth.py:192-212` | ~2,300 INSERT/s, separate commit (fsync) per request |
| P3 | Rate-limiter key does its own session + token SELECT (+pre-ping) before the route does the same again | `backend/utilities/cbom_sources/http.py:92-104` | 2 extra round trips/request |
| P4 | Heartbeat: reap (loads all open jobs of node), settings, cancel ids (per job: source get + config validation + hash), loads ALL pending ids to count them, busy select | `cbom_node.py:303-350` | 8-10 statements per beat |
| P5 | `recompute_run` loads every job of the run on every claim/finish/cancel | `jobs.py:111-143` | 10k-job run: ~2x10^8 row loads |
| P6 | Two concurrent finishes of the last two jobs both see the other job open: run stays `running` | `jobs.py:111-143` (no lock) | stuck runs at the end of big runs |
| P7 | Job pinned to `source.node_id` | `runs.py:94-98`, `jobs.py:497-516` | no balancing, no failover |
| P8 | Global reaper loads every open job into Python every REAP_EVERY_S | `jobs.py:147-229`, `workers/cbom_cloud_worker.py:177-208` | 10k pending ORM rows per pass |
| P9 | Hard caps: 50 agentless nodes, 500 sources (also CMDB import), 1,000 agent nodes, 50 pools, 1,000 enrollments per pool | `routers/cbom_sources.py:107-108`, `integrations/cmdb.py:37`, `agents.py:39-41` | a 10k fleet cannot be enrolled |
| P10 | Only single-column indexes on job (team, run, source, node, status): claim/heartbeat filters scan a node's whole job history | `new_models.py:418-446` | grows with history |

## Design

### D1 Protocol 2 (node <-> server), versioned with fallback
* A node declares `protocol: 2` in enroll/heartbeat/claim bodies (`capabilities.protocol` for heartbeat). Older nodes
  send nothing: protocol 1, served exactly as today (same routes, same fields).
* **Heartbeat interval is server-driven**: `heartbeat_interval_s` = base (env `CBOM_NODE_HEARTBEAT_S`, default 60)
  with +-20% jitter per answer; busy with a network job (stop-all must reach it fast): `CBOM_NODE_NETWORK_BUSY_S`
  (5); busy with other jobs: `CBOM_NODE_BUSY_HEARTBEAT_S` (30). Protocol-1 nodes clamp to [5,60] themselves: they get
  the same jittered value (<=60 for them).
* **Claim on signal (protocol 2)**: the heartbeat answer carries `claim: true` when a job this node may claim is
  waiting; a p2 node claims only then, keeps claiming while it gets jobs (drain), and otherwise waits for the next
  heartbeat. Against an old server (no `claim` key) a p2 node falls back to polling every 5 s.
* Answers keep every protocol-1 key (`pending_jobs` is capped at 100 instead of loading every pending id).

### D2 Replay protection without a per-request INSERT
* Protocol 2 nonces are a per-node sequence: `s2_<19-digit seq>` (fits the existing nonce regex, so an old server
  treats it as an opaque nonce: a new node works against an old server). seq = (process start, Unix s) << 24 | counter:
  dense within a process (reordering of concurrent requests stays inside the window), larger after every restart.
* Server: an RFC 4303 / RFC 6479 style anti-replay window (high-water mark + 64-bit bitmap) in two columns of the
  node row, checked and advanced by ONE conditional UPDATE that also stamps `last_heartbeat_at`/`last_seen_ip`:
  `UPDATE cbomscannode SET hwm=..., bits=..., ... WHERE id=:id AND (seq > hwm OR (hwm-seq < 64 AND bit not set))`.
  Row lock + re-evaluated WHERE make it atomic across workers/replicas. rowcount 0 = replay (403 `replay`) or too
  old (403 `replay_window` + `X-ZS-Seq-Next`, the node rebases its counter and re-signs once).
* Protocol-1 random nonces keep the `cbomnodenonce` INSERT path unchanged (fallback; same guarantee as today).
* Enrollment / re-enrollment resets the window (new key).

### D3 Lean hot path
* Limiter key: token-hash -> node id cached in-process (TTL 60 s, positive only; only used to pick the rate-limit
  bucket, never for auth).
* Heartbeat (idle p2 node): node SELECT, one UPDATE (window + last seen + changed facts), settings SELECT, claimed
  jobs SELECT (partial index), claimable EXISTS (partial index), COMMIT. No reap, no INSERT.
* Claim: no per-node reap; pinned jobs first, then group jobs, `FOR UPDATE SKIP LOCKED` (PostgreSQL).
* Reaper: SQL predicates fetch only jobs that need action (lease expired, max runtime, stale cancel, pending TTL),
  oldest first, bounded batch, `SKIP LOCKED`; still called by the cloud worker loop and read paths.

### D4 Runs: no O(N^2)
* `recompute_run` uses indexed EXISTS on (run_id, status) instead of loading every job; the final status is one
  GROUP BY when no job is open. A transition that ENDS a job locks the run row (`FOR UPDATE`) before deciding, which
  fixes P6 (the later transaction re-reads after the earlier one committed). Claims never lock the run row.
* Migration: indexes `(run_id, status)`, partial `(node_id, id) WHERE status='pending'`, `(node_group, id) WHERE
  status='pending' AND node_id IS NULL`, `(node_id) WHERE status='claimed'`, `(lease_expires_at) WHERE status='claimed'`.

### D5 Jobs not pinned: node groups (data model follows CONTRACT.md when it lands)
* Provisional: `cbomscannode.node_group`, `cbomcollectionsource.node_group`, `cbomcollectionjob.node_group` (string,
  per team). A source assigned to a group (node_id NULL) queues group jobs; any enrolled agentless node of the team in
  that group claims them (SKIP LOCKED); a node that dies mid-job: lease expiry re-queues it (attempts < 3) and another
  node takes it. Lease length `CBOM_JOB_LEASE_S` (default 900 = today). Pinned sources behave exactly as today.
  Agent-mode `host_agent` sources stay pinned to their own node (by design: an agent collects only its own host).

### D6 Configurable caps (env, enterprise defaults)
| Limit | Today | Env | New default |
|---|---|---|---|
| agentless scan nodes / team | 50 | `CBOM_MAX_SCAN_NODES` | 1,000 |
| sources / team (UI + CMDB import) | 500 | `CBOM_MAX_SOURCES` | 20,000 |
| agent nodes / team | 1,000 | `CBOM_MAX_AGENT_NODES` | 50,000 |
| pool tokens / team | 50 | `CBOM_MAX_POOLS` | 200 |
| enrollments / pool token | 1,000 | `CBOM_MAX_POOL_ENROLLMENTS` | 50,000 |
Invalid env values fall back to the default with a log line; the limit is read per request (no restart needed in tests).

## Acceptance criteria -> how each is proven
1. 10k nodes @60 s, p99 < 300 ms, 0 errors, 10 min: `bench/f1_node_api/sim.py --nodes 10000 --duration 600`
   against gunicorn+PostgreSQL (docker), under `flock heavy-tests.lock`; report p50/p95/p99, errors, CPU, DB QPS
   (pg_stat_database xact + pg_stat_statements calls deltas). Baseline: same simulator, protocol 1, on dev code.
   No INSERT: pg_stat_statements shows 0 `INSERT INTO cbomnodenonce` calls in the p2 run; unit test asserts no
   nonce row is written for a p2 request. Replay: tests send the same signed p2 request twice -> 403 replay; an old
   seq outside the window -> 403 replay_window; concurrent reordered requests inside the window -> all accepted;
   cross-worker replay (two engines/sessions) refused.
2. 10k-job run: bench `run` scenario: queue 10k jobs, simulated nodes claim+complete; overhead = start -> run done
   (job work time 0); kill 5% of nodes mid-job with a short lease -> jobs re-queued and finished by others.
   Unit tests: recompute_run issues O(1) queries (statement counter) regardless of job count; P6 race test on
   PostgreSQL (two threads finishing the last two jobs -> run done); SKIP LOCKED: two sessions claim distinct jobs.
3. Caps: unit tests for each env var (create node/source/pool past the limit -> 400 naming the limit).
4. Suites: targeted backend tests + scan_node tests locally, full suites in CI. Old node: (a) the dev version of
   `zs_scan_node` (api.py/agent.py vendored from origin/dev as a test fixture) enrolls, heartbeats, claims and posts a
   result against the new routes; (b) live: the existing image `registry.zeroshield.ai/cbom/scan-node:1.0` against
   the branch backend (docker, `flock stack.lock`), job completes.
5. Bench committed under `bench/f1_node_api/` with README and the report in the PR.

## Risks
* Protocol change for deployed nodes: none forced; p1 path unchanged, p2 negotiated per request by the nonce form.
* Run-row lock on job end: serialises finishes of one run (held only to commit, ~1 ms): 10k finishes ~10 s total.
* Busy heartbeat 5 s -> 30 s for non-network jobs: cancel reaches the node later (its next asset post already gets 409).
* Shared 2-CPU machine: p99 may be noise-bound; if so, propose a tagged t3 EC2 run (coordinator OK first).
