## Summary

F1.1, the lean node API (PARALLEL-PLAN "F1.1"; contract `$R6/f1/CONTRACT.md` sections 2, 3 and 5). This change makes the scan-node hot path and the job queue fit 10,000 nodes and 10,000-job runs. It also adds the extension points that F1.2, F1.3 and F1.4 plug into. Every route and response shape stays compatible. A node on today's image (1.0) keeps working unchanged.

**Problems found on dev 3399452, each reproduced before it was changed**

| # | Problem | Where | Evidence |
|---|---|---|---|
| P1 | Nodes poll claim every 5 s and heartbeat every 30 s (every 5 s while busy). | `agent.py:48`, `cbom_node.py:53-54` | about 2,333 req/s at 10k nodes |
| P2 | A nonce INSERT and its own COMMIT on every signed request. | `node_auth.py:192-199` | 32,603 INSERTs in the 10-minute baseline |
| P3 | The rate-limiter key does a second token SELECT on every node call. | `http.py:92-104` | 68,572 token SELECTs for 77,106 requests |
| P4 | The heartbeat reaps, reads settings, gets every claimed job's source, and loads **every** pending id to count them. | `cbom_node.py:303-350` | 20 statements/request (smoke) |
| P5 | `recompute_run` loads every job of the run on each claim, finish and cancel. | `jobs.py:111-143` | quadratic: 1k jobs took 279 s, 200 jobs took 13.7 s |
| P6 | **Bug:** when the last two jobs of a run end at the same time, each transaction sees the other job still claimed, and the run stays `running` for ever. | `jobs.py:111-143` | `p6_repro.py` on PostgreSQL: dev `run_status=running`, jobs `[success, success]` |
| P7 | A job is pinned to `source.node_id`. | `runs.py:94-98`, `jobs.py:497-516` | no balancing, no failover |
| P8 | The global reaper loads every open job into Python, and only on the cloud worker's job loop, which can be busy for hours. | `jobs.py:147-229`, `cbom_cloud_worker.py:205` | |
| P9 | Hard caps: 50 agentless nodes, 500 sources (also CMDB), 1,000 agent nodes, 50 pools, 1,000 enrollments per pool. | `cbom_sources.py:107-108`, `cmdb.py:37`, `agents.py:39-41` | |

**What changed**

- **Replay protection without a per-request INSERT** (`node_auth.py`).
  - Protocol-2 nodes sign with sequence nonces: `s2_<19 digits>` = (process start in µs) << 11, plus one per request. The format fits today's nonce regex, so an older server treats it as an ordinary nonce.
  - The node row holds an RFC 4303 / RFC 6479 anti-replay window: a high-water mark plus a 63-bit bitmap (`replay_hwm`, `replay_bits`).
  - ONE conditional `UPDATE … WHERE id=:id AND (seq > hwm OR (hwm-seq < 63 AND bit clear))` checks the request and advances the window. It also stamps `last_heartbeat_at` and `last_seen_ip`, and is committed at once.
  - The row lock plus the re-checked WHERE make it atomic across workers and replicas.
  - Results: a repeat is answered `403 replay`. A sequence below the window is answered `403 replay_window` with `X-ZS-Seq-Next`, and the node rebases its counter and signs again. Protocol-1 random nonces keep the `cbomnodenonce` table exactly as before.
- **Protocol 2, server-driven** (`cbom_node.py`, `limits.py`, `scan_node/agent.py`, `api.py`).
  - `heartbeat_interval_s` is 60 s ±20% jitter (`CBOM_NODE_HEARTBEAT_S`). While a node runs a network job it is about 5 s, so a stop-all reaches it fast. While it runs another job it is 30 s.
  - Every heartbeat answer carries `claim` and `protocol: 2`. A protocol-2 node claims only when told, drains, and claims again when a job slot frees.
  - Against a server without `claim` (dev), the new node polls every 5 s, as before.
  - The node keeps the Docker HEALTHCHECK fresh for any interval.
- **Lean hot path.**
  - Idle protocol-2 heartbeat: 7 statements, 1 UPDATE, no INSERT. A test asserts this budget.
  - The heartbeat reads the node's claimed jobs once (partial index) and reuses them for lease renewal, cancels and the busy check.
  - The pending count is bounded (`LIMIT 100`).
  - Node facts are written only when they change.
  - A lease is renewed only once less than half of it is left.
  - The limiter key is an in-process TTL cache. It only picks the rate-limit bucket and never authenticates anything.
  - The claim no longer reaps per node. Its first page is 1 row, so 10k concurrent claims each lock one row, not 50.
- **Runs without O(N²)** (`jobs.recompute_run`).
  - The status comes from indexed EXISTS probes on `(run_id, status)`. The final status is one GROUP BY, once.
  - Near the end of a run (open jobs ≤ PostgreSQL `max_connections`), the run row is locked first, which fixes P6. While more jobs are open than transactions could be ending at once, the lock is skipped, so 10k results never queue on one row.
  - `reconcile_runs` in the reaper closes any run left open.
  - `mark_run_running` writes the run once, at its first claim.
- **Segment jobs, not pinned to one node** (contract section 2).
  - A source with `node_segment` and no `node_id` queues jobs with `node_segment`.
  - Any **agentless** node of the team whose `cbomscannode.segment` matches claims them with `FOR UPDATE SKIP LOCKED`, through a guarded UPDATE that sets `node_id` to the claimer.
  - On lease expiry (`CBOM_JOB_LEASE_S`, default 900), or when the node stops reporting the job, the job goes back to `pending` and `node_id` is cleared.
  - The cloud worker and agent-mode nodes never take segment jobs.
  - `plan_run` counts a segment as having a node when an enrolled agentless node of that segment exists.
  - Pinned and host-agent jobs behave exactly as before.
- **Reaper.** It reads only the jobs a rule applies to, through partial indexes, in batches of 500. In the cloud worker it now runs on its own thread every 30 s.
- **Configurable caps** (`limits.py`, names and defaults from contract section 3):

  | Cap | Variable | New default | Was |
  |---|---|---|---|
  | Agentless nodes | `CBOM_MAX_AGENTLESS_NODES` | 500 | 50 |
  | Sources (UI, API and CMDB) | `CBOM_MAX_SOURCES` | 5,000 | 500 |
  | Agent nodes | `CBOM_MAX_AGENT_NODES` | 20,000 | 1,000 |
  | Pools | `CBOM_MAX_POOLS` | 200 | 50 |
  | Enrollments per pool | `CBOM_MAX_POOL_ENROLLMENTS` | 20,000 | 1,000 |

  A missing or invalid value falls back to the default.
- **Extension points for F1.2 to F1.4** (contract section 3):
  - `secret_refs.py`: a fixed plugin list for claim, cloud claim, `finish_job`, `add_assets` and the secret part of `connection_version`. A missing module is skipped; a broken one fails loudly. A source's version is unchanged when no plugin contributes.
  - `capabilities.py`: a job whose required capability the node lacks stays pending.
  - `cbom_node.authenticate_node()` and `jobs.leased_job()`.
  - `backend/tests/test_alembic_single_head.py`.
- **Migration `r6f11node001`.**
  - `cbomscannode.replay_hwm` and `replay_bits` (BIGINT, 0).
  - `node_segment` on sources and jobs (NULL).
  - Six job indexes: `(run_id, status)`, `(team_id, status, node_segment, id)`, and partial indexes on pending and claimed jobs.
- **Bench** (`bench/f1_node_api/`):
  - `sim.py`, an asyncio fleet simulator. It signs exactly like a node, in protocol 1 or 2, and measures latency per call, errors, simulator loop lag, server and PostgreSQL CPU, PostgreSQL TPS and `pg_stat_statements`.
  - `seed.py`, `stack.sh` (PostgreSQL in docker plus gunicorn), `run_bench.sh`, `reaper.py`, and `ec2_bench.sh` for the dedicated box.

## Acceptance criteria → evidence

| # | Acceptance criterion | Evidence |
|---|---|---|
| 1 | 10,000 simulated nodes with a 60 s heartbeat: p99 < 300 ms and no errors, sustained for 10 minutes | pending: EC2 run in progress (c6i.xlarge, coordinator-approved). Numbers are added here and under "Scale" when it finishes |
| 1a | No per-request INSERT on the hot path; nonce/replay protection kept by another means | `test_protocol2_replay_is_refused_without_a_nonce_row`: repeat → 403 replay; overtaken requests accepted once each; old sequence → 403 `replay_window` + `X-ZS-Seq-Next`; 0 nonce rows. `test_a_replay_to_another_worker_is_refused_too`: second engine refuses. `test_window_sql_matches_the_reference_{sqlite,postgres}`: 705 random/reordered/repeated sequences, the SQL equals the reference on both. `test_an_idle_heartbeat_does_not_read_the_queue_or_write_a_nonce`: 7 statements, 1 UPDATE, 0 INSERT. `test_protocol1_random_nonces_keep_the_nonce_table` |
| 2 | A 10,000-job run: scheduling overhead under 5 min, no O(N²) `recompute_run` | pending: EC2 `after-run`. `test_claim_and_finish_cost_does_not_grow_with_the_run[20/400]`: identical statement counts for claim, finish and the next claim at 20 and 400 jobs |
| 2a | Jobs claimed with Postgres `FOR UPDATE SKIP LOCKED` and not pinned to one node; a node that dies mid-job has its job re-queued after a lease timeout | `test_many_nodes_claim_one_segment_at_once_without_a_double_claim` (PostgreSQL, 12 threads, 60 jobs: each claimed once, spread over nodes). `test_segment_jobs_go_to_any_agentless_node_of_the_segment_and_back_on_lease_expiry`: node a dies, lease expires, reaper re-queues with `node_id` cleared, node b claims attempt 2 and the run ends `done`; a's late result is refused. `test_cloud_worker_and_agent_nodes_never_take_segment_jobs`. EC2 `after-run-kill` (5% of nodes die holding jobs) pending |
| 2b | (found on the way) The last two jobs of a run ending together leave it `running` | `test_the_last_two_jobs_ending_together_finish_the_run` (PostgreSQL). Repro on dev: `{'run_status': 'running', 'jobs': ['success', 'success']}`; branch: `done`. Safety net: `test_the_reaper_closes_a_run_left_running_with_no_open_job` |
| 3 | The 500-sources and 50-agentless-node caps become configurable limits, with defaults sized for enterprise use | `test_caps_come_from_the_environment` (nodes, sources, pools, pool enrollments), `test_limit_defaults_are_sized_for_an_enterprise_fleet`; the existing cap tests now set the env (`test_two_pool_tokens_created_at_once_cannot_pass_the_cap`, `test_two_pods_of_two_pools_cannot_pass_the_agent_node_cap`, `test_agent_nodes_do_not_count_against_the_agentless_node_cap`) |
| 4 | The existing scan-node suite and backend suite stay green | CI run (link below). Locally: 25 F1.1 tests, 13 node-auth tests, a 332-test targeted CBOM/integrations subset, and the scan-node agent and signing tests (including `test_protocol2_node_claims_only_when_a_heartbeat_says_so`) |
| 4a | An old scan node, running the current image, still works | `test_scan_node_1_0_client_works_against_the_new_server`: dev 3399452 `zs_scan_node/api.py`, vendored verbatim, enrolls, heartbeats, claims a pinned and a segment job, posts results, run `done`, its nonces in the nonce table. Live: image `registry.zeroshield.ai/cbom/scan-node:1.0` against the branch backend is pending (stack lock) |
| 5 | Proof: a load-test script under bench/ and its report (p50/p95/p99, error rate, CPU and DB QPS), run where results are trustworthy, under `flock heavy-tests.lock` | `bench/f1_node_api/`. The local 2-CPU box was too noisy (load average up to 42, host 192-198% busy before the server works), so the coordinator approved a dedicated c6i.xlarge. Report: pending, under "Scale" |

## Scale

pending: the EC2 numbers (before = dev 3399452, after = this branch, same box, same simulator parameters).

**Local baseline on dev 3399452** (noisy shared 2-CPU box: direction only, not a p99 claim):

| Scenario | Achieved | p50 | p99 | Errors | DB statements/s | Nonce INSERTs |
|---|---|---|---|---|---|---|
| 10k nodes, 60 s heartbeat, no claims (the target profile), 10 min | 128 of 167 req/s | 30.8 s | 31.4 s | 61,303 of 77,106 timeouts (80%) | 1,566 | 32,603 |
| 1k-job run, 200 nodes, protocol 1 | 279 s to `done` | n/a | n/a | n/a | n/a | n/a |
| 200-job run, 200 nodes, protocol 1 | 13.7 s to `done` | n/a | n/a | n/a | n/a | n/a |

## How it was tested

- `backend/tests/test_cbom_f1_node_api.py` (25 tests). It runs on SQLite with the real routers; with `CBOM_TEST_PG_URL` (CI sets it) it also runs on PostgreSQL 15: the claim race, the end-of-run race and the window SQL.
- `backend/tests/test_alembic_single_head.py`.
- Updated tests:
  - The two node-auth tests now expect the replay window instead of nonce rows.
  - The cap tests set env vars instead of patching module constants.
  - The two decryption-spy tests patch `secret_refs.decrypt_secrets`, the one place secrets are now decrypted for a job.
- `scan_node/tests/test_agent.py::test_protocol2_node_claims_only_when_a_heartbeat_says_so`.
- `p6_repro.py`, the end-of-run race, on dev and on the branch against PostgreSQL 15.

## Risk and rollback

- **Protocol.**
  - Nothing is forced on a deployed node. Protocol-1 nodes use the unchanged paths: heartbeat keys, claim shape, nonce table.
  - New nodes against an old server poll and use their sequence nonces as ordinary nonces.
  - Old nodes now get a heartbeat interval of 48-60 s (they clamp to 60). They still poll claim every 5 s.
- **Behaviour changes.**
  - The heartbeat while a non-network job runs is 30 s, not 5 s. Cancels still reach the node at its next asset post (409).
  - A job's lease is written only once less than half of it is left.
  - Clock skew is rewritten only when it moves by more than 10 s.
- **Locking.** The run row is locked only by job ends near a run's end.
- **Migration.** It is additive: two BIGINT columns with a default, two nullable columns and six indexes. `downgrade()` drops them.
- **Rollback.** Revert the merge and run alembic downgrade to `rv6p1nodename001`.
- **Release order.** At merge time, re-chain `down_revision` to dev's head; `test_alembic_single_head.py` enforces a single head.

## Checklist

- [x] Tests added or updated for the change
- [x] No secrets, `.env` files or private keys in the diff (use `.env.example` with placeholders)
- [x] Database changes have a migration; config changes are documented
- [x] Docs / runbooks updated where operators or users must act (`limits.py` table, node/server docstrings)

🤖 Generated with [Claude Code](https://claude.com/claude-code)

https://claude.ai/code/session_01SDCVQSqoacevwbyX9VGquR
