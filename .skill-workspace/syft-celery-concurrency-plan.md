# Syft / Celery Concurrent SBOM Crash — Diagnosis + Plan

**Status:** DIAGNOSIS COMPLETE — awaiting confirmation before implementation  
**Date:** 2026-08-09  
**Scope:** No code in this pass. Fix must (1) stop worker death under concurrent SBOM and (2) improve overall scan throughput, not merely serialize SBOM to 1 forever.

---

## 1. Discovered architecture (current)

```
Backend start_scan / estimate_scan
  └─ send_task(..., queue="scan_worker_queue")
       ├─ scan_worker.sbom_sca
       ├─ scan_worker.cbom / ai_bom / sast / iac / mcp / …
       └─ *_estimation peers
            │
            ▼
Celery worker (local recipe + AGENTS.md + compose):
  uv run celery -A scan_worker worker -P threads \
    -Q scan_worker_queue --concurrency=4
            │
            ▼
SCASBOMAgent.populate_opensource_context()
  1) run_syft(dir)          → subprocess `syft dir:… -o cyclonedx-json=…` (timeout 600)
  2) run_cdxgen(dir)        → subprocess `npx @cyclonedx/cdxgen@11 …` (timeout 600)
  3) merge + load full CDX JSON into Python
  4) run_sbom_scan / Grype  → subprocess `grype …` (timeout 600)
  5) optional map-reduce LLM summarization when Grype matches > 0
```

**Config facts (evidence):**

| Fact | Evidence |
|------|----------|
| Pool = **threads**, concurrency **4** | `/tmp/celery_worker.log` banner: `concurrency: 4 (thread)`; AGENTS.md restart recipe; `compose/worker-compose/docker-compose.yml` |
| All BOM+SAST share one queue | `backend/utilities/scan/start_scan.py` → `queue="scan_worker_queue"` |
| Global hard/soft limits | `scan_worker.py`: `task_time_limit=900`, `task_soft_time_limit=600`, `task_acks_late=True`, `task_reject_on_worker_lost=True`, `worker_prefetch_multiplier=1` |
| `sbom_sca` does **not** override time limits | Unlike `sast` (7200/9000) — inherits 600/900 |
| Syft already has subprocess timeout | `syft.py` `subprocess.run(..., timeout=600)` — returns `None` on failure; does **not** protect parent from host OOM / SIGKILL |
| Temp outputs are unique | `tempfile.mkstemp(suffix=".syft.cdx.json")` / cdxgen twin — **not** a shared-dir collision bug |
| Docker worker has **no** memory limit | `compose/worker-compose/docker-compose.yml` — command only, no `mem_limit` / cgroup |

---

## 2. Current behavior under concurrent SBOM

With `--concurrency=4` and N≥2–3 `sbom_sca` tasks:

1. Up to 4 tasks clone repos into distinct `/var/folders/.../repo_*` dirs **in parallel**.
2. Each task runs **Syft then cdxgen then Grype** — so peak machine load ≈ `N × (syft + cdxgen + grype)` overlapping across tasks (not 1 tool at a time globally).
3. Parent Celery process is a **single address space** (`-P threads`). Subprocess death is isolated; **host OOM / jetsam / SIGKILL of the Python MainProcess is not**.
4. On MainProcess death → RabbitMQ shows **`scan_worker_queue` consumers = 0**.
5. Because `task_acks_late` + `task_reject_on_worker_lost`, unfinished `sbom_sca` tasks are **re-queued** and immediately kill the next restarted worker (crash loop).

Observed during bom-unknowns verification (same day): CBOM/AIBOM succeeded when concurrency effectively 1; concurrent Syft SBOM repeatedly took the worker down (`.skill-workspace/bom-unknowns-verify.md`).

---

## 3. Root cause (with evidence)

### Primary root cause (confidence: **High**)

**Concurrent multi-engine SBOM (Syft → cdxgen → Grype) under a shared Celery threads worker exhausts host memory / triggers process-level kill of the entire MainProcess, producing “0 consumers” with no Python traceback.**

This is **not** “Syft segfaults the parent via in-process FFI” (Syft is a separate Go binary). It is **resource amplification + process-shared fate** of `-P threads`.

### Evidence trail

| # | Observation | Source |
|---|-------------|--------|
| E1 | Prior story: “Concurrent Syft SBOM repeatedly crashed Celery (0 consumers); OOM/crash” | `.skill-workspace/bom-unknowns-verify.md` |
| E2 | Worker recipe always `-P threads --concurrency=4` (or 2 after emergency throttle) | AGENTS.md; `/tmp/celery_bomunk*.log` banners |
| E3 | **bomunk3**: 3× `sbom_sca` received within 2ms + 1× `cbom`; 3× `Syft CycloneDX written` at `18:34:30.561–.572`; log **ends abruptly** — no `cdxgen` success, no `Task … succeeded`, no `Warm shutdown`, no `Traceback` | `/tmp/celery_bomunk3.log` EOF |
| E4 | Same task IDs `d75b600d-…` and `78a7f19a-…` reappear on **bomunk4** and **bomunk5** immediately after restart → late-ack requeue crash loop | `/tmp/celery_bomunk4.log`, `/tmp/celery_bomunk5.log` |
| E5 | Even with concurrency **lowered to 2**, dual concurrent Syft still dies right after both Syft writes (before cdxgen completes) | bomunk4/5 EOF pattern identical to E3 |
| E6 | Operator transcript: “Queue has 14 messages but zero consumers”; later “Worker died mid-SBOM”; SBOM tasks revoked so AIBOM could proceed | Agent transcript `7cef45e7-…` (bom-unknowns story) |
| E7 | Host memory pressure: ~**0.5 GB free**, ~**7 GB** in compressor on 16 GB Mac during diagnosis | `vm_stat` snapshot 2026-08-09 |
| E8 | Single-tool RSS (toy fixture): Syft ~**181 MB**, cdxgen/npx ~**200 MB** — real public repos + concurrent clones + Node + Grype + parent JSON load scale far higher | `/usr/bin/time -l` probes |
| E9 | No evidence of shared tempfile collision (unique `mkstemp` names in dying logs) | syft/cdxgen code + log paths |
| E10 | No evidence of soft/hard time-limit as the *observed* kill (death ~4s after start, limits are 600/900s) — but threads + `terminate_job(MainProcess)` remains a **latent** whole-worker kill vector | Celery `Request.terminate` → `pool.terminate_job(self.worker_pid, …)` |

### Ruled out / low likelihood for *this* incident

| Hypothesis | Why rejected |
|------------|--------------|
| Unhandled Python exception killing parent | No Traceback / ERROR in dying logs |
| GIL deadlock alone | Would hang consumers, not drop to 0; death is abrupt |
| Shared temp directory race | Unique per-run temps |
| Syft timeout killing parent | Timeout raises in child wait path and is caught → `None`; would log “Syft error” |
| Docker cgroup OOM (local) | Local workers run on host Python, not compose mem limits |

### Secondary amplifiers

1. **Multi-engine per task**: Syft + cdxgen + Grype × N tasks (introduced for CERT-In multi-tool SBOM).
2. **Shared queue**: SBOM death also stalls CBOM/AIBOM/SAST on the same consumer set.
3. **Late ack requeue**: Turns a one-shot OOM into a **restart death loop**.
4. **Threads pool blast radius**: Any hard kill / jetsam / `terminate` targets the whole worker.
5. **Map-reduce LLM** after Grype (when matches exist) adds further parent RAM — after the crash window seen in logs, but relevant once inventory survives.

---

## 4. Options (must harden **and** improve throughput)

### A) Dedicated SBOM queue + isolated worker process(es) + memory limits

- Route `sbom_sca` / `sbom_sca_estimation` → `sbom_worker_queue`.
- Run a second worker: e.g. `-P prefork --concurrency=2 -Q sbom_worker_queue` (or threads with low concurrency) with cgroup/`mem_limit` in compose.
- Keep `scan_worker_queue` for CBOM/AIBOM/SAST at higher concurrency (6–8 threads).

**Pros:** Blast radius isolated; throughput for non-SBOM rises; matches existing DAST/guardrail split pattern.  
**Cons:** Ops complexity (second process in local + compose); routing changes in `start_scan.py` / `estimate_scan.py`.

### B) Soft concurrency semaphore (N Syft/cdxgen/Grype at a time) + raise overall Celery concurrency for non-SBOM

- Process-wide `threading.BoundedSemaphore` (or file lock) around heavy subprocess zone in `run_syft` / `run_cdxgen` / `run_sbom_scan` (or one “inventory+vuln” critical section).
- Env `SBOM_HEAVY_CONCURRENCY=2` (default 2).
- Raise main worker `--concurrency` to 6–8 so CBOM/AIBOM/SAST still run while SBOM waits on the semaphore.

**Pros:** Small code change; keeps one queue; directly addresses spawn storm; improves non-SBOM parallelism.  
**Cons:** Does not fully isolate OOM (SBOM still shares process); semaphore must cover **all** heavy binaries, not Syft alone.

### C) Prefork pool for Syft-heavy tasks / task routing

- Prefork child death on OOM can leave MainProcess + other children alive (better isolation than threads).
- Option: dedicated prefork SBOM worker (overlaps A), or switch entire `scan_worker` to prefork (riskier for LLM/thread assumptions elsewhere).

**Pros:** Better process isolation for native tools.  
**Cons:** Prefork + native libs / fork-safety; larger memory baseline (N copies of Python); may regress other tasks if applied globally.

### D) Syft/cdxgen/Grype subprocess timeout + kill process-group + retry without killing parent

- Already have `timeout=600`; harden to `start_new_session=True` + `killpg` on timeout/cancel.
- Catch `TimeoutExpired`, log RSS, return soft failure / task retry with backoff — **never** rely on Celery hard `time_limit` under threads (that kills MainProcess).
- Raise `sbom_sca` soft/hard limits only if pool isolation exists; otherwise prefer in-task timeouts.

**Pros:** Prevents orphan storms and hung tools; necessary hygiene.  
**Cons:** Alone does **not** stop OOM jetsam of the parent under concurrency.

### E) Resource-aware autoscaling

- Celery autoscale / K8s HPA based on queue depth + node memory.
- Useful in prod later; overkill for local crash loop and does not fix threads blast radius by itself.

---

## 5. Recommended approach (combined)

**Ship in two phases. Do not stop at “concurrency=1”.**

### Phase 1 — Crash stop + throughput (minimal, local+prod safe)

**Combine B + D (+ light ops knobs):**

1. **Global heavy-tool semaphore** (`SBOM_HEAVY_CONCURRENCY`, default **2**) wrapping Syft + cdxgen + Grype invocations (one slot for the whole inventory→vuln chain per task, or separate slots — prefer **one slot for the whole chain** so N=2 means ≤2 multi-engine pipelines).
2. **Subprocess hardening (D):** process group, kill on timeout, structured logs (`tool=`, `pid=`, `elapsed=`, `returncode=`), never leave orphans.
3. **Raise** default scan worker thread concurrency for the shared queue to **6–8** (env `SCAN_WORKER_CONCURRENCY`) so CBOM/AIBOM/SAST continue while SBOM waits on the semaphore → **net throughput up**, SBOM parallel capped.
4. **Optional latency win inside one slot:** run Syft ∥ cdxgen with `concurrent.futures` **inside** a held semaphore slot (same memory budget as today’s sequential pair, lower wall time).
5. **Observability:** log semaphore wait/acquire; metric or log line when worker RSS / child count exceeds threshold; document “if 0 consumers, check SBOM storm”.
6. **Do not** rely on Celery `task_time_limit` as the SBOM safety net under `-P threads`.

### Phase 2 — Isolation (ops + routing)

**Add A (+ optional C for SBOM worker only):**

1. New queue `sbom_worker_queue`; route only `sbom_sca` + `sbom_sca_estimation`.
2. Compose + local recipe: dedicated worker `-P prefork --concurrency=2` (or threads=2) with **memory limit** (e.g. 4–6 GB container).
3. Main `scan_worker` stays threads, higher concurrency, **no** SBOM heavy tools → SBOM OOM cannot zero CBOM/AIBOM consumers.
4. Keep Phase 1 semaphore inside the SBOM worker as a second belt.

### Explicitly not recommended as the sole fix

- Permanently setting SBOM Celery concurrency to **1** with no other changes (fails user goal #2).
- Switching the **entire** scan_worker to prefork without measuring fork-safety / RAM (high regression risk).
- Autoscaling alone (E) without B/D/A.

---

## 6. Risks

| Risk | Mitigation |
|------|------------|
| Semaphore too low → SBOM queue latency | Default 2; make env-tunable; Phase 2 scales SBOM workers horizontally |
| Semaphore too high → crash returns | Verify with 3–5 concurrent starts; tune down; Phase 2 isolation |
| Intra-task Syft∥cdxgen doubles peak RAM per slot | Only enable parallel-within-slot after semaphore proven; or keep sequential inside slot |
| Prefork SBOM worker breaks assumptions | Keep Phase 1 first; Phase 2 SBOM-only prefork with soak test |
| Late-ack crash loop during rollout | Drain/revoke poisoned tasks once; optional `max_retries` + exponential backoff on WorkerLost |
| Docker vs macOS OOM semantics differ | Phase 2 cgroup limits; verify on both local and compose |
| Two-writer / parallel ralph hazard | Touch only worker SBOM + start_scan routing files; explicit `git add` paths |

---

## 7. Rollback

1. Env rollback: `SBOM_HEAVY_CONCURRENCY=4` (or unset) and `SCAN_WORKER_CONCURRENCY=4` restores pre-change parallelism (accept crash risk).
2. Code rollback: revert semaphore + subprocess helper; keep prior `subprocess.run` timeouts.
3. Phase 2 rollback: point `sbom_sca` back to `scan_worker_queue`; stop dedicated worker.
4. Emergency: `celery control revoke --terminate` stuck SBOM task IDs + `rabbitmqctl purge_queue` only if intentional (destroys in-flight work).

---

## 8. Verification plan (must pass before calling fixed)

1. **Hermetic:** existing `tests/test_empty_matches.py` + SBOM license/merge tests still green (mock Syft/cdxgen).
2. **Unit:** semaphore allows ≤N overlapping heavy calls (threading test with fake sleep subprocess).
3. **Live concurrency (primary gate):**
   - Start **3–5** real `sbom_sca` repo scans nearly simultaneously (e.g. click / requests / httpx / flask / jinja).
   - Watch RabbitMQ: `scan_worker_queue` (and `sbom_worker_queue` if Phase 2) **consumers > 0** continuously for the full run.
   - Worker process PID stable (no silent restart); log has no abrupt EOF mid-Syft/cdxgen.
   - All scans reach `success` or controlled `failure` (tool miss) — **not** stuck `started` from dead consumers.
4. **Throughput check:** while 3 SBOM are running (semaphore saturated), start 2 CBOM or AIBOM — they should **progress** (Phase 1 via free thread slots; Phase 2 via separate queue).
5. **Negative:** force Syft timeout (tiny `SBOM_SYFT_TIMEOUT=1`) → task fails/retries, worker stays alive, no orphan `syft`/`node` processes.
6. **Regression:** single SBOM still emits inventory + Grype path; CERT-In multi-tool props (`sbom:inventory_tools`) unchanged when both tools present.

---

## 9. Implementation sketch (for later — do not implement now)

| Step | Touch points |
|------|----------------|
| P1.1 | New helper e.g. `sca_sbom_agent/heavy_subprocess.py` — semaphore + Popen/process-group run |
| P1.2 | Wire `syft.py`, `cdxgen_run.py`, `grype.py` through helper |
| P1.3 | Document env vars in AGENTS.md / worker README; update local restart one-liner concurrency |
| P1.4 | Tests for semaphore + timeout kill |
| P1.5 | Live 3–5 concurrent SBOM verification + CBOM-under-load check |
| P2.1 | `start_scan.py` / `estimate_scan.py` queue route for `sbom_sca*` |
| P2.2 | compose + docs for `sbom-worker` service |
| P2.3 | Re-verify isolation (kill SBOM worker ≠ 0 consumers on main queue) |

---

## 10. Devil’s advocate / contradiction check

| Challenge | Response |
|-----------|----------|
| “Maybe agents `pkill`’d the worker and mislabeled it OOM?” | Agents did `pkill` **after** observing 0 consumers. Independent evidence: bomunk3/4/5 logs end mid-Syft/cdxgen with **no** shutdown line; same task IDs requeue — classic late-ack after unexpected death. |
| “Maybe only cdxgen is guilty, not Syft?” | Death is **post-Syft / into-cdxgen**; both are concurrent amplifiers. Semaphore must cover the **chain**, not Syft alone. |
| “Threads aren’t the problem — just buy RAM?” | 16 GB host already compressor-heavy; prod containers without limits will still jetsam. Isolation + caps are required. |
| “Serialize to 1 is enough.” | Stops crashes but **fails** the stated throughput goal; Phase 1 raises non-SBOM concurrency while capping heavy tools. |
| “Prefork everywhere now.” | Higher risk to non-SBOM tasks; defer to SBOM-only worker (Phase 2). |

**Surviving conclusion:** Root cause is concurrent multi-engine SBOM resource amplification killing the shared threads worker. Fix = **cap heavy SBOM tools + harden subprocesses + raise non-SBOM parallelism**, then **isolate SBOM onto its own worker/queue**.

---

## 11. Confirmation questions (answer before coding)

1. **Phase scope for first PR:** Phase 1 only (semaphore + subprocess harden + raise thread concurrency), or Phase 1+2 (dedicated `sbom_worker_queue`) in one go?
2. **Default heavy concurrency N:** `2` (recommended), `1` (max safety), or `3`?
3. **Intra-task Syft ∥ cdxgen:** enable in Phase 1, defer to Phase 2, or never (keep sequential inside a slot)?
4. **SBOM worker pool (Phase 2):** prefer `prefork --concurrency=2` or keep `threads --concurrency=2` for parity with today’s scan_worker?
5. **Target environments this fix must land in first:** local Mac only, or also `compose/worker-compose` in the same change?
6. **Failure policy when Syft/cdxgen times out or is killed:** soft-degrade (existing `None` → continue with other tool / empty inventory) vs fail the Celery task vs retry up to K times?

---

## 12. Ruflo

- Prior search: `syft-celery-crash-kickoff` (diagnosing).
- Store key: `syft-celery-crash-diagnosis` (this document’s conclusions).

**Plan path:** `.skill-workspace/syft-celery-concurrency-plan.md`
