# DevSecShield Production Load Test Report

**Date:** April 1, 2026  
**Target API:** `https://devsecshieldapi.zeroshield.ai`  
**Target Frontend:** `https://devsecshield.zeroshield.ai`  
**Server:** AWS EC2 t3a.medium (2 vCPU, 4 GB RAM)  
**Tool:** Locust 2.37.4 (Python, headless mode)  
**Test Duration:** ~27 minutes (5 levels × 5 minutes + cooldowns)  

---

## Executive Summary

The DevSecShield production API was load tested with 5 progressively increasing concurrency levels (10 → 50 → 100 → 500 → 1000 simultaneous users) across 32 distinct endpoint categories covering auth, teams, scans, guardrails, CI/CD, and admin operations.

### Key Findings

| Metric                        | Value         |
|-------------------------------|---------------|
| **Total Requests Sent**       | 85,134        |
| **Total Failures**            | 2,788         |
| **Overall Failure Rate**      | 3.27%         |
| **Peak RPS Achieved**         | ~116 req/s    |
| **Server Crash / 5xx Errors** | 0             |
| **Breakpoint (severe degradation)** | **500 concurrent users** |

### Verdict

| Load Level | Verdict |
|------------|---------|
| 10 users   | ✅ **Excellent** — avg 118ms, 4% fail (rate-limit expected) |
| 50 users   | ✅ **Good** — avg 97ms, 2.1% fail |
| 100 users  | ✅ **Acceptable** — avg 161ms, 1.8% fail |
| 500 users  | ⚠️ **Degraded** — avg 1,505ms, 2.4% fail |
| 1000 users | ❌ **Poor** — avg 5,949ms, 4.8% fail |

---

## Summary by Load Level

| Level | Users | Total Reqs | Failures | Fail % | Avg (ms) | Median (ms) | P95 (ms) | P99 (ms) | Max (ms) | RPS |
|-------|-------|-----------|----------|--------|----------|------------|----------|----------|----------|-----|
| ✅ Level 1 - Light | 10 | 1,090 | 44 | 4.0% | 118 | 45 | 580 | 1,500 | 2,058 | 3.6 |
| ✅ Level 2 - Moderate | 50 | 5,292 | 109 | 2.1% | 97 | 43 | 230 | 880 | 4,010 | 17.7 |
| ✅ Level 3 - Medium | 100 | 10,388 | 184 | 1.8% | 161 | 47 | 380 | 3,200 | 10,220 | 34.7 |
| ⚠️ Level 4 - Heavy | 500 | 34,675 | 827 | 2.4% | 1,505 | 1,300 | 3,200 | 5,200 | 11,167 | 115.8 |
| ❌ Level 5 - Stress | 1000 | 33,689 | 1,624 | 4.8% | 5,949 | 5,300 | 7,500 | 23,000 | 22,812 | 112.2 |

### Key Observations

1. **Throughput plateaus at ~115 RPS** — going from 500 to 1000 users didn't increase throughput (115.8 vs 112.2 RPS), meaning the server is saturated.
2. **Median response time jumps 27x** between 100 users (47ms) and 500 users (1,300ms).
3. **P99 latencies at 1000 users hit 23 seconds** — which is catastrophic for user experience.
4. **Zero 5xx errors** — the server never crashed, but it became extremely slow.
5. **Failure rate dominated by rate limiting (429)**, not actual errors.

---

## Detailed Results by Load Level

### Level 1 — 10 Concurrent Users (Light)

**Performance Rating:** 🟢 Excellent

| Metric | Value |
|--------|-------|
| Concurrent Users | 10 |
| Total Requests | 1,090 |
| Failed Requests | 44 (4.0%) |
| Avg Response Time | 118 ms |
| Median Response Time | 45 ms |
| 95th Percentile | 580 ms |
| 99th Percentile | 1,500 ms |
| Max Response Time | 2,058 ms |
| Requests/sec | 3.6 |

**Endpoint Performance (Top/Bottom):**

| Endpoint | Avg (ms) | P95 (ms) | Max (ms) | Note |
|----------|----------|----------|----------|------|
| `/send_code (setup)` | 1,658 | 2,100 | 2,058 | Email sending is slow |
| `/send_code` | 392 | 740 | 1,259 | Email verification |
| `/openapi.json` | 170 | 460 | 1,670 | Large JSON payload (57KB) |
| `/team/{id} (update)` | 40 | 55 | 55 | Fast write |
| `/get_user` | 73 | 140 | 693 | Fast auth read |
| `/teams` | 118 | 660 | 1,449 | Multiple DB queries |

**Failures:** All 44 failures are rate-limiting (429) or expected auth errors (400 for invalid codes).

---

### Level 2 — 50 Concurrent Users (Moderate)

**Performance Rating:** 🟢 Good

| Metric | Value |
|--------|-------|
| Concurrent Users | 50 |
| Total Requests | 5,292 |
| Failed Requests | 109 (2.1%) |
| Avg Response Time | 97 ms |
| Median Response Time | 43 ms |
| 95th Percentile | 230 ms |
| 99th Percentile | 880 ms |
| Max Response Time | 4,010 ms |
| Requests/sec | 17.7 |

**Key Insight:** Average response time actually *improved* from Level 1 (118ms → 97ms) because the auth setup overhead (email verification calls with high latency) became proportionally smaller. The system handles 50 users comfortably.

**Failures (109):**
- 40 × 429 on `/login (attempt)` — rate limited
- 31 × 429 on `/send_code (setup)` — rate limited  
- 6 × 429 on `/signup (attempt)` — rate limited
- 29 × 400 on `/login (invalid)` — expected (bad credentials)
- 3 × 400 on `/signup (attempt)` — expected (bad verification code)

---

### Level 3 — 100 Concurrent Users (Medium)

**Performance Rating:** 🟡 Acceptable

| Metric | Value |
|--------|-------|
| Concurrent Users | 100 |
| Total Requests | 10,388 |
| Failed Requests | 184 (1.8%) |
| Avg Response Time | 161 ms |
| Median Response Time | 47 ms |
| 95th Percentile | 380 ms |
| 99th Percentile | 3,200 ms |
| Max Response Time | 10,220 ms |
| Requests/sec | 34.7 |

**Degradation Signal:** While the median stays low (47ms), the P99 jumps to 3.2 seconds and max spikes to 10.2 seconds. This indicates **intermittent queue buildup** — most requests are fast, but a small percentage get stuck waiting.

**Failures (184):**
- 80 × 429 on `/login (attempt)` — rate limiting tightening
- 62 × 429 on `/send_code (setup)` — rate limiting
- 16 × 429 on `/signup (attempt)` — rate limiting
- 24 × 400 on `/login (invalid)` — expected
- 2 × 400 on `/signup (attempt)` — expected

---

### Level 4 — 500 Concurrent Users (Heavy) ⚠️

**Performance Rating:** 🔴 Poor — **This is the breakpoint**

| Metric | Value |
|--------|-------|
| Concurrent Users | 500 |
| Total Requests | 34,675 |
| Failed Requests | 827 (2.4%) |
| Avg Response Time | 1,505 ms |
| Median Response Time | 1,300 ms |
| 95th Percentile | 3,200 ms |
| 99th Percentile | 5,200 ms |
| Max Response Time | 11,167 ms |
| Requests/sec | 115.8 |

**Critical Finding:** The median response time jumped from 47ms to **1,300ms** — a **27x increase**. Every single endpoint is now averaging over 1.3 seconds, regardless of complexity.

**Endpoint Breakdown (all endpoints equally slow):**

| Endpoint | Avg (ms) | P95 (ms) | Requests |
|----------|----------|----------|----------|
| `/docs (health)` | 1,465 | 2,800 | 3,511 |
| `/teams` | 1,485 | 3,100 | 2,881 |
| `/openapi.json` | 1,574 | 3,400 | 1,994 |
| `/get_user` | 1,467 | 3,000 | 1,891 |
| `/{team_id}/{type}/scans` | 1,460 | 2,700 | 3,580 |
| `/team/{id}/dashboard` | 1,477 | 3,100 | 1,820 |
| `/login` | 1,457 | 3,100 | 1,099 |
| `/signup` | 1,499 | 3,200 | 1,063 |
| `/send_code (setup)` | 3,849 | 10,000 | 400 |

**The fact that even trivial endpoints like `/docs` (a static HTML page) take 1.4 seconds proves this is NOT a database bottleneck — it's a server-level saturation issue (CPU or connection handling).**

**Failures (827):**
- 400 × 429 on `/login (attempt)` — rate limiting
- 383 × 429 on `/send_code (setup)` — rate limiting
- 17 × 429 on `/signup (attempt)` — rate limiting
- 27 × 400 on `/login (invalid)` — expected

---

### Level 5 — 1000 Concurrent Users (Stress) ❌

**Performance Rating:** 🔴 Critical — **Unusable**

| Metric | Value |
|--------|-------|
| Concurrent Users | 1000 |
| Total Requests | 33,689 |
| Failed Requests | 1,624 (4.8%) |
| Avg Response Time | 5,949 ms |
| Median Response Time | 5,300 ms |
| 95th Percentile | 7,500 ms |
| 99th Percentile | 23,000 ms |
| Max Response Time | 22,812 ms |
| Requests/sec | 112.2 |

**Critical Findings:**
1. **Average response is ~6 seconds** — users will abandon the page.
2. **P99 is 23 seconds** — complete timeout territory.
3. **RPS dropped from 115.8 to 112.2** — the server is fully saturated and unable to process more requests.
4. **Every endpoint equally affected** — even `/admin/check_superuser` (a simple DB query) takes 6.1 seconds avg.
5. **No server crashes or 5xx errors** — the server stays alive but becomes essentially unresponsive.

**Endpoint Performance at 1000 Users:**

| Endpoint | Avg (ms) | P95 (ms) | Max (ms) |
|----------|----------|----------|----------|
| `/admin/users` | 6,296 | 7,800 | 22,719 |
| `/{team_id}/cicd/integration (create)` | 6,387 | 22,000 | 22,717 |
| `/teams/dashboard` | 6,118 | 7,500 | 22,803 |
| `/team/{id} (update)` | 6,164 | 7,400 | 22,754 |
| `/{team_id}/{type}/scans` | 6,056 | 7,500 | 22,781 |
| `/signup (attempt)` | 6,480 | 12,000 | 11,758 |
| `/send_code (setup)` | 5,979 | 12,000 | 12,889 |

---

## Performance Trend Analysis

### Response Time Scaling

```
Avg Response Time vs Concurrent Users:

6000ms │                                                          ●
       │                                                         ╱
5000ms │                                                        ╱
       │                                                       ╱
4000ms │                                                      ╱
       │                                                     ╱
3000ms │                                                    ╱
       │                                                   ╱
2000ms │                                                  ╱
       │                                        ●────────╱
1000ms │                                       ╱
       │                                      ╱
       │  ●           ●           ●──────────╱
  0ms  └──────────────────────────────────────────────────────────
       10          50         100         500         1000
                      Concurrent Users
```

### Throughput (RPS) Scaling

```
RPS vs Concurrent Users:

120 │                                        ●────────────────●
    │                                       ╱
100 │                                      ╱
    │                                     ╱
 80 │                                    ╱
    │                                   ╱
 60 │                                  ╱
    │                               ╱
 40 │                    ●─────────╱
    │                   ╱
 20 │         ●────────╱
    │        ╱
  4 │  ●────╱
    └─────────────────────────────────────────────────────────────
       10          50         100         500         1000
                      Concurrent Users

    → Throughput plateaus at ~115 RPS (server saturation)
```

---

## Failure Analysis

### Failure Breakdown by Category

| Category | Description | Total Count | Impact |
|----------|-------------|-------------|--------|
| **429 Too Many Requests** | Rate limiting (expected behavior) | 2,707 | Low — intentional protection |
| **400 Bad Request** | Invalid auth credentials (expected) | 81 | None — test design artifact |
| **5xx Server Errors** | Server crashes / internal errors | **0** | None — server is resilient |
| **Timeouts** | Connection or read timeouts | **0** | None — server always responds |

### Rate Limiting Impact by Level

| Level | 429 Errors | % of Total Failures | Affected Endpoints |
|-------|-----------|---------------------|-------------------|
| 10 users | 5 | 11.4% | `/login`, `/signup` |
| 50 users | 77 | 70.6% | `/login`, `/signup`, `/send_code` |
| 100 users | 158 | 85.9% | `/login`, `/signup`, `/send_code` |
| 500 users | 800 | 96.7% | `/login`, `/signup`, `/send_code` |
| 1000 users | 1,600 | 98.5% | `/login`, `/signup`, `/send_code` |

**Note:** Rate limiting is configured at 20 requests/30 seconds per client IP. Since all load test traffic comes from a single IP, this is expected behavior. In production with distributed users, the 429 rate would be much lower.

---

## Root Cause Analysis

### Why Does Performance Collapse at 500 Users?

#### Root Cause 1: Single-Process Uvicorn (Primary Cause)

The FastAPI backend runs on a single Uvicorn process. With only 1 async event loop on 2 CPUs:
- At 100 users: The event loop can handle requests faster than they arrive → low latency
- At 500 users: Request arrival rate exceeds processing capacity → requests queue up → latency multiplies
- At 1000 users: Queue depth grows linearly → each request waits 5+ seconds before being processed

**Evidence:** Even static endpoints like `/docs` (no DB, no computation) show 1.3s latency at 500 users. This can only be explained by request queuing at the server process level.

#### Root Cause 2: CPU Saturation on t3a.medium (2 vCPUs)

The t3a.medium has 2 vCPUs with burstable performance:
- Base CPU performance: 20% (0.4 vCPU equivalent sustained)
- Burst capacity: 200% (both vCPUs at full speed, limited by CPU credits)
- Under sustained load for 5+ minutes, **CPU credits deplete** and performance drops to baseline 20%

**Evidence:** The performance degradation between Level 4 (1,505ms avg) and Level 5 (5,949ms avg) — a 4x increase for only 2x the users — suggests CPU credit exhaustion kicked in during the 500-user test.

#### Root Cause 3: Shared Infrastructure Contention

On the single EC2 instance, all services compete for resources:
- FastAPI backend process
- PostgreSQL database
- MongoDB database
- RabbitMQ message broker
- Celery workers (scan, CICD, guardrail)

At 500+ concurrent users, the backend's CPU/memory usage starves the databases, creating cascading delays.

#### Root Cause 4: No Connection Pooling / Async DB Pool Exhaustion

PostgreSQL's default max_connections is 100. With FastAPI using SQLModel/SQLAlchemy:
- Each request may use 1+ DB connections
- At 500 concurrent users, all connections are occupied
- New requests block waiting for a free connection

#### Root Cause 5: Synchronous Operations Blocking the Event Loop

Several backend operations are synchronous (blocking):
- `bcrypt.hashpw()` for password hashing (CPU-intensive, blocks ~100ms)
- Email sending via SMTP (`/send_code` — 1.6s avg even at 10 users)
- File I/O operations
- Some DB operations not using async drivers

When these block the async event loop, all other requests queue behind them.

---

## Scalability Assessment

### Current Capacity

| Metric | Value |
|--------|-------|
| **Maximum comfortable concurrency** | **~100 users** |
| **Maximum degraded concurrency** | **~500 users** (1.5s avg latency) |
| **Maximum before unusable** | **~1000 users** (6s avg latency) |
| **Peak throughput** | **~116 RPS** |
| **Server crash threshold** | **Not reached** (server is resilient) |

### Instance Sizing Assessment

| Instance | vCPU | RAM | Est. Max Users | Est. Max RPS | Monthly Cost |
|----------|------|-----|----------------|-------------|-------------|
| t3a.medium (current) | 2 | 4 GB | ~100 | ~115 | ~$27 |
| t3a.large | 2 | 8 GB | ~150 | ~150 | ~$55 |
| t3a.xlarge | 4 | 16 GB | ~300 | ~250 | ~$109 |
| c6a.xlarge (compute) | 4 | 8 GB | ~400 | ~350 | ~$110 |
| c6a.2xlarge (compute) | 8 | 16 GB | ~800 | ~600 | ~$220 |

*Estimates assume proper Uvicorn worker configuration (workers = 2 × CPU + 1).*

---

## Recommendations

### Tier 1: Immediate Fixes (1-2 hours, highest impact)

#### 1.1 Run Uvicorn with Multiple Workers
**Impact:** 2-4x throughput increase  
**Effort:** 5 minutes  

```bash
# Current (single process):
uvicorn main:app --host 0.0.0.0 --port 8080

# Recommended (multi-worker):
gunicorn main:app -w 5 -k uvicorn.workers.UvicornWorker --bind 0.0.0.0:8080
# workers = (2 × vCPU) + 1 = 5 for t3a.medium
```

Update the Dockerfile:
```dockerfile
CMD ["gunicorn", "main:app", "-w", "5", "-k", "uvicorn.workers.UvicornWorker", "--bind", "0.0.0.0:8080", "--timeout", "120"]
```

#### 1.2 Offload bcrypt to Thread Pool
**Impact:** Prevents event loop blocking during auth operations  
**Effort:** 30 minutes  

```python
# In auth_utils.py - wrap bcrypt in asyncio thread executor
import asyncio
from concurrent.futures import ThreadPoolExecutor

_executor = ThreadPoolExecutor(max_workers=4)

async def verify_password(plain: str, hashed: str) -> bool:
    loop = asyncio.get_event_loop()
    return await loop.run_in_executor(_executor, bcrypt.checkpw, plain.encode(), hashed.encode())
```

#### 1.3 Offload Email Sending to Background Task
**Impact:** Reduces `/send_code` from 1.6s to <50ms  
**Effort:** 30 minutes  

```python
# Instead of sending email synchronously in the request handler:
from fastapi import BackgroundTasks

@router.post("/send_code")
async def send_code(email: str, background_tasks: BackgroundTasks):
    code = generate_code()
    store_code(email, code)  # Save to DB
    background_tasks.add_task(send_email, email, code)  # Send async
    return {"message": "Verification code sent"}
```

#### 1.4 Increase PostgreSQL max_connections
**Impact:** Eliminates connection pool exhaustion at scale  
**Effort:** 10 minutes  

```bash
# In PostgreSQL configuration or docker-compose:
POSTGRES_MAX_CONNECTIONS=300
```

---

### Tier 2: Short-Term Improvements (1-2 days)

#### 2.1 Add Redis/In-Memory Caching for Read-Heavy Endpoints
**Impact:** 50-80% latency reduction on dashboards and listings  

Endpoints that benefit most:
- `GET /teams` — cache for 30 seconds
- `GET /team/{id}/dashboard` — cache for 60 seconds  
- `GET /{team_id}/{type}/scans` — cache for 30 seconds
- `GET /teams/dashboard` — cache for 60 seconds

#### 2.2 Separate Workers from API Server
**Impact:** Eliminates resource contention  

Move Celery workers to a separate EC2 instance:
```
Instance 1 (t3a.medium): FastAPI + PostgreSQL + MongoDB
Instance 2 (t3a.small):  RabbitMQ + Celery Workers
```

#### 2.3 Add PgBouncer for Connection Pooling
**Impact:** 5-10x more efficient DB connection reuse  

```yaml
# docker-compose addition
pgbouncer:
  image: edoburu/pgbouncer
  environment:
    DATABASE_URL: postgres://user:pass@postgres:5432/db
    MAX_CLIENT_CONN: 1000
    DEFAULT_POOL_SIZE: 40
```

#### 2.4 Add API Response Compression (gzip)
**Impact:** 60-80% bandwidth reduction, faster response delivery  

```python
from fastapi.middleware.gzip import GZipMiddleware
app.add_middleware(GZipMiddleware, minimum_size=1000)
```

#### 2.5 Add a Health Check Endpoint
**Impact:** Enables ALB health checks and monitoring  

```python
@app.get("/health")
async def health():
    return {"status": "ok", "timestamp": datetime.utcnow().isoformat()}
```

---

### Tier 3: Architecture Improvements (1-2 weeks)

#### 3.1 Add Application Load Balancer (ALB) with Auto-Scaling

```
                    ┌─── EC2 Instance 1 (API)
User → ALB ────────┼─── EC2 Instance 2 (API)
                    └─── EC2 Instance 3 (API)
                              │
                    ┌─── RDS PostgreSQL
                    ├─── DocumentDB/MongoDB Atlas
                    └─── ElastiCache Redis
```

Auto-scaling policy: Scale out when CPU > 60% for 2 minutes.

#### 3.2 Migrate to Managed Database Services
- **RDS PostgreSQL** — connection management, read replicas, automated backups
- **MongoDB Atlas** or **DocumentDB** — auto-scaling storage, built-in indexes
- **ElastiCache Redis** — session store, rate limit state, API cache

#### 3.3 Add CloudFront CDN for Frontend
**Impact:** <50ms frontend load globally, offload static asset serving  

#### 3.4 Containerize with ECS/Fargate
**Impact:** Easy horizontal scaling, rolling deployments, resource isolation  

---

## Rate Limiting Observations

The rate limiter (20 req/30s per IP) works correctly but has implications for load testing:

| Observation | Detail |
|-------------|--------|
| Rate limiter is per-IP | All load test traffic from one IP hits the same limit |
| Auth endpoints are rate-limited | `/login`, `/signup`, `/send_code` correctly limited |
| Read endpoints are NOT rate-limited at failure threshold | Dashboard/scan listing endpoints never returned 429 |
| Rate limit response time stays fast | 429 responses are immediate (<50ms), not queued |

**Production Recommendation:** The rate limiter is well-configured. For multi-user production traffic (each user from their own IP), rate limiting will not be a bottleneck.

---

## Test Configuration

```
Tool:            Locust 2.37.4
Target:          https://devsecshieldapi.zeroshield.ai
Server:          EC2 t3a.medium (2 vCPU, 4 GB RAM)
TLS:             Verified (SSL warnings suppressed for test)

Load Levels:
  Level 1:  10 users,  spawn rate  2/s, duration 5m
  Level 2:  50 users,  spawn rate  5/s, duration 5m
  Level 3: 100 users,  spawn rate 10/s, duration 5m
  Level 4: 500 users,  spawn rate 25/s, duration 5m
  Level 5: 1000 users, spawn rate 50/s, duration 5m

Cooldown: 15 seconds between levels

User Classes:
  PublicEndpointUser (weight=2):  /docs, /openapi.json, invalid login/auth
  AuthenticatedUser  (weight=8):  Full workflow (auth, teams, scans, guardrails, CICD, admin)

Endpoints Tested (32):
  Auth:       /send_code, /signup, /login, /refresh, /get_user, /reset_password, /logout
  Teams:      /teams, /team/{id}, /team (create/update), /team/{id}/dashboard, /teams/dashboard
  Scans:      /{team_id}/{type}/scans, /{team_id}/{type}/scan/{id} (get/create/update)
  Guardrails: /guardrails/{team_id}/integrations, /guardrails/{team_id}/integration (create)
  CI/CD:      /{team_id}/cicd/integrations, /{team_id}/cicd/integration (create)
  Admin:      /admin/check_superuser, /admin/teams, /admin/users
  Health:     /docs, /openapi.json
```

---

## Raw Data Reference

All raw CSV data, HTML reports, and log files are available in:
```
load_testing/results/
├── level_1_stats.csv          # Per-endpoint stats (10 users)
├── level_1_failures.csv       # Failure details
├── level_1_stats_history.csv  # Time-series data
├── level_1_report.html        # Interactive HTML report
├── level_2_*                  # 50 users
├── level_3_*                  # 100 users
├── level_4_*                  # 500 users
└── level_5_*                  # 1000 users
```

---

## Conclusion

The DevSecShield API on a single EC2 t3a.medium instance:

1. **Handles 100 concurrent users comfortably** (sub-200ms avg response)
2. **Begins degrading at 500 users** (1.5s avg response — noticeable but functional)
3. **Becomes unusable at 1000 users** (6s avg response — users will abandon)
4. **Never crashes** — the server is resilient but becomes slow under load
5. **Rate limiting works correctly** — protecting against abuse
6. **Peak throughput is ~116 RPS** — limited by single-process architecture

**Immediate priority:** Add Gunicorn multi-worker setup (5 minutes, 2-4x improvement) and offload blocking operations (bcrypt, email). This alone should push the comfortable capacity to 200-300 concurrent users on the same hardware.

**For 500+ users:** Horizontal scaling with ALB + auto-scaling group + managed databases is required.

---

*Report generated on April 1, 2026 by DevSecShield Load Testing Suite*  
*Contact: Infrastructure Team | Tool: Locust 2.37.4*
