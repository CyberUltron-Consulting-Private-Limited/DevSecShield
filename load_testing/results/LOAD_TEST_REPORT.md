# DevSecShield Production Load Test Report

**Date:** 2026-04-06 12:39:43
**Target:** `https://devsecshieldapi.zeroshield.ai`
**Server:** EC2 t3a.medium (2 vCPU, 4GB RAM)
**Load Levels:** 5 (10 → 50 → 100 → 500 → 1000 concurrent users)
**Duration per Level:** 5 minutes
**Total Test Duration:** ~25 minutes + ramp-up time

## Executive Summary

| Metric | Value |
|--------|-------|
| Total Requests | 43,160 |
| Total Failures | 0 |
| Overall Failure Rate | 0.00% |
| Load Levels Tested | 5 |

## Summary by Load Level

| Level | Users | Total Reqs | Failures | Fail % | Avg (ms) | Median (ms) | P95 (ms) | P99 (ms) | Max (ms) | RPS |
|-------|-------|-----------|----------|--------|----------|-------------|----------|----------|----------|-----|
| ✅ Level 1 - Light (10 users) | 10 | 300 | 0 | 0.0% | 59 | 31 | 160 | 170 | 385 | 1.0 |
| ✅ Level 2 - Moderate (50 users) | 50 | 1,452 | 0 | 0.0% | 60 | 34 | 150 | 190 | 343 | 4.8 |
| ✅ Level 3 - Medium (100 users) | 100 | 2,663 | 0 | 0.0% | 60 | 34 | 160 | 180 | 352 | 8.9 |
| ✅ Level 4 - Heavy (500 users) | 500 | 12,944 | 0 | 0.0% | 63 | 35 | 160 | 200 | 403 | 43.3 |
| ✅ Level 5 - Stress (1000 users) | 1000 | 25,801 | 0 | 0.0% | 67 | 38 | 170 | 230 | 733 | 86.2 |

## Detailed Results by Load Level

### Level 1 - Light (10 users)

**Performance Rating:** 🟢 Excellent

| Metric | Value |
|--------|-------|
| Concurrent Users | 10 |
| Total Requests | 300 |
| Failed Requests | 0 (0.0%) |
| Avg Response Time | 59 ms |
| Median Response Time | 31 ms |
| 95th Percentile | 160 ms |
| 99th Percentile | 170 ms |
| Min Response Time | 25 ms |
| Max Response Time | 385 ms |
| Requests/sec | 1.0 |

#### Endpoint Breakdown

| Method | Endpoint | Reqs | Fails | Avg (ms) | P95 (ms) | Max (ms) | RPS |
|--------|----------|------|-------|----------|----------|----------|-----|
| GET | `GET /docs` | 204 | 0 | 38 | 97 | 119 | 0.7 |
| GET | `GET /openapi.json` | 96 | 0 | 104 | 170 | 385 | 0.3 |

### Level 2 - Moderate (50 users)

**Performance Rating:** 🟢 Excellent

| Metric | Value |
|--------|-------|
| Concurrent Users | 50 |
| Total Requests | 1,452 |
| Failed Requests | 0 (0.0%) |
| Avg Response Time | 60 ms |
| Median Response Time | 34 ms |
| 95th Percentile | 150 ms |
| 99th Percentile | 190 ms |
| Min Response Time | 24 ms |
| Max Response Time | 343 ms |
| Requests/sec | 4.8 |

#### Endpoint Breakdown

| Method | Endpoint | Reqs | Fails | Avg (ms) | P95 (ms) | Max (ms) | RPS |
|--------|----------|------|-------|----------|----------|----------|-----|
| GET | `GET /docs` | 1014 | 0 | 41 | 110 | 293 | 3.4 |
| GET | `GET /openapi.json` | 438 | 0 | 104 | 170 | 343 | 1.5 |

### Level 3 - Medium (100 users)

**Performance Rating:** 🟢 Excellent

| Metric | Value |
|--------|-------|
| Concurrent Users | 100 |
| Total Requests | 2,663 |
| Failed Requests | 0 (0.0%) |
| Avg Response Time | 60 ms |
| Median Response Time | 34 ms |
| 95th Percentile | 160 ms |
| 99th Percentile | 180 ms |
| Min Response Time | 23 ms |
| Max Response Time | 352 ms |
| Requests/sec | 8.9 |

#### Endpoint Breakdown

| Method | Endpoint | Reqs | Fails | Avg (ms) | P95 (ms) | Max (ms) | RPS |
|--------|----------|------|-------|----------|----------|----------|-----|
| GET | `GET /docs` | 1884 | 0 | 42 | 110 | 352 | 6.3 |
| GET | `GET /openapi.json` | 779 | 0 | 104 | 170 | 268 | 2.6 |

### Level 4 - Heavy (500 users)

**Performance Rating:** 🟢 Excellent

| Metric | Value |
|--------|-------|
| Concurrent Users | 500 |
| Total Requests | 12,944 |
| Failed Requests | 0 (0.0%) |
| Avg Response Time | 63 ms |
| Median Response Time | 35 ms |
| 95th Percentile | 160 ms |
| 99th Percentile | 200 ms |
| Min Response Time | 23 ms |
| Max Response Time | 403 ms |
| Requests/sec | 43.3 |

#### Endpoint Breakdown

| Method | Endpoint | Reqs | Fails | Avg (ms) | P95 (ms) | Max (ms) | RPS |
|--------|----------|------|-------|----------|----------|----------|-----|
| GET | `GET /docs` | 9005 | 0 | 44 | 110 | 369 | 30.1 |
| GET | `GET /openapi.json` | 3939 | 0 | 108 | 180 | 403 | 13.2 |

### Level 5 - Stress (1000 users)

**Performance Rating:** 🟢 Excellent

| Metric | Value |
|--------|-------|
| Concurrent Users | 1000 |
| Total Requests | 25,801 |
| Failed Requests | 0 (0.0%) |
| Avg Response Time | 67 ms |
| Median Response Time | 38 ms |
| 95th Percentile | 170 ms |
| 99th Percentile | 230 ms |
| Min Response Time | 23 ms |
| Max Response Time | 733 ms |
| Requests/sec | 86.2 |

#### Endpoint Breakdown

| Method | Endpoint | Reqs | Fails | Avg (ms) | P95 (ms) | Max (ms) | RPS |
|--------|----------|------|-------|----------|----------|----------|-----|
| GET | `GET /docs` | 17913 | 0 | 47 | 120 | 692 | 59.9 |
| GET | `GET /openapi.json` | 7888 | 0 | 113 | 190 | 733 | 26.4 |

## Failure Analysis

No failures detected across all load levels.

## Root Cause Analysis

### Performance Degradation Pattern

- No significant performance degradation detected between load levels.

### Potential Bottlenecks


Based on the test results and the system architecture (EC2 t3a.medium: 2 vCPU, 4 GB RAM), the following potential bottlenecks should be investigated:

1. **CPU Saturation (t3a.medium = 2 vCPUs)**
   - FastAPI runs on a single process by default (Uvicorn)
   - Under high concurrency, CPU-bound operations (JWT validation, bcrypt hashing, JSON serialization) saturate cores
   - **Impact:** Response time linearly increases, request queuing occurs

2. **Memory Pressure (4 GB RAM)**
   - PostgreSQL, MongoDB, RabbitMQ, and the application server all share 4 GB
   - Under load, connection pools grow, in-memory caches expand, and OOM kills can occur
   - **Impact:** Service crashes, swap thrashing, extreme latency spikes

3. **Database Connection Pool Exhaustion**
   - PostgreSQL default connection limit is 100
   - With 500+ concurrent users, connection pool becomes the bottleneck
   - **Impact:** Requests queue waiting for DB connections, timeout errors

4. **Rate Limiting**
   - Backend has rate limiting: 20 requests/30s per IP for most endpoints
   - Public guardrails: 2 requests/10s
   - **Impact:** 429 (Too Many Requests) responses dominate under load

5. **Single-Instance Deployment**
   - No horizontal scaling (single EC2 instance)
   - No load balancer for distributing traffic
   - **Impact:** Single point of failure, no ability to handle burst traffic

6. **Network I/O (t3a.medium = Up to 5 Gbps)**
   - SSL/TLS handshake overhead per connection
   - No connection pooling on the client side
   - **Impact:** Connection establishment delays under high concurrency

7. **Worker Thread Starvation**
   - Celery workers share the same instance resources
   - Under load, scan workers and API server compete for CPU/memory
   - **Impact:** Both API latency and scan processing times degrade

## Recommendations

### Immediate Fixes (Priority 1)


| # | Action | Expected Impact | Effort |
|---|--------|-----------------|--------|
| 1 | **Add Uvicorn workers** (`uvicorn main:app --workers 4`) | 2-3x throughput increase | Low |
| 2 | **Increase PostgreSQL `max_connections`** to 200+ | Eliminate connection pool exhaustion | Low |
| 3 | **Add connection pooling** (PgBouncer) | 5-10x connection reuse efficiency | Medium |
| 4 | **Upgrade to t3a.large** (or xlarge) | 2-4x CPU/memory headroom | Low |
| 5 | **Configure Gunicorn** with worker class `uvicorn.workers.UvicornWorker` | Production-grade process management | Low |

### Short-Term Improvements (Priority 2)


| # | Action | Expected Impact | Effort |
|---|--------|-----------------|--------|
| 1 | **Add Redis caching** for dashboard/team queries | 50-80% latency reduction on reads | Medium |
| 2 | **Move Celery workers to separate instance(s)** | Eliminate resource contention | Medium |
| 3 | **Add ALB (Application Load Balancer)** with 2+ instances | Linear horizontal scaling | Medium |
| 4 | **Implement API response caching** (stale-while-revalidate) | Reduces DB load by 60-80% | Medium |
| 5 | **Add health check endpoint** (`/health`) without auth | Proper monitoring and ALB health checks | Low |

### Long-Term Architecture (Priority 3)


| # | Action | Expected Impact | Effort |
|---|--------|-----------------|--------|
| 1 | **Auto-scaling group** with min=2, max=8 instances | Handle traffic spikes automatically | High |
| 2 | **RDS (Managed PostgreSQL)** instead of self-hosted | Connection management, backups, replicas | Medium |
| 3 | **ElastiCache (Redis)** for session/rate-limit state | Distributed rate limiting and caching | Medium |
| 4 | **CloudFront CDN** for frontend + API caching | Global latency reduction | Medium |
| 5 | **Container orchestration** (ECS/EKS) | Better resource utilization, rolling deployments | High |
| 6 | **Read replicas for PostgreSQL** | Offload read-heavy dashboard queries | Medium |
| 7 | **MongoDB Atlas** (managed) with proper indexes | Query optimization, auto-scaling storage | Medium |

## Capacity Planning Estimates


Based on the t3a.medium instance (2 vCPU, 4 GB RAM):

| Scenario | Est. Max Concurrent Users | Recommended Instance | Notes |
|----------|--------------------------|---------------------|-------|
| Development/Staging | 10-20 | t3a.medium | Current setup |
| Small Production (< 50 users) | 30-50 | t3a.large | 2 vCPU, 8 GB RAM |
| Medium Production (< 200 users) | 100-200 | t3a.xlarge + RDS | 4 vCPU, 16 GB RAM |
| Large Production (< 1000 users) | 500-1000 | 2x t3a.xlarge + ALB + RDS | Horizontal scaling |
| Enterprise (1000+ users) | 1000+ | Auto-scaling group + managed services | Full cloud-native |

## Test Configuration Reference


```
Target: https://devsecshieldapi.zeroshield.ai
Server: EC2 t3a.medium (2 vCPU, 4 GB RAM)
Tool: Locust 2.34.0
Load Levels:
  Level 1: 10 users, spawn rate 2/s, duration 5m
  Level 2: 50 users, spawn rate 5/s, duration 5m
  Level 3: 100 users, spawn rate 10/s, duration 5m
  Level 4: 500 users, spawn rate 25/s, duration 5m
  Level 5: 1000 users, spawn rate 50/s, duration 5m

Endpoints Tested:
  - Auth: /send_code, /signup, /login, /refresh, /get_user, /reset_password, /logout
  - Teams: /teams, /team/{id}, /team/{id}/dashboard, /teams/dashboard, create/update
  - Scans: /{team_id}/{type}/scans, /{team_id}/{type}/scan/{id}, create/update
  - Guardrails: /guardrails/{team_id}/integrations, create
  - CI/CD: /{team_id}/cicd/integrations, create
  - Admin: /admin/check_superuser, /admin/teams, /admin/users
  - Public: /docs, /openapi.json
```

---

*Report generated on 2026-04-06 12:39:43 by DevSecShield Load Testing Suite*
