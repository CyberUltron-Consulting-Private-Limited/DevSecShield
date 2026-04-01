#!/usr/bin/env python3
"""
DevSecShield Production Load Test Runner
=========================================
Orchestrates incremental load testing: 10 → 50 → 100 → 500 → 1000 concurrent users
Each level runs for 5 minutes with a 30-second ramp-up
Generates CSV stats and a comprehensive Markdown report
"""

import os
import sys
import csv
import json
import time
import subprocess
import datetime
from pathlib import Path

# ────────────────────────────────────────────────────────────────────────────────
# Configuration
# ────────────────────────────────────────────────────────────────────────────────
API_HOST = "https://devsecshieldapi.zeroshield.ai"
LOCUSTFILE = os.path.join(os.path.dirname(os.path.abspath(__file__)), "locustfile.py")
RESULTS_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "results")

LOAD_LEVELS = [
    {"users": 10, "spawn_rate": 2, "duration": "5m", "label": "Level 1 - Light (10 users)"},
    {"users": 50, "spawn_rate": 5, "duration": "5m", "label": "Level 2 - Moderate (50 users)"},
    {"users": 100, "spawn_rate": 10, "duration": "5m", "label": "Level 3 - Medium (100 users)"},
    {"users": 500, "spawn_rate": 25, "duration": "5m", "label": "Level 4 - Heavy (500 users)"},
    {"users": 1000, "spawn_rate": 50, "duration": "5m", "label": "Level 5 - Stress (1000 users)"},
]


def ensure_results_dir():
    Path(RESULTS_DIR).mkdir(parents=True, exist_ok=True)


def run_load_level(level_config, level_num):
    """Run a single load level test using Locust CLI in headless mode."""
    prefix = os.path.join(RESULTS_DIR, f"level_{level_num}")

    cmd = [
        sys.executable, "-m", "locust",
        "-f", LOCUSTFILE,
        "--host", API_HOST,
        "--headless",
        "--users", str(level_config["users"]),
        "--spawn-rate", str(level_config["spawn_rate"]),
        "--run-time", level_config["duration"],
        "--csv", prefix,
        "--csv-full-history",
        "--html", f"{prefix}_report.html",
        "--skip-log-setup",
        "--only-summary",
    ]

    print(f"\n{'='*80}")
    print(f"  {level_config['label']}")
    print(f"  Users: {level_config['users']} | Spawn Rate: {level_config['spawn_rate']}/s | Duration: {level_config['duration']}")
    print(f"{'='*80}\n")

    start_time = time.time()
    result = subprocess.run(
        cmd,
        capture_output=True,
        text=True,
        cwd=os.path.dirname(os.path.abspath(__file__)),
    )
    elapsed = time.time() - start_time

    # Save stdout/stderr
    with open(f"{prefix}_stdout.txt", "w") as f:
        f.write(result.stdout)
    with open(f"{prefix}_stderr.txt", "w") as f:
        f.write(result.stderr)

    print(f"\n  Completed in {elapsed:.1f}s (exit code: {result.returncode})")
    if result.returncode != 0:
        print(f"  STDERR (last 500 chars): {result.stderr[-500:]}")

    # Print summary from stdout
    for line in result.stdout.split("\n"):
        if any(kw in line.lower() for kw in ["aggregated", "type", "name", "# reqs", "avg", "fails"]):
            print(f"  {line}")

    return {
        "level": level_num,
        "label": level_config["label"],
        "users": level_config["users"],
        "spawn_rate": level_config["spawn_rate"],
        "duration": level_config["duration"],
        "elapsed_seconds": elapsed,
        "exit_code": result.returncode,
        "stdout": result.stdout,
        "stderr": result.stderr,
        "prefix": prefix,
    }


def parse_csv_stats(prefix):
    """Parse Locust CSV output files for a given level."""
    stats_file = f"{prefix}_stats.csv"
    failures_file = f"{prefix}_failures.csv"
    stats_history_file = f"{prefix}_stats_history.csv"

    stats = []
    failures = []
    history = []

    if os.path.exists(stats_file):
        with open(stats_file, "r") as f:
            reader = csv.DictReader(f)
            for row in reader:
                stats.append(row)

    if os.path.exists(failures_file):
        with open(failures_file, "r") as f:
            reader = csv.DictReader(f)
            for row in reader:
                failures.append(row)

    if os.path.exists(stats_history_file):
        with open(stats_history_file, "r") as f:
            reader = csv.DictReader(f)
            for row in reader:
                history.append(row)

    return {"stats": stats, "failures": failures, "history": history}


def generate_markdown_report(all_results):
    """Generate comprehensive Markdown report from all load test results."""
    now = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    report = []
    report.append("# DevSecShield Production Load Test Report")
    report.append(f"\n**Date:** {now}")
    report.append(f"**Target:** `{API_HOST}`")
    report.append(f"**Server:** EC2 t3a.medium (2 vCPU, 4GB RAM)")
    report.append(f"**Load Levels:** {len(LOAD_LEVELS)} (10 → 50 → 100 → 500 → 1000 concurrent users)")
    report.append(f"**Duration per Level:** 5 minutes")
    report.append(f"**Total Test Duration:** ~25 minutes + ramp-up time")
    report.append("")

    # ─── Executive Summary ───────────────────────────────────────────────────
    report.append("## Executive Summary\n")

    total_requests = 0
    total_failures = 0
    overall_avg_response = 0
    level_summaries = []

    for result in all_results:
        csv_data = parse_csv_stats(result["prefix"])
        agg_row = None
        for row in csv_data["stats"]:
            if row.get("Type") == "" or row.get("Name", "").lower() == "aggregated":
                agg_row = row
                break
        # Try the last row as aggregate
        if not agg_row and csv_data["stats"]:
            agg_row = csv_data["stats"][-1]

        if agg_row:
            reqs = int(agg_row.get("Request Count", agg_row.get("# Requests", 0)))
            fails = int(agg_row.get("Failure Count", agg_row.get("# Failures", 0)))
            avg_rt = float(agg_row.get("Average Response Time", agg_row.get("Average response time", 0)))
            median_rt = float(agg_row.get("Median Response Time", agg_row.get("Median response time", 0)))
            p95 = float(agg_row.get("95%", agg_row.get("95th percentile", 0)))
            p99 = float(agg_row.get("99%", agg_row.get("99th percentile", 0)))
            rps = float(agg_row.get("Requests/s", agg_row.get("Requests per second", 0)))
            max_rt = float(agg_row.get("Max Response Time", agg_row.get("Max response time", 0)))
            min_rt = float(agg_row.get("Min Response Time", agg_row.get("Min response time", 0)))
            fail_pct = (fails / reqs * 100) if reqs > 0 else 0

            total_requests += reqs
            total_failures += fails

            level_summaries.append({
                "level": result["label"],
                "users": result["users"],
                "total_requests": reqs,
                "failures": fails,
                "fail_pct": fail_pct,
                "avg_response_ms": avg_rt,
                "median_ms": median_rt,
                "p95_ms": p95,
                "p99_ms": p99,
                "max_ms": max_rt,
                "min_ms": min_rt,
                "rps": rps,
                "csv_data": csv_data,
            })
        else:
            level_summaries.append({
                "level": result["label"],
                "users": result["users"],
                "total_requests": 0,
                "failures": 0,
                "fail_pct": 0,
                "avg_response_ms": 0,
                "median_ms": 0,
                "p95_ms": 0,
                "p99_ms": 0,
                "max_ms": 0,
                "min_ms": 0,
                "rps": 0,
                "csv_data": csv_data,
            })

    overall_fail_pct = (total_failures / total_requests * 100) if total_requests > 0 else 0
    report.append(f"| Metric | Value |")
    report.append(f"|--------|-------|")
    report.append(f"| Total Requests | {total_requests:,} |")
    report.append(f"| Total Failures | {total_failures:,} |")
    report.append(f"| Overall Failure Rate | {overall_fail_pct:.2f}% |")
    report.append(f"| Load Levels Tested | {len(LOAD_LEVELS)} |")
    report.append("")

    # ─── Summary by Load Level ───────────────────────────────────────────────
    report.append("## Summary by Load Level\n")
    report.append("| Level | Users | Total Reqs | Failures | Fail % | Avg (ms) | Median (ms) | P95 (ms) | P99 (ms) | Max (ms) | RPS |")
    report.append("|-------|-------|-----------|----------|--------|----------|-------------|----------|----------|----------|-----|")
    for s in level_summaries:
        status = "✅" if s["fail_pct"] < 5 else ("⚠️" if s["fail_pct"] < 20 else "❌")
        report.append(
            f"| {status} {s['level']} | {s['users']} | {s['total_requests']:,} | "
            f"{s['failures']:,} | {s['fail_pct']:.1f}% | {s['avg_response_ms']:.0f} | "
            f"{s['median_ms']:.0f} | {s['p95_ms']:.0f} | {s['p99_ms']:.0f} | "
            f"{s['max_ms']:.0f} | {s['rps']:.1f} |"
        )
    report.append("")

    # ─── Detailed Results per Level ──────────────────────────────────────────
    report.append("## Detailed Results by Load Level\n")

    for i, s in enumerate(level_summaries):
        report.append(f"### {s['level']}\n")

        # Performance classification
        if s["avg_response_ms"] < 200:
            perf = "🟢 Excellent"
        elif s["avg_response_ms"] < 500:
            perf = "🟡 Acceptable"
        elif s["avg_response_ms"] < 1000:
            perf = "🟠 Degraded"
        else:
            perf = "🔴 Poor"

        report.append(f"**Performance Rating:** {perf}\n")
        report.append(f"| Metric | Value |")
        report.append(f"|--------|-------|")
        report.append(f"| Concurrent Users | {s['users']} |")
        report.append(f"| Total Requests | {s['total_requests']:,} |")
        report.append(f"| Failed Requests | {s['failures']:,} ({s['fail_pct']:.1f}%) |")
        report.append(f"| Avg Response Time | {s['avg_response_ms']:.0f} ms |")
        report.append(f"| Median Response Time | {s['median_ms']:.0f} ms |")
        report.append(f"| 95th Percentile | {s['p95_ms']:.0f} ms |")
        report.append(f"| 99th Percentile | {s['p99_ms']:.0f} ms |")
        report.append(f"| Min Response Time | {s['min_ms']:.0f} ms |")
        report.append(f"| Max Response Time | {s['max_ms']:.0f} ms |")
        report.append(f"| Requests/sec | {s['rps']:.1f} |")
        report.append("")

        # Per-endpoint breakdown
        endpoint_rows = [r for r in s["csv_data"]["stats"]
                        if r.get("Name", "").lower() != "aggregated" and r.get("Type", "") != ""]
        if endpoint_rows:
            report.append(f"#### Endpoint Breakdown\n")
            report.append("| Method | Endpoint | Reqs | Fails | Avg (ms) | P95 (ms) | Max (ms) | RPS |")
            report.append("|--------|----------|------|-------|----------|----------|----------|-----|")
            for row in endpoint_rows:
                name = row.get("Name", "?")
                method = row.get("Type", "?")
                reqs = int(row.get("Request Count", row.get("# Requests", 0)))
                fails = int(row.get("Failure Count", row.get("# Failures", 0)))
                avg = float(row.get("Average Response Time", row.get("Average response time", 0)))
                p95 = float(row.get("95%", row.get("95th percentile", 0)))
                maxr = float(row.get("Max Response Time", row.get("Max response time", 0)))
                rps = float(row.get("Requests/s", row.get("Requests per second", 0)))
                report.append(f"| {method} | `{name}` | {reqs} | {fails} | {avg:.0f} | {p95:.0f} | {maxr:.0f} | {rps:.1f} |")
            report.append("")

        # Failures detail
        if s["csv_data"]["failures"]:
            report.append(f"#### Failures Detail\n")
            report.append("| Method | Endpoint | Error | Occurrences |")
            report.append("|--------|----------|-------|-------------|")
            for fail in s["csv_data"]["failures"]:
                method = fail.get("Method", "?")
                name = fail.get("Name", "?")
                error = fail.get("Error", fail.get("Message", "Unknown"))
                count = fail.get("Occurrences", fail.get("# Occurrences", "?"))
                # Truncate long errors
                if len(str(error)) > 120:
                    error = str(error)[:120] + "..."
                report.append(f"| {method} | `{name}` | {error} | {count} |")
            report.append("")

    # ─── Failure Analysis ────────────────────────────────────────────────────
    report.append("## Failure Analysis\n")

    # Collect all failures across levels
    all_failures = {}
    for i, s in enumerate(level_summaries):
        for fail in s["csv_data"]["failures"]:
            key = f"{fail.get('Method', '?')} {fail.get('Name', '?')}"
            error = fail.get("Error", fail.get("Message", "Unknown"))
            if key not in all_failures:
                all_failures[key] = {"errors": {}, "levels_affected": []}
            if error not in all_failures[key]["errors"]:
                all_failures[key]["errors"][error] = 0
            all_failures[key]["errors"][error] += int(fail.get("Occurrences", fail.get("# Occurrences", 0)))
            all_failures[key]["levels_affected"].append(s["level"])

    if all_failures:
        report.append("### Failure Categories\n")
        for endpoint, data in all_failures.items():
            report.append(f"#### `{endpoint}`\n")
            report.append(f"**Affected Load Levels:** {', '.join(set(data['levels_affected']))}\n")
            for error, count in data["errors"].items():
                report.append(f"- **Error:** `{error[:200]}`")
                report.append(f"  - **Total Occurrences:** {count}")
            report.append("")
    else:
        report.append("No failures detected across all load levels.\n")

    # ─── Root Cause Analysis ─────────────────────────────────────────────────
    report.append("## Root Cause Analysis\n")

    # Analyze patterns
    report.append("### Performance Degradation Pattern\n")

    if len(level_summaries) >= 2:
        # Check where performance starts degrading
        degradation_level = None
        for i in range(1, len(level_summaries)):
            curr = level_summaries[i]
            prev = level_summaries[i - 1]
            if prev["avg_response_ms"] > 0:
                increase = (curr["avg_response_ms"] - prev["avg_response_ms"]) / prev["avg_response_ms"] * 100
                if increase > 50:
                    degradation_level = curr
                    report.append(
                        f"- **Significant degradation detected at {curr['users']} users**: "
                        f"avg response time increased by {increase:.0f}% "
                        f"(from {prev['avg_response_ms']:.0f}ms to {curr['avg_response_ms']:.0f}ms)\n"
                    )

        if not degradation_level:
            report.append("- No significant performance degradation detected between load levels.\n")

    # Identify potential bottlenecks
    report.append("### Potential Bottlenecks\n")
    report.append("""
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
""")

    # ─── Recommendations ─────────────────────────────────────────────────────
    report.append("## Recommendations\n")

    report.append("### Immediate Fixes (Priority 1)\n")
    report.append("""
| # | Action | Expected Impact | Effort |
|---|--------|-----------------|--------|
| 1 | **Add Uvicorn workers** (`uvicorn main:app --workers 4`) | 2-3x throughput increase | Low |
| 2 | **Increase PostgreSQL `max_connections`** to 200+ | Eliminate connection pool exhaustion | Low |
| 3 | **Add connection pooling** (PgBouncer) | 5-10x connection reuse efficiency | Medium |
| 4 | **Upgrade to t3a.large** (or xlarge) | 2-4x CPU/memory headroom | Low |
| 5 | **Configure Gunicorn** with worker class `uvicorn.workers.UvicornWorker` | Production-grade process management | Low |
""")

    report.append("### Short-Term Improvements (Priority 2)\n")
    report.append("""
| # | Action | Expected Impact | Effort |
|---|--------|-----------------|--------|
| 1 | **Add Redis caching** for dashboard/team queries | 50-80% latency reduction on reads | Medium |
| 2 | **Move Celery workers to separate instance(s)** | Eliminate resource contention | Medium |
| 3 | **Add ALB (Application Load Balancer)** with 2+ instances | Linear horizontal scaling | Medium |
| 4 | **Implement API response caching** (stale-while-revalidate) | Reduces DB load by 60-80% | Medium |
| 5 | **Add health check endpoint** (`/health`) without auth | Proper monitoring and ALB health checks | Low |
""")

    report.append("### Long-Term Architecture (Priority 3)\n")
    report.append("""
| # | Action | Expected Impact | Effort |
|---|--------|-----------------|--------|
| 1 | **Auto-scaling group** with min=2, max=8 instances | Handle traffic spikes automatically | High |
| 2 | **RDS (Managed PostgreSQL)** instead of self-hosted | Connection management, backups, replicas | Medium |
| 3 | **ElastiCache (Redis)** for session/rate-limit state | Distributed rate limiting and caching | Medium |
| 4 | **CloudFront CDN** for frontend + API caching | Global latency reduction | Medium |
| 5 | **Container orchestration** (ECS/EKS) | Better resource utilization, rolling deployments | High |
| 6 | **Read replicas for PostgreSQL** | Offload read-heavy dashboard queries | Medium |
| 7 | **MongoDB Atlas** (managed) with proper indexes | Query optimization, auto-scaling storage | Medium |
""")

    # ─── Capacity Planning ───────────────────────────────────────────────────
    report.append("## Capacity Planning Estimates\n")
    report.append("""
Based on the t3a.medium instance (2 vCPU, 4 GB RAM):

| Scenario | Est. Max Concurrent Users | Recommended Instance | Notes |
|----------|--------------------------|---------------------|-------|
| Development/Staging | 10-20 | t3a.medium | Current setup |
| Small Production (< 50 users) | 30-50 | t3a.large | 2 vCPU, 8 GB RAM |
| Medium Production (< 200 users) | 100-200 | t3a.xlarge + RDS | 4 vCPU, 16 GB RAM |
| Large Production (< 1000 users) | 500-1000 | 2x t3a.xlarge + ALB + RDS | Horizontal scaling |
| Enterprise (1000+ users) | 1000+ | Auto-scaling group + managed services | Full cloud-native |
""")

    # ─── Test Configuration Reference ────────────────────────────────────────
    report.append("## Test Configuration Reference\n")
    report.append(f"""
```
Target: {API_HOST}
Server: EC2 t3a.medium (2 vCPU, 4 GB RAM)
Tool: Locust {get_locust_version()}
Load Levels:
  Level 1: 10 users, spawn rate 2/s, duration 5m
  Level 2: 50 users, spawn rate 5/s, duration 5m
  Level 3: 100 users, spawn rate 10/s, duration 5m
  Level 4: 500 users, spawn rate 25/s, duration 5m
  Level 5: 1000 users, spawn rate 50/s, duration 5m

Endpoints Tested:
  - Auth: /send_code, /signup, /login, /refresh, /get_user, /reset_password, /logout
  - Teams: /teams, /team/{{id}}, /team/{{id}}/dashboard, /teams/dashboard, create/update
  - Scans: /{{team_id}}/{{type}}/scans, /{{team_id}}/{{type}}/scan/{{id}}, create/update
  - Guardrails: /guardrails/{{team_id}}/integrations, create
  - CI/CD: /{{team_id}}/cicd/integrations, create
  - Admin: /admin/check_superuser, /admin/teams, /admin/users
  - Public: /docs, /openapi.json
```
""")

    report.append("---\n")
    report.append(f"*Report generated on {now} by DevSecShield Load Testing Suite*\n")

    return "\n".join(report)


def get_locust_version():
    try:
        import locust
        return locust.__version__
    except Exception:
        return "unknown"


def main():
    print("\n" + "=" * 80)
    print("  DevSecShield Production Load Testing Suite")
    print(f"  Target: {API_HOST}")
    print(f"  Levels: {len(LOAD_LEVELS)} (10 → 50 → 100 → 500 → 1000 users)")
    print("=" * 80 + "\n")

    ensure_results_dir()

    all_results = []
    for i, level in enumerate(LOAD_LEVELS, 1):
        print(f"\n🚀 Starting {level['label']}...")
        result = run_load_level(level, i)
        all_results.append(result)

        # Brief pause between levels to let the server recover
        if i < len(LOAD_LEVELS):
            print(f"\n⏸  Cooling down for 15 seconds before next level...")
            time.sleep(15)

    # Generate report
    print(f"\n\n📊 Generating comprehensive report...")
    report = generate_markdown_report(all_results)

    report_path = os.path.join(RESULTS_DIR, "LOAD_TEST_REPORT.md")
    with open(report_path, "w") as f:
        f.write(report)

    print(f"\n✅ Report saved to: {report_path}")
    print(f"📁 CSV data saved to: {RESULTS_DIR}/")

    # Also save to project root for easy access
    root_report = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "LOAD_TEST_REPORT.md")
    with open(root_report, "w") as f:
        f.write(report)
    print(f"📄 Report also saved to: {root_report}")

    return report_path


if __name__ == "__main__":
    main()
