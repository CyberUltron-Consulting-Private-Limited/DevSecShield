# ZeroShield — 90-Day Launch Playbook

**Author:** CTO  
**Date:** 2026-04-11  
**Version:** 1.0  
**Premise:** Solo developer, bus factor=1, building in the open. Budget: $300/mo (Phase 1). DevSecShield code reuse saves ~73h.  
**Scope:** npm changes feed monitor, SCA worker (Grype+OSV), tarball integrity, priority queue, PostgreSQL schema, basic API, GitHub Pages, PGP email.

---

## Table of Contents

1. [Week 1 Day-by-Day](#1-week-1-day-by-day)
2. [Weeks 2–4 Weekly Goals](#2-weeks-24-weekly-goals)
3. [Weeks 5–8 First Vulnerability](#3-weeks-58-first-vulnerability)
4. [Weeks 9–12 First CVE](#4-weeks-912-first-cve)
5. [Community Building (Parallel)](#5-community-building-parallel)
6. [Risk Contingencies](#6-risk-contingencies)
7. [Milestone Checkpoints (Go/No-Go)](#7-milestone-checkpoints-gonogo)
8. [Setup Checklist](#8-setup-checklist)

---

## 1. Week 1 Day-by-Day

Week 1 is the steel-thread week. The goal is a single scan running end-to-end on Day 7: npm package in → SCA findings out → PostgreSQL row written. Everything else is a distraction.

### Day 1 (Monday) — Project Skeleton + Infra Bootstrap

**Morning (4h):**
- **0:00–0:30** — Create GitHub repo `zeroshield/zeroshield` (public, Apache 2.0). Initialize with README, LICENSE, `.gitignore` (Python), `pyproject.toml` (uv/rye). **Done when:** `git clone` and `uv sync` succeeds locally.
- **0:30–1:30** — Extract DevSecShield Phase 1 foundation (enums, progress writer, qdrant utils) into `zeroshield/shared/`. These are zero-dependency copies. Rename imports. Run `python -c "from zeroshield.shared.enums import Impact"` successfully. **Effort saved: ~1.5h from DevSecShield.**
- **1:30–3:00** — Write `docker-compose.yml`: PostgreSQL 16-alpine (2CPU/2GB), MongoDB 7-alpine (2CPU/2GB), RabbitMQ 3.12-management (1CPU/512MB), Redis 7-alpine (512MB). All on `zeroshield-net`. Health checks. Persistent volumes. **Done when:** `docker compose up -d && docker compose ps` shows all healthy.
- **3:00–4:00** — Write PostgreSQL schema (`db/schema.sql`): `registry_state`, `monitored_targets`, `scan_jobs`, `advisories`, `disclosure_events`, `api_keys`, `scan_dlq`, `false_positive_patterns`. Apply with `psql -f schema.sql`. Add indexes on `(ecosystem, name)`, `(status)`, `(created_at)`. **Done when:** `\dt` shows all 8 tables.

**Afternoon (4h):**
- **4:00–5:30** — Extract DevSecShield Celery worker config pattern (`scan_worker.py` config block). Create `zeroshield/worker/celery_config.py` with RabbitMQ broker, MongoDB backend, `task_time_limit=900`, `task_acks_late=True`, `worker_prefetch_multiplier=1`. **Effort saved: ~3h.** **Done when:** `celery -A zeroshield.worker.celery_config worker --loglevel=info` connects to RabbitMQ.
- **5:30–7:00** — Create FastAPI skeleton (`zeroshield/api/main.py`). Mount `/api/v1/` prefix. Add `/health` returning `{"status": "ok", "version": "0.1.0"}`. Add CORS middleware. Wire `get_db()` session dependency (extract from DevSecShield `backend/get_db.py`, change connection string). **Effort saved: ~1h.** **Done when:** `curl localhost:8000/api/v1/health` returns 200.
- **7:00–8:00** — Write SQLAlchemy/SQLModel ORM models for `registry_state`, `monitored_targets`, `scan_jobs`. Map to schema.sql tables. **Done when:** `python -c "from zeroshield.db.models import MonitoredTarget; print(MonitoredTarget.__tablename__)"` succeeds.

**Blockers:** Docker daemon not running (fix: `open -a Docker`). PostgreSQL port 5432 in use (fix: change to 5433 in compose). RabbitMQ management port conflict (fix: 15673→15672).

**Definition of Done for Day 1:** GitHub repo exists. `docker compose up` starts 4 services. PostgreSQL has 8 tables. Celery worker connects to RabbitMQ. FastAPI returns `/health`. Total: ~8h.

---

### Day 2 (Tuesday) — npm Changes Feed Monitor

**Morning (4h):**
- **0:00–1:00** — Implement `zeroshield/orchestrator/npm_monitor.py`. Core function: `poll_changes_feed(since: int, limit: int = 2500) -> list[dict]`. HTTP GET to `https://replicate.npmjs.com/_changes?since={seq}&limit=2500&include_docs=true`. Parse JSON stream. Store `last_seq` in `registry_state` table. **Done when:** function returns 2500 change docs.
- **1:00–2:30** — Implement Celery Beat schedule. Create `zeroshield/orchestrator/scheduler.py`. Register `poll-npm-changes` task running every 30 seconds via `app.conf.beat_schedule`. Inside the task: call `poll_changes_feed()`, extract package names, bulk UPSERT into `monitored_targets`. Use `INSERT ... ON CONFLICT (ecosystem, name) DO UPDATE SET latest_version = EXCLUDED.latest_version`. **Done when:** Celery Beat runs and `SELECT count(*) FROM monitored_targets` increases every 30s.
- **2:30–4:00** — Add popularity tier enrichment stub. For now, just set all packages to `popularity_tier='C'`. Add TODO for weekly download count fetch from `api.npmjs.org/downloads/point/last-month/{pkg}`. Write a quick CLI command `python -m zeroshield.orchestrator.seed_top100` that fetches top 100 npm packages by downloads and inserts them as Tier A.

**Afternoon (4h):**
- **4:00–5:30** — Implement tarball download + integrity verification. `zeroshield/scanner/npm_scanner.py::download_tarball(name, version) -> Path`. Fetch `https://registry.npmjs.org/{name}/-/{name}-{version}.tgz`. Verify SHA512 against registry `integrity` field (base64-encoded `sha512-...`). Size check: reject >500MB. Extract to temp directory with zip-slip prevention (reject any path containing `..`). **Done when:** `download_tarball("lodash", "4.17.21")` succeeds and SHA512 matches.
- **5:30–7:00** — Write `scan_npm_package` Celery task. Accepts `(package_name, version)`. Creates `scan_jobs` row (status=RUNNING). Downloads tarball. Extracts. Returns file list. Updates `scan_jobs` (status=COMPLETED). Error path: updates status=FAILED, writes to `scan_dlq`. **Done when:** `scan_npm_package.delay("lodash", "4.17.21")` completes and `scan_jobs` has a row.
- **7:00–8:00** — Test the full chain manually: Beat discovers a package → task queued → worker downloads → integrity check passes → scan_jobs updated. Write a 5-step integration test shell script for this flow. Fix any issues.

**Blockers:** npm registry may require User-Agent header (fix: set `User-Agent: zeroshield/0.1.0`). CouchDB changes feed may timeout on large `since` values (fix: start from `seq=now`). SHA512 mismatch on scoped packages (fix: URL-encode `@scope/name`).

**Definition of Done for Day 2:** Changes feed polls every 30s. `monitored_targets` populates. Tarball download + SHA512 verification works. Celery task runs end-to-end. Total: ~8h.

---

### Day 3 (Wednesday) — SCA Worker (Grype + OSV)

**Morning (4h):**
- **0:00–1:30** — Install Grype binary. Download from GitHub releases, version-pin it. Create `zeroshield/scanner/sca_worker.py`. Implement `run_grype(tarball_dir: Path) -> list[dict]`. Shell out: `grype dir:{path} -o json`. Parse JSON output into list of `{cve_id, package, version, severity, description, fix_version}`. **Done when:** `run_grype(lodash_4.17.18_dir)` returns CVE-2018-16487, CVE-2020-8203, etc.
- **1:30–3:00** — Extract DevSecShield NVD API client (`output_model.py`). Rename database from `new_devsecshield_backend_server_db` → `zeroshield_db`. Keep the 4-tier caching (in-memory → MongoDB → NVD API → FallbackCVEEnum). Adapt for ecosystem-specific queries. **Effort saved: ~6h.** **Done when:** `fetch_cve("CVE-2020-8203")` returns CVSS score.
- **3:00–4:00** — Add OSV.dev batch query. Implement `query_osv_batch(packages: list[tuple[str,str]]) -> list[dict]`. POST to `https://api.osv.dev/v1/querybatch` with `{"queries": [{"package": {"name": n, "ecosystem": "npm"}, "version": v}]}`. Map response to same schema as Grype output.

**Afternoon (4h):**
- **4:00–5:30** — Merge SCA results. Create `merge_sca_findings(grype_results, osv_results) -> list[Finding]`. Deduplicate by CVE ID. Enrich with CVSS from NVD client. Mark if in CISA KEV (start with a static JSON file of KEV catalog, fetched once at startup from `https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json`).
- **5:30–7:00** — Extract DevSecShield vulnerability Pydantic models (`schema.py`). Keep `BaseVulnerability`, `DependencyVulnerability`. Strip `IACVulnerability`, `LLMBenchmarkingVulnerability`, `MCPVulnerability`, `CryptographicAssetVulnerability`. Add `zeroshield_id` field. **Effort saved: ~4h.** Wire SCA results into `DependencyVulnerability` model. Store merged findings in MongoDB `scan_findings` collection.
- **7:00–8:00** — Run the SCA worker against `lodash@4.17.18` (known vulnerable). Verify it finds at least 3 known CVEs. Run against `express@4.21.0` (current, should be clean or low-sev). Log results. Fix any parsing issues.

**Blockers:** Grype binary not available for ARM Mac (fix: use `grype` Go binary from Homebrew or x86 Docker). OSV.dev batch endpoint returns 400 on malformed queries (fix: validate package names). NVD API rate limit hit (fix: use API key from Day 1 setup).

**Definition of Done for Day 3:** SCA worker runs Grype + OSV + NVD enrichment. Findings stored in MongoDB. Known vulnerable packages (lodash@4.17.18) produce correct CVE matches. Total: ~8h.

---

### Day 4 (Thursday) — Priority Queue + Scan Orchestration

**Morning (4h):**
- **0:00–1:30** — Implement priority queue. `zeroshield/orchestrator/priority.py`. Score function: `priority = (popularity_weight * recency_factor) / time_since_last_scan`. Popularity weight: Tier A=100, B=10, C=1. Recency: published in last 24h=10x, last week=5x, last month=2x, older=1x. Time divisor: hours since last scan (min 1). Map score to 5 RabbitMQ queues: Critical (>1000), High (100-1000), Normal (10-100), Low (1-10), AI (<1, for future). **Done when:** `calculate_priority("express", tier="A", published_hours_ago=2, last_scanned_hours_ago=24)` returns a Critical-tier score.
- **1:30–3:00** — Wire priority queue into npm monitor. When Beat discovers a new/updated package, calculate priority and route to appropriate RabbitMQ queue. Celery task routing: `app.conf.task_routes = {"zeroshield.worker.tasks.scan_sca": {"queue": "sca.{priority}"}}`. Workers consume from highest priority first: `celery worker -Q sca.critical,sca.high,sca.normal,sca.low`.
- **3:00–4:00** — Add scan deduplication. Before queuing, check: is there a `scan_jobs` row for this (package, version) in status RUNNING or COMPLETED in the last N hours? If yes, skip. Prevents duplicate scans from rapid changes-feed updates.

**Afternoon (4h):**
- **4:00–5:30** — Extract DevSecShield `StateUpdateWriter` and Celery connection utilities. Apply to ZeroShield's backend-to-worker communication. Backend can now submit scan tasks and poll status. **Effort saved: ~4h.** **Done when:** FastAPI endpoint `POST /api/v1/scan` queues a task and returns `{scan_id, status: "queued"}`. `GET /api/v1/scan/{id}/status` returns task state.
- **5:30–7:00** — Implement `GET /api/v1/advisories` endpoint (read-only, no auth for Phase 1). Returns published advisories from PostgreSQL. Cursor-based pagination. Filter by `ecosystem`, `severity`, `cwe`. Response format: `{data: [...], next_cursor, has_more, total_count}`.
- **7:00–8:00** — Run 10 packages through the full pipeline: monitor discovers → priority calculated → task queued → SCA worker runs → findings stored → API returns results. Fix any queue routing issues. Document the 10-package test results.

**Blockers:** RabbitMQ queue naming with dots may cause routing issues (fix: use underscores `sca_critical`). Celery task routing config is finicky (fix: test with `celery inspect active_queues`). PostgreSQL connection pool exhaustion under concurrent scans (fix: set `pool_size=5, max_overflow=10`).

**Definition of Done for Day 4:** Priority queue routes scans correctly. No duplicate scans. API endpoints return scan status and advisories. 10 packages scanned end-to-end. Total: ~8h.

---

### Day 5 (Friday) — API Polish + GitHub Pages Stub

**Morning (4h):**
- **0:00–1:30** — Add remaining API endpoints: `GET /api/v1/advisories/{zeroshield_id}` (single advisory detail), `GET /api/v1/packages/{ecosystem}/{name}` (package scan history), `GET /api/v1/stats` (total scans, total findings, packages monitored). Add OpenAPI metadata (title, description, version, contact, license).
- **1:30–3:00** — Set up GitHub Pages site. Create `dashboard/` directory with Jekyll/Hugo minimal template. Index page with: project name, mission statement, latest advisories table (pulled from `advisories.json` at build time). RSS feed at `/feed.xml`. JSON feed at `/feed.json`. Create GitHub Actions workflow `.github/workflows/publish_site.yml` that builds and deploys on push to main + daily cron. **Done when:** `https://zeroshield.github.io/zeroshield/` loads.
- **3:00–4:00** — Add `security.txt` at `/.well-known/security.txt` with: Contact (email), Encryption (PGP key URL), Preferred-Languages, Canonical, Policy. This is ZeroShield's own security policy for receiving reports about the scanner itself.

**Afternoon (4h):**
- **4:00–5:30** — Rate limiting. Add `slowapi` or manual Redis-based rate limiter to FastAPI. Public endpoints: 60/min per IP. Scan endpoints: stub for future API key auth. Return `RateLimit-Limit`, `RateLimit-Remaining`, `RateLimit-Reset` headers. 429 response with `retry-after`.
- **5:30–7:00** — Error handling sweep. Add global exception handler. Structured error responses: `{"error": {"code": "...", "message": "...", "request_id": "uuid"}}`. Add request ID middleware. Add structured logging (JSON format, include request_id, scan_id where applicable).
- **7:00–8:00** — Write `README.md` with: what ZeroShield is, architecture diagram (ASCII), quickstart (`docker compose up`), API docs link, contributing guidelines, license. Push everything. Tag `v0.1.0-alpha`.

**Blockers:** GitHub Pages may take 5-10 min to deploy (fix: be patient, check Actions tab). Jekyll build may fail on Ruby version mismatch (fix: use Hugo instead, single binary). Rate limiter Redis connection string mismatch (fix: use same Redis from docker-compose).

**Definition of Done for Day 5:** Full API with rate limiting and error handling. GitHub Pages live. README complete. `v0.1.0-alpha` tagged. Total: ~8h.

---

### Day 6 (Saturday) — Email + PGP Setup

**Morning (3h):**
- **0:00–1:00** — Generate PGP keypair for `security@zeroshield.dev`. 4096-bit RSA. Upload public key to keys.openpgp.org. Export ASCII-armored public key to `dashboard/pgp-key.asc`. Add to `security.txt`.
- **1:00–2:00** — Set up email sending. Use Amazon SES or Mailgun (free tier). Configure DKIM, SPF, DMARC for `zeroshield.dev`. Verify domain. Send test email. **Done when:** `nslookup -type=TXT zeroshield.dev` shows SPF/DKIM/DMARC records.
- **2:00–3:00** — Implement `zeroshield/reporter/email_reporter.py`. Functions: `send_disclosure_email(to, advisory, pgp_sign=True)`, `send_followup_email(to, advisory, day_number)`. Use PGP library (`python-gnupg`) to sign outbound emails. Template: professional, includes ZeroShield advisory ID, severity, affected versions, suggested fix, 90-day disclosure timeline, opt-out instructions.

**Afternoon (3h):**
- **3:00–4:30** — Implement maintainer resolution stub. `zeroshield/reporter/maintainer_resolver.py`. For npm: parse `maintainers` array from registry metadata → extract emails. Fall back to GitHub repo owner from `repository` field. Fall back to `SECURITY.md` in repo. Hash all emails with SHA-256 before storage (GDPR). **Done when:** `resolve_maintainer("express")` returns a contact method.
- **4:30–6:00** — Implement disclosure timeline tracker. `zeroshield/reporter/coordinator.py`. States: DISCOVERED → REPORTED → ACKNOWLEDGED → PATCHED → PUBLISHED. On create: set `disclosure_deadline = now + 90 days`. Write `disclosure_events` row on each state transition. Celery Beat task: check for overdue disclosures daily, send follow-up at Day 14, Day 30, Day 60.

**Blockers:** PGP library may have native dependency issues on Mac (fix: `brew install gnupg` + use `python-gnupg` wrapper). SES sandbox mode limits recipients (fix: request production access, takes 24h). Domain DNS propagation may take up to 48h (fix: start Day 1, verify Day 6).

**Definition of Done for Day 6:** PGP key generated and published. Email sending works with DKIM/SPF/DMARC. Maintainer resolver returns contacts. Disclosure coordinator tracks states. Total: ~6h.

---

### Day 7 (Sunday) — Integration Testing + Steel Thread Proof

**Morning (3h):**
- **0:00–1:30** — End-to-end integration test. Manually trigger: npm monitor polls → discovers `serialize-javascript@5.0.0` (known CVE-2020-7660) → priority queue routes to SCA → worker downloads tarball → SHA512 verification → Grype + OSV scan → findings stored in MongoDB → advisory drafted in PostgreSQL → API returns advisory → GitHub Pages builds with new advisory.
- **1:30–3:00** — Fix every issue found during the integration test. Common issues: task serialization (fix: use JSON not pickle), MongoDB connection timeout (fix: increase timeout), scan_jobs foreign key violations (fix: ensure monitored_targets row exists first), GitHub Pages build fails (fix: check Actions logs).

**Afternoon (3h):**
- **3:00–4:30** — Run the known-vulnerable test suite: `lodash@4.17.18`, `serialize-javascript@5.0.0`, `ua-parser-js@1.0.33`, `event-stream@3.3.4`. Plus one clean baseline: `normalizer@2.0.0`. Record: found CVEs, false positives, scan duration, any crashes.
- **4:30–6:00** — Write Week 1 retrospective. Document: what's working, what's brittle, what was cut, what needs attention in Week 2. Push to repo as `docs/retro-week1.md`. Update project board.

**Blockers:** event-stream is a famous supply-chain attack — Grype may not flag it as SCA (it was a backdoor, not a dependency CVE). This is expected — flag for Behavioral worker in Phase 2.

**Definition of Done for Day 7:** Steel thread proven — package → scan → finding → advisory → API → website. 4 known-vuln packages scanned correctly. Retrospective written. Total: ~6h.

---

**Week 1 Totals:** ~54h across 7 days. DevSecShield reuse saved ~19.5h (enums, Celery config, NVD client, models, progress writer, connection utils).

---

## 2. Weeks 2–4 Weekly Goals

### Week 2: Scale to 50 Packages/Day + Monitoring

**Goals:**
- Seed the top 100 npm packages (by downloads) as Tier A. Run full SCA scan on all 100.
- Add Prometheus metrics: `scans_total`, `scans_duration_seconds`, `findings_total`, `queue_depth`, `worker_errors_total`.
- Add Grafana dashboard with 4 panels: scan throughput, queue depth, error rate, findings by severity.
- Add health check endpoint that verifies all downstream dependencies (PG, Mongo, RabbitMQ, Redis).
- Implement CISA KEV enrichment (download JSON catalog, match against SCA findings, flag as `actively_exploited`).
- Write 3 unit tests: tarball integrity failure, Grype output parsing, priority score calculation.

**What to cut if behind:** Grafana dashboard (use Prometheus raw queries). CISA KEV (hardcode top 10 KEV CVEs). Unit tests (defer to Week 3).

**Milestone:** 50 packages/day scanned with zero crashes for 48h continuous operation.

---

### Week 3: Scale to 100/Day + GHSA Integration + Docker Prep

**Goals:**
- Integrate GitHub Advisory Database (GHSA). `GET https://api.github.com/advisories?ecosystem=npm&per_page=100`. Merge with Grype + OSV results. Now have 3 SCA sources.
- Scale changes feed processing: handle 2500 changes per poll without backpressure. Add batch UPSERT (single SQL statement for 2500 rows, not 2500 individual inserts — this is the difference between 200ms and 5s).
- Implement download count fetcher. Weekly Celery Beat task: `GET api.npmjs.org/downloads/point/last-month/{pkg}` for all Tier A packages. Update `popularity_score` and `popularity_tier`.
- Add scan deduplication by content hash: `SHA256(package + version + tarball_integrity)` → skip if already scanned. This eliminates ~70% of redundant scans.
- Begin Docker Hub exploration: authenticate (`POST hub.docker.com/v2/users/login`), list official images, understand tag/digest/manifest structure. No scanning yet — just the monitoring API client.

**What to cut if behind:** Docker Hub exploration (defer to Week 5). Download count fetcher (keep static Tier A list). GHSA integration (2 sources are enough for Phase 1).

**Milestone:** 100 packages/day. 3 SCA data sources. Content-hash deduplication working. Zero data loss for 72h.

---

### Week 4: Hardening + First Public Scan Results

**Goals:**
- Harden error handling: every external API call has timeout (30s), retry (3x exponential), and circuit breaker. No silent failures — every error writes to `scan_dlq` and increments `worker_errors_total` counter.
- Implement scan result export: `GET /api/v1/scan/{id}/findings` returns SARIF 2.1.0 format (for GitHub Code Scanning compatibility). This is a differentiator.
- Publish first batch of scan results to GitHub Pages. Advisories page with table: package, CVE, severity, CVSS, affected versions, patched version, EPSS score. JSON + RSS feeds.
- Add npm provenance verification stub. Check for SLSA attestation on Tier A packages. Log whether provenance exists (don't block on it yet).
- Write integration test: full pipeline from changes feed → scan → advisory → website publish. Run daily via GitHub Actions.
- Prepare blog post draft: "How ZeroShield Works: Automated npm Vulnerability Scanning at Scale."

**What to cut if behind:** SARIF export (plain JSON is fine). Provenance verification (defer to Phase 2). Blog post (defer to Week 6).

**Milestone:** 100/day for 7 consecutive days. Public scan results on website. RSS feed working. Zero unhandled exceptions in logs for 48h.

**End of Phase 1 Status Check:**
| Metric | Target | How to verify |
|--------|--------|---------------|
| Packages scanned/day | 100 | `SELECT count(*) FROM scan_jobs WHERE created_at > now() - interval '1 day'` |
| Known CVEs correctly identified | >90% | Test suite of 5 known-vuln packages |
| False positive rate | <20% | Manual review of 50 random findings |
| Uptime | >95% | Prometheus `up` metric |
| Data sources | 3 (Grype + OSV + GHSA) | API `/stats` endpoint |
| Public advisories | 10+ | GitHub Pages count |

---

## 3. Weeks 5–8: First Vulnerability

### Strategy: Systematic Known-CVE Rediscovery

Before hunting zero-days, prove the system can reliably find known vulnerabilities. This is your credibility foundation.

**Week 5 — Scan Top 1000 npm Packages:**
- Fetch top 1000 by weekly downloads from `api.npmjs.org/downloads/point/last-week`. Seed as Tier A.
- Run full SCA scan on all 1000, all published versions from the last 2 years.
- Expected yield: 200-500 known CVEs across these packages (many unpatched older versions).
- Build a "CVE coverage" report: for each known npm CVE in NVD (2023-2026), did ZeroShield flag it? Target: >85% coverage.
- Use this report as the first piece of marketing content: "ZeroShield correctly identifies X% of known npm CVEs."

**Week 6 — Add Semgrep (Custom Rules):**
- Install Semgrep CLI. Run community rules against top 100 packages.
- Write 3 of the 5 planned custom rules:
  1. `npm-prototype-pollution` (HIGH, CWE-1321): Detect `Object.assign({}, untrusted)` and `obj[key] = value` where key is user-controlled.
  2. `npm-command-injection` (CRITICAL, CWE-78): Detect `exec()`, `spawn()`, `execSync()` with string concatenation from external input.
  3. `npm-install-hook-network-exfil` (CRITICAL, CWE-200): Detect network calls (`fetch`, `http.get`, `axios`) inside `preinstall`/`postinstall` scripts.
- Run custom rules against top 100. Expect 5-15 true positives from Semgrep custom rules.
- **This is where real findings start.** A Semgrep custom rule hit on a popular package that isn't in any CVE database is potentially a zero-day.

**Week 7 — First Real Finding (Target):**
- Expand scanning to top 5000 packages. Focus Semgrep custom rules on packages with `postinstall` scripts (supply-chain risk surface).
- Strategy for finding first real vulnerability:
  1. Query npm registry for packages with `scripts.preinstall` or `scripts.postinstall` entries. There are ~50,000 such packages.
  2. Filter to packages with >10,000 weekly downloads (reduces to ~2,000).
  3. Run `npm-install-hook-network-exfil` rule against all 2,000.
  4. Manually review top 20 findings. Look for: unauthorized analytics/telemetry, data exfiltration, cryptocurrency miners, command-and-control callbacks.
  5. Cross-reference with Socket.dev's known-malicious list to avoid duplicates.
- Alternative strategy: scan packages that were recently transferred to new maintainers (maintainer hijack signal). Query npm for packages where `maintainers[0]` changed in the last 90 days.

**Week 8 — First Disclosure Email:**
- Once you have a confirmed finding (either a known CVE in an unpatched popular package or a new Semgrep finding):
  1. **Day 0:** Write internal advisory. Generate `zeroshield_id` (e.g., `ZS-2026-0001`). Compute SHA-3 proof-of-discovery hash: `SHA3-256(zeroshield_id + package + version + vuln_description + timestamp)`. Store in PostgreSQL.
  2. **Day 1:** Resolve maintainer email. Draft disclosure email using template. PGP-sign. Send to maintainer email + open draft GitHub Security Advisory if repo supports it.
  3. **Day 1 (same day):** Post in `#disclosures` channel on your Discord. Share timeline (no details, just "ZS-2026-0001: disclosure sent, 90-day clock started").
  4. **Day 14:** First follow-up email if no response.
- **Communication plan for first disclosure:**
  - Do NOT tweet about it until 90-day window expires or maintainer patches.
  - Do NOT share technical details publicly.
  - DO share that "ZeroShield has sent its first disclosure" (without naming the package).
  - DO update GitHub Pages with a count: "1 active disclosure."

**Email template (first disclosure):**
```
Subject: [ZeroShield] Security Vulnerability in {package}@{version} — {zeroshield_id}

Dear {maintainer_name},

I am writing from the ZeroShield project, an open-source automated vulnerability
scanner for npm packages. Our scanning system has identified a potential security
vulnerability in {package} version {version}.

**Advisory ID:** {zeroshield_id}
**Severity:** {severity} (CVSS {score})
**CWE:** {cwe_id} — {cwe_name}
**Affected Versions:** {affected_versions}
**Detection Method:** {method}

**Description:**
{description}

**Proof of Concept:**
{poc_description}

**Suggested Fix:**
{fix_suggestion}

**Disclosure Timeline:**
- Day 0 ({date}): This initial report
- Day 14: First follow-up if no response
- Day 30: Second follow-up
- Day 60: Third follow-up + prepare publication
- Day 90 ({deadline}): Public disclosure

We follow responsible disclosure practices with a 90-day window. If you need
more time, please let us know and we can extend.

If you believe this is a false positive, please respond with your assessment
and we will promptly retract.

To opt out of future ZeroShield scans for your packages, please reply with
"opt-out" or add a .zeroshield-optout file to your repository root.

This email is PGP-signed. Our public key is available at:
https://zeroshield.dev/.well-known/pgp-key.asc

Best regards,
ZeroShield Automated Vulnerability Scanner
https://zeroshield.dev
security@zeroshield.dev
```

---

## 4. Weeks 9–12: First CVE

### Week 9 — CVE Assignment Process

**GitHub CNA (Preferred Path — Faster):**
GitHub is a CVE Numbering Authority (CNA). If the affected package has a GitHub repository:
1. Create a draft Security Advisory: `POST /repos/{owner}/{repo}/security-advisories`.
2. Fill in: ecosystem (npm), package name, vulnerable versions, patched version, severity, CWE, description.
3. Request CVE: click "Request CVE" on the GitHub Advisory UI, or set `"cve_id": "request"` in the API call.
4. GitHub typically assigns a CVE within 1-3 business days.
5. Once assigned, the CVE appears in GHSA and propagates to NVD within 1-2 weeks.

**MITRE Fallback (If No GitHub Repo):**
1. Go to `https://cveform.mitre.org/`.
2. Select "Request a CVE ID."
3. Fill in: vulnerability type, product (npm package name), version, vendor (package maintainer), description, references.
4. MITRE typically assigns within 5-15 business days.
5. After assignment, submit full CVE record to NVD via the CVE Services API or web form.

**ZeroShield process for first CVE:**
1. Ensure the finding has been through full 90-day disclosure (or maintainer has patched and agreed to publication).
2. Write a detailed advisory with: title, description, impact, affected versions, patched version, CVSS vector, CWE, PoC, timeline, credits.
3. Submit via GitHub CNA first. If 403/404 (repo doesn't support advisories), fall back to MITRE.
4. Once CVE assigned: update PostgreSQL `advisories.cve_id`, update GitHub Pages, update RSS feed.
5. Write blog post (see below).

### Week 10 — First Blog Post

**Title:** "ZS-2026-0001: {Vulnerability Type} in {Package} — Our First CVE"

**Structure (1500-2000 words):**
1. **Hook (100 words):** What we found, severity, impact scope (weekly downloads).
2. **Discovery (300 words):** How ZeroShield's scanning pipeline detected it. Which scanner layer. What the confidence score was. How the triage engine validated it.
3. **Technical Deep Dive (500 words):** The vulnerability explained. Code snippets (from the patched version, not the vulnerable one — responsible disclosure). Attack scenario. CVSS breakdown.
4. **Disclosure Timeline (200 words):** Day-by-day timeline. Maintainer response time. Patching time.
5. **Methodology (300 words):** How our SCA/SAST/behavioral pipeline works. What open-source tools we use. How we reduce false positives.
6. **Lessons Learned (200 words):** What this finding teaches about npm ecosystem security. What we'd improve.
7. **Call to Action (100 words):** Link to ZeroShield, how to use the API, how to contribute.

**Publish on:** GitHub Pages blog, dev.to, Medium. Cross-post link on Twitter/X.

### Week 11 — Social Media Launch

**Hacker News Strategy:**
- Post title: "Show HN: ZeroShield — Open-source automated npm vulnerability scanner (found our first CVE)"
- Post on Tuesday or Wednesday, 9-10 AM ET (peak HN traffic).
- Be in the comments immediately. Answer every technical question in the first 2 hours.
- Expected outcome: 50-200 upvotes if the CVE is interesting. 5-20 GitHub stars.
- **Do NOT post if you don't have a real CVE yet.** HN will destroy a "we plan to find vulnerabilities" post.

**Reddit Strategy:**
- Post to: r/netsec (most important), r/javascript, r/node, r/cybersecurity, r/devsecops.
- r/netsec requires self-post with technical depth. Include code examples and CVSS breakdown.
- r/javascript and r/node: frame as "here's a vulnerability we found in the npm ecosystem."
- Timing: stagger posts across 2-3 days. Don't carpet-bomb all subreddits simultaneously.

**Twitter/X Strategy:**
- Thread format: "🧵 We just published our first CVE found by ZeroShield, an open-source npm scanner. Here's what happened:"
  1. What we found (screenshot of advisory page).
  2. How we found it (pipeline diagram).
  3. Disclosure timeline.
  4. Link to full blog post.
  5. Link to GitHub repo.
- Tag: @npmjs, @github, @graborenern (npm security), relevant package maintainer (only if they've publicly acknowledged the fix).

### Week 12 — Consolidation + Second CVE Hunt

- Run expanded scanning: top 5000 npm packages, all versions from last 12 months.
- Add remaining 2 custom Semgrep rules: `npm-eval-dynamic-input` (HIGH, CWE-95), `npm-redos` (MEDIUM, CWE-1333).
- Target: identify 5 more known CVEs that ZeroShield can independently verify, plus 1-2 more potential zero-days.
- Begin Phase 3 planning: AI worker architecture, batch API integration with Anthropic, sandbox design.
- Update roadmap document with actual vs. planned progress.

---

## 5. Community Building (Parallel Track)

This runs alongside the technical work. Budget: 30 min/day.

### GitHub Profile

**Week 1:** Create `zeroshield` GitHub organization. Set profile README with logo, mission, links. Pin the main repo.

**Ongoing:**
- Use GitHub Issues for public task tracking. Label: `good-first-issue`, `help-wanted`, `documentation`, `enhancement`.
- Create issue templates: Bug Report, Feature Request, False Positive Report.
- Create `CONTRIBUTING.md` with: how to run locally, how to add a Semgrep rule, how to report a false positive.
- Respond to every star/fork notification with a thank-you comment (first 100 only — doesn't scale).
- GitHub Discussions: enable for Q&A and announcements.

### Twitter/X Content Calendar (Weeks 1-12)

| Week | Content | Type |
|------|---------|------|
| 1 | "Starting ZeroShield — building an open-source npm vulnerability scanner in public" | Announcement |
| 2 | "Day 14: ZeroShield can scan 100 npm packages/day. Here's the architecture." | Progress |
| 3 | "TIL: npm's changes feed gives you real-time package updates via CouchDB. Here's how to consume it." | Educational |
| 4 | "ZeroShield scanned the top 100 npm packages. Here's what we found (spoiler: lots of known CVEs in old versions)." | Data |
| 5 | "We wrote 3 custom Semgrep rules for npm supply-chain attacks. They're open-source. Thread 🧵" | Technical |
| 6 | "Burnout check: 6 weeks in, solo dev on a security tool. What keeps me going and what's hard." | Personal |
| 7 | "ZeroShield just sent its first responsible disclosure email. 90-day clock started." | Milestone |
| 8 | "How we verify npm tarball integrity: SHA512, SLSA attestation, and why it matters." | Educational |
| 9 | "Our first CVE was assigned! ZS-2026-0001. Blog post dropping tomorrow." | Announcement |
| 10 | Blog post thread (see Week 11 above) | Launch |
| 11 | "AMA: building a solo vulnerability scanner. Ask me anything about npm security, Grype, Semgrep, or disclosure." | Engagement |
| 12 | "90-day retrospective: what worked, what didn't, what's next for ZeroShield." | Reflective |

**Posting cadence:** 3 tweets/week (Mon, Wed, Fri). 1 thread/week (Tuesday).

### Discord Server

**Week 2:** Create Discord. Channels:
- `#announcements` — New advisories, CVEs, releases.
- `#general` — Discussion.
- `#false-positives` — Report FPs (faster feedback than GitHub Issues).
- `#disclosures` — Timeline updates for active disclosures (no details until published).
- `#contributors` — For people who want to help.
- `#build-log` — Daily standup-style updates from you.

**Moderation:** Solo developer, so keep it simple. Use a bot for welcome messages. Set slow mode (1 message/10s) to prevent spam. Don't over-invest in Discord until you have >50 members.

### Blog Topics (Queue)

1. "How ZeroShield Works: Architecture of an Open-Source npm Scanner" (Week 4)
2. "Building a Real-Time npm Monitor with CouchDB Changes Feed" (Week 3)
3. "Custom Semgrep Rules for npm Supply-Chain Attacks" (Week 6)
4. "The 90-Day Disclosure Process: A Solo Developer's Guide" (Week 8)
5. "{First CVE Title}" (Week 10)
6. "False Positive Reduction: 5-Stage Triage for Automated Vulnerability Scanning" (Week 12)
7. "Scanning Docker Images for Secrets: What We Found in Official Images" (Post Phase 1)
8. "AI-Assisted Vulnerability Discovery: Our 4-Stage LLM Pipeline" (Post Phase 3)

### Conference Proposals (Draft by Week 10, Submit by Week 12)

**Target conferences (CFP deadlines are 3-6 months out, so submit early):**
- **DEF CON / Black Hat** (August): "Automated Zero-Day Discovery in npm: How We Found {N} Vulnerabilities Using Open-Source Tools and LLMs"
- **BSides {your city}**: Lower bar, good first talk. "Building a Solo Vulnerability Scanner on $300/mo"
- **NodeConf / JSConf**: "npm Supply-Chain Security: 1000 Packages, 500 Vulnerabilities, and What It Means for Your Lock File"
- **KubeCon** (if Docker scanning is mature): "Container Image Security at Scale: Scanning Docker Hub's Top 100"
- **Open Source Summit**: "From DevSecShield to ZeroShield: Extracting a Public Vulnerability Platform from a Private Security Tool"

**Talk format:** 30 min. Structure: problem (2 min), demo (5 min), architecture (10 min), findings (8 min), lessons (5 min).

---

## 6. Risk Contingencies

### Risk 1: npm Blocks IP/User-Agent

**Probability:** Medium (npm has rate-limited scrapers before).  
**Detection:** HTTP 429 responses from registry.npmjs.org or replicate.npmjs.com. Sudden zero results from changes feed.  
**Impact:** ZeroShield goes blind. No new packages discovered. Existing scans unaffected (tarballs already cached).

**Mitigation (Layered):**
1. **Immediate (0h):** Switch to npm's official Replicate CouchDB endpoint (`replicate.npmjs.com`) if `registry.npmjs.org` blocks you. They're separate systems.
2. **Short-term (1-2h):** Implement request throttling. Respect `Retry-After` headers. Drop from 30s polling to 5-minute polling. Queue requests with 100ms delay between them.
3. **Medium-term (1-2 days):** Set up a second monitoring source. Use `npms.io` API as a secondary package discovery channel. Use GitHub's npm advisory feed as a discovery fallback.
4. **Long-term (1 week):** Contact npm's security team directly (`security@npmjs.com`). Explain ZeroShield's mission. Ask for a research partnership or rate-limit exemption. Most registries support bona fide security researchers.
5. **Nuclear option:** Run a local npm registry mirror (`verdaccio` or CouchDB replica). ~50GB storage, eliminates dependency on npm API entirely.

### Risk 2: Anthropic Rate-Limits (Phase 3)

**Probability:** High (batch API has quotas, burst usage triggers throttling).  
**Detection:** HTTP 429 from `api.anthropic.com`. `RateLimitError` exceptions in Celery worker.

**Mitigation:**
1. **Immediate:** Fall back from Sonnet to Haiku (cheaper, higher rate limit).
2. **Short-term:** Implement token bucket rate limiter in the AI worker. Queue requests and dispatch at sustainable rate.
3. **Medium-term:** Apply for Anthropic's research tier (higher limits, discounted pricing). Cite CVE publications as evidence of legitimate research use.
4. **Long-term:** Implement local LLM fallback (CodeLlama-34B or DeepSeek-Coder-V2 via Ollama). Quality will decrease, but availability maintained.
5. **Cost cap:** Hard-stop at $2.50/package. Kill API call if accumulated cost exceeds cap. Never exceed $300/mo budget.

### Risk 3: Hostile Maintainer Pushback

**Probability:** Certain (eventually). Some maintainers will react angrily to vulnerability reports, especially from automated systems.  
**Detection:** Angry email reply. Public tweet attacking ZeroShield. GitHub issue opened on your repo. Threatened legal action.

**Response playbook:**
1. **Do NOT respond emotionally.** Wait 24 hours before replying.
2. **Do NOT engage on public social media.** All communication through private PGP-signed email.
3. **If they dispute the finding:** Provide additional PoC evidence. Offer to do a Zoom call to walk through the vulnerability. If they present a convincing argument it's FP, retract immediately and publicly apologize.
4. **If they demand retraction without technical basis:** Politely refer to the 90-day disclosure policy. Note that you follow the same process as Google Project Zero, GitHub Security Lab, and HackerOne.
5. **If they threaten legal action:** Do NOT respond directly. Consult with EFF (they have a legal defense fund for security researchers). Pause the disclosure clock. Do not publish.
6. **If they opt out:** Immediately honor the opt-out. Add package to exclusion list. Confirm via email. Never scan again.
7. **Template for hostile response:**
```
Thank you for your response. We take your concerns seriously.

We believe this finding is valid based on [specific evidence]. We would be
happy to provide additional details or discuss on a call.

If you believe this is a false positive, please share your technical
assessment and we will promptly retract and publicly correct our advisory.

If you would like to opt out of future ZeroShield scans, please reply with
"opt-out" and we will immediately exclude your packages.

We follow responsible disclosure practices consistent with industry standards
(ISO 29147, Google Project Zero, GitHub Security Lab).
```

### Risk 4: Critical 0-Day Found Early (Before Process is Ready)

**Probability:** Low (but non-zero — automated scanning can stumble on critical supply-chain attacks).  
**Detection:** Semgrep or behavioral analysis flags a critical finding (CVSS ≥9.0) in a package with >1M weekly downloads. Manual review confirms it's real and actively exploitable.

**Response playbook:**
1. **Do NOT panic-publish.** Even for critical findings, responsible disclosure applies.
2. **Do NOT tweet or post anywhere.**
3. **Immediately:** Notify the maintainer via PGP-signed email with "URGENT" flag. Set 7-day accelerated disclosure timeline (not 90 days) for critical infrastructure-affecting vulns.
4. **Within 24h:** If the package has >10M weekly downloads or is in CISA KEV, notify CISA (cisa.gov/report) and npm security team (`security@npmjs.com`). This is not optional for critical findings.
5. **Within 48h:** If maintainer is unresponsive and the vuln is actively exploitable, consider coordinated disclosure with npm security team. They can publish a registry advisory and deprecate the vulnerable version.
6. **Within 7 days:** If no response and actively exploited, publish advisory with redacted PoC (enough for defenders to mitigate, not enough for attackers to exploit).
7. **Document everything.** SHA-3 proof-of-discovery hash. Timestamped email logs. Decision rationale at every step. This is your legal protection.

### Risk 5: Burnout at Week 6

**Probability:** Near-certain for a solo developer. Week 6 is the "trough of disillusionment" — the novelty wears off, the first scan results aren't exciting, and nobody cares yet.

**Detection (Self-Assessment):**
- Haven't committed code in 3+ days.
- Dreading opening the project.
- Spending time on "meta-work" (reorganizing, re-architecturing) instead of shipping.
- Comparing ZeroShield unfavorably to AISLE or ZAST.AI.

**Mitigation:**
1. **Prevention (Weeks 1-4):** Build in public from Day 1. Tweet progress. Each public signal creates social accountability.
2. **Prevention (Before Week 6):** Schedule one "fun" feature for Week 6. Something visible and satisfying (e.g., a dashboard visualization, a pretty report, a CLI tool with colored output).
3. **During burnout:**
   - Take 2 full days off. Do not touch code.
   - After break, do ONE small visible task. Merge a tiny PR. Fix a typo. Ship something trivially small.
   - Review your `docs/retro-week1.md` and the first successful scan result. Remember why you started.
   - Reach out to 1-2 friends in security and show them the project. Fresh eyes + external validation is medicine.
4. **Structural defense:** Timebox to 6h/day max (even on weekends). No late-night coding sessions. Keep a physical handwritten todo list (max 3 items, satisfying to cross off).
5. **Escape hatch:** If by Week 8 you have zero findings and zero community traction, it's okay to pivot. The DevSecShield code reuse and infrastructure knowledge is not wasted. Consider: pivoting to a consulting service, contributing to an existing scanner (Socket.dev, Snyk), or open-sourcing the custom Semgrep rules as a standalone project.

### Risk 6: Infrastructure Failure (Database Corruption, Worker Crash Loop)

**Probability:** Medium for a solo-dev Docker Compose deployment.

**Mitigation:**
1. **Daily automated PostgreSQL backup:** `pg_dump` to local file + S3. Test restore monthly.
2. **MongoDB:** Enable oplog. Daily `mongodump` to S3.
3. **Worker crash loop:** `task_reject_on_worker_lost=True` + `task_acks_late=True` ensures tasks return to queue on crash. Celery `max_retries=5` with exponential backoff.
4. **Nuclear recovery:** `docker compose down -v && docker compose up -d && psql -f schema.sql`. Reseed from backup. Total recovery time: ~30 min.

---

## 7. Milestone Checkpoints (Go/No-Go)

### Day 14 — End-to-End Scan (GO/NO-GO)

**Criteria:**
| Check | Pass | Fail Action |
|-------|------|-------------|
| Can scan `lodash@4.17.18` and find ≥3 CVEs | ✅ Required | Stop everything. Fix SCA worker. |
| Celery Beat polls npm changes feed every 30s | ✅ Required | Fix scheduler. |
| PostgreSQL has `scan_jobs` rows with status=COMPLETED | ✅ Required | Fix DB writes. |
| MongoDB has `scan_findings` documents | ✅ Required | Fix finding storage. |
| API returns findings at `/api/v1/advisories` | ✅ Required | Fix API. |
| ≥50 packages scanned in last 24h | Nice to have | Scale up Beat, add more workers. |
| GitHub Pages site live | Nice to have | Fix Actions workflow. |

**Decision:** If any "Required" fails → extend Week 2 by 3 days. Do NOT move to new features until the steel thread works.

---

### Day 30 — 100 Scans/Day (GO/NO-GO)

**Criteria:**
| Check | Pass | Fail Action |
|-------|------|-------------|
| ≥100 packages scanned per day for 3 consecutive days | ✅ Required | Profile bottleneck. Is it downloads? Grype? DB writes? |
| ≥3 SCA data sources (Grype + OSV + GHSA) | ✅ Required | Implement missing source. |
| Zero unhandled exceptions in last 48h | ✅ Required | Fix error handling. |
| Priority queue routes Tier A first | ✅ Required | Fix priority calculation. |
| Content-hash deduplication working | Nice to have | Implement. Saves compute. |
| Public website has ≥10 advisories | Nice to have | Push advisory generation. |
| Monitoring (Prometheus) operational | Nice to have | Defer. Use `docker compose logs` for debugging. |

**Decision:** If throughput <50/day → investigate. Likely bottleneck: Grype binary speed (fix: parallelize with concurrency=4), tarball download speed (fix: connection pooling), or DB write contention (fix: batch inserts).

---

### Day 45 — 5 Known CVEs Independently Verified (GO/NO-GO)

**Criteria:**
| Check | Pass | Fail Action |
|-------|------|-------------|
| ≥5 known CVEs correctly identified with full advisory detail | ✅ Required | Review SCA pipeline for gaps. |
| CVE coverage ≥80% against NVD npm CVEs (2024-2026) | ✅ Required | Add missing data sources. |
| False positive rate <20% (manual sample of 50) | ✅ Required | Add FP filters. |
| Custom Semgrep rules deployed (≥3 of 5) | ✅ Required | Prioritize rule writing. |
| Email sending works (PGP-signed, DKIM verified) | ✅ Required | Fix email pipeline before first real disclosure. |
| ≥1 finding from Semgrep custom rules (not just SCA) | Nice to have | Adjust rules, expand scanning scope. |

**Decision:** This checkpoint validates that ZeroShield is not just a Grype wrapper — it adds value through multi-source correlation and custom SAST rules. If custom rules find nothing in 5000 packages, expand to 10,000 or tune rule sensitivity.

---

### Day 60 — 1 Unknown/Unreported Vulnerability (GO/NO-GO)

**Criteria:**
| Check | Pass | Fail Action |
|-------|------|-------------|
| ≥1 finding that is NOT in any public CVE database | ✅ Required | Expand scanning scope. Try behavioral analysis. Manually audit packages with install hooks. |
| Finding manually verified as true positive | ✅ Required | If FP, back to scanning. |
| Finding has CVSS ≥4.0 (at least Medium severity) | ✅ Required | Low-sev findings don't warrant disclosure effort. |
| Disclosure email drafted and ready to send | ✅ Required | Use template from Week 8. |
| GitHub Security Advisory draft can be created | Nice to have | If repo doesn't support GHSA, email-only is fine. |

**Decision:** This is the hardest checkpoint. Finding a genuine unknown vulnerability takes luck and volume. If Day 60 arrives with no unknown finding:
- **Option A:** Lower the bar. Report a known CVE that has no GHSA entry yet (common — many NVD CVEs lack a GitHub advisory for the npm package).
- **Option B:** Focus on supply-chain signals. Scan recently-published packages (<7 days old) with install hooks. These are the highest-probability targets for malicious packages.
- **Option C:** Defer Day 60 to Day 75. Start AI worker development (Phase 3) while continuing to scan.

---

### Day 75 — 1 Disclosure Sent (GO/NO-GO)

**Criteria:**
| Check | Pass | Fail Action |
|-------|------|-------------|
| ≥1 disclosure email sent to a maintainer | ✅ Required | Something is wrong with maintainer resolution or email pipeline. Fix and send. |
| Email is PGP-signed and DKIM-verified | ✅ Required | Fix email security. |
| Disclosure tracked in `disclosure_events` table | ✅ Required | Fix coordinator. |
| 90-day clock started and visible on public dashboard | ✅ Required | Fix dashboard. |
| Proof-of-discovery hash computed and stored | ✅ Required | Fix hash generation. |
| Blog post draft written | Nice to have | Write it on the weekend. |

**Decision:** If no disclosure by Day 75, the project risks being "just another scanner." Reframe: create a blog series about the scanning methodology itself. Content like "How to Build an npm Vulnerability Scanner" has value even without CVE publications.

---

### Day 90 — 1 Published Advisory (GO/NO-GO)

**Criteria:**
| Check | Pass | Fail Action |
|-------|------|-------------|
| ≥1 advisory published on ZeroShield website | ✅ Required | If maintainer hasn't responded, publish per 90-day policy (only for ≤Medium severity). For High/Critical, extend 30 days. |
| Advisory has: zeroshield_id, CVE (if assigned), CVSS, CWE, affected versions, fix | ✅ Required | Complete the advisory. |
| Blog post published | ✅ Required | Ship it. |
| HN/Reddit post made | Nice to have | Only if CVE is assigned and blog post is polished. |
| ≥10 GitHub stars | Nice to have | Marketing is ongoing. |
| ≥3 active disclosures in pipeline | Nice to have | Indicates healthy scanning volume. |

**Decision:** Day 90 is the "does this project have legs?" checkpoint.
- **If YES (published advisory + CVE + community interest):** Proceed to Phase 3 (AI worker). Increase budget to $415/mo.
- **If PARTIAL (published advisory, no CVE yet):** Continue Phase 2 for 4 more weeks. Focus on scanning volume.
- **If NO (no publishable finding):** Honest retrospective. Options: pivot to consulting, contribute upstream, or open-source the tooling with a "research framework" framing.

---

## 8. Setup Checklist

Every account, API key, domain, pipeline, and tool needed — with time estimates.

### Accounts & Services (Total: ~4h)

| # | Item | URL/Command | Time | Cost | Priority |
|---|------|-------------|------|------|----------|
| 1 | GitHub Organization `zeroshield` | github.com/organizations/new | 5 min | Free | Day 1 AM |
| 2 | GitHub repo `zeroshield/zeroshield` | github.com/new | 5 min | Free | Day 1 AM |
| 3 | Domain `zeroshield.dev` | Google Domains / Cloudflare | 15 min | $12/yr | Day 1 AM |
| 4 | Cloudflare DNS (free tier) | cloudflare.com | 15 min | Free | Day 1 AM |
| 5 | NVD API Key | nvd.nist.gov/developers/request-an-api-key | 5 min | Free | Day 1 AM |
| 6 | GitHub PAT (fine-grained: `security_events:write`) | github.com/settings/tokens | 10 min | Free | Day 1 AM |
| 7 | Amazon SES or Mailgun (free tier) | aws.amazon.com/ses or mailgun.com | 30 min | Free (10K/mo) | Day 1 PM |
| 8 | Docker Hub account (authenticated API access) | hub.docker.com | 5 min | Free | Week 3 |
| 9 | Anthropic API key | console.anthropic.com | 5 min | Pay-as-you-go | Week 9 (Phase 3) |
| 10 | Discord server | discord.com/developers | 10 min | Free | Week 2 |
| 11 | Twitter/X account `@zeroshield_dev` | x.com | 5 min | Free | Week 1 |
| 12 | dev.to account | dev.to | 5 min | Free | Week 4 |
| 13 | PGP Keypair (4096-bit RSA) | `gpg --full-generate-key` | 10 min | Free | Day 6 |
| 14 | keys.openpgp.org (publish PGP key) | keys.openpgp.org | 5 min | Free | Day 6 |
| 15 | Uptime monitoring (UptimeRobot free tier) | uptimerobot.com | 10 min | Free | Week 2 |

### DNS Records (Total: ~30 min, Day 1)

| Record | Type | Value | Purpose |
|--------|------|-------|---------|
| `zeroshield.dev` | A | GitHub Pages IP (185.199.108-111.153) | Website |
| `www.zeroshield.dev` | CNAME | `zeroshield.github.io` | Website redirect |
| `zeroshield.dev` | TXT | `v=spf1 include:amazonses.com ~all` | SPF |
| `_dmarc.zeroshield.dev` | TXT | `v=DMARC1; p=reject; rua=mailto:dmarc@zeroshield.dev` | DMARC |
| `ses-key._domainkey.zeroshield.dev` | CNAME | SES-provided | DKIM |

### Local Development Tools (Total: ~1h)

| Tool | Install Command | Version | Purpose |
|------|----------------|---------|---------|
| Python 3.12+ | `brew install python@3.12` | 3.12.x | Runtime |
| uv (package manager) | `curl -LsSf https://astral.sh/uv/install.sh \| sh` | Latest | Fast deps |
| Docker Desktop | `brew install --cask docker` | Latest | Containers |
| Grype | `brew install grype` or `curl -sSfL install.sh` | Latest | SCA scanner |
| Semgrep | `pip install semgrep` | Latest | SAST scanner |
| Trivy | `brew install trivy` | Latest | Docker scanner |
| GnuPG | `brew install gnupg` | 2.4+ | PGP signing |
| PostgreSQL client | `brew install postgresql@16` | 16 | `psql` CLI |
| MongoDB client | `brew install mongosh` | Latest | `mongosh` CLI |
| Hugo (for GitHub Pages) | `brew install hugo` | Latest | Static site |
| jq | `brew install jq` | Latest | JSON parsing |

### CI/CD Pipelines (Total: ~2h, Day 5)

**GitHub Actions Workflows:**

1. `.github/workflows/ci.yml` — On every push/PR:
   - `uv sync && uv run pytest`
   - `uv run ruff check .`
   - `uv run mypy zeroshield/`
   - Build Docker image (don't push)

2. `.github/workflows/publish_site.yml` — On push to main + daily cron (6 AM UTC):
   - Generate advisory JSON from PostgreSQL
   - Build Hugo site
   - Deploy to GitHub Pages

3. `.github/workflows/scan_npm.yml` — Manual trigger + daily cron:
   - Run integration test: seed 5 packages → scan → verify findings

### Environment Variables (`.env.example`)

```bash
# Database
POSTGRES_URL=postgresql://zeroshield:password@localhost:5432/zeroshield
MONGO_URL=mongodb://zeroshield:password@localhost:27017/zeroshield_db
REDIS_URL=redis://localhost:6379/0

# Message Broker
RABBITMQ_URL=amqp://zeroshield:password@localhost:5672/zeroshield

# External APIs
NVD_API_KEY=your-nvd-api-key
GITHUB_PAT=your-github-pat
DOCKER_HUB_USERNAME=your-dockerhub-username
DOCKER_HUB_PASSWORD=your-dockerhub-password

# Email
SES_REGION=us-east-1
SES_FROM_EMAIL=security@zeroshield.dev

# PGP
PGP_KEY_ID=your-pgp-key-fingerprint
PGP_PASSPHRASE=your-pgp-passphrase

# Anthropic (Phase 3)
ANTHROPIC_API_KEY=your-anthropic-key

# Application
ZEROSHIELD_ENV=development
ZEROSHIELD_LOG_LEVEL=INFO
ZEROSHIELD_SCAN_CONCURRENCY=4
ZEROSHIELD_MAX_TARBALL_SIZE_MB=500
```

### Docker Compose Services (Day 1)

```yaml
services:
  postgres:
    image: postgres:16-alpine
    environment:
      POSTGRES_DB: zeroshield
      POSTGRES_USER: zeroshield
      POSTGRES_PASSWORD: ${POSTGRES_PASSWORD:-dev_password}
    ports: ["5432:5432"]
    volumes: [pgdata:/var/lib/postgresql/data]
    healthcheck:
      test: ["CMD-SHELL", "pg_isready -U zeroshield"]
      interval: 5s
      timeout: 5s
      retries: 5

  mongodb:
    image: mongo:7-alpine
    environment:
      MONGO_INITDB_ROOT_USERNAME: zeroshield
      MONGO_INITDB_ROOT_PASSWORD: ${MONGO_PASSWORD:-dev_password}
    ports: ["27017:27017"]
    volumes: [mongodata:/data/db]

  rabbitmq:
    image: rabbitmq:3.12-management-alpine
    environment:
      RABBITMQ_DEFAULT_USER: zeroshield
      RABBITMQ_DEFAULT_PASS: ${RABBITMQ_PASSWORD:-dev_password}
      RABBITMQ_DEFAULT_VHOST: zeroshield
    ports: ["5672:5672", "15672:15672"]

  redis:
    image: redis:7-alpine
    ports: ["6379:6379"]

volumes:
  pgdata:
  mongodata:
```

### Cost Breakdown — Phase 1 ($300/mo Budget)

| Item | Monthly Cost | Notes |
|------|-------------|-------|
| VPS (Hetzner CX21 or DigitalOcean Droplet 4GB) | $12-24 | Run all containers here |
| PostgreSQL (managed, smallest tier) OR self-host | $0-15 | Self-host saves money |
| MongoDB Atlas free tier OR self-host | $0 | Free tier is sufficient for Phase 1 |
| CloudAMQP free tier OR self-host RabbitMQ | $0 | Free tier: 1M messages/mo |
| Domain (zeroshield.dev) | $1 | $12/yr |
| Amazon SES | $1 | 10K emails free/mo, then $0.10/1K |
| Cloudflare (DNS + CDN) | $0 | Free tier |
| GitHub (org + actions minutes) | $0 | Free for public repos |
| NVD API key | $0 | Free |
| Uptime monitoring | $0 | UptimeRobot free tier |
| **Subtotal** | **$14-40** | |
| **Reserve for unexpected costs** | **$260-286** | LLM experiments, extra compute, domain renewals |

**Key insight:** Phase 1 is _way_ under the $300 budget. Save the surplus for Phase 3 when LLM costs kick in (~$60-150/mo for Anthropic batch API).

---

## Appendix A: DevSecShield Code Reuse Inventory (73h Saved)

| Component | Source | Target | Hours Saved |
|-----------|--------|--------|-------------|
| BaseAgent pattern | `RabbitMQ/worker/helpers/context/base_agent.py` | `zeroshield/shared/agent.py` | 8h |
| NVD API client + 4-tier cache | `RabbitMQ/worker/helpers/context/output_model.py` | `zeroshield/shared/cve_client.py` | 10h |
| Vulnerability Pydantic models | `RabbitMQ/worker/helpers/context/schema.py` | `zeroshield/shared/models.py` | 8h |
| Enums (OWASP, Impact, CWE, Compliance) | `RabbitMQ/worker/helpers/context/enums.py` | `zeroshield/shared/enums.py` | 4h |
| Celery worker config pattern | `RabbitMQ/worker/scan_worker.py` | `zeroshield/worker/celery_config.py` | 6h |
| Celery connection utilities | `backend/utilities/celery/celery_connection.py` | `zeroshield/api/celery_client.py` | 5h |
| StateUpdateWriter | `RabbitMQ/worker/helpers/context/progress_writer.py` | `zeroshield/shared/progress.py` | 2h |
| BaseUtilities (LLM init, Qdrant) | `RabbitMQ/worker/helpers/context/base_utilities.py` | `zeroshield/shared/llm.py` | 6h |
| BaseSummaryManager | `RabbitMQ/worker/helpers/context/base_summary_manager.py` | `zeroshield/shared/summarizer.py` | 3h |
| Vulnerability parsers | `RabbitMQ/worker/helpers/parsers/` | `zeroshield/shared/parsers/` | 4h |
| BaseContext pattern | `RabbitMQ/worker/helpers/context/base_context.py` | `zeroshield/shared/context.py` | 8h |
| S3 utilities | `RabbitMQ/worker/helpers/context/s3_utils.py` | `zeroshield/shared/s3.py` | 3h |
| FastAPI boilerplate (CORS, deps, health) | `backend/main.py` + `backend/get_db.py` | `zeroshield/api/main.py` | 4h |
| Qdrant utilities | `RabbitMQ/worker/helpers/context/qdrant_utils.py` | `zeroshield/shared/qdrant.py` | 2h |
| **Total** | | | **73h** |

---

## Appendix B: Critical Path Diagram

```
Week 1: [Project Setup] → [npm Monitor] → [SCA Worker] → [Priority Queue] → [API] → [Email/PGP] → [Steel Thread]
                                                                                                         |
Week 2-4: [Scale to 100/day] → [GHSA Integration] → [Hardening] → [Public Results] ----------------→ [Day 30 ✓]
                                                                                                         |
Week 5-6: [Top 1000 Scan] → [Semgrep Custom Rules] → [CVE Coverage Report] -------------------------→ [Day 45 ✓]
                                                                                                         |
Week 7-8: [First Real Finding] → [Disclosure Email #1] → [90-Day Clock Starts] ---------------------→ [Day 60 ✓]
                                                                                                         |
Week 9-10: [CVE Application] → [Blog Post #1] → [HN/Reddit Launch] ---------------------------------→ [Day 75 ✓]
                                                                                                         |
Week 11-12: [Published Advisory] → [Social Proof] → [Phase 3 Planning] → [Retrospective] ----------→ [Day 90 ✓]
```

**Parallel track (all weeks):** Community building • Twitter content • Discord • Conference CFPs • Building in public

---

## Appendix C: Decision Log Template

For every non-trivial decision, record:

```markdown
## Decision: {title}
**Date:** YYYY-MM-DD
**Context:** Why this decision was needed.
**Options Considered:**
1. Option A — pros, cons
2. Option B — pros, cons
**Decision:** Option {X}
**Rationale:** Why.
**Consequences:** What this means for the project.
**Revisit By:** YYYY-MM-DD (when to reconsider).
```

First decisions to record:
- ADR-001: PostgreSQL as SoT (not MongoDB)
- ADR-002: GitHub Pages over self-hosted dashboard (Phase 1)
- ADR-003: Grype + OSV + GHSA (not Trivy for npm SCA)
- ADR-004: 90-day disclosure window (not 45 or 120)
- ADR-005: Solo developer (not co-founder search)
- ADR-006: Apache 2.0 license (not MIT or AGPL)

---

*Last updated: 2026-04-11. This is a living document. Update after each weekly retrospective.*
