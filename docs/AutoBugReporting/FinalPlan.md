# ZeroShield — Comprehensive Master Plan v5.0 (FINAL)
## Automated Zero-Day Vulnerability Reporting for npm Packages & Docker Images

**Version:** 5.0 (Round 4 synthesis: +realistic timelines, +cost corrections, +security fixes, +90-day playbook, +risk quantification, +competitive war games, +94 failure modes, +Semgrep rule specs, +technical debt map, +migration plan, +revenue reality check)

---

# 1. EXECUTIVE SUMMARY

ZeroShield is an automated vulnerability detection, reporting, and publishing platform that:
- Continuously monitors npm packages and Docker Hub images for known CVEs and zero-day vulnerabilities
- Uses multi-layer scanning (SCA + SAST + behavioral + AI/LLM) inspired by AISLE's modular pipeline
- Automatically reports findings to maintainers via coordinated responsible disclosure (90-day window)
- Publishes validated results on a public ZeroShield website and GitHub repository
- Provides analytical dashboards with categorized findings and transparency reports
- Tracks full vulnerability lifecycle from detection → disclosure → patch → CVE → closure

**Core Thesis:** "The moat is the system, not the model" — deploy cheap models broadly with strong scaffolding, multi-stage verification, and maintainer trust.

**Positioning:** Public Zero-Day Research Platform for npm & Docker. Professional-grade AI discovery with transparent, verifiable results. Every CVE published. Every finding traceable. Built on open-source tools, augmented with multi-model LLMs, verified by human experts.

**Competitive Context:** ZAST.AI (119 CVEs), TrendAI ÆSIR (21 CVEs), AISLE (180+ CVEs). All closed/black-box. Our niche: dedicated npm + Docker ecosystem scanner with full public transparency and open methodology.

**Race Condition (CRITICAL):** Socket.dev is the most dangerous competitor — already has npm monitoring + behavioral sandbox. 85% chance of adding LLM-based zero-day detection within 2-4 months. **ZeroShield must publish 10+ CVEs BEFORE Socket.dev ships their zero-day feature.** Speed to credible CVE track record is the #1 strategic priority.

---

# 2. TWO-TIER ARCHITECTURE

**Tier 1 — Known CVE Scanner** (Weeks 1-4): Pull existing CVE databases (NVD, OSV, GHSA, CISA KEV), match against npm/Docker SBOMs. Automated reporting + public dashboard.

**Tier 2 — Zero-Day Discovery** (Weeks 9-16): AI + static + behavioral analysis for vulnerabilities with no CVE yet.
- **npm:** Prototype pollution, command injection, path traversal, deserialization, ReDoS, SSRF, eval abuse, timing side-channels, supply-chain attacks
- **Docker:** Privilege escalation, exposed secrets, unsafe base images, layer persistence, misconfigured capabilities

---

# 2A. LEGAL & COMPLIANCE FRAMEWORK

## CFAA Safe Harbor
Static analysis on publicly-available code only. No exploitation, no private repo access, no auth bypass.

**Opt-In/Opt-Out:** Default opt-in-by-silence (industry standard). Opt-out via SECURITY.md, email, or GitHub issue `#opt-out`. Opted-out packages skip scanning entirely.

**Data Retention:** Disclosure emails: 180 days post-publication. Audit hashes: indefinite. Maintainer addresses: **Argon2id hash with per-record random salt** (REVISED v5 — SHA-256 is vulnerable to rainbow table attacks).

**Legal Review Triggers:** PoC spans live exploit, maintainer disputes timeline, supply-chain backdoor → law enforcement path, abandoned package with critical vuln.

**Insurance:** Cyber liability insurance for disclosure activities: $1K-3K/yr. Annual legal counsel (CFAA review): ~$500/yr. Budget from Phase 2.

---

# 3. SYSTEM ARCHITECTURE

```
Registry Monitor (Celery Beat, 30s npm / tiered Docker)
  → Scan Orchestrator (Priority Queue: Critical/High/Normal/Low/AI)
    → 5 Workers (SCA, SAST, Behavioral, AI, Docker)
      → Triage & Verification Engine (5-stage FP reduction)
        → PostgreSQL SoT (Phase 1 JSONB-only; Phase 2+ add MongoDB read model)
          → Disclosure Engine (GHSA API + PGP email + npm form)
            → Public Website (GitHub Pages → Next.js)
            → API Service (FastAPI, OpenAPI 3.1)
            → Integration Ecosystem (GitHub Actions, CI/CD, IDE, Slack)
```

**REVISED v5:** Phase 1 uses PostgreSQL-only with JSONB columns for findings (saves 3-5 days of dual-write debugging). MongoDB read model added Phase 2 when read performance matters. Outbox Pattern for eventual consistency when dual-write is needed.

---

# 4. SECURITY ARCHITECTURE

## 4.0A Sandboxing & Isolation
gVisor/Firecracker microVMs. Network isolation (workers cannot reach internal APIs/DBs/secrets). 2 CPU / 4GB RAM / 10GB disk per container. Ephemeral filesystem. Non-root with dropped capabilities. AppArmor/SELinux MAC profiles. `task_time_limit=900s`.

## 4.0B Secrets Management
HashiCorp Vault (prod) / `.env` (dev only, rotate monthly). 90-day auto-rotation for all API keys **with overlap window for in-flight batch jobs** (REVISED v5). PII/credential masking in all logs. Audit trail on all secret access. Per-stage API key scoping.

## 4.0C Prompt Injection Defense
Strip control characters, limit code to 40K chars. XML `<code_under_review>` tag isolation. Separate API conversation per scan. `json_repair` library for invalid JSON. Hard cap: 32K input / 4K output tokens. Anomaly monitoring for system prompt echoing.

## 4.0D API Security
Public: no auth, 60/min rate limit. Scan: API key, 10/hour. Admin: JWT + IP allowlist + MFA. Pre-disclosure: NEVER exposed via public API. Per-IP + per-API-key sliding window. `/api/v1/` prefix from day 1. **Constant-time API key comparison** (ADDED v5 — prevents timing attacks).

## 4.0E Email Security
PGP/GPG signing. DKIM (2048-bit RSA minimum, split TXT records for providers) + SPF + DMARC (`p=reject`). Custom DKIM domain signing for SES. Public key at `zeroshield.dev/.well-known/security.txt`. Optional encryption if maintainer provides PGP key. **Dedicated IP ($25/mo) required for deliverability** (ADDED v5). **2-4 week email warm-up period** (5-10 emails/day, gradually increasing) before full disclosure throughput.

## 4.0F Database Security
Encryption at rest (PG TDE, MongoDB encrypted storage). Network segmentation. Audit logging + triggers on advisory table modifications. Daily encrypted backups to S3, tested monthly. **Pre-disclosure advisory columns encrypted at application level** (ADDED v5 — defense against DB access compromise).

## 4.0G Artifact Integrity
npm tarballs: SHA512 verification against registry `integrity` field + npm attestation/provenance (SLSA). Docker: digest pinning, DCT signature. Tools: version-pinned in private S3 with immutable object lock + cryptographic signature validation. Zip slip prevention. **Symlink prevention and directory depth limit (max 20 levels) for npm tarball extraction** (ADDED v5). Size limits: 500MB tarball, 5GB Docker image.

## 4.0H External Interface Control Matrix

| Interface | Rate Limits | Auth | Fallback |
|-----------|-------------|------|----------|
| npm Registry | ~10 req/s (40% chance of throttling if sustained) | None | Cached changes feed |
| Docker Hub API | 300/min (auth) | JWT (12h TTL, Redis cached) + retry-with-reauth | Unauth (100/min) |
| Anthropic Claude | Per-plan (separate rate tracking for batch vs regular) | API key | Haiku fallback; batch API |
| NVD API v2 | 50/30s (key) = 144K/day max | API key | Cached DB (7-day staleness OK); local mirror at Phase 5 |
| GitHub API | 5000/h (token) | PAT (security_events:write) | Email-only disclosure |
| RabbitMQ | N/A (internal) | AMQP auth | Firewall: API/Beat only |
| PostgreSQL/MongoDB | N/A | DB credentials | Connection pool w/ health check |

## 4.0I Self-Defense Against Adversarial Scanning
1. **Deobfuscation Pre-Processing:** js-beautify + AST decompilation, entropy flagging (>6 bits/byte), ~5s/package
2. **Intent-Based Scoring:** Credential access + network call combined? Encode/decode before send?
3. **Behavioral Simulation:** npm install in ephemeral sandbox with **realistic fake env vars** (JWT, GITHUB_TOKEN, AWS_ACCESS_KEY_ID — must match real patterns to avoid sandbox detection) (REVISED v5). strace/seccomp monitoring. ~30-60s/package (Tier A + suspects only)
4. **Increased Token Budget:** If Stage 1 flags string manipulation near fetch/axios → 30K→50K tokens in Stage 2
5. **TOCTOU Integrity Validation:** Re-download tarball, re-extract, re-run SAST+Behavioral, compare checksums
6. **Post-Publication Validation:** 30-day re-scan of all published findings to catch tarball modifications

## 4.0J FP Database Access Controls (NEW v5)
FP database write access restricted to authorized reviewers only. All mutations logged with reviewer ID. Bulk operations require admin approval. Detection of >5% FP confirmation rate change in 24h → alert + investigation. Prevents FP database poisoning attack (rated 20/25 threat severity by Round 4 security audit).

---

# 5. COMPONENT DETAILS

## 5.1 Registry Monitor Service

### npm Monitoring — Three-Tier
**Tier 1A (Real-Time):** `GET /-/changes?since={seq}&limit=2500` every 30s. Stores `last_seq` in `registry_state`. Detects new packages within 30-60s. Bulk UPSERT for performance.
- **TRAP (v5):** `seq` can be a string, not just int. Always start with `seq=0` (never `"now"`). If `new_seq < last_seq`, npm did a registry rebuild → reset tracking. `_deleted: true` documents require advisory retraction. Scoped packages arrive as `@scope%2Fpackage` (URL-encoded).
**Tier 1B (Popularity):** `GET api.npmjs.org/downloads/point/last-month/{pkg}` weekly. Tier A (>1M): 6h. Tier B (100K-1M): monthly. Tier C (<100K): on-demand.
**Tier 1C (Metadata):** `GET registry.npmjs.org/{pkg}` per-scan. Scoped: `%40scope%2Fpkg`. Store versions, tarball URLs, integrity SHA512, maintainers, repository.
- **TRAP (v5):** `repository` field in package.json is often wrong/non-standard. Need URL normalization (1 day of effort). Monorepo packages (`@babel/*`) all point to same repo.
**Provenance:** `GET /-/npm/v1/keys` daily for SLSA attestation verification.

### Docker Hub Monitoring
**Auth:** `POST hub.docker.com/v2/users/login` → JWT (12h TTL, Redis cache at 11h). **TRAP (v5):** Hub API auth ≠ Registry auth — need both tokens. JWT can be revoked server-side mid-session → retry-with-reauth logic required. All containers behind same host IP share unauthenticated rate limit.
**Discovery:** `GET /v2/repositories/library?page_size=100` (official), search (community), single repo.
**Tags:** `GET /v2/repositories/{ns}/{name}/tags?page_size=100`. Digest-based rebuild detection (tag unchanged but digest changed → re-scan).
**Multi-Arch:** Track per-platform digests (linux/amd64, arm64, arm/v7) separately; detect platform-specific backdoors.
**Tiered:** A (100 images, 6h), B (500, 24h), C (5000, weekly 2% sample). 1 req/0.5s (120/min, under 300 limit).

## 5.2 Scan Orchestrator
Priority = (Popularity × Recency × RiskProfile) / TimeSinceLastScan. 5 queues: Critical, High, Normal, Low, AI.
**Idempotency (ADDED v5):** `INSERT ... ON CONFLICT (target_id, version) DO NOTHING` before dispatch. Prevents duplicate scan jobs when package publishes multiple versions rapidly.

## 5.3 Scanning Workers (5 Types)

### Worker 1: SCA (Known CVEs)
Grype + OSV.dev batch + NVD v2 + GHSA + CISA KEV. SHA512 integrity verification. Cross-reference EPSS exploitation probability. DevSecShield NVD client reuse.
- **TRAP (v5):** Grype is a Go binary (can't pip install) — needs 60MB binary + 200MB vulnerability DB. OSV.dev batch API: max 1000 queries/request, undocumented rate limits. NVD API: 50/30s = max 100 CVEs/min enrichment. At 5K scans/day (Phase 4), consumes 69% of NVD daily limit.

### Worker 2: SAST (Static Analysis)
Semgrep (community + 5 custom rules). See **Section 5.3B** for complete rule specifications.
- **TRAP (v5):** Community `p/javascript` ruleset produces 50-200 findings per package (mostly informational). Filter by severity+confidence before storage. `metavariable-regex` adds ~10ms per file per filter. Custom rule testing needs 5 days not 2 (need TS, JSX, ESM variants).

### Worker 3: Behavioral & Supply-Chain
Credential harvesting (process.env + network exfil in same file/hook). RAT/malware detection (eval(fetch()), shell spawn, reverse shell, base64). Install hook analysis. Crypto mining (pool connections). Typosquatting (Levenshtein against top 10K). Maintainer hijack (new maintainer + immediate release + hook changes).

### Worker 4: AI Analysis (AISLE 4-Stage Pipeline)
**Stage 1 (Haiku, batch):** File risk scoring 1-5. If all <2 → CLEAN.
**Stage 2 (Sonnet, regular):** Zero-shot detection on high-risk files, 10 vuln classes. Only if traceable input→sink path.
**Stage 3 (Haiku, batch):** Independent cross-validation. ~60% FP reduction.
**Stage 4 (Sonnet, batch):** PoC generation for confirmed findings.
**REVISED Cost Model (v5):** Stage 2 trigger rate is 40-70% (NOT 10% as v4 stated). With current Claude 3.5 Haiku/Sonnet pricing: blended $0.029/scan. With 70% cache hit: $0.0087/scan amortized. **Haiku pricing risk:** If Claude 3 Haiku fully deprecated → Haiku 3.5 costs 4× more overnight. Budget must accommodate 2-4× LLM cost increase.
**Schedule:** 12:00 UTC batch submit → 08:00 UTC results → Stage 2 regular API.
**Caching:** `SHA256(pkg+version+integrity_hash)` → skip re-analysis.
**Fallback (REVISED v5):** Sonnet → Haiku → GPT-4o-mini → skip. Circuit breaker per model (3 failures in 5 min → open for 5 min). Separate rate limit tracking for batch vs regular API.
**Hard cap:** $2.50/package. **LLM auto-kill switch:** Daily cost >120% budget → automatic halt + alert.
**Batch API traps (v5):** `custom_id` on every request (required for result matching). Results URL expires in 24h. Low-tier accounts limited to 1-3 concurrent batches. `ended` status includes both success and failure — must parse JSONL to distinguish. Batch has separate rate limit from regular API.

### Worker 5: Docker Image Scanner
Trivy + Grype + Dockerfile blob analysis. Multi-arch manifest handling. Layer content inspection. Size limit: 5GB (pre-check via manifest size response). Decode base64/hex in RUN commands. AI analysis for Tier A images.

## 5.3A Failure Mode Catalog (EXPANDED v5 — 94 Modes)

**npm Changes Feed (13 modes):** CouchDB hangup, sequence gap, corrupted checkpoint, rate throttling (npm CAN throttle despite being "unlimited"), memory pressure from >10K backlog, _deleted document handling, scoped package URL encoding, registry rebuild reset, malformed JSON at batch boundary, network partition, DNS resolution failure, TLS certificate change, CDN 502/503.

**Docker Hub (14 modes):** JWT revocation mid-session, tag vanish race condition, repository access change (public→private), manifest format variation, multi-arch resolution failure, rate limit exhaustion, adaptive limit detection, image too large, layer download corruption, registry v1/v2 format mismatch, auth vs registry token confusion, shared IP rate limiting, tag pagination cursor invalidation, digest format change.

**Scanning Tools (16 modes):** Binary crash (SIGSEGV/OOM), Grype DB update failure, output exceeds memory (>20MB JSON), tool hang/deadlock, empty output masquerading as no-findings (CRITICAL), version incompatibility post-update, Semgrep rule syntax error (silently skipped), UNKNOWN severity handling, output schema format change, conflicting cross-scanner results, zip-bomb variant in tarball, Grype DB staleness (>7 days), zombie processes after timeout kill, missing binary in container (no readiness probe), disk full during scan, race condition on duplicate scan dispatch.

**LLM API (15 modes):** 529 overloaded, batch job stuck >24h, truncated JSON response, content policy refusal, token count exceeds limit, API key rotation during active batch, batch API deprecation, cost exceeds hard cap without kill, hallucination passes all triage, batch result misattribution (wrong package), model downgraded server-side, batch+regular rate limit exhaustion, network partition (request never completes), cache poisoning, daily cost overrun without automatic halt.

**Standardized Executor Pattern (ADDED v5):**
All scanners wrapped in `ScannerExecutor` class: binary existence check on startup, version assertion, disk space pre-check (1GB minimum), Grype DB freshness check (7-day max), output size limiting via streaming, empty output validation, schema version verification, explicit zombie process reaping. All wrapped with `asyncio.wait_for(timeout)`.

**LLM Cost Guard (ADDED v5):**
Pre-authorize estimated cost before each call. Track daily spend in Redis. Per-package cumulative cost tracking. Auto-kill at 120% daily budget. Alert at 80%. Token estimation before API call (using tiktoken or cl100k_base approximation — note: Anthropic has no public tokenizer library).

## 5.3B Semgrep Custom Rule Specifications (NEW v5)

### Rule 1: `npm-prototype-pollution` (HIGH, CWE-1321, CVSS 7.5)
Patterns: `$OBJ[$KEY] = $VALUE` where key derives from user input, recursive merge functions with `__proto__`/`constructor.prototype`. Not-inside: `Object.create(null)`, `Map`/`Set` usage. FP rate: 12-18%. Edge cases: computed property names, Proxy objects, JSON.parse boundary.

### Rule 2: `npm-command-injection` (CRITICAL, CWE-78, CVSS 9.8)
Patterns: `exec($CMD)`, `execSync($CMD)`, `spawn($CMD, {shell: true})`, `child_process.*` with non-literal args. Not: string literal args, `execFile` (no shell), `spawn` without shell option. FP rate: 5-8%. Edge cases: aliased require, dynamic require, ESM imports.

### Rule 3: `npm-install-hook-network-exfil` (CRITICAL, CWE-200, CVSS 8.1)
Patterns: `fetch`/`axios`/`http.request` co-occurring with `process.env` access in same scope. DNS exfiltration pattern (`dns.resolve` with encoded env vars in subdomain). **Highest FP producer** — legitimate packages access `process.env` for config AND make network requests. FP rate: 15-22%. Recommended: add `pattern-not-inside` for `process.env.HTTP_PROXY` and similar.

### Rule 4: `npm-eval-dynamic-input` (HIGH, CWE-95, CVSS 7.5)
Patterns: `eval($EXPR)`, `new Function($BODY)`, `vm.runInNewContext($CODE)`, `setTimeout($STR)` with non-literal args. FP rate: 8-12%.

### Rule 5: `npm-redos` (MEDIUM, CWE-1333)
Patterns: `new RegExp($X)` from user input, `/pattern/.test($INPUT)` with known evil patterns (nested quantifiers, overlapping alternations). Integrated with redos-detector library for static regex analysis. FP rate: 10-15%.

**Missing rules identified (v5):** shelljs `exec()`, execa `{shell: true}`, ESM `import { exec } from 'node:child_process'`, `require('vm2')` sandbox escapes, WebAssembly instantiation, `globalThis.__proto__` pollution.

## 5.4 Triage & Verification Engine (5-Stage FP Reduction)

### 47 FP Categories Identified
SCA: 10 types. SAST: 13 types. Behavioral: 10 types. AI/LLM: 10 types (including hallucinated vuln, misunderstood context, pattern without data flow, unexploitable theory, dead code path).

### 5-Stage Verification Pipeline
**Stage A (Static Confidence):** `base = rule_confidence × scanner_precision × semantic_match`. Grype: 0.94, Semgrep: 0.95, Trivy: 0.93, AI: 0.92.
**Stage B (Cross-Scanner Correlation):** 2+ scanners agree → +40%. Different rules same CWE → +25%. Independent LLM agrees → +35%.
**Stage C (Reachability Analysis):** Is vuln function in public API? Feature-gated disabled? Dead code → reject. User-controlled input? Taint analysis.
**Stage D (AI Second-Opinion):** Different model/prompt validates independently. Requires line numbers + code snippet + attack scenario. Disagreement → -40%.
**Stage E (Historical FP Database):** Exact pattern marked FP before → -80%. Similar (Levenshtein <30%) → -50%. Exact CVE disputed → -60%.

### Confidence Thresholds
- **Auto-publish + CVE request (>95%):** Fully validated, multiple scanner agreement
- **Report to maintainer (>80%):** High confidence, send disclosure
- **Human review queue (30-80%):** Expert examination required
- **Auto-dismiss (<30%):** Log as research, don't report
- **Weekly threshold tuning:** Review FP/FN rates, adjust by ±5%

### Quality Metrics
Precision, Recall, Time-to-triage, Maintainer agreement rate, CVE assignment rate. Target: <5% FP rate at 12 months.

## 5.5 Disclosure Engine (Ethics Framework)

### Severity-Based Decision Authority
CRITICAL confirmed: Automated + human review queue, Day 0 email, 30-day embargo (or 7-day for critical infrastructure). CRITICAL uncertain: Mandatory human review, 3-5 day expert analysis. HIGH confirmed: Automated + 3-day async review, 45-day embargo. MEDIUM confirmed: Batch disclosure weekly, 60-day embargo. LOW: Suppress unless cluster (3+ in same package) or supply-chain context.

**Automated threshold:** Severity ≥ HIGH (7.0) + Confidence ≥ 80% + Traceable input→sink.

### Critical Infrastructure Exception
If vulnerability affects critical infrastructure + >50% market share in sector + actively exploitable + maintainer unresponsive >5 days: accelerated 7-day disclosure.

### 90-Day Workflow
Day 0: Confirm + SHA-3 proof-of-discovery hash + internal advisory. Day 1: Resolve maintainer (GitHub Advisory draft + PGP email + npm form). Day 14: First follow-up. Day 30: Second follow-up + escalate CVSS≥7. Day 60: Third follow-up + prepare publication. Day 90: Publish + CVE request.

### GitHub Advisory API
`POST /repos/{owner}/{repo}/security-advisories` (draft). `PATCH .../{ghsa_id}` (publish). Fallback: 403 "not enabled" → email-only. 404 "repo not found" → email-only. CVE: GitHub CNA (auto-assigns, 1-3 days) → MITRE fallback (5-15 days). **TRAP (v5):** Can only create advisories on repos with push access OR where security advisories are enabled. For most npm packages, you won't have this access. **Email-only disclosure is the DEFAULT path, not the exception.**

### Abandoned Package Protocol
**Detection:** No response >90 days + zero repo activity >24 months + still has downloads (≥100/week).
**Tier 1 (Days 0-30):** Disclosure email + private advisory + npm form.
**Tier 2 (Days 31-60):** Escalate to npm security team (`security@npmjs.com`).
**Tier 3 (Days 61+):** Publish with "UNMAINTAINED" label + community fork recommendations.

### Dispute Resolution
1. Provide PoC + affected versions + CVSS justification. 2. Technical discussion (private). 3. Independent third-party review. 4. If still disputed: publish with "disputed" label + maintainer response. 5. Retract if proven wrong.

### Communication Templates
Initial disclosure, 14-day follow-up, 30-day reminder, 60-day escalation, 90-day publication notice, false positive apology, severity upgrade notification. All PGP-signed.

## 5.6 Public Website
Phase 1: GitHub Pages (Jekyll/Hugo, daily rebuild, advisory markdown, JSON/RSS feeds, Lunr.js search).
Phase 3+: Next.js (real-time dashboard, Recharts, disclosure lifecycle viz, Schema.org markup, diff viewer).

## 5.7 API Service (Complete Design)

### OpenAPI 3.1 Specification
```
# Public (no auth, 60/min)
GET  /api/v1/advisories?limit=20&cursor=&ecosystem=npm&severity=HIGH&cwe=CWE-79&published_since=
GET  /api/v1/advisories/{zeroshield_id}
GET  /api/v1/packages/{ecosystem}/{name}?include_history=true
GET  /api/v1/packages/{ecosystem}/{name}/timeline
GET  /api/v1/stats
GET  /api/v1/feed/rss|json|atom?ecosystem=&severity=
GET  /api/v1/health

# Authenticated (API key in X-API-Key header)
POST /api/v1/scan   {ecosystem, name, version?}
GET  /api/v1/scan/{id}/status
GET  /api/v1/scan/{id}/findings
POST /api/v1/webhooks   {url, events[], secret}
GET|DELETE /api/v1/webhooks/{id}
POST /api/v1/webhooks/{id}/test

# Admin (JWT + IP allowlist + MFA)
GET  /api/v1/admin/pre-disclosure
POST /api/v1/admin/advisory/{id}/publish

# Privacy (GDPR, identity-verified)
GET|DELETE /api/v1/privacy/data/{maintainer_id}
```

### Pagination
Cursor-based (recommended) + offset-based (backward compat). Response: `{data, next_cursor, has_more, total_count}`.

### Webhook Events
`new_advisory`, `advisory_updated`, `advisory_retracted`, `scan_completed`, `disclosure_status_changed`. HMAC-SHA256 signature in `X-ZeroShield-Signature` header.

### Output Formats
SARIF 2.1.0, CycloneDX BOM, VEX, CSAF, JSON, RSS/Atom.

## 5.8 User Personas & UX Design (NEW v5)

### 8 Target Personas
1. **Marcus (Staff Security Engineer):** Needs integration with existing CSPM/SIEM. Time-to-value: 2h.
2. **Priya (OSS Maintainer):** Receives disclosure emails. Time-to-value: immediate (email arrives).
3. **David (DevOps Lead):** Needs GitHub Actions integration. Time-to-value: 15min (copy YAML).
4. **Lisa (CISO):** Needs compliance reports, SLA guarantees. Time-to-value: 1 week (trial).
5. **Raj (Security Researcher):** Needs API access, raw findings. Time-to-value: 5min (API key).
6. **Sarah (VP Engineering):** Needs business metrics, ROI evidence. Time-to-value: demo.
7. **Anton (Platform Engineer):** Needs webhook integration, self-hosted option. Time-to-value: 30min.
8. **Emma (GRC Analyst):** Needs SBOM/VEX output, audit trails. Time-to-value: 1 day.

### Trust Building Strategy
Blog post per CVE published (methodology + timeline). Public FP rate dashboard. Maintainer testimonials. Conference talk recordings. GitHub star evidence. Response time SLA.

---

# 6. DATA SOURCES & FEEDS

| Source | Frequency | Rate Limit | Purpose |
|--------|-----------|------------|---------|
| npm Changes Feed | Every 30s | "Unlimited" (can throttle >10 req/s) | Real-time new packages |
| npm Package Metadata | Per-scan | ~10 req/s | Version/maintainer data |
| npm Downloads | Weekly | None | Popularity ranking |
| Docker Hub API | Tiered | 300/min (auth) | Image monitoring |
| OSV.dev | Per-scan | 1000/batch, undocumented limits | CVE matching |
| NVD API v2.0 | Every 2h | 50/30sec = 144K/day | CVSS enrichment |
| GitHub Advisories | Hourly | 5000/h (token) | Known advisories |
| CISA KEV | Daily | None | Active exploitation |
| Socket.dev | Daily | TBD | Malicious package reports |
| OpenSSF Scorecard | Weekly | TBD | Package health signals |

---

# 7. TECH STACK

FastAPI (Python 3.12+), Celery + RabbitMQ, Celery Beat, PostgreSQL 16 (SoT, JSONB for findings Phase 1), MongoDB 7 (read model Phase 2+), Redis 7 (cache + cost tracking), Next.js + shadcn/ui + Recharts (dashboard from Day 1), GitHub Pages + Actions, Grype (Go binary, 60MB + 200MB DB) + OSV.dev + NVD, Trivy, Semgrep (community + 5 custom rules), Claude Haiku + Sonnet (batch + regular), Dedicated domain + PGP (email), HashiCorp Vault (prod), S3/MinIO, gVisor/Firecracker, Docker Compose → Kubernetes, Prometheus + Grafana + OpenTelemetry.

---

# 8. DATABASE SCHEMA

## PostgreSQL (Core Records)
```sql
registry_state (id, registry, last_seq, last_checked_at)
monitored_targets (id, ecosystem, name, latest_version, popularity_score, popularity_tier, last_scanned_at, scan_frequency_hours, is_active, opted_out, provenance_supported, created_at, UNIQUE(ecosystem,name))
advisories (id, target_id FK, cve_id, ghsa_id, zeroshield_id UNIQUE, title, description, severity, cvss_score, cvss_vector, epss_score, cwe_ids JSONB, affected_versions, patched_version, discovery_method, confidence_score, status, proof_of_discovery_hash, disclosure_deadline, reported_at, acknowledged_at, patched_at, published_at, maintainer_email_hash, maintainer_email_salt, github_advisory_url, poc_description, llm_cost_usd, created_at)
scan_jobs (id, target_id FK, scan_type, status, task_id, findings JSONB, findings_count, duration_seconds, llm_cost_usd, llm_cache_hit, error_message, created_at, UNIQUE(target_id, version))
scan_dlq (id, scan_job_id FK, worker_type, error_message, error_traceback, failed_at, retry_count, status)
disclosure_events (id, advisory_id FK, event_type, channel, details, created_at)
api_keys (id, key_hash UNIQUE, owner_name, tier, rate_limit_per_hour, is_active, created_at)
false_positive_patterns (id, package, version, scanner, rule_id, finding_hash, reason, confirmed_by, confirmed_at)
webhooks (id, api_key_id FK, url, events JSONB, secret_hash, is_active, created_at)
gdpr_requests (id, maintainer_identifier, request_type, status, requested_at, deadline, completed_at)
incident_log (id, incident_type, severity, description, detected_at, resolved_at, rca_url)
```

**REVISED v5:** `scan_jobs.findings` is JSONB in Phase 1 (no MongoDB needed). `advisories` has `maintainer_email_salt` column (per-record Argon2id). `scan_jobs` has UNIQUE constraint on `(target_id, version)` for idempotent dispatch.

## MongoDB Collections (Phase 2+)
`scan_findings` (read-optimized), `llm_cache`, `threat_intelligence_feed`.

---

# 9. SCANNING PIPELINE

## npm Scan Flow
1. DISCOVER → Changes feed (30s) → UPSERT `monitored_targets` + idempotent `scan_job` creation
2. DOWNLOAD → Fetch tarball → SHA512 verify + npm attestation → Sandboxed extract (500MB max, 20-level depth limit, symlink prevention)
3. LAYER 1: SCA Worker (5-15s) → Grype → OSV.dev batch (1000/req) → NVD CVSS → CISA KEV
4. LAYER 2: SAST Worker (30-120s) → Deobfuscation → Semgrep (community + 5 custom) → Filter by severity
5. LAYER 3: Behavioral Worker (10-30s) → Full behavioral analysis suite
6. LAYER 4: AI Worker → Cache check → 4-stage pipeline (see 5.3)
7. TRIAGE → 5-stage FP reduction → Confidence scoring → Threshold routing
8. STORE → PostgreSQL JSONB (Phase 1) / PostgreSQL + MongoDB (Phase 2+)
9. DISCLOSE → Maintainer resolution → Email-only (default) → GHSA (when available) → Timeline tracking

---

# 10. PROJECT STRUCTURE

```
zeroshield/
├── scanner/ (npm_scanner, docker_scanner, scanner_executor, docker_blob_analyzer, ai_analyzer, behavioral_analyzer, hook_analyzer, hook_simulator, typosquat_detector, deobfuscator)
├── reporter/ (email_reporter, github_reporter, maintainer_resolver, dashboard_publisher, cve_requester, coordinator)
├── orchestrator/ (scheduler, npm_monitor, docker_monitor, priority, watchlist.json)
├── triage/ (deduplicator, fp_filter, fp_database, severity_enricher, confidence_scorer, reachability_analyzer)
├── security/ (sandbox, integrity, prompt_guard, secrets)
├── observability/ (metrics, alerting, tracing, dashboards)
├── privacy/ (gdpr_handler, data_export, erasure_scheduler)
├── integrations/ (github_action, sarif_output, cyclonedx_output, webhook_dispatcher)
├── threat_intel/ (feed_aggregator, ttp_signatures)
├── incidents/ (runbooks/, incident_tracker)
├── llm/ (llm_abstraction, cost_guard, batch_monitor, prompt_templates/)
├── db/ (schema.sql, models.py, outbox.py)
├── dashboard/ (Next.js app)
├── semgrep-rules/ (5 custom YAML rules + test fixtures)
├── tests/
├── docker-compose.yml
├── .env.example (30+ vars documented)
└── README.md
```

---

# 11. DEVSECSHIELD REUSE (REVISED v5 — Migration Plan)

## Strategy: Copy-and-Diverge (No Shared Library)
Copy relevant code into ZeroShield, modify as needed. No cross-repo imports or shared packages.

## Reusable Components (~73h savings)
- BaseAgent + BaseUtilities pattern (8h savings)
- NVD API client + 4-tier caching (8h savings)
- Vulnerability Pydantic models (5h savings)
- StateUpdateWriter (copy as-is)
- Celery connection utilities (7h savings)
- shadcn/ui component library + chart components
- Axios interceptor pattern

## NOT Reusing
Team/Credit system, User/TeamMembership, Jira integration, PDF export, RBAC.

## Extraction Plan
7 phases, 9 working days, ~47h total effort. Start Next.js dashboard from Day 1 (use `output: 'export'` for GitHub Pages compatibility initially).

---

# 12. INITIAL WATCHLIST

**npm (high-risk: packages with `postinstall` hooks):** litellm, langchain, @langchain/core, openai, @anthropic-ai/sdk, axios, express, fastify, socket.io, ws, node-fetch, got, superagent, jsonwebtoken, bcrypt, passport, multer, serialize-javascript, lodash, moment, sharp, pino, winston.
**Docker:** nginx, node:20-alpine, node:22-alpine, python:3.11-slim, redis:7-alpine, postgres:16-alpine, mongo:7, ollama/ollama, open-webui/open-webui, qdrant/qdrant, grafana/grafana.

**Phase 1 scanning strategy (v5):** Start with packages that have `postinstall` hooks — highest probability of supply-chain findings. Write 3 custom Semgrep rules targeting install hooks specifically.

---

# 13. IMPLEMENTATION ROADMAP (REVISED v5 — Realistic Timelines)

## Phase 1: Foundation (Weeks 1-8, REVISED from 4) ~$450-650/mo
**Minimum Viable Pipeline (Weeks 1-4):**
- PostgreSQL schema (core tables with JSONB findings — no MongoDB yet)
- FastAPI skeleton with 3 endpoints: `POST /scan`, `GET /scan/{id}`, `GET /advisories`
- Celery + RabbitMQ with ONE worker type (SCA via Grype only)
- Manual scan trigger (no changes feed yet)
- Basic confidence scoring (Grype confidence only)
- GitHub Pages with one advisory (static site, daily rebuild)

**Full Phase 1 (Weeks 5-8):**
- npm changes feed automation (with seq tracking, bulk UPSERT)
- OSV.dev + NVD enrichment
- CISA KEV cross-reference
- Email setup (PGP/DKIM/SPF/DMARC) — **3-5 days minimum**
- Email warm-up period (2-4 weeks at 5-10 emails/day)
- Watchlist management
- LLM abstraction layer (implement now, use later) — **per ADR-004**

**CRITICAL: What NOT to build in Phase 1:**
- ~~Dual-write (PostgreSQL + MongoDB)~~ → Use PG JSONB only
- ~~Full disclosure workflow~~ → GitHub issue only, no PGP email
- ~~npm changes feed~~ → Manual triggers until pipeline proven
These 3 cuts save 10-12 days and make 4 weeks achievable for MVP.

## Phase 2: SAST + Behavioral + Docker + Disclosure (Weeks 9-20, REVISED from 8) ~$600-900/mo
Semgrep (community + 5 custom), deobfuscation pipeline, behavioral analyzer, install hook simulator, Docker Hub monitoring (JWT, multi-arch, digest), container scanning, 5-stage triage engine, full 90-day disclosure workflow (GHSA + PGP + npm), MongoDB read model (Outbox Pattern for consistency), maintainer resolver.
**Post-first-publication hardening (2 weeks):** Budget for FP recovery, pipeline fixes, threshold tuning after first public finding.

## Phase 3: AI Zero-Day Discovery (Weeks 21-36) ~$1,000-1,500/mo
AI worker with 4-stage AISLE pipeline, batch API routing, LLM result caching, prompt injection defense, cross-model validation, token/cost guardrails, adversarial countermeasures, sandboxing (gVisor), CVE automation, API auth + rate limiting, GitHub Actions integration.

## Phase 4: Scale & Harden (Weeks 37-52) ~$2,000-3,500/mo
Kubernetes with HPA, expand to 10K npm + 1K Docker, Vault for secrets, coordinated multi-vendor disclosure, transitive dependency analysis, Next.js dashboard (replace GitHub Pages), Prometheus + Grafana + OpenTelemetry (dedicated monitoring instance), SARIF/CycloneDX output.

## Phase 5: Monetization & Community (Week 53+) ~$5,000-8,000/mo
Local LLM option, open-source AI code, community portal, freemium SaaS, Slack/webhook integration, PyPI/Maven expansion, conferences. Local NVD mirror (required at 10K+/day).

---

# 14. COST ESTIMATES (REVISED v5 — Corrected)

| Phase | Scale | Compute | DB | LLM | Email | Storage | Hidden* | Total/mo |
|-------|-------|---------|-----|-----|-------|---------|---------|----------|
| 1 | 100/day | $16-120† | $24-75 | $2 | $35‡ | $20 | $80 | ~$450-650 |
| 2 | 500/day | $140-250 | $102-150 | $15-45§ | $40 | $40 | $120 | ~$600-900 |
| 3 | 1K/day | $280-400 | $166-250 | $87-200 | $50 | $60 | $150 | ~$1,000-1,500 |
| 4 | 5K/day | $840-1200 | $490-600 | $130-300 | $60 | $150 | $250 | ~$2,000-3,500 |
| 5 | 10K+/day | $1,400-2,500 | $980-1,200 | $260-500 | $80 | $400 | $400 | ~$5,000-8,000 |

† **Phase 1 Compute Options:**
- **Option A (recommended start):** Hetzner CX41 (8 vCPU, 16GB): $16/mo. Manual ops, no managed services.
- **Option B:** Managed DBs (free tiers) + EC2 t3.large ($60/mo): ~$70-82/mo.
- **Option C:** All-in-one EC2 t3.2xlarge: $240/mo (on-demand) or $154/mo (1yr RI).

‡ Includes $25/mo dedicated IP for email deliverability.

§ **LLM cost correction:** Blended $0.029/scan (was $0.012 in v4). With 70% cache: $0.0087/scan. At 500/day: $15-45/mo depending on cache hit rate.

*Hidden costs: monitoring ($0-60), backups ($2-15), error tracking ($0-26), DNS ($0.50), insurance/legal ($42 amortized), Docker Hub Pro ($7), NVD API (free but local mirror needed at Phase 5: $5-10/mo).

**Monitoring Stack (Phase 3+):** Prometheus + Grafana + Loki self-hosted needs 3-7GB RAM + 31-151GB disk → dedicated t3.large ($60/mo). NOT included in DB column.

---

# 15. KEY DESIGN DECISIONS

1. Separate project (ZeroShield public, DevSecShield team). 2. Multi-model LLM with abstraction layer from Day 1. 3. Quality over quantity (traceable input→sink only). 4. Ship MVP in 4 weeks, full Tier 1 in 8 weeks (REVISED). 5. 90-day disclosure with proof-of-discovery hash. 6. Open-source AI methodology (Apache 2.0). 7. 5 dedicated workers. 8. Tiered scanning (A: 6h, B: weekly, C: monthly). 9. PG-only Phase 1, dual-write Phase 2 (REVISED). 10. Email-only disclosure as default path (REVISED).

---

# 16. RISKS & MITIGATIONS (REVISED v5 — Quantified)

## Risk Quantification Model
**Total Expected Annual Loss: $220,415** across 15 identified risks.

| Risk | Probability | Impact | Expected Annual Loss |
|------|------------|--------|---------------------|
| Key person unavailable (bus factor=1) | 85/100 | HIGH | Top risk. Hire FTE #2 by Month 12. |
| Competitor launch (Socket.dev zero-day) | 70/100 | HIGH | $90K EAL. Speed to 10+ CVEs is mitigation. |
| False positive CVE published | 60/100 | MEDIUM | Budget 2 weeks post-first-publication hardening. |
| LLM cost spike (model deprecation) | 50/100 | MEDIUM | Abstraction layer + budget buffer. |
| npm rate limiting/ban | 40/100 | HIGH | Cached feed, respectful polling. |
| First CVE wrong | 30-50% | HIGH | Every platform's first public finding. FP apology template ready. |

**Recommended mitigation investment:** $40,000/yr → 1.68× ROI Year 1.
**Insurance + legal:** $36,500/yr (~$3K/mo).

---

# 17. SUCCESS METRICS

| Metric | 6 months | 12 months |
|--------|----------|-----------|
| Advisories published | 30+ | 150+ |
| CVEs assigned | 5+ | 30+ |
| npm monitored | 10,000 | 50,000 |
| Docker monitored | 500 | 2,000 |
| FP rate | <15% | <5% |
| Disclosure-to-patch | <60 days | <45 days |
| Maintainer ack rate | >50% | >75% |
| LLM cost/scan | <$0.03 | <$0.01 (with caching) |

---

# 18. COMPETITIVE POSITIONING (REVISED v5 — War-Gamed)

| Dimension | Snyk | Socket.dev | AISLE | ZAST.AI | ZeroShield |
|-----------|------|-----------|-------|---------|------------|
| Known CVEs | ✅ | ❌ | ❌ | ❌ | ✅ |
| Zero-day AI | ❌ (90% chance "Snyk AI" soon, won't publish) | ❌ (85% chance in 2-4mo) | ✅ | ✅ | ✅ |
| Supply-chain | ❌ | ✅ | ❌ | ❌ | ✅ |
| Public findings | ❌ | ❌ | ✅ | ❌ | ✅ |
| Open methodology | ❌ | ❌ | ❌ | ❌ | ✅ |
| npm+Docker focus | ✅ | ✅(npm) | ❌ | ❌ | ✅ |

### True Moat (After 50+ CVEs)
**Defensible:** CVE track record, maintainer trust network, FP pattern database.
**NOT defensible:** Public transparency alone, AI methodology, open documentation.

### Competitive Timeline
- **Months 1-6:** Race to 10+ published CVEs. Socket.dev has ~2-4 month window.
- **Months 7-12:** If 10+ CVEs published, moat begins forming. GitHub becomes amplification partner.
- **Months 13+:** CVE track record is self-reinforcing. New entrants can't replicate 12 months of verified findings.

### Platform Risk
npm: 40% chance of rate-limiting if >10 req/s sustained. Docker Hub: rate limit tightening likely. GitHub: possible TOS changes for automated advisory creation. **Mitigation:** Respectful API usage, official partnership outreach, cached/local mirrors.

---

# 19. TESTING STRATEGY

Unit coverage: SCA 70%, SAST 65%, Behavioral 60%, AI 50%, Triage 75%. Mock boundaries: Real (tarball fixtures, test PG, Semgrep binary) / Mock (external APIs, LLM, email via MailHog). Known vuln test suite: lodash@4.17.18, serialize-javascript@5.0.0, ua-parser-js@1.0.33, event-stream@3.3.4 + clean baseline. Integration: full pipeline e2e. Test infra: docker-compose.test.yml.

---

# 20. DEPLOYMENT & SCALABILITY

## Docker Compose (Phase 1-3)
postgres:16-alpine (2CPU/2GB), rabbitmq:3.12-management (1CPU/512MB), redis:7-alpine (0.5CPU/512MB), backend FastAPI (2CPU/2GB), worker-sca (4c, 2CPU/2GB). **Phase 1 only needs 5 containers** (no MongoDB, no SAST/Behavioral/AI/Docker workers).

## Scalability Analysis
**At 50K scans/day:** RabbitMQ single node OK but need 3-node cluster for HA. PG: bulk UPSERT for changes feed (2500 rows in 200ms). PgBouncer for connection pooling. Celery AI Worker: 2 concurrent = 1,440/day → need 10 workers at scale via K8s HPA.

## Kubernetes Migration (Phase 4)
Trigger: >5K scans/day OR >3 worker types need independent scaling. HPA per worker type (scale on RabbitMQ queue depth). NetworkPolicies. Ingress.

---

# 21. REVENUE & SUSTAINABILITY (REVISED v5 — Reality Check)

**Freemium SaaS (Phase 5+):**
Free (advisory search, feeds, 60/h API). Starter $29/mo (50 scans, 600/h, email alerts). Pro $299/mo (unlimited, Slack, webhooks, watchlists, 99.5% SLA). Enterprise custom (1h cadence, SOC 2, pre-disclosure 7-day, 99.9% SLA).

**Revenue Target at 24mo:** ~$68K/mo.
**REALITY CHECK (v5):** $68K/mo requires ~687 paid customers. Organic growth for bootstrapped security startup produces ~50 customers in Year 1. **Enterprise contracts are mandatory** — 5 Enterprise at $5K-10K/mo could close the gap. Revenue gap requires either: (a) venture funding, (b) enterprise sales focus from Month 6, or (c) adjusted burn rate expectations.

**Go-to-market:** Technical blog per CVE (mandatory — proves methodology), HN/Reddit posts on each finding, conference CFPs, GitHub ecosystem partnerships.

---

# 22. PRIVACY & COMPLIANCE

## PII Inventory
12 PII elements mapped. Each with: collection point, storage, purpose, retention, deletion method, encryption status.

## GDPR Compliance
Lawful basis: Legitimate interest (Art 6(1)(f)). Data subject rights: Access (30 days), Erasure (limited per Art 17(3) for legal evidence). Privacy API: `GET/DELETE /api/v1/privacy/data/{id}`. Dedicated `privacy@zeroshield.dev`.

## SOC 2 Readiness
Target: Type I by Phase 4, Type II by Phase 5.

## Third-Party DPAs
Required with: Anthropic (confirm no training on scan data), email service provider, cloud provider.

---

# 23. OBSERVABILITY & SRE

## SLO/SLI Framework
| Service | Availability | Latency p95 | Error Rate |
|---------|-------------|-------------|------------|
| Public API | 99.9% | 500ms | <0.1% |
| Disclosure Engine | 99.95% | 2s | <0.05% |
| Scan Orchestrator | 99.5% | 300ms | <0.5% |

**Error Budgets:** 99.9% = 43.2 min/month. <20% remaining: code freeze. Exhausted: mandatory post-incident review.

## Alerting
Worker queue >1000 for >5min → CRITICAL. LLM daily cost >120% → auto-kill (not just WARNING). Pre-disclosure unauthorized access → CRITICAL. npm feed >5 min behind → WARNING. Zero scans in 30 min → CRITICAL. DLQ >50 → HIGH.

## Distributed Tracing
Trace ID from API request → Celery task → scanner → LLM call → DB write. Structured JSON logging. PII masking. Loki log aggregation.

---

# 24. THREAT INTELLIGENCE

## MITRE ATT&CK Mapping
Initial Access: Typosquatting (T1195.002), dependency confusion (T1195.001), maintainer compromise (T1078), abandoned package takeover, lockfile injection.
Execution: Install hooks (T1059.007), eval/Function (T1496), dynamic require (T1106), WebAssembly payload.
Persistence, Credential Access, Exfiltration, Evasion — all mapped to specific TTPs.

## Emerging Vectors
Lockfile injection, dependency confusion in monorepos, GitHub Actions cache poisoning, npm publish automation hijack, Docker build-time secrets in layer cache, WebAssembly binary obfuscation, multi-stage payload delivery, compiler/transpiler attacks (babel plugin backdoors).

## Proactive Hunting
Monitor npm firehose for name similarity to top 10K. Monitor Docker Hub for "official-looking" unofficial images. Cross-reference maintainer email changes with publishing activity.

---

# 25. INCIDENT RESPONSE & RUNBOOKS

## Key Runbooks
1. PostgreSQL Connection Exhaustion (pool >80%)
2. LLM Poisoning / False Finding Published (retract → re-validate 7 days → tighten thresholds)
3. Sandbox Escape Attempt (pod kill → evidence → secret rotation)
4. False Positive CVE Retraction (formal retract → NVD/GHSA update → apology → blog)

## Disaster Recovery
| Store | RPO | RTO |
|-------|-----|-----|
| PostgreSQL | 1 hour | 15 min |
| MongoDB | 24 hours | 1 hour |
| S3 Artifacts | 1 day | 2 hours |
| Redis | N/A (ephemeral) | 5 min |

---

# 26. INTEGRATION ECOSYSTEM

**Tier 0 (MVP):** GitHub Actions (`zeroshield-security/scan@v1`) + Public API.
**Tier 1 (Scale):** GitLab CI template + npm CLI (`npx zeroshield audit`) + Renovate/Dependabot compat.
**Tier 2 (Ecosystem):** VS Code extension + Slack bot + Docker CLI plugin.

---

# 27. ARCHITECTURE DECISION RECORDS

## ADR-001: Celery+RabbitMQ (proven at DevSecShield scale). Revisit at >5K/day.
## ADR-002: PG-only Phase 1 with JSONB → add MongoDB Phase 2 (REVISED v5).
## ADR-003: Monolith Phases 1-3 → extract services Phase 4-5.
## ADR-004: Anthropic primary with LLM abstraction layer from Month 1 (CRITICAL).
## ADR-005: Python-only as long as possible (bus factor = 1).
## ADR-006: Docker Compose → Kubernetes at >5K/day or >3 worker types.
## ADR-007: CRUD + disclosure_events audit → event sourcing Phase 5.
## ADR-008: Abstract Scanner + Ecosystem Adapter for multi-ecosystem expansion (PyPI, Maven, Go, Cargo).

---

# 28. TECHNICAL DEBT PREDICTIONS (NEW v5)

| Shortcut | Taken In | Hurts At | Refactor Cost | Description |
|----------|----------|----------|---------------|-------------|
| Grype DB in worker image | Phase 1 | Phase 3 (1K/day) | 3-5 days | Move to shared volume/sidecar updater |
| Flat env var config | Phase 1 | Phase 2 (50+ vars) | 2-3 days | Need hierarchical YAML/TOML config |
| Single Celery app | Phase 1 | Phase 3 (AI worker) | 3-5 days | Split per-worker Celery apps |
| No idempotency on dispatch | Phase 1 | Phase 2 | 2-3 days | Dedup: ON CONFLICT DO NOTHING |
| Hardcoded vuln classes | Phase 2 | Phase 3-4 | 3 days | Should be DB-driven |
| Semgrep rules without versioning | Phase 2 | Phase 3 | 2 days | Rule updates change findings on re-scan |
| GitHub Pages for website | Phase 1 | Phase 4 | 2-3 weeks | Can't support real-time dashboard, auth, search |
| No behavioral sandboxing | Phase 2 | Phase 3 | 5-8 days | Add gVisor/Firecracker |
| PostgreSQL advisory table too wide | Phase 1 | Phase 3 | 3-5 days | Normalize into advisory_metadata, advisory_scores, advisory_timeline |

**Recommendation:** Accept all Phase 1 shortcuts for speed. Budget 2-3 weeks Phase 2 specifically for tech debt remediation.

---

# 29. FIRST 90 DAYS PLAYBOOK (NEW v5)

## Week 1 (Day-by-Day, 54h total)
- **Day 1 (Mon):** Domain purchase + DNS (1h). GitHub org + repos (1h). PG schema v1 (3h). FastAPI skeleton (2h). Dev environment (1h).
- **Day 2 (Tue):** Celery + RabbitMQ setup (3h). Grype binary install + DB (2h). First manual scan (3h).
- **Day 3 (Wed):** OSV.dev integration (3h). NVD enrichment (3h). Findings JSONB storage (2h).
- **Day 4 (Thu):** GitHub Pages setup (2h). Advisory markdown template (2h). JSON/RSS feed (2h). API endpoints (2h).
- **Day 5 (Fri):** End-to-end test: manual scan → finding → advisory page (4h). Bug fixes (4h).

## Weeks 2-4
Npm changes feed, watchlist management, basic confidence scoring, CI/CD pipeline, documentation.

## Weeks 5-8
Email setup (PGP, DKIM, warm-up), first disclosures, GitHub advisory API integration.

## Go/No-Go Gates
1. **Week 2:** Can scan 10 packages manually and produce findings?
2. **Week 4:** Can produce an advisory page with valid CVE references?
3. **Week 6:** Changes feed running, processing >100 packages/day?
4. **Week 8:** First disclosure email sent with PGP signature?
5. **Week 12:** First CVE assigned?
6. **Month 6:** 10+ CVEs published? (Critical competitive deadline)

## Setup Checklist
15 accounts (GitHub, npm, NVD, Anthropic, AWS/Hetzner, domain registrar, SES, CloudFlare, Sentry, Docker Hub, Grafana Cloud, PagerDuty, Let's Encrypt, KeyServer, MITRE CNA). 5 DNS records (A, MX, SPF, DKIM, DMARC). 11 tools (Python 3.12, Node.js, Grype, Trivy, Semgrep, Docker, GPG, PostgreSQL, RabbitMQ, Redis, Celery). 3 CI/CD pipelines (test, build, deploy).

## Realistic Phase 1 Costs: $14-40/mo
Using Hetzner ($16), free-tier DBs, no LLM yet, Let's Encrypt SSL, free Grafana Cloud, free GitHub Actions.

## Burnout Mitigation (Solo Developer)
Max 50h/week. No weekend deploys. Weekly progress journal. Monthly "stop and assess" day. Clear definition of "good enough for Phase 1."

---

# 30. RISK QUANTIFICATION MODEL (NEW v5)

## Expected Annual Loss Matrix
**Total EAL: $220,415** across 15 identified risks.

| Risk Category | Top Risk | Probability | EAL |
|--------------|----------|------------|-----|
| Operational | Key person unavailable (bus factor=1) | 85/100 | Highest overall |
| Competitive | Socket.dev zero-day feature launch | 70/100 | $90,000 |
| Reputation | False CVE published | 60/100 | $30,000 |
| Financial | LLM cost spike (model deprecation) | 50/100 | $15,000 |
| Platform | npm rate limiting/ban | 40/100 | $40,000 |

## Most Sensitive Variable
CVE discovery rate has 10× range swing. If pessimistic (1 CVE/month) vs optimistic (10 CVE/month), NPV swings by $600K over 3 years.

## Recommended Mitigation Investment
$40,000/yr in risk mitigation → 1.68× ROI Year 1. Priority: bus factor (documentation, hire), competitive speed (ship fast), FP prevention (5-stage triage).

---

# 31. ENVIRONMENT VARIABLES (NEW v5)

```bash
# Database
PG_HOST, PG_PORT, PG_USER, PG_PASSWORD, PG_DB
MONGO_HOST, MONGO_PORT, MONGO_USER, MONGO_PASSWORD, MONGO_DB  # Phase 2+
REDIS_HOST, REDIS_PORT, REDIS_PASSWORD

# Message Broker
RABBITMQ_HOST, RABBITMQ_PORT, RABBITMQ_USER, RABBITMQ_PASSWORD

# External APIs
NVD_API_KEY, GITHUB_PAT, ANTHROPIC_API_KEY, NPM_TOKEN

# Email
SMTP_HOST, SMTP_PORT, SMTP_USER, SMTP_PASSWORD
PGP_PRIVATE_KEY_PATH, PGP_PASSPHRASE, DKIM_PRIVATE_KEY_PATH

# Docker Hub
DOCKER_HUB_USERNAME, DOCKER_HUB_PASSWORD

# Application
ZEROSHIELD_DOMAIN, SECRET_KEY, API_KEY_SALT, ENVIRONMENT, LOG_LEVEL

# Cost Controls
LLM_DAILY_BUDGET_USD, LLM_PER_PACKAGE_CAP_USD
```
30+ variables. All documented in `.env.example` from Day 1.

---

# 32. OPEN QUESTIONS & FUTURE RESEARCH

1. Fuzzing integration (lightweight JS fuzzing compute cost?)
2. Local LLM economics (break-even ~2,100 scans/day for A10)
3. Multi-ecosystem expansion timing (PyPI/Maven Month 18+)
4. Post-quantum cryptography for proof-of-discovery hashes
5. Confidential computing for scan execution (SGX/SEV)
6. Fine-tuning specialized model at 10K+ confirmed findings
7. Dependency graph visualization (Neo4j?)
8. Counter-intelligence (how to make methodology partially opaque while transparent about results?)
9. Insurance (cyber liability for disclosure — budget from Phase 2, $1-3K/yr)
10. WebAssembly binary analysis toolchain
11. Bus factor: hire FTE #2 by Month 12, target 3+ by Month 24
12. Batch API reliability long-term (Anthropic deprecation risk?)
13. Docker-in-Docker vs socket mount security tradeoff for Docker scanner worker
14. Revenue path: enterprise sales required — organic growth insufficient for $68K/mo target
