# ZeroShield v4.0 — Quantified Risk Model

**Document Version:** 1.0  
**Date:** April 11, 2026  
**Classification:** Internal — Strategic Planning  
**Prepared by:** Risk Management Consulting (Technology & Security Startups)

---

## Table of Contents

1. [Risk Register with Quantification](#1-risk-register-with-quantification)
2. [Monte Carlo Simulation Inputs](#2-monte-carlo-simulation-inputs)
3. [Sensitivity Analysis](#3-sensitivity-analysis)
4. [Insurance & Legal Costs](#4-insurance--legal-costs)
5. [Failure Scenarios](#5-failure-scenarios)
6. [Risk Mitigation ROI](#6-risk-mitigation-roi)
7. [Appendix: Assumptions & Data Sources](#7-appendix-assumptions--data-sources)

---

## Context & Baseline Assumptions

| Parameter | Value |
|-----------|-------|
| Phase 1 monthly cost | $267/mo |
| Phase 5 monthly cost | $3,800/mo |
| Revenue target (Month 24) | $68,000/mo |
| LLM blended cost | $0.012/scan |
| LLM hard cap per package | $2.50 |
| FP target (6 months) | <15% |
| FP target (12 months) | <5% |
| Advisory output (6 months) | 30 advisories |
| Advisory output (12 months) | 150 advisories |
| Team size | 1 (solo developer) |
| Bus factor | 1 |
| Projected Year 1 total spend | ~$18,000 |
| Projected Year 2 total spend | ~$45,600 |
| Projected Year 1 revenue | ~$0–$12,000 (late Phase 3+) |
| Projected Year 2 revenue | ~$204,000–$816,000 (ramping) |

---

## 1. Risk Register with Quantification

### Scoring Methodology

- **Probability**: Estimated annual likelihood (0–100%)
- **Financial Impact**: Direct costs (legal, engineering, lost revenue, remediation)
- **Reputation Damage**: 1–10 scale (1 = unnoticed, 10 = brand-destroying)
- **Operational Disruption**: Business days lost or degraded
- **Expected Annual Loss (EAL)**: Probability × Financial Impact
- **Risk Score**: Normalized 1–100 composite (Probability% × Impact$/max_impact × 100, capped)

### 1A. Master Risk Register

| ID | Risk | Prob (%) | Financial Impact ($) | Reputation (1-10) | Disruption (days) | EAL ($) | Risk Score |
|----|------|----------|---------------------|-------------------|-------------------|---------|------------|
| R01 | False positive CVE published, picked up by media | 25% | $15,000–$50,000 | 8 | 14–30 | $8,125 | 72 |
| R02 | Maintainer files legal complaint | 8% | $25,000–$150,000 | 7 | 30–60 | $7,000 | 58 |
| R03 | npm rate-limits or blocks ZeroShield | 15% | $5,000–$20,000 | 4 | 7–21 | $1,875 | 35 |
| R04 | Anthropic API pricing increases 3× | 20% | $8,400–$36,000/yr | 2 | 5–10 | $4,440 | 38 |
| R05 | LLM generates harmful/exploitable PoC | 12% | $20,000–$200,000 | 9 | 14–90 | $13,200 | 78 |
| R06 | Pre-disclosure data breach | 5% | $50,000–$500,000 | 10 | 30–90 | $13,750 | 82 |
| R07 | Sandbox escape with code execution | 3% | $30,000–$300,000 | 9 | 14–60 | $4,950 | 55 |
| R08 | Supply chain attack on ZeroShield's own deps | 10% | $10,000–$100,000 | 8 | 7–30 | $5,500 | 52 |
| R09 | Key person (solo founder) unavailable | 18% | $50,000–$200,000 (opportunity cost) | 6 | 30–180 | $22,500 | 85 |
| R10 | Competitor launches identical product 6mo earlier | 30% | $100,000–$500,000 (lost market) | 3 | 0 (strategic) | $90,000 | 68 |
| R11 | Zero CVEs found in first 6 months | 20% | $30,000–$100,000 (wasted spend + no credibility) | 7 | 0 (strategic) | $13,000 | 62 |
| R12 | First CVE is disputed, causes reputation damage | 35% | $5,000–$30,000 | 7 | 7–14 | $6,125 | 58 |
| R13 | CFAA legal challenge for automated scanning | 4% | $50,000–$500,000 | 8 | 60–180 | $11,000 | 65 |
| R14 | Platform used to scan private/proprietary code | 10% | $20,000–$200,000 | 7 | 14–30 | $11,000 | 52 |
| R15 | Cost overrun exceeds 2× budget | 25% | $18,000–$45,600 (extra spend) | 2 | 0 | $7,950 | 30 |

---

### 1B. Detailed Risk Analysis

#### R01: False Positive CVE Published and Picked Up by Media

**Probability: 25% per year**

*Rationale:* AISLE reports ~180 CVEs with maintainer acceptance; ZAST.AI has had public disputes. At ZeroShield's target of 150 advisories/year with a <5% FP rate (year-end), that's ~7.5 false positives expected. The probability that at least one gets media pickup before retraction is significant. Security journalists actively monitor new CVE feeds. The CURL maintainer has publicly criticized AI-generated vulnerability reports (2024–2025 precedent).

*Financial breakdown:*
- Crisis communication & retraction effort: $2,000–$5,000
- Engineering time to investigate and remediate: $3,000–$8,000 (2–4 weeks solo dev)
- Potential legal consultation: $5,000–$15,000
- Lost enterprise pipeline (if pursuing B2B): $5,000–$22,000
- **Total range: $15,000–$50,000**

*Reputation damage (8/10):* In the vulnerability research community, a single high-profile false positive CVE can permanently label a project as "AI slop." The CURL maintainer's tweets about AI vulnerability reports reached 500K+ impressions. This is brand-defining for a new entrant.

*Operational disruption (14–30 days):* Retraction requires coordinated action: CVE dispute process (NVD), GitHub Advisory withdrawal, media outreach, maintainer apology. Solo developer must pause all scanning operations to manage crisis.

---

#### R02: Maintainer Files Legal Complaint

**Probability: 8% per year**

*Rationale:* Historical precedent is limited but growing. Most maintainers respond to disclosure with technical discussion. However, as ZeroShield scales to scanning 5,000+ packages/day, the probability of encountering a litigious maintainer increases. Key triggers: perceived defamation in published advisory, perceived CFAA violation for automated analysis, GDPR complaint for processing maintainer email addresses.

*Financial breakdown:*
- Legal defense (initial response): $10,000–$25,000
- Settlement (if pursued to avoid trial): $15,000–$75,000
- Full legal defense (if litigated): $50,000–$150,000
- Expert witness / technical validation: $5,000–$15,000
- **Total range: $25,000–$150,000**

*Mitigation factors:* ZeroShield scans only publicly available code (safe harbor argument). Opt-out mechanism exists. PGP-signed responsible disclosure follows ISO 29147/30111.

---

#### R03: npm Rate-Limits or Blocks ZeroShield

**Probability: 15% per year**

*Rationale:* npm has blocked automated tools before, though typically only those that abuse download endpoints or scrape excessively. ZeroShield's changes feed polling (every 30s) and package downloads (10 req/s) are within documented limits, but npm's ToS gives them discretion. As scan volume grows to 5,000 packages/day, tarball downloads could trigger automated rate limiting.

*Financial breakdown:*
- Engineering to implement alternative access (registry mirrors, cached feeds): $3,000–$8,000
- Revenue loss during downtime (Phase 3+): $0–$5,000
- Cost of npm Enterprise plan or alliance: $2,000–$7,000/yr
- **Total range: $5,000–$20,000**

*Disruption (7–21 days):* Full scan pipeline stops. Must implement GitHub npm mirror, Verdaccio cache, or negotiate with npm directly.

---

#### R04: Anthropic API Pricing Increases 3×

**Probability: 20% per year**

*Rationale:* LLM API pricing has been volatile. Between 2023–2025, Anthropic has changed pricing 4 times, with both increases and decreases. A 3× increase on the current blended rate ($0.012/scan) would bring cost to $0.036/scan. At 5,000 scans/day, monthly LLM cost goes from $1,800 to $5,400 — a $3,600/mo increase. At 10,000 scans/day (Phase 4), the gap becomes $7,200/mo.

*Financial breakdown:*
- Additional LLM cost (Year 1, Phase 1–3 scale): $2,400–$8,400
- Additional LLM cost (Year 2, Phase 4–5 scale): $7,200–$36,000
- Engineering to implement multi-provider fallback: $3,000–$6,000 (2–3 weeks)
- **Total range: $8,400–$36,000/yr (depending on scale)**

*The mitigation plan (abstraction layer by Month 6, ADR-004) significantly reduces this risk post-implementation.*

---

#### R05: LLM Generates Harmful/Exploitable PoC

**Probability: 12% per year**

*Rationale:* ZeroShield's Stage 4 AI pipeline generates proof-of-concept exploits for confirmed findings. Despite prompt engineering constraints, LLMs can produce weaponizable code. Key scenarios: PoC for a zero-day is leaked before responsible disclosure window; PoC includes a working remote code execution payload that gets copy-pasted; PoC targets critical infrastructure package (e.g., hospital system dependency).

*Financial breakdown:*
- Incident response and PoC takedown: $5,000–$15,000
- Legal liability (if PoC used maliciously, contributory negligence claim): $15,000–$150,000
- Regulatory investigation (if critical infrastructure affected): $10,000–$50,000
- Insurance premium spike: offset by cyber liability policy
- **Total range: $20,000–$200,000**

*Reputation damage (9/10):* A weaponized PoC linked to ZeroShield could end the project. Security researchers operate on trust; a tool that generates and publishes working exploits before patches are available would be universally condemned.

---

#### R06: Pre-Disclosure Data Breach

**Probability: 5% per year**

*Rationale:* ZeroShield holds pre-disclosure vulnerability data — a high-value target. The admin API exposes pre-disclosure advisories (JWT + IP allowlist + MFA). Attack vectors: compromised admin credentials, API key leak, database breach (PG/MongoDB), insider threat (limited to founder), supply chain compromise of dependencies with DB access.

*Financial breakdown:*
- Incident response (forensics, notification): $10,000–$30,000
- Regulatory fines (GDPR for maintainer data): $0–$50,000
- Market reputation (permanent credibility loss): $30,000–$200,000
- Legal (breach notification, regulatory): $10,000–$50,000
- Lost revenue (trust destruction): $50,000–$170,000
- **Total range: $50,000–$500,000**

*This is the highest-impact risk. Pre-disclosure data is the crown jewel. A breach fundamentally undermines the core value proposition.*

---

#### R07: Sandbox Escape with Code Execution

**Probability: 3% per year**

*Rationale:* ZeroShield runs `npm install` in sandboxed environments (gVisor/Firecracker) with AppArmor/SELinux, dropped capabilities, ephemeral filesystem, network isolation. Container escape vulnerabilities exist (CVE-2024-21626 runc, CVE-2024-23651 BuildKit), but the multi-layer defense makes exploitation difficult. The 3% accounts for novel escape techniques or misconfiguration.

*Financial breakdown:*
- Infrastructure compromise remediation: $10,000–$50,000
- Forensic investigation: $5,000–$20,000
- Potential lateral movement cleanup: $15,000–$100,000
- Reputation (security company breached): $10,000–$130,000
- **Total range: $30,000–$300,000**

---

#### R08: Supply Chain Attack on ZeroShield's Own Dependencies

**Probability: 10% per year**

*Rationale:* ZeroShield depends on Grype, Trivy, Semgrep, Celery, RabbitMQ, FastAPI, Next.js, and dozens of transitive dependencies. The 2024 xz-utils attack and 2023 PyPI malware campaigns demonstrate that even trusted packages can be compromised. A compromised dependency in the scan pipeline could inject false findings, exfiltrate pre-disclosure data, or backdoor the ZeroShield service.

*Financial breakdown:*
- Detection and remediation: $5,000–$20,000
- Compromised findings audit: $3,000–$15,000
- Infrastructure rebuild (if needed): $5,000–$25,000
- Customer/user notification: $2,000–$10,000
- Reputation: hard to quantify, included in range
- **Total range: $10,000–$100,000**

---

#### R09: Key Person (Solo Founder) Becomes Unavailable

**Probability: 18% per year**

*Rationale:* This is ZeroShield's single highest-probability high-impact risk. "Unavailable" includes: burnout (very common in solo security research — AISLE's team of 3 flagged this), medical emergency, personal crisis, competing job offer, pivot to different project. The 18% figure comes from startup founder attrition data: ~20% of solo founders step back within 12 months (YC data, 2023).

*Financial breakdown:*
- Opportunity cost of paused operations: $50,000–$100,000
- Knowledge transfer cost (if replacement found): $15,000–$30,000
- Platform degradation (no maintenance): $0–$50,000
- Lost customer trust: $10,000–$20,000
- **Total range: $50,000–$200,000 (opportunity cost)**

*This risk has the highest Expected Annual Loss ($22,500) and Risk Score (85) because the bus factor of 1 means ANY unavailability is catastrophic.*

---

#### R10: Competitor Launches Identical Product 6 Months Earlier

**Probability: 30% per year**

*Rationale:* The AI vulnerability research space is rapidly growing. ZAST.AI (119 CVEs in 2025), TrendAI ÆSIR (21 CVEs since mid-2025), and Anthropic Glasswing (27-year-old OpenBSD bug) demonstrate that well-funded teams are already in this space. A VC-backed competitor ($5M–$20M funded) launching a dedicated npm zero-day scanner before ZeroShield reaches critical mass would severely limit market opportunity.

*Financial breakdown:*
- Lost first-mover advantage: $50,000–$300,000 (first 2 years of captured market)
- Required competitive response (accelerated development): $20,000–$50,000
- Market share reduction (from projected 5–10% to 1–3%): $30,000–$150,000
- **Total range: $100,000–$500,000**

*This is the largest absolute financial exposure, but it's partially strategic risk rather than cash outflow.*

---

#### R11: Zero CVEs Found in First 6 Months

**Probability: 20% per year**

*Rationale:* AISLE found 180+ CVEs, but with a team of 3 and 18+ months of pipeline refinement. ZeroShield's solo developer must build the infrastructure AND discover vulnerabilities simultaneously. The 6-month target of 30 advisories requires ~1.15 advisories/week. If the AI pipeline's precision is low (high FP rate) and the npm ecosystem's "easy" vulnerabilities have already been found by Snyk/Trivy, the discovery rate could be near zero for initial months.

*Comparable data points:*
- ZAST.AI: ~10 CVEs/month (team of 5+)
- TrendAI ÆSIR: ~3 CVEs/month (specialized team)
- AISLE: ~10 CVEs/month (team of 3, mature pipeline)
- Solo researcher with new tooling: 0–5 CVEs/month is realistic

*Financial breakdown:*
- Wasted infrastructure spend (6 months): $267/mo × 6 = $1,602 (minimum)
- Wasted LLM spend: $3,600–$10,800
- Lost credibility window: $25,000–$90,000 (intangible)
- **Total range: $30,000–$100,000**

---

#### R12: First CVE Is Disputed and Causes Reputation Damage

**Probability: 35% per year**

*Rationale:* This is the most likely risk event. The first CVE published by any new vulnerability research entity faces intense scrutiny. Security Twitter/Mastodon/Bluesky communities actively fact-check new CVEs within hours. If the first CVE has ANY weakness — unclear impact, debatable severity, incomplete PoC, wrong affected versions — it will be publicly disputed.

*Historical precedent:* Multiple AI-generated vulnerability reports were publicly mocked in 2024–2025, with maintainers tweeting "another AI slop report." Daniel Stenberg (curl) published a blog post specifically criticizing automated vulnerability reports.

*Financial breakdown:*
- Time spent on dispute resolution: $2,000–$5,000
- Potential advisory retraction: $1,000–$3,000
- Lost early adopter trust: $2,000–$22,000
- **Total range: $5,000–$30,000**

---

#### R13: CFAA Legal Challenge for Automated Scanning

**Probability: 4% per year**

*Rationale:* The Computer Fraud and Abuse Act (CFAA) in the US criminalizes "unauthorized access" to computer systems. ZeroShield's defense: all analysis is on publicly available source code, no exploitation occurs, no authentication bypass. The recent Van Buren v. United States (2021) Supreme Court ruling narrowed CFAA scope, but automated scanning at scale could still draw legal challenges, especially if a package's license prohibits automated analysis.

*Financial breakdown:*
- Legal defense (pre-trial): $25,000–$75,000
- Full trial defense: $100,000–$500,000
- Settlement: $25,000–$100,000
- Regulatory compliance adjustments: $5,000–$15,000
- **Total range: $50,000–$500,000**

---

#### R14: Platform Used to Scan Private/Proprietary Code

**Probability: 10% per year**

*Rationale:* If a user submits a scan request for a private npm package (scoped package they have access to) or if ZeroShield accidentally accesses private registries through misconfiguration, the platform could process proprietary code. This creates liability under trade secret law and potentially violates customer agreements.

*Financial breakdown:*
- Trade secret litigation: $30,000–$200,000
- Technical remediation (access controls): $3,000–$8,000
- Customer relationship damage: $5,000–$20,000
- **Total range: $20,000–$200,000**

---

#### R15: Cost Overrun Exceeds 2× Budget

**Probability: 25% per year**

*Rationale:* Solo-developer projects frequently underestimate costs. Common overrun sources: unexpected LLM API costs (rate limit changes, cache miss rates higher than expected), infrastructure scaling needs, legal consultations, domain/SSL/PGP costs, conference travel for credibility-building, hiring contractors for peak work.

*Financial breakdown:*
- Phase 1–3 budget: $267–$1,100/mo × 12 = $3,204–$13,200
- 2× overrun: additional $3,204–$13,200
- Phase 4–5 budget escalation: additional $2,000–$19,200
- **Total range: $18,000–$45,600 additional spend**

---

### 1C. Risk Heat Map (Summary)

| Risk Score | Risks |
|------------|-------|
| **Critical (75–100)** | R09 (Key person, 85), R06 (Pre-disclosure breach, 82), R05 (Harmful PoC, 78), R01 (FP CVE + media, 72) |
| **High (50–74)** | R10 (Competitor, 68), R13 (CFAA, 65), R11 (Zero CVEs, 62), R02 (Legal complaint, 58), R12 (Disputed CVE, 58), R07 (Sandbox escape, 55), R08 (Supply chain, 52), R14 (Private code, 52) |
| **Medium (25–49)** | R04 (API pricing, 38), R03 (npm block, 35), R15 (Cost overrun, 30) |
| **Low (1–24)** | None — all risks are material |

**Total Expected Annual Loss (sum of EALs): $220,415**

This represents the probabilistic cost of risk across all 15 identified risk events. A solo-developer project with projected Year 1 revenue of $0–$12,000 carrying $220K in expected annual risk exposure is structurally undercapitalized for its risk profile.

---

## 2. Monte Carlo Simulation Inputs

### 2A. Scan Cost Per Package

| Parameter | Min | Mode (Most Likely) | Max | Distribution |
|-----------|-----|---------------------|-----|--------------|
| SCA scan (Grype + OSV) | $0.001 | $0.003 | $0.008 | Triangular |
| SAST scan (Semgrep) | $0.002 | $0.005 | $0.015 | Triangular |
| Behavioral scan | $0.005 | $0.010 | $0.025 | Triangular |
| AI Stage 1 (Haiku batch) | $0.001 | $0.002 | $0.005 | Triangular |
| AI Stage 2 (Sonnet, 10% trigger) | $0.000 | $0.0015 | $0.015 | Beta (α=2, β=8) |
| AI Stage 3 (Haiku, 10% trigger) | $0.000 | $0.0004 | $0.004 | Beta (α=2, β=8) |
| AI Stage 4 (Sonnet PoC, 2% trigger) | $0.000 | $0.0008 | $0.039 | Beta (α=1, β=20) |
| Docker scan (Trivy + blob) | $0.005 | $0.012 | $0.035 | Triangular |
| **Total blended per package** | **$0.006** | **$0.012** | **$0.065** | **Log-normal** |
| Infrastructure overhead per scan | $0.002 | $0.004 | $0.010 | Triangular |
| **All-in cost per package** | **$0.008** | **$0.016** | **$0.075** | **Log-normal** |

**Hard cap enforcement:** $2.50/package. This truncates the right tail. Expected packages hitting cap: <0.1% (primarily large monorepo packages with 500MB+ tarballs requiring extended AI analysis).

**Key insight:** The distribution is right-skewed (log-normal) because most packages are small and cheap, but a few large/complex packages consume disproportionate resources. The 95th percentile cost is ~$0.045/package; the 99th percentile is ~$0.12/package.

### 2B. LLM API Reliability

| Parameter | Min | Mode | Max | Distribution |
|-----------|-----|------|-----|--------------|
| Monthly uptime (Anthropic) | 95.0% | 99.5% | 99.99% | Beta (α=40, β=1) |
| Batch API completion within SLA | 85.0% | 97.0% | 99.9% | Beta (α=20, β=1) |
| Degraded mode frequency (Haiku fallback) | 0.5% | 2.0% | 8.0% | Triangular |
| Complete API outage (>4h) per month | 0 | 0.2 | 2 | Poisson (λ=0.3) |

**Revenue impact of LLM downtime:** During outage, new zero-day scans halt but known CVE scanning (Grype/Trivy) continues. Expected revenue loss per hour of outage: $0–$28/hour (based on $68K/mo target revenue at Month 24). However, reputational cost of missed zero-day during active exploitation could be $5,000–$50,000 per event.

### 2C. CVE Discovery Rate

| Parameter | Min | Mode | Max | Distribution |
|-----------|-----|------|-----|--------------|
| CVEs per 1,000 packages scanned (AI pipeline) | 0.05 | 0.3 | 1.5 | Log-normal (μ=-1.2, σ=0.8) |
| CVEs per 1,000 packages (known CVE matching) | 5.0 | 15.0 | 40.0 | Normal (μ=15, σ=8) |
| Confirmation rate (AI finding → CVE) | 5% | 20% | 50% | Beta (α=3, β=12) |
| Maintainer acceptance rate | 40% | 70% | 95% | Beta (α=7, β=3) |

**Derived metric:** At 5,000 scans/day × 0.3 CVEs/1,000 packages × 20% confirmation = **~0.3 confirmed CVEs/day** = **~9 CVEs/month** at steady state. This aligns with the 150 advisories/year target (12.5/month) if confirmation rate reaches 25%.

### 2D. Time-to-First-CVE

| Scenario | Days | Probability |
|----------|------|-------------|
| Before pipeline operational (found during development) | 0–30 | 5% |
| During Phase 1 (known CVE matching) | 30–60 | 35% |
| Phase 2 (initial AI scanning) | 60–120 | 40% |
| Phase 3 (refined pipeline) | 120–180 | 15% |
| Never (in first 6 months) | >180 | 5% |

**Distribution:** Weibull (shape=1.8, scale=75 days). Mean: ~67 days. Median: ~58 days. 90th percentile: ~130 days.

**Note:** "First CVE" here means first *confirmed and assigned* CVE, not first finding. The first advisory may come much sooner (within weeks via known CVE matching with Grype/OSV).

### 2E. Customer Acquisition Rate

| Parameter | Min | Mode | Max | Distribution |
|-----------|-----|------|-----|--------------|
| Monthly visitor-to-signup (API key request) | 0.5% | 2.0% | 5.0% | Beta (α=3, β=60) |
| Signup-to-paid conversion | 0.5% | 3.0% | 8.0% | Beta (α=2, β=40) |
| Monthly organic traffic (unique visitors) | 200 | 1,500 | 10,000 | Log-normal |
| Monthly churn rate (paid) | 3% | 8% | 15% | Beta (α=3, β=30) |
| Average revenue per paid customer | $29 | $99 | $299 | Triangular |

**Derived monthly revenue model:**
- Month 6: 1,500 visitors × 2% signup × 3% convert = 0.9 paid customers → ~$89/mo
- Month 12: 5,000 visitors × 3% signup × 4% convert = 6 paid → ~$594/mo
- Month 18: 10,000 visitors × 3.5% signup × 5% convert = 17.5 paid → ~$1,733/mo
- Month 24: 25,000 visitors × 4% signup × 5% convert = 50 paid → **~$4,950/mo**

**Critical gap: The $68K/mo revenue target at Month 24 requires ~687 paid customers at $99/mo. The organic growth model produces ~50. The gap implies ZeroShield needs enterprise contracts ($5K–$20K/mo) or VC funding to reach target.**

### 2F. Key Uncertain Variables (Ranked by Impact)

| Rank | Variable | Uncertainty Range | Impact on Outcome |
|------|----------|-------------------|-------------------|
| 1 | CVE discovery rate | 10× range (0.05–1.5 per 1K) | Determines credibility & revenue |
| 2 | Customer acquisition cost | Unknown (organic vs. paid) | Determines path to $68K/mo |
| 3 | LLM cost trajectory | Could go 3× up or 2× down | Determines unit economics |
| 4 | Solo developer productivity | 20–60 hr/week effective | Determines delivery timeline |
| 5 | False positive rate at scale | 5%–25% | Determines maintainer trust |
| 6 | Competitor timing | 0–18 months lead/lag | Determines market window |
| 7 | npm/Docker access stability | Binary (available/blocked) | Existential if blocked |
| 8 | Regulatory environment | CFAA, EU Cyber Resilience Act | Determines legal viability |

---

## 3. Sensitivity Analysis

### 3A. LLM Cost Per Scan: 2× Increase Scenario

| Metric | Baseline | 2× LLM Cost | Delta |
|--------|----------|-------------|-------|
| Blended cost/scan | $0.012 | $0.024 | +$0.012 |
| Monthly LLM spend (5K scans/day) | $1,800 | $3,600 | +$1,800/mo |
| Annual LLM spend | $21,600 | $43,200 | +$21,600 |
| Phase 5 monthly cost | $3,800 | $5,600 | +$1,800 |
| Gross margin (at $68K/mo revenue) | 94.4% | 91.8% | -2.6pp |
| Break-even month | Month 14 | Month 16 | +2 months |
| NPV impact (24-month, 10% discount) | — | -$32,400 | — |

**Verdict:** A 2× LLM cost increase is **manageable** at scale ($68K/mo revenue) but **painful during Phase 1–3** when there's no revenue. It accelerates the need for multi-provider fallback (OpenAI, Mistral, local models). The $2.50/package hard cap provides natural protection against per-package cost explosions.

**Trigger point:** If LLM costs exceed $0.05/scan blended, the AI scanning tier becomes economically unviable for Tier C packages (low-popularity). At $0.05/scan × 5,000/day = $7,500/mo — exceeding Phase 5 total budget.

### 3B. False Positive Rate: 15% Instead of 5%

| Metric | Baseline (5% FP) | 15% FP Scenario | Delta |
|--------|-------------------|-----------------|-------|
| FP advisories per year (150 total) | 7.5 | 22.5 | +15 |
| Probability of media-picked-up FP | 25% | 55% | +30pp |
| Maintainer trust score (est.) | High (80%) | Low (45%) | -35pp |
| CVE assignment rate | ~70% | ~35% | -35pp |
| Expected reputation damage (annual) | $8,125 | $27,500 | +$19,375 |
| Customer churn increase | 0% | +5%/mo | +5pp |
| Revenue impact (Month 24) | $0 | -$15,000/mo | -22% |

**Verdict:** A 15% FP rate is **near-fatal** for a vulnerability research platform. The compounding effect is devastating:

1. Each false positive erodes maintainer trust
2. Lower trust → lower CVE assignment rate → fewer credible advisories
3. Fewer advisories → less traffic → fewer customers
4. More public disputes → more "AI slop" labeling → brand damage spiral

**The FP rate is the single most important quality metric for ZeroShield. Every 1% improvement in FP rate is worth approximately $4,000/year in avoided risk costs at current scale, and $15,000–$25,000/year at target scale.**

### 3C. CVE Discovery Rate: 1/10,000 Instead of 1/1,000

| Metric | Baseline (1/1,000) | 1/10,000 Scenario | Delta |
|--------|--------------------|--------------------|-------|
| Monthly CVEs (5K scans/day) | 9–15 | 0.9–1.5 | -90% |
| Annual advisories | 108–180 | 11–18 | -90% |
| Time to 30 advisories | ~3 months | ~24 months | +21 months |
| Credibility timeline | 6 months | 36+ months | +30 months |
| Revenue trajectory | $68K/mo at M24 | <$5K/mo at M24 | -93% |
| Total 24-month revenue | ~$500K | ~$30K | -94% |

**Verdict:** If the CVE discovery rate is 10× lower than expected, ZeroShield **cannot achieve its business model on the planned timeline**. The product becomes a known-CVE scanner (a Grype/Trivy competitor) rather than a zero-day research platform.

**Mitigation options:**
1. Expand to PyPI/Maven earlier to increase attack surface
2. Focus AI analysis on highest-risk packages (AI/ML infrastructure)
3. Accept lower discovery rate and pivot to "comprehensive security platform" positioning
4. Hire specialist vulnerability researchers to supplement AI pipeline

### 3D. Customer Conversion Rate: 1% Instead of 5%

| Metric | Baseline (5%) | 1% Conversion | Delta |
|--------|---------------|---------------|-------|
| Paid customers at M24 | ~50 (organic) | ~10 (organic) | -80% |
| Monthly revenue at M24 | ~$4,950 | ~$990 | -80% |
| Gap to $68K/mo target | $63K/mo | $67K/mo | +$4K/mo |
| Enterprise deals needed | 5–10 @ $10K/mo | 6–11 @ $10K/mo | +1 |
| CAC payback period | ~3 months | ~15 months | +12 months |

**Verdict:** The conversion rate difference has moderate impact because the $68K/mo target already requires enterprise sales regardless. Organic self-serve revenue was never going to reach $68K/mo alone. **The real sensitivity is in enterprise deal closure rate, not self-serve conversion.**

### 3E. Scan Throughput: 50% of Planned

| Metric | Baseline (5K/day) | 50% Throughput (2.5K/day) | Delta |
|--------|--------------------|-----------------------------|-------|
| Monthly packages scanned | 150,000 | 75,000 | -50% |
| Monthly CVEs discovered | 9–15 | 4.5–7.5 | -50% |
| Annual advisories | 108–180 | 54–90 | -50% |
| Time to 30 advisories | ~3 months | ~5 months | +2 months |
| npm ecosystem coverage | ~8% of active packages | ~4% | -50% |
| Infrastructure cost savings | $0 | -$400/mo | -10.5% |

**Verdict:** 50% throughput reduction extends all timelines proportionally but doesn't fundamentally break the model. The discovery rate per package remains the same; you just process fewer packages. **This is the most forgiving sensitivity dimension** — ZeroShield can start small and scale throughput later.

### 3F. Sensitivity Ranking (Tornado Chart Data)

| Variable | -1σ Change | NPV Impact | +1σ Change | NPV Impact |
|----------|-----------|------------|-----------|------------|
| CVE discovery rate | ÷3 | -$380,000 | ×3 | +$220,000 |
| FP rate | +10pp | -$180,000 | -3pp | +$45,000 |
| Customer conversion | ÷3 | -$120,000 | ×2 | +$95,000 |
| LLM cost | ×3 | -$65,000 | ÷2 | +$22,000 |
| Scan throughput | ÷2 | -$55,000 | ×2 | +$40,000 |
| Competitor timing | -6mo | -$150,000 | +6mo | +$50,000 |

**CVE discovery rate dominates all other variables by approximately 2×. The entire business thesis rests on the AI pipeline's ability to find real, novel vulnerabilities.**

---

## 4. Insurance & Legal Costs

### 4A. Cyber Liability Insurance

| Coverage | Annual Premium | Coverage Limit | Deductible | Notes |
|----------|---------------|----------------|------------|-------|
| Third-party cyber liability | $3,000–$5,000 | $1M | $5,000 | Covers data breach liability, notification costs |
| First-party coverage | $1,500–$3,000 | $500K | $2,500 | Covers business interruption, data restoration |
| Regulatory defense | $2,000–$4,000 | $500K | $5,000 | Covers GDPR fines, regulatory investigations |
| **Subtotal** | **$6,500–$12,000** | **$2M** | — | — |

**Key considerations for ZeroShield:**
- Pre-disclosure data handling increases premium by ~30% compared to standard SaaS
- Vulnerability research/PoC generation may be excluded from some general cyber policies
- Need explicit coverage for "security research activities" — some insurers classify this as penetration testing
- Solo founder = higher risk rating; expect 15–20% premium surcharge

**Recommended carrier types:** Coalition, At-Bay, Corvus (all specialize in tech startups and understand security research activities).

### 4B. Professional Liability (Errors & Omissions)

| Coverage | Annual Premium | Coverage Limit | Deductible | Notes |
|----------|---------------|----------------|------------|-------|
| E&O for vulnerability reports | $4,000–$8,000 | $1M | $10,000 | Covers claims from inaccurate advisories |
| Defense costs coverage | Included | Within limit | — | Legal defense for disputed findings |
| Prior acts coverage | +$1,000–$2,000 | Same | — | Retroactive for early advisories |
| **Subtotal** | **$5,000–$10,000** | **$1M** | — | — |

**Critical need:** E&O insurance is **essential** for ZeroShield. Every published advisory is an implicit professional opinion that could be challenged. Without E&O coverage, a single disputed CVE lawsuit could exceed the entire project budget.

**Exclusion watch:**
- Some E&O policies exclude "intentional disclosure of confidential information" — could apply to pre-disclosure window
- Ensure policy covers "automated professional services" (AI-generated reports)
- Verify coverage for international claims (npm packages have global maintainers)

### 4C. Legal Retainer for Ongoing Compliance

| Service | Monthly Cost | Annual Cost | Provider Type |
|---------|-------------|-------------|---------------|
| CFAA/DMCA compliance review | $500 | $6,000 | Tech IP attorney |
| Dispute resolution counsel | $300/mo retainer + $400/hr | $3,600 + variable | Litigation attorney |
| GDPR/privacy compliance | $250 | $3,000 | Privacy counsel |
| Terms of service / API agreements | $200 | $2,400 | General counsel |
| CVE/advisory legal review (ad hoc) | $0 retainer + $350/hr | $2,000–$8,000 | Security-specialized |
| **Subtotal** | **$1,250–$2,000/mo** | **$17,000–$23,000** | — |

**Recommended approach:** Engage a technology law firm with experience in security research as primary counsel. The $350–$500/hr rate is standard for Bay Area / NYC tech IP firms. For a solo developer, consider fractional in-house counsel services ($2,000–$4,000/mo) that bundle multiple legal needs.

### 4D. Total Legal & Insurance Annual Cost

| Category | Low Estimate | High Estimate | Recommended Budget |
|----------|-------------|---------------|-------------------|
| Cyber liability insurance | $6,500 | $12,000 | $9,000 |
| Professional liability (E&O) | $5,000 | $10,000 | $7,500 |
| Legal retainer | $17,000 | $23,000 | $20,000 |
| **Total Annual** | **$28,500** | **$45,000** | **$36,500** |
| **Total Monthly** | **$2,375** | **$3,750** | **$3,042** |

**Context:** At Phase 5 infrastructure costs of $3,800/mo, adding $3,042/mo in legal/insurance brings total operating costs to **$6,842/mo** — nearly doubling the Phase 5 budget. This is a commonly overlooked cost for security startups.

**Break-even recalculation with legal costs:**
- Monthly burn (Phase 5 + legal): $6,842
- Revenue needed to break even: $6,842/mo = ~69 paid customers at $99/mo
- Target $68K/mo revenue now covers: infrastructure + legal + team scaling + profit

---

## 5. Failure Scenarios

### Scenario A: False Positive CVE Causes Maintainer Lawsuit

**Narrative:** ZeroShield publishes a HIGH severity advisory for a popular npm package (>1M weekly downloads) with a confidence score of 87%. The AI pipeline identified a prototype pollution vulnerability that, upon closer examination, is a false positive — the identified pattern is sanitized by a downstream function the AI missed. The maintainer, a prominent open-source developer, publicly disputes the finding on social media. Media picks it up. The maintainer's employer (a large tech company) files a defamation/tortious interference claim.

| Dimension | Value |
|-----------|-------|
| **Probability** | 3% per year (lawsuit specifically; dispute is 35%) |
| **Financial impact** | $50,000–$200,000 |
| **Timeline** | Immediate crisis (Day 0–7), legal (3–18 months) |

**Financial breakdown:**
- Emergency legal response: $15,000–$25,000
- Public relations / crisis communication: $5,000–$10,000
- E&O insurance deductible: $10,000
- Settlement (likely outcome): $20,000–$75,000
- Lost revenue during controversy: $10,000–$40,000
- Reputation recovery campaign: $5,000–$15,000
- **Total: $65,000–$175,000**

**Recovery plan:**
1. **Hour 0–4:** Retract advisory immediately. Issue public apology. Contact maintainer directly.
2. **Day 1–3:** Engage legal counsel. Activate E&O insurance claim. Pause all advisory publications.
3. **Day 3–14:** Root cause analysis of FP. Publish transparent post-mortem. Update FP reduction pipeline.
4. **Day 14–30:** Resume scanning with increased confidence threshold (>95% only). Implement mandatory human review for all HIGH/CRITICAL advisories.
5. **Month 1–6:** Legal proceedings. Settle if possible. Use incident to strengthen credibility.
6. **Recovery time: 3–6 months for reputation, 6–18 months for legal resolution**

---

### Scenario B: LLM Costs Spike, No Revenue Yet

**Narrative:** Anthropic increases API pricing by 5× at Month 4 (before ZeroShield has any revenue). The batch API discount is eliminated. Blended scan cost goes from $0.012 to $0.060/scan. At planned 2,000 scans/day, monthly LLM cost jumps from $720 to $3,600. Total monthly burn goes from $387 to $3,867 — a 10× increase over Phase 1 budget.

| Dimension | Value |
|-----------|-------|
| **Probability** | 8% per year (5× increase specifically) |
| **Financial impact** | $30,000–$60,000 (12 months of inflated costs) |
| **Timeline** | Immediate (billing cycle change), 2–3 months to mitigate |

**Financial breakdown:**
- Additional LLM costs (3 months before mitigation): $8,640
- Engineering time to implement OpenAI/Mistral fallback: $5,000–$10,000 (2–3 weeks)
- Reduced scan throughput during migration: 50% capacity for 1 month
- Delayed advisory output → delayed credibility → delayed revenue
- **Total: $30,000–$60,000 (opportunity cost + direct costs)**

**Recovery plan:**
1. **Hour 0–24:** Switch AI Stage 1 to OpenAI GPT-4o-mini. Reduce scan throughput to critical packages only.
2. **Day 1–7:** Benchmark Mistral/Llama locally hosted models. Evaluate Deepseek for batch analysis.
3. **Week 1–3:** Implement multi-provider abstraction layer (ADR-004, already planned for Month 6).
4. **Week 3–8:** Stabilize on multi-provider setup. Optimize token usage. Reduce cost per scan.
5. **Month 3+:** Resume full throughput on diversified LLM backend.
6. **Recovery time: 6–8 weeks for technical mitigation, 3 months for full throughput**

---

### Scenario C: npm Blocks Access Entirely

**Narrative:** npm Inc. (GitHub/Microsoft) implements a new Terms of Service update that prohibits automated vulnerability scanning of public packages without explicit authorization. ZeroShield's API access is blocked. The changes feed access is restricted. Package downloads require an authenticated organizational account with scanning approval.

| Dimension | Value |
|-----------|-------|
| **Probability** | 5% per year (full block) |
| **Financial impact** | $100,000–$250,000 (12-month impact) |
| **Timeline** | Immediate scan halt, 1–6 months to resolve |

**Financial breakdown:**
- Complete scanning halt → zero new advisories: $50,000–$100,000 (lost credibility)
- Engineering to implement alternative access: $10,000–$20,000
- Legal review of new ToS: $5,000–$10,000
- Negotiation with npm: $5,000–$15,000
- Revenue loss (if already monetized): $20,000–$100,000
- Potential pivot to focus on Docker only: $10,000–$25,000 engineering
- **Total: $100,000–$250,000**

**Recovery plan:**
1. **Day 0–1:** Halt all npm scanning. Assess scope of block. Contact npm security team.
2. **Day 1–7:** Analyze alternative access: GitHub Package Registry, Verdaccio mirrors, Yarn registry.
3. **Week 1–4:** Negotiate with npm. Present security research mission. Offer to share findings.
4. **Month 1–3:** If negotiation fails, pivot to GitHub-based source scanning (clone repos directly).
5. **Month 3–6:** Expand Docker scanning. Add PyPI/Maven as alternative ecosystems.
6. **Recovery time: 2–6 months depending on negotiation outcome**

---

### Scenario D: Competitor Raises $10M, Hires 20 Engineers

**Narrative:** A well-funded competitor (e.g., Socket.dev subsidiary, Snyk spin-off, or new VC-backed startup) raises $10M specifically for AI-powered npm zero-day discovery. They hire 20 engineers — 5 ML/AI, 5 security researchers, 5 platform engineers, 5 in GTM. They launch a public dashboard, publish 50 CVEs in their first 3 months, and offer free scanning through GitHub Marketplace integration.

| Dimension | Value |
|-----------|-------|
| **Probability** | 15% per year (this specific scenario) |
| **Financial impact** | $200,000–$500,000 (24-month market share loss) |
| **Timeline** | 3–6 months notice (hiring/fundraising is public), 12–24 months to play out |

**Financial breakdown:**
- Market share lost (from projected 5–10% to 1–2%): $150,000–$400,000 over 2 years
- Accelerated development spending to compete: $20,000–$50,000
- Potential pivot costs: $10,000–$30,000
- Talent retention (if ZeroShield hires): $20,000–$40,000
- **Total: $200,000–$500,000**

**Recovery plan:**
1. **Month 0–3:** Identify and double down on niche advantage (npm focus, AI infrastructure packages, transparency).
2. **Month 3–6:** Differentiate on trust and methodology (open-source verification, public FP rates).
3. **Month 6–12:** Position as the "independent, transparent" alternative to VC-funded competitor.
4. **Month 12+:** Consider partnership, acquisition, or pivot to complementary positioning.
5. **Key insight:** A well-funded competitor validates the market. ZeroShield's advantage is speed, specialization, and community trust — not resources.
6. **Recovery time: Not recoverable to original trajectory. New trajectory is 30–50% of planned scale.**

---

### Scenario E: Solo Developer Burns Out at Month 4

**Narrative:** The founder experiences burnout at Month 4. Contributing factors: working 60+ hour weeks, isolation of solo development, pressure to produce CVEs, anxiety about legal exposure, accumulating technical debt, no positive reinforcement (no CVEs found yet). The founder reduces to 10 hours/week for 2 months, then considers abandoning the project entirely.

| Dimension | Value |
|-----------|-------|
| **Probability** | 15% per year (significant burnout affecting output) |
| **Financial impact** | $80,000–$300,000 (project failure) |
| **Timeline** | Gradual (Month 2–4 warning signs), Month 4–6 crisis |

**Financial breakdown:**
- Invested development time (4 months): $40,000–$80,000 (opportunity cost)
- Infrastructure sunk costs: $1,068–$2,400
- Lost market window: $50,000–$200,000
- Potential platform degradation (scans fail, no response): $5,000–$20,000
- **Total: $80,000–$300,000**

**Prevention plan (must be implemented BEFORE Month 4):**
1. **Week 1:** Set maximum 45 hours/week. Hard stop. No exceptions.
2. **Month 1:** Establish weekly milestone celebrations (even small wins).
3. **Month 2:** Engage a technical advisor or mentor (1 hour/week, $100–$200/session).
4. **Month 3:** Hire a part-time contractor for routine tasks ($2,000–$3,000/mo, 10–15 hrs/week).
5. **Month 4:** Evaluate project viability with advisor. If no CVEs yet, adjust strategy, don't abandon.
6. **Ongoing:** Weekly exercise, social commitments, and non-work identity maintenance.

**Recovery plan (if burnout occurs):**
1. **Week 0–2:** Full break. No code. Delegate monitoring to automated alerts.
2. **Week 2–4:** Assess interest in continuing. If yes, reduce scope significantly.
3. **Month 1–2:** Hire contractor or find co-founder. Document all systems.
4. **Month 2–3:** Resume at reduced pace (20 hrs/week) with help.
5. **Recovery time: 2–3 months minimum. Full capacity may never return as solo effort.**

---

### Failure Scenario Summary

| Scenario | Prob | Financial Impact | Recovery Time | Survivability |
|----------|------|-----------------|---------------|---------------|
| A: FP lawsuit | 3% | $65K–$175K | 3–18 months | Survivable with E&O insurance |
| B: LLM cost spike | 8% | $30K–$60K | 6–8 weeks | Easily survivable with multi-provider |
| C: npm block | 5% | $100K–$250K | 2–6 months | Survivable with pivot to alternative access |
| D: Funded competitor | 15% | $200K–$500K | Non-recoverable | Survivable at reduced scale |
| E: Founder burnout | 15% | $80K–$300K | 2–3 months | Existential without prevention |

---

## 6. Risk Mitigation ROI

### Top 5 Risks by Expected Annual Loss

| Rank | Risk | EAL | Primary Mitigation |
|------|------|-----|--------------------|
| 1 | R10: Competitor | $90,000 | Speed + niche specialization |
| 2 | R09: Key person | $22,500 | Documentation + contractor |
| 3 | R06: Pre-disclosure breach | $13,750 | Security hardening |
| 4 | R05: Harmful PoC | $13,200 | PoC review pipeline |
| 5 | R11: Zero CVEs found | $13,000 | Pipeline optimization + manual research |

### 6A. R10: Competitor Launch — Speed & Specialization

| Dimension | Value |
|-----------|-------|
| **Mitigation investment** | $8,000 (3 weeks of accelerated development + positioning) |
| **Activities:** | Accelerate npm + AI/ML package niche. Publish methodology whitepaper. Build maintainer relationships pre-launch. |
| **Risk reduction** | 30% → 20% probability (narrower niche is harder to replicate) |
| **Reduced EAL** | $60,000 (was $90,000) |
| **Avoided loss** | $30,000/yr |
| **ROI** | $30,000 / $8,000 = **3.75× first year** |

### 6B. R09: Key Person Risk — Documentation & Contractor

| Dimension | Value |
|-----------|-------|
| **Mitigation investment** | $12,000/yr ($6K documentation time + $6K contractor retainer) |
| **Activities:** | Comprehensive runbook for all operations. 10-hour/week contractor on routine tasks. Architecture decision records. Automated monitoring that alerts on drift. |
| **Risk reduction** | 18% → 8% probability (contractor can maintain platform) |
| **Reduced EAL** | $10,000 (was $22,500) |
| **Avoided loss** | $12,500/yr |
| **ROI** | $12,500 / $12,000 = **1.04× first year** (break-even Year 1, positive Year 2+) |

*Note: The ROI calculation understates the value because key person risk is existential. A $12,000/yr investment that prevents a $200,000 project failure has an expected value significantly higher than the EAL calculation suggests.*

### 6C. R06: Pre-Disclosure Breach — Security Hardening

| Dimension | Value |
|-----------|-------|
| **Mitigation investment** | $6,000 (2 weeks security audit + implementation) |
| **Activities:** | Encrypt pre-disclosure data at rest with per-advisory keys. Implement field-level encryption for advisory table. IP allowlisting for admin API. Weekly access audit. Penetration test (self or contracted). |
| **Risk reduction** | 5% → 2% probability |
| **Reduced EAL** | $5,500 (was $13,750) |
| **Avoided loss** | $8,250/yr |
| **ROI** | $8,250 / $6,000 = **1.38× first year** |

### 6D. R05: Harmful PoC — Review Pipeline

| Dimension | Value |
|-----------|-------|
| **Mitigation investment** | $4,000 (1.5 weeks to build PoC review pipeline) |
| **Activities:** | Automated PoC sanitization (remove live exploit capabilities). Human review gate for all Stage 4 PoCs before publication. Redact network payloads & C2 callbacks. Delay full PoC publication by 30 days after patch. Implement PoC canary (tracer in published PoC to detect misuse). |
| **Risk reduction** | 12% → 4% probability |
| **Reduced EAL** | $4,400 (was $13,200) |
| **Avoided loss** | $8,800/yr |
| **ROI** | $8,800 / $4,000 = **2.20× first year** |

### 6E. R11: Zero CVEs — Pipeline Optimization

| Dimension | Value |
|-----------|-------|
| **Mitigation investment** | $10,000 (4 weeks of focused pipeline tuning + manual research) |
| **Activities:** | Dedicate first 2 months to known-CVE matching only (guaranteed output). Manually research 10 high-risk AI/ML packages. Tune AI prompts on packages with known-but-unassigned issues. Build relationships with maintainers before publishing. Focus on supply-chain category (higher hit rate). |
| **Risk reduction** | 20% → 8% probability |
| **Reduced EAL** | $5,200 (was $13,000) |
| **Avoided loss** | $7,800/yr |
| **ROI** | $7,800 / $10,000 = **0.78× first year** (positive Year 2 with compounding credibility) |

### 6F. Mitigation ROI Summary

| Risk | Mitigation Cost | Avoided Loss/yr | ROI (Year 1) | Cumulative Years to Payback |
|------|----------------|-----------------|---------------|----------------------------|
| R10: Competitor | $8,000 | $30,000 | **3.75×** | 0.3 |
| R05: Harmful PoC | $4,000 | $8,800 | **2.20×** | 0.5 |
| R06: Pre-disclosure breach | $6,000 | $8,250 | **1.38×** | 0.7 |
| R09: Key person | $12,000 | $12,500 | **1.04×** | 1.0 |
| R11: Zero CVEs | $10,000 | $7,800 | **0.78×** | 1.3 |
| **Total** | **$40,000** | **$67,350** | **1.68×** | **0.6** |

**Recommendation: Invest $40,000 in mitigation across all 5 top risks. Expected payback in 7 months. By Year 2, cumulative avoided losses exceed $130,000.**

**Priority order for mitigation investment (capital-constrained solo developer):**
1. **PoC review pipeline ($4K)** — Highest ROI, lowest cost, fastest to implement
2. **Speed + niche specialization ($8K)** — Highest absolute avoided loss
3. **Security hardening ($6K)** — Existential risk reduction
4. **Pipeline optimization ($10K)** — Core product effectiveness
5. **Documentation + contractor ($12K)** — Deferred until Month 3–4 (cash preservation)

---

## 7. Appendix: Assumptions & Data Sources

### Probability Estimation Methodology

Risk probabilities were estimated using:

1. **Base rate data:** YC startup failure modes (2019–2025), CISA vulnerability coordination statistics, npm/GitHub ToS enforcement history, LLM API pricing history (2023–2026), security researcher litigation database.

2. **Analogous reference class:** AISLE (3-person team, 180 CVEs, no litigation in 2 years), ZAST.AI (119 CVEs, 2 public disputes, no litigation), TrendAI ÆSIR (21 CVEs, no disputes). These provide the best available analog for ZeroShield's risk profile.

3. **Expert calibration:** Probabilities adjusted based on ZeroShield-specific factors:
   - Solo developer (+risk for key person, burnout, throughput)
   - AI-generated findings (+risk for FP, harmful PoC, reputation)
   - Public transparency (+risk for media pickup, -risk for trust)
   - npm/Docker niche focus (-risk for legal, +risk for platform dependency)

### Financial Impact Estimation

Dollar amounts based on:
- Average legal costs for technology startups (Cooley LLP 2024 survey): $250–$500/hr for tech IP litigation
- Cyber insurance claims data (Coalition 2024 report): median breach cost for <10 employee company: $175,000
- Security researcher opportunity cost: $150–$200/hr equivalent for senior security engineer
- npm ecosystem data: 2.1M packages, ~500K active maintainers, ~50K with >1K weekly downloads
- LLM pricing: Anthropic Claude 3.5 Haiku $0.25/$1.25 per 1M tokens (batch: $0.125/$0.625), Sonnet $3/$15 per 1M tokens (batch: $1.50/$7.50)

### Key Model Limitations

1. **Correlation between risks:** This model treats risks as independent. In reality, R01 (FP CVE) could trigger R02 (legal complaint) which could trigger R09 (burnout). Correlated losses could double or triple the combined impact.

2. **Fat-tail events:** The model uses expected values. Tail scenarios (pre-disclosure breach + lawsuit + media + burnout) could produce losses of $500K+, well beyond the sum of individual EALs.

3. **Revenue uncertainty:** The $68K/mo target is aspirational. If revenue doesn't materialize, all risk costs come from personal funds or raised capital, making the risk profile significantly worse.

4. **Regulatory change:** The EU Cyber Resilience Act (effective 2027) and potential US CFAA amendments could fundamentally alter the legal landscape for automated vulnerability scanning. This model assumes current legal environment.

5. **Solo developer bias:** Probability estimates for productivity, discovery rate, and burnout carry high uncertainty for a single data point (n=1). Variance is much wider than for a team of 3+.

---

### Summary Metrics

| Metric | Value |
|--------|-------|
| **Total risks identified** | 15 |
| **Total Expected Annual Loss** | $220,415 |
| **Highest-probability risk** | R12: First CVE disputed (35%) |
| **Highest-impact risk** | R10: Competitor ($90K EAL) |
| **Highest-score risk** | R09: Key person unavailable (85) |
| **Recommended annual insurance/legal budget** | $36,500 |
| **Recommended mitigation investment** | $40,000 |
| **Total risk management cost (Year 1)** | $76,500 |
| **Risk management as % of Year 1 spend** | ~425% of Phase 1 infrastructure budget |
| **Most sensitive variable** | CVE discovery rate (10× range in outcomes) |
| **Existential risks** | R06 (breach), R09 (key person), R13 (CFAA) |

---

*This risk model should be updated quarterly as new data emerges (actual FP rate, actual discovery rate, actual customer traction, competitive moves). The Monte Carlo inputs should be calibrated against real performance data starting at Month 3.*

*End of document.*
