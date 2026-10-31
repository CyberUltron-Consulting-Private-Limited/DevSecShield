# DevSecShield — Client Demo Script (Detailed)

> **Audience:** Business leaders, security decision-makers, engineering managers  
> **Duration:** ~35 to 40 minutes (includes ~90-second demo context + walkthrough; SBOM + CBOM results get extra time)  
> **Format:** Frontend-first, screen-by-screen walkthrough  
> **Tone:** Clear, explanatory, outcome-driven — set context first, then show the product

---

## 1. What Is DevSecShield? (Reference — not spoken verbatim)

**Elevator version (use in intros, emails, or when asked "what do you do?"):**

> **DevSecShield is one security platform for everything you ship** — code, dependencies, cloud, crypto, and AI. Find what's broken. Fix it fast. Prove it to auditors. That's it.

DevSecShield is a unified, AI-powered DevSecOps platform that helps organizations identify, prioritize, and remediate risk across:

- Source code (SAST)
- Open-source dependencies (SCA + SBOM)
- Cryptographic assets and algorithms (CBOM)
- AI/ML components, models, and datasets (AI BOM)
- Infrastructure-as-code (IAC)
- Running apps and APIs (DAST)
- LLM behavior and safety (LLM scans)
- MCP server and tool exposure (MCP scans)

It combines scanning, AI guidance, integrations, and reporting in one product experience.

---

## 2. Real-World Value: What It Does, Where It Is Used, and Why It Matters

### Real customer situation

A fintech product team is preparing a release with new APIs, frontend updates, Terraform changes, and an AI assistant feature. They need to ship quickly without introducing security risk.

### How DevSecShield is used in that release cycle

- SAST catches insecure auth or unsafe code paths before merge.
- SCA + SBOM identifies vulnerable third-party packages and affected services.
- CBOM inventories cryptographic usage and flags weak or outdated algorithms before they become compliance or breach risk.
- AI BOM maps models, datasets, and AI dependencies into a governed inventory with compliance and shadow-AI visibility.
- IAC finds risky cloud misconfigurations before infrastructure deployment.
- DAST validates runtime security posture on staging environments.
- LLM scan tests prompt injection and data leakage behavior.
- MCP scan checks tool/server exposure and access risk.
- CI/CD integration automates checks per commit/PR.
- Guardrails enforce runtime safety policies for AI interactions.
- Jira integration turns findings into trackable engineering tickets.
- PDF export provides evidence for leadership, audits, and compliance reviews.

### Business outcomes

- Fewer late-stage surprises in release windows
- Faster remediation cycles with AI-assisted prioritization
- Better governance via team-based access and credit visibility
- Higher confidence for security, engineering, and executive stakeholders

---

## 3. Demo Opening — Context Before the Walkthrough (~90 seconds)

**Purpose:** Before clicking through screens, answer four questions the audience will have: *What is this? What's broken in the market? Why do we need it? How is this different?* This is setup for the demo — not a sales close.

**Delivery tips:**
- Speak plainly. You're explaining, not selling.
- Use the four headers below as natural beats — don't rush the market problem.
- End by telling them exactly what they'll see in the walkthrough.

---

### 1) What DevSecShield is

> "DevSecShield is a unified DevSecOps platform. From one frontend, teams can scan and manage security across:
> - **Source code** — SAST
> - **Open-source dependencies** — SCA and SBOM
> - **Cryptography** — CBOM: algorithms, keys, certificates, TLS
> - **AI and ML components** — AI BOM: models, datasets, frameworks, compliance
> - **Cloud infrastructure** — IAC scanning on Terraform and similar
> - **Running applications** — DAST on live APIs and web apps
> - **AI behavior** — LLM security testing and MCP tool exposure
>
> On top of scanning, it includes AI-assisted triage, CI/CD integration, Guardrails for runtime AI policy, Jira ticketing, and PDF reporting — so findings move from detection to fix, not just a dashboard."

---

### 2) The actual problem in the market

> "Most organizations don't have one security problem — they have a **fragmentation** problem.
>
> Code scanning lives in one tool. Dependency/CVE tracking in another. Cloud misconfigs in a third. AI governance? Often a spreadsheet — or nothing at all.
>
> Each tool uses different severity scales, different dashboards, and different export formats. Security teams reconcile reports manually. Engineering teams get alert fatigue. Leadership can't get a single answer to: *'Are we safe to release?'*
>
> On top of that, modern software added new blind spots that legacy AppSec stacks weren't built for: **weak or outdated cryptography**, **untracked AI models and shadow AI**, **LLM prompt injection**, and **agent/MCP tool over-permissioning**. These don't show up in a traditional SAST scan."

---

### 3) Why teams need this now

> "A typical release today isn't just code. It's APIs, npm packages, Terraform, TLS configs, and an AI feature — all shipping together.
>
> Regulators and auditors are starting to ask questions AppSec tools from five years ago can't answer: *What AI is in our product? What crypto are we using? Are we post-quantum ready?*
>
> Teams need one place to see risk across the full stack — before release, not after an incident or audit scramble."

---

### 4) How DevSecShield is different (vs. point tools)

> "We're not asking you to rip out your dev workflow. The difference is **coverage and workflow in one product**:
>
> | Typical approach | DevSecShield |
> |---|---|
> | 5–6 separate tools, separate dashboards | One frontend, one severity model, one report |
> | SCA tool finds CVEs; no AI/crypto visibility | Code + deps + cloud + crypto + AI in the same scan cycle |
> | Findings exported as raw lists | AI chat helps explain and prioritize what to fix first |
> | Manual handoff to Jira or email | Built-in Jira sync, CI/CD gates, Guardrails for live AI |
> | Audit prep = weeks of manual report assembly | One-click PDF export across scan types |
>
> Point tools are good at one layer. DevSecShield is built for teams where **one release touches every layer** — and they need one answer, not six."

---

### Transition into the demo (~10 seconds)

> "With that context, I'll walk you through the product — starting from login and team dashboard, then each scan type. I'll spend extra time on **SCA + SBOM** and **CBOM** results — the inventory tables, crypto graph, PQC roadmap, downloads, and board deliverables — then cover integrations and reporting. Same flow your engineers and security team would use day to day."

---

## 5. Frontend Walkthrough (Detailed)

This walkthrough follows the actual product flow:
`/login` -> `/home` -> `/[team_id]` -> scan modules -> results -> integrations -> settings.

## Screen 1 — Login and Access Entry (1.5 to 2 minutes)

### Route
`/login`

### Script (What to say)

> "Every user logs into a shared platform, but work is segmented by team. That means clear ownership and controlled access from the first screen."

---

## Screen 2 — Home: Multi-Team Oversight and Credits (2.5 to 3 minutes)

### Route
`/home`

### Script (What to say)

> "This is the portfolio view for organizations with multiple teams. You can instantly see which teams are active, which ones are integrating CI/CD and Guardrails, and how credits are distributed before planning scan execution."

> "A simple real-world example: if Team A is preparing a release and Team B is in maintenance mode, leadership can immediately see where scan activity and credits are being consumed, and allocate effort accordingly."

---

## Screen 3 — Team Dashboard: Security Posture Command Center (3 minutes)

### Route
`/[team_id]`

### Script (What to say)

> "This page answers leadership questions quickly: Are we scanning enough? Are critical findings increasing or decreasing? Are integrations actually being adopted?"

> "In practice, this is where a release meeting starts. Product, engineering, and security can align on risk posture in one minute instead of reading multiple tools and reports."

---

## Screen 4 — SAST: Code Risk Detection and Prioritization (3 minutes)

### Routes
`/[team_id]/sast` -> `/{scan_id}` -> `/results`

### Script (What to say)

> "SAST stands for Static Application Security Testing. Static means we analyze source code without running the application. This helps teams find vulnerabilities early, before deployment and before attackers can exploit them in production."

> "Typical SAST findings include SQL injection risks, insecure authentication logic, weak cryptography usage, hardcoded secrets, and unsafe input handling."

> "Real-life use case: a fintech team adds a new money-transfer endpoint. During SAST, the platform detects an unsafe query path that could allow injection. Because this is caught pre-release, the team patches it immediately and avoids a production incident."

> "Business benefit: lower breach risk, faster code review, and reduced rework cost because fixing issues in pre-release is much cheaper than fixing them after go-live."

> "Operational benefit: this page makes triage practical. Teams can quickly move from detection to action by reviewing severity, opening detailed findings, and syncing remediation into existing workflows."

---

## Screen 5 — SCA + SBOM: Dependency and Supply Chain Exposure (4 to 5 minutes)

### Routes
`/[team_id]/sbom_sca` → open a **completed** scan → `/results`  
*(Demo tip: use a rich scan such as the DPDPA / dependency-heavy repo so the BOM and CVE columns are populated.)*

### What this module is (say first)

> "SCA + SBOM is our software supply-chain view. **SCA** finds known vulnerabilities in third-party packages. **SBOM** is the inventory itself — every component, version, license, and relationship — so when a new CVE drops you can answer *where am I exposed* and *what do I patch first* without hunting through lockfiles by hand."

### Landing page (brief)

> "Same pattern as the other scanners: **New Scan** / **Refresh**, Dashboard vs Table, scan list with status. Start from a Git repo or a zip. When the scan finishes, open **Results**."

### Results page — walk the UI top to bottom

**1) Header actions (point as you click)**

> "From the results header you can export what auditors and partners usually ask for:
> - **Download SBOM** — CycloneDX JSON inventory of every component
> - **VEX** — Vulnerability Exploitability eXchange: which findings you accept, fix, or mark not affected
> - **Signature** — cryptographic signature over the BOM for integrity
> - **Evidence pack** — bundled evidence for CERT-In / audit handoff
> - **Download Scan Report** — PDF for leadership or the ticket trail
> - **Chat with the Results** — ask plain-language questions over this scan"

**2) Summary cards and charts**

> "Up top: repository, branch, total vulnerabilities, severity mix. Charts show remediation progress, findings over time, license distribution, risk by reachability, and top CVEs by risk score — so a release meeting can prioritize without opening every row."

**3) Software bill of materials table (spend time here)**

> "This is the living inventory. One row per unique component and version.
>
> Columns to call out:
> - **Component / version / supplier / license** — what shipped and under what terms
> - **Relationship** — how it got into the app (e.g. included via `package-lock.json`)
> - **Sub dependencies** — what that package pulls in
> - **Author / hash** — provenance and integrity hints
> - **Known vulnerabilities** — linked CVE / GHSA / PYSEC ids from the scan. Packages assessed with no match show **None**; if the scan never linked advisories you'd see N/A
> - **Date added** — when this BOM snapshot was produced
>
> Demo move: turn on **Vulnerable only** (or search `cryptography` / a known CVE). Show that vulnerable packages surface first with real CVE ids in red — not buried under hundreds of clean Babel packages."

**4) Findings table**

> "Below the BOM, the findings table is the actionable CVE list: title, dependency, impact, risk score, status, reachability, license, OWASP, compliance. Click a row for detail; sync to Jira when ticketing is configured."

### Real-world close

> "Example: a critical CVE lands in a widely used library. Instead of grepping every repo, this page shows which services pin the bad version, the SBOM trail for auditors, and a PDF/VEX pack for the incident channel. That's faster supply-chain response and audit-ready evidence in one screen."

---

## Screen 6 — CBOM: Cryptography Inventory, Graph, PQC, and Deliverables (5 to 6 minutes)

### Routes
`/[team_id]/cbom` → open a **completed** crypto-rich scan → `/results`  
*(Also show the team CBOM page **Deliverables** dropdown before or after results.)*

### What this module is (say first)

> "CBOM is the **Cryptography Bill of Materials**. Where SBOM inventories packages, CBOM inventories *crypto itself*: algorithms, certificates, keys and other material, TLS/SSH/IPsec protocols, policy files — plus weakness flags, compliance against crypto frameworks, and a post-quantum migration path. Regulators increasingly ask *what crypto do you run* and *are you quantum-ready*; this page answers both."

### Landing page (brief)

> "Again: New Scan from repo, zip, or an existing CBOM file; optional binary scanning when you only have a package. Scan list, Dashboard/Table. **Deliverables** in the header is team-wide — we'll come back to that. Open a finished scan into Results."

### Results page — walk the UI section by section

**1) Header downloads (point as you click)**

> "Per-scan exports:
> - **CycloneDX JSON** — machine-readable CBOM (CycloneDX 1.6 crypto-asset)
> - **VEX** — exploitability statements for crypto findings
> - **Signature** — signed BOM for integrity
> - **Evidence pack** — audit bundle
> - **PDF Report** — single-scan executive/technical PDF
> - Plus chat with the results when you need a quick narrative for a stakeholder"

**2) Summary and classic dashboard charts**

> "Risk band, finding counts, OWASP / risk radar / compliance control bars — same operational language as the other scanners, so security and engineering don't context-switch."

**3) Crypto analytics (Cbom charts — go slowly)**

Walk these cards in order; pause on each:

| UI block | What to say |
|---|---|
| **Algorithm distribution** | "How crypto breaks down by primitive — block cipher, hash, PKE, signature, key agreement. Instant sense of the estate." |
| **Weak-crypto findings** | "Counts by finding code: weak algorithms, weak modes (e.g. ECB), undersized keys, weak protocols, expired or weak certs. Severity-toned so High vs Medium is obvious." |
| **PQC readiness gauge** | "Share of inventoried algorithms that are quantum-safe vs quantum-vulnerable, derived from NIST quantum security levels. This is the board-friendly one-number view." |
| **Certificate expiry** | "Cert estate and validity — what's expiring, self-signed, already expired." |
| **Protocols / TLS** | "Pinned TLS/SSH/IPsec versions and suites. Call out anything below TLS 1.2 as weak." |
| **Asset-type breakdown** | "Algorithms vs certificates vs protocols vs related crypto material vs libraries — what *kinds* of crypto assets we found." |
| **Crypto dependency graph** | "This is the lineage view. Nodes are crypto assets; edges show how they connect — e.g. a certificate *signed with* a digest, *public key* is RSA-2048, a protocol *uses* a cipher suite. Red ring = weak today; orange = quantum-vulnerable but not necessarily broken classically. Click around so they see cert → algorithm relationships, not a flat list." |

**4) Quantum-vulnerable list + PQC migration roadmap (emphasize)**

> "Here we go from inventory to *plan*.
>
> - **Quantum-vulnerable algorithms** — public-key assets at NIST level 0 (broken by a cryptographically relevant quantum computer). Grouped by algorithm family with impact and instance count.
> - **PQC migration roadmap** — for each vulnerable algorithm, the NIST-standardized replacement (for example ML-KEM / ML-DSA / SLH-DSA targets) and a **CNSA 2.0 milestone strip** so leadership sees *when* migration pressure hits, not only *what* to change.
>
> Demo line: 'RSA-2048 may still be fine classically today, but it shows here as quantum-vulnerable with a concrete migration target — so PQC work can be scheduled instead of surprise-audited.'"

**5) Compliance matrix (tri-state)**

> "This is framework coverage for crypto — NIST 1800-38 / SP 800-57, OMB, EU CRA/DORA, FIPS, BSI, PCI, and related controls.
>
> Verdicts are **tri-state and honest**:
> - **Pass / Fail** — we could evidence from the BOM
> - **Out of scope** — no crypto in the repo, not a fake 0%
> - **Not BOM-evidenceable** — needs operational proof (e.g. lab attestation) we don't invent
>
> Coverage is pass ÷ (pass + fail). Use the group chips — Quantum-safe / Baseline crypto / Regulatory — and **Failures only** when you want a remediation punch-list. Click a bar to drill into the requirement table."

**6) Findings table**

> "Each crypto finding: asset, weakness code, severity, suggested direction. Same triage → Jira path as SCA."

### Team Deliverables (from CBOM landing — open the **Deliverables** menu)

> "These are **team-rolled PDF packs**, not just one scan — they aggregate CBOM history for governance and board packs:"

| # | Deliverable | One-line pitch |
|---|---|---|
| 1 | **Scope Baseline & Asset Population Register** | What crypto assets are in scope across the team's scans |
| 3 | **Cryptographic Discovery Methodology & Evidence Plan** | How we discover crypto and what evidence we keep |
| 7 | **Certificate Estate Register** | Cert inventory, validity bands, ownership trail |
| 10 | **Third-Party Cryptographic Assurance & Attestation Register** | Supplier / third-party crypto assurance status |
| 15 | **PQC Migration Roadmap** | Board-ready migration document from the estate |
| 16 | **Board / IT Strategy Committee Regulatory & Executive Report** | Executive narrative for committees and regulators |

> "Click one — it downloads a PDF. No LLM calls, no external lookups: generated in-house from your CBOM data. That's what you hand an auditor or the board without rebuilding slides overnight."

### Real-world close

> "Example: a regulated team facing a crypto and PQC questionnaire. They open one CBOM results page for the technical graph and weak findings, download CycloneDX + evidence pack for the assessor, and pull the **PQC Migration Roadmap** and **Board report** deliverables for leadership — same dataset, three audiences, one product."

---


## Screen 7 — AI BOM: AI/ML Inventory, Compliance, and Shadow-AI Visibility (2.5 minutes)

### Routes
`/[team_id]/ai_bom` -> `/{scan_id}` -> `/results`

### Script (What to say)

> "AI BOM gives organizations a governed inventory of AI and ML components — models, datasets, frameworks, and AI-related dependencies — so teams know exactly what AI is in their software and where it runs."

> "Real-world example: a healthcare product team ships features that rely on multiple models and third-party AI services. AI BOM maps those components, flags unapproved or shadow-AI usage, and aligns findings with compliance frameworks such as NIST AI RMF, EU AI Act, HIPAA, FDA, and GMLP."

> "Teams can scan from a repository, upload a zip, or import an existing inventory file — the same practical workflow security and engineering teams already use for other scan types."

> "Benefit: clearer AI governance, faster compliance conversations with auditors and regulators, and reduced risk from unmanaged or shadow-AI adoption."

---

## Screen 8 — IAC: Cloud Misconfiguration Prevention (2 minutes)

### Routes
`/[team_id]/iac` -> `/{scan_id}` -> `/results`

### Script (What to say)

> "IAC protects infrastructure before it goes live. Teams use this to prevent avoidable incidents like public exposure or weak default policies."

> "Real-world example: a Terraform change accidentally leaves a storage resource publicly accessible. This module flags it before deployment, so sensitive data is never exposed."

> "Benefit: fewer cloud security incidents and safer deployments by design."

---

## Screen 9 — DAST: Runtime Validation on Live Targets (2.5 minutes)

### Routes
`/[team_id]/dast` -> `/{scan_id}` -> `/results`

### Script (What to say)

> "DAST complements static checks by testing behavior of running applications, so teams catch issues that only appear at runtime."

> "Real-world example: an API looks safe in code review but exposes a weak runtime header configuration in staging. DAST catches that exposure before production rollout."

> "Benefit: production-like validation and reduced risk of runtime surprises."

---

## Screen 10 — LLM Security: AI Behavior Risk Testing (2.5 minutes)

### Routes
`/[team_id]/llm` -> `/[conversation_id]` -> `/results`

### Script (What to say)

> "This module helps AI teams validate model behavior before and after release, using concrete attack-style testing rather than assumptions."

> "Real-world example: a customer-facing AI assistant is tested for prompt injection and jailbreak prompts. If risky behavior appears, teams can harden prompt strategy and guardrails before launch."

> "Benefit: safer AI feature rollouts and reduced brand/compliance risk from model misuse."

---

## Screen 11 — MCP Security: Tool and Server Exposure Review (2 minutes)

### Routes
`/[team_id]/mcp` -> `/[conversation_id]` -> `/results`

### Script (What to say)

> "As agentic systems grow, MCP becomes a real attack surface. This gives teams visibility and prioritization where traditional app scanning does not."

> "Real-world example: an over-permissioned MCP tool can execute sensitive operations. This module highlights that risk so teams can tighten access before abuse happens."

> "Benefit: safer agent tooling and better control over AI system blast radius."

---

## Screen 12 — CI/CD Integrations: Automated Security Gates (2.5 minutes)

### Routes
`/[team_id]/ci_cd` -> `/[integration_id]`

### Script (What to say)

> "This is how security shifts left in practice. Instead of ad-hoc manual scans, checks run as part of release workflows and reduce risky merges."

> "Real-world example: a pull request introduces a high-severity issue. CI/CD integration catches it automatically and blocks promotion until fixed."

> "Benefit: fewer risky deployments and less manual security overhead for engineering teams."

---

## Screen 13 — Guardrails Integrations: Runtime AI Policy Controls (2 minutes)

### Routes
`/[team_id]/guardrails` -> `/[integration_id]`

### Script (What to say)

> "Guardrails extends security beyond build time into live AI behavior, helping teams enforce safety controls after deployment."

> "Real-world example: if a production chatbot receives toxic or policy-violating input, guardrails can enforce rules and reduce unsafe outputs."

> "Benefit: stronger runtime governance for AI products in customer-facing environments."

---

## Screen 14 — Jira and Team Settings: Ownership and Execution (3 minutes)

### Route
`/[team_id]/settings`

### Script (What to say)

> "This is the handoff from detection to delivery. Security findings become engineering work with clear ownership and traceability."

> "Real-world example: a critical finding is raised from SAST. Instead of sending separate emails, the issue is tracked in Jira with severity and context, assigned to the right owner, and closed with evidence."

> "Benefit: faster remediation accountability and cleaner security-to-engineering collaboration."

---

## Screen 15 — AI Chat and Reporting: Fast Decisions for Mixed Teams (2 minutes)

### Routes
Any scan detail page and results page

### Script (What to say)

> "AI guidance shortens triage time, and one-click reporting keeps engineering, security, and business stakeholders aligned."

> "Real-world example: a product manager asks, 'What is blocking release this week?' The team uses AI chat to summarize top risks instantly and exports a report for leadership review."

> "Benefit: faster decisions, clearer communication, and stronger executive visibility."

---

## 6. Scenario Wrap-Up (1 minute)

> "In one release cycle, the team used DevSecShield to secure code, dependencies, cryptography, AI inventory, infrastructure, runtime behavior, LLM safety, and MCP exposure."

> "Then they operationalized fixes through CI/CD and Jira, while maintaining governance with team-level controls and credit visibility."

---

## 7. Closing — Wrap the Demo (~30 seconds)

**Purpose:** Tie back to the opening context. Invite questions.

> "So that's DevSecShield — one platform covering code, dependencies, cloud, cryptography, and AI, with the workflow to actually fix issues and report on them.
>
> The market problem we started with was tool sprawl and blind spots. What you saw is one place to answer *'Are we safe to release?'* without juggling six dashboards.
>
> Happy to go deeper on any scan type, integration, or how this would fit your team's setup."

---

## 8. Common Questions (Optional Q&A)

| Question | Answer |
|---|---|
| Does this replace existing developer workflows? | No. It integrates into existing engineering workflows and release processes. |
| Can non-security teams use it? | Yes. The frontend flow is designed for mixed security and engineering audiences. |
| How do we track remediation? | Through severity-based findings, Jira ticketing integration, and scan history. |
| How do we control usage and spend? | Credits are team-scoped and visible in home/settings experiences. |
| Can we start small? | Yes. Most teams begin with SAST + SCA, then expand into CBOM, AI BOM, IAC, DAST, LLM, and MCP. |

---

## Contact

- **General Contact:** vartul@zeroshield.ai
- **Support:** support@zeroshield.ai
