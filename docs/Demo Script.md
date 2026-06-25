# DevSecShield — Client Demo Script (Detailed)

> **Audience:** Business leaders, security decision-makers, engineering managers  
> **Duration:** ~30 to 35 minutes  
> **Format:** Frontend-first, screen-by-screen walkthrough  
> **Tone:** Sales-focused, non-technical, outcome-driven

---

## 1. What Is DevSecShield?

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

## 3. Demo Opening (30-45 seconds)

> "In this walkthrough, I'll show how DevSecShield helps teams ship secure releases faster using one frontend workflow.  
> We'll go from team-level visibility to scan execution across supply chain, cryptography, and AI inventory, then AI-guided remediation, CI/CD automation, Guardrails, and Jira-based closure."

---

## 4. Frontend Walkthrough (Detailed)

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

## Screen 5 — SCA + SBOM: Dependency and Supply Chain Exposure (2.5 minutes)

### Routes
`/[team_id]/sbom_sca` -> `/{scan_id}` -> `/results`

### Script (What to say)

> "When a new CVE drops, SCA + SBOM answers two urgent questions quickly: where we are exposed and what to patch first."

> "Real-world example: a critical vulnerability is announced in a widely used package. Instead of manually checking every repository, this module identifies impacted projects, dependency versions, and remediation priority in one place."

> "Benefit: faster supply-chain response and stronger audit readiness because SBOM gives a clear software inventory trail."

---

## Screen 6 — CBOM: Cryptography Inventory and Post-Quantum Readiness (2.5 minutes)

### Routes
`/[team_id]/cbom` -> `/{scan_id}` -> `/results`

### Script (What to say)

> "CBOM stands for Cryptography Bill of Materials. It gives teams a complete inventory of where cryptography is used across applications and infrastructure — algorithms, keys, certificates, and protocols — so weak or outdated choices are visible before they become compliance or breach risk."

> "Real-world example: a regulated fintech team is preparing for post-quantum migration and an upcoming audit. Instead of manually tracing every TLS configuration and encryption library, CBOM surfaces weak algorithms, deprecated ciphers, and certificate gaps in one prioritized view."

> "Teams can scan from a repository, upload a zip, or import an existing CBOM file. Optional binary scanning extends coverage to packaged applications where source code is not available."

> "Benefit: stronger cryptographic governance, faster audit readiness, and a practical path toward post-quantum preparedness without slowing release velocity."

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

## 5. Scenario Wrap-Up (1 minute)

> "In one release cycle, the team used DevSecShield to secure code, dependencies, cryptography, AI inventory, infrastructure, runtime behavior, LLM safety, and MCP exposure."

> "Then they operationalized fixes through CI/CD and Jira, while maintaining governance with team-level controls and credit visibility."

---

## 6. Closing Message (30 seconds)

> "DevSecShield gives organizations one practical path from detection to remediation across modern software and AI environments.  
> It helps teams ship faster, safer, and with stronger governance."

---

## 7. Common Questions (Optional Q&A)

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
