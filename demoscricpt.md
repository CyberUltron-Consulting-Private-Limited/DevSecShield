# DevSecShield — Demo Video Script (spoken)

Say this out loud while you click. Keep it casual. No pitch.

---

## Login

Alright, first we log in.

Email, password, verification code — and we're in.

---

## Home

This is the home page.

Here you can see all your teams, utilization across teams, and credit balance.

I'll pick a team and go in.

---

## Team dashboard + left panel

Okay, this is the main team dashboard.

On the left we have all the scanners.

DevSecShield covers:

- **SAST** — static analysis on source code
- **SCA + SBOM** — dependencies and software bill of materials
- **CBOM** — cryptography bill of materials, certificates, TLS, PQC
- **AI BOM** — AI/ML models, datasets, frameworks
- **IAC** — infrastructure as code, Terraform and similar
- **DAST** — live running apps and APIs
- **LLM** — LLM / model security scans
- **MCP** — MCP servers and tools
- and under workflow, **CI / CD** integrations

On the main dashboard here you can see scan activity by type, vulnerabilities by severity, scans over time, and integration activity.

Team switcher and credits are up here in the sidebar. Settings at the bottom.

Now let's go into SAST first.

---

## SAST — list / dashboard

Click **SAST** on the left.

This is the SAST page.

Up top you have **New Scan** and **Refresh**.

You can switch between Dashboard and Table.

Here you see all your SAST scans — status, timing, and the key stats: risk, findings counts, that kind of thing.

If I want to run a new one, I hit **New Scan**, give it a repo or a zip, pick the language, submit — it queues and runs async.

Let's open an existing completed scan into results.

---

## SAST — results

Okay, this is the SAST results view.

At the top you get the summary — overall risk, severity breakdown, finding counts.

Below that, charts and the findings table.

Each row is a finding — severity, rule, file, line.

Click one and you get the detail: snippet, location, what failed.

You can filter, sort, export the report from here, and if chat / remediation is on this page you can ask about a finding directly.

Same pattern for the other scanners — list page, new scan, results.

Let's jump to SCA + SBOM.

---

## SCA + SBOM — list, then a real results page

Left nav → **SCA + SBOM**.

Same layout — Dashboard / Table, scan list, **New Scan** from a repo or zip.

This module is supply chain: **SCA** finds known CVEs in dependencies; **SBOM** is the inventory of every component you ship.

Open a **completed** scan → **Results**. Stay here and walk the page.

### Header — what you can download

Point at each control as you name it:

- **Download SBOM** — CycloneDX JSON of the full inventory
- **VEX** — which vulns you fix, accept, or mark not affected
- **Signature** — signed BOM for integrity
- **Evidence pack** — audit / CERT-In style bundle
- **Download Scan Report** — PDF for leadership or tickets
- **Chat with the Results** — ask questions in plain language over this scan

### Summary + charts

Repo, branch, total vulns, severity mix.

Charts: remediation progress, findings over time, licenses, risk by reachability, top CVEs — enough for a release meeting without opening every row.

### Software bill of materials table

This is the inventory.

One row per component + version. Call out:

- name, supplier, version, license
- relationship — how it got into the app
- sub-dependencies
- author, hash
- **Known vulnerabilities** — real CVE / GHSA ids when the package is hit; **None** when assessed and clean

Demo move: filter **Vulnerable only**, or search something like `cryptography`. Show that CVE rows come up with ids — not a wall of N/A.

### Findings table

Under the BOM: actionable CVE list — impact, risk score, reachability, status. Row click → detail. Jira when ticketing is on.

That's SCA + SBOM: inventory for auditors, CVEs for engineers, exports for the incident channel.

Next — CBOM.

---

## CBOM — list, results deep-dive, deliverables

Left nav → **CBOM**.

Same list pattern — New Scan from repo, zip, or an existing CBOM file.

Before results: notice **Deliverables** in the header — team-wide PDF packs. We'll open that after the results page.

Open a **completed** crypto-rich scan → **Results**.

### What CBOM is (one sentence)

SBOM inventories packages. **CBOM inventories cryptography** — algorithms, certs, keys, protocols — plus weakness, compliance, and post-quantum migration.

### Header downloads

- **CycloneDX JSON** — machine-readable CBOM
- **VEX** / **Signature** / **Evidence pack**
- **PDF Report** — this scan
- Chat if you want a quick narrative

### Crypto charts — go one by one

Scroll the crypto analytics and explain each:

1. **Algorithm distribution** — mix by primitive (cipher, hash, RSA, signatures…)
2. **Weak-crypto findings** — weak algos, bad modes like ECB, short keys, weak TLS, bad certs
3. **PQC readiness** — gauge: how much of the estate is quantum-safe vs vulnerable
4. **Certificates** — expiry / self-signed / estate health
5. **Protocols** — TLS / SSH / IPsec versions; call out anything old
6. **Asset-type breakdown** — algorithms vs certs vs protocols vs key material
7. **Crypto dependency graph** — the important visual  
   Nodes = crypto assets. Edges = relationships (cert *signed with* SHA-256, *public key* RSA-2048, protocol *uses* a suite).  
   Red ring = weak today. Orange = quantum-vulnerable.  
   Click a node so they see lineage, not a flat list.

### PQC — roadmap and migration

Two cards to emphasize:

- **Quantum-vulnerable algorithms** — public-key stuff at NIST level 0 (broken by a future CRQC), grouped with impact
- **PQC migration roadmap** — for each one, the NIST replacement target (ML-KEM / ML-DSA / etc.) plus the **CNSA 2.0** timeline strip so leadership sees *when*, not only *what*

Say: RSA-2048 might still be fine classically, but it shows here as quantum-vulnerable with a concrete migration target — so PQC is a plan, not a surprise audit.

### Compliance matrix

Framework grid — NIST, OMB, EU CRA/DORA, FIPS, BSI, PCI, and related.

Tri-state, honest:

- Pass / Fail when the BOM can evidence it
- Out of scope if there's no crypto
- Not BOM-evidenceable when you need operational proof we won't fake

Use the chips (Quantum-safe / Baseline / Regulatory) and **Failures only**, then click a bar for the requirement drill-down.

### Findings table

Crypto findings with codes and severity — same triage path as SCA.

### Deliverables (back on the CBOM team page)

Open **Deliverables**. These roll up the team's CBOM scans into governance PDFs:

1. **Scope Baseline & Asset Population Register**
3. **Cryptographic Discovery Methodology & Evidence Plan**
7. **Certificate Estate Register**
10. **Third-Party Cryptographic Assurance & Attestation Register**
15. **PQC Migration Roadmap** — board-ready migration doc
16. **Board / IT Strategy Committee Regulatory & Executive Report**

Download one live so they see a real PDF. No external AI call — built from your CBOM data.

Close: one CBOM results page for engineers (graph, weak crypto, PQC); CycloneDX + evidence for assessors; Deliverables for the board — same data, three audiences.

Next — IAC.

---

## IAC

Left nav → **IAC**.

Same flow.

New Scan — pick the IAC type, Terraform, K8s, whatever, point at the repo or zip.

Results are misconfigurations — open resources, weak policies, that kind of thing — with path and severity.

Next — DAST.

---

## DAST

Left nav → **DAST**.

This is for live targets, not source.

New Scan — give it a URL. If the app needs login, fill the auth fields.

Results are runtime findings against that running app or API.

So quick contrast:

- SAST = source at rest
- DAST = app while it's running

Next — LLM.

---

## LLM

Left nav → **LLM**.

Same idea — start a scan, wait for it to finish, open results.

This one is LLM / model behavior testing — prompt injection style checks, safety findings, scores on the results page.

Next — MCP.

---

## MCP

Left nav → **MCP**.

Scans MCP servers and tools.

Results give you exposure / risk on those tools — severity, categories, charts, findings table. Same click-through: row → detail.

---

## CI / CD

Left nav → **CI / CD**.

This is integrations, not a scan list.

You create an integration, open it, wire tokens / pipeline config.

Once it's set up, scans can be triggered from CI and then show up under the normal scanner pages — SAST, SCA, etc. — with the same status and results.

---

## Settings

Bottom of the sidebar → **Settings**.

Team-level stuff — members, credits, Jira / ticketing if configured.

That's where ownership and integrations for the team live.

---

## Wrap (15 seconds)

So that's the walkthrough.

Left panel = scanners.  
Each scanner = list → new scan → results.  
SAST for source, SCA + SBOM for deps and inventory, CBOM for crypto / certs / PQC, AI BOM for models, IAC for infra, DAST for live apps, LLM and MCP for AI surfaces, CI/CD to hook it into pipelines.

On SBOM and CBOM especially: don't stop at the list page — open a results page, walk the charts and downloads, and for CBOM show the graph, PQC roadmap, and team Deliverables.

That's the product.
