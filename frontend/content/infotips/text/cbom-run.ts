/**
 * (i) tip text of the "cbom-run" area (ids: cbom.run.*), loaded on demand by
 * content/infotips/load.ts. The label of each tip is in content/infotips/labels.ts; the rules for the text are in
 * content/infotips/index.ts (checked by content/infotips.test.ts).
 */
import type { TipAreaText } from "../types";

const TEXT = {
  // ────────────────────────────────────────────────────────────── CBOM Sources run results page (components/cbom/results/*, CB-38 #120)
  // src: frontend/components/cbom/results/RunSections.tsx:211-213 — jobs, skipped sources, provenance
  "cbom.run.covered": {
    what: "Every job of the run with where it ran and how it ended, the sources skipped when it started, per source what was collected, and each target's outcome.",
    why: "A finding list is only as complete as what was read; this shows what the run could and could not read.",
    example: "9 jobs: 8 done, 1 expired on node-dr1; dc-mumbai-windows skipped (node offline).",
  },
  // src: frontend/components/cbom/results/views/SummaryKpis.tsx:38-46,76-99 — posture readiness, the seven KPI tiles, RunMetaCards
  "cbom.run.summary": {
    what: "The run's headline figures: PQC readiness from the run posture (ready judged assets over judged assets), the seven counts of the run results (crypto assets, weak, quantum vulnerable, certificates, keys, quantum ready, average risk score), then the run's sources, scan nodes, endpoints probed and duration.",
    why: "Says how ready and how exposed the scanned estate is before you open any detail.",
    example: "16.7% ready · 44 crypto assets · 21 weak · 25 quantum vulnerable · 6 sources · 1 scan node · 12 min.",
  },
  // src: frontend/components/cbom/results/views/DrillTiles.tsx:15-49, frontend/components/cbom/results/views/selectors.ts:80-132 — one tile per view, figures from the view's own data
  "cbom.run.drill": {
    what: "One tile per detail view of this run: collection jobs and targets, quantum grades and fix effort, inventory and certificates, the PQC migration plan, compliance, and remediation waves and changes. Each shows the figure its view starts with, or a dash and the reason; Open shows the view and Back to summary returns here.",
    why: "Keeps the summary short while every chart, list and table stays one click away.",
    example: "Quantum grades & fix effort: Q0 Unknown 25 · Q4 Low 5 · No grade 14 · self-fixable 24.2%.",
  },
  // src: frontend/components/cbom/results/RunSections.tsx:217-231 — per source: kind, runner, outcome, assets, endpoints, duration, credits
  "cbom.run.provenance": {
    what: "For each source of the run: its kind, where it ran (a scan node or ZeroShield's cloud), its outcome, the assets collected (not counting the Not collected rows), endpoints probed, duration and credits.",
    why: "Lets an auditor trace every asset back to the job that read it.",
    example: "dc-mumbai-linux · Linux servers · node-dc1 · success · 212 assets · 0 endpoints · 4 min · 51.20.",
  },
  // src: frontend/components/cbom/results/RunSections.tsx:228 — the source kind
  "cbom.run.col.kind": {
    what: "The kind of source: Linux servers, database, AWS account, network range and so on.",
    why: "Each kind is read differently and has its own blind spots.",
    example: "AWS account.",
  },
  // src: frontend/components/cbom/results/RunSections.tsx:230 — job outcome
  "cbom.run.col.outcome": {
    what: "How the source's job ended: success, partial (some targets or checks could not be read), failed, expired or cancelled.",
    why: "A partial or failed outcome means some of that source's crypto is missing from the results.",
    example: "partial: 2 of 254 servers refused the login.",
  },
  // src: frontend/components/cbom/results/RunSections.tsx:231 — collected assets only
  "cbom.run.col.assets_collected": {
    what: "Assets collected from this source. Rows that only record a part the job could not read (Not collected) are left out; the jobs table above counts them.",
    why: "Separates what was actually read from what was attempted.",
    example: "212 assets collected.",
  },
  // src: frontend/components/cbom/results/RunSections.tsx:232 — TLS/SSH endpoints probed
  "cbom.run.col.endpoints": {
    what: "How many network endpoints (address and port) the job probed with a TLS or SSH handshake.",
    why: "Shows how much of a network range answered.",
    example: "48 endpoints on 10.20.0.0/24.",
  },
  // src: frontend/components/cbom/results/RunSections.tsx:233 — job duration
  "cbom.run.col.duration": {
    what: "How long the source's job ran, from claim to result.",
    why: "A very long job may hit timeouts; consider splitting the source.",
    example: "4 min 12 s.",
  },
  // src: frontend/components/cbom/results/RunSections.tsx:234, backend/utilities/cbom_sources/planning.py:25 — credits of the source's job
  "cbom.run.col.credits": {
    what: "The credits charged for this source's job (0.2 per server target, 1 per database, 2 per cluster, 4 per cloud account, 1 per /24).",
    why: "Shows where the run's cost went.",
    example: "51.20 for 256 server targets.",
  },
  // src: frontend/components/cbom/results/RunSections.tsx:349-356 — within this run's scope
  "cbom.run.certs": {
    what: "Within this run's scope: orphaned certificates are stored somewhere but presented by no endpoint the run read; unmanaged ones are held by no managing system the run saw (ACM, cert-manager, AD CS, Key Vault and similar).",
    why: "Orphaned certificates are clutter that can be stolen; unmanaged ones expire without anyone being told.",
    example: "3 orphaned (old keystore copies), 5 unmanaged (hand-installed on web servers).",
  },
  // src: frontend/components/cbom/results/views/CertificatesCard.tsx:1-12 — expiry list, calendar, orphaned and unmanaged, as tabs
  "cbom.run.certificates": {
    what: "The run's certificates and key material in three tabs: the expiry list (X.509 certificates with their validity, then keys and keystores, which have no expiry), the expiry calendar by month, and the orphaned and unmanaged certificates within this run's scope.",
    why: "One place to see what expires when and which certificates nobody manages before an outage or an audit finds them.",
    example: "Expiry list: 3 certificates, 1 expired; Calendar: 2 expire in December; Orphaned and unmanaged: 1 unmanaged.",
  },
  // src: frontend/components/cbom/results/RunSections.tsx:358 — stored, presented by no endpoint read
  "cbom.run.certs.orphaned": {
    what: "Certificates found in files, keystores or secrets that no endpoint read by this run presents.",
    why: "A forgotten certificate with its private key is a credential waiting to be misused.",
    example: "/opt/app/old/server.p12, CN=api-old.bank.in.",
  },
  // src: frontend/components/cbom/results/RunSections.tsx:355 — no managing system saw them
  "cbom.run.certs.unmanaged": {
    what: "Certificates the run found that no certificate manager in this run's scope (ACM, cert-manager, AD CS, Key Vault and similar) holds.",
    why: "Nothing renews or reports on them, so they expire unnoticed.",
    example: "CN=intranet.bank.local installed by hand on web-07.",
  },
  // src: frontend/components/cbom/results/RunSections.tsx:312 — certificate subject
  "cbom.run.cert.subject": {
    what: "The certificate's subject: whom it was issued to.",
    why: "Identifies the service the certificate belongs to.",
    example: "CN=api.bank.in, O=Bank Ltd.",
  },
  // src: frontend/components/cbom/results/RunSections.tsx:313 — certificate issuer
  "cbom.run.cert.issuer": {
    what: "The CA that issued the certificate.",
    why: "An unexpected issuer can mean a certificate bought outside policy.",
    example: "CN=BANK-ISSUING-CA.",
  },
  // src: frontend/components/cbom/results/RunSections.tsx:314 — not_after
  "cbom.run.cert.expires": {
    what: "When the certificate stops being valid.",
    why: "Expired certificates break services; long-lived ones delay migration.",
    example: "2 Dec 2026.",
  },
  // src: frontend/components/cbom/results/RunSections.tsx:315 — where it was found
  "cbom.run.cert.location": {
    what: "Where the run found the certificate: a file path, keystore, secret or endpoint.",
    why: "Tells you where to remove or renew it.",
    example: "web-07:/etc/ssl/intranet.pem.",
  },
  // src: frontend/components/cbom/results/RunSections.tsx:316 — the source that found it
  "cbom.run.cert.source": {
    what: "The source whose job found the certificate.",
    why: "Points to the owner of the system.",
    example: "dc-mumbai-linux.",
  },
  // src: frontend/components/cbom/results/RunSections.tsx:365-373 — drift against each source's previous complete collection
  "cbom.run.changes": {
    what: "What changed against each source's previous complete collection: assets added, removed or changed. Partial or failed collections are not compared.",
    why: "Drift shows new weak crypto, and fixes that landed, as soon as they happen.",
    example: "+3 certificates, -1 SSH host key, 2 changed.",
  },
  // src: backend/utilities/cbom_sources/posture.py:314-329,368-372, backend/utilities/cbom_sources/cbom_metrics.py:29-46 — ready judged / judged; unknown and not-applicable left out (#271)
  "cbom.run.readiness": {
    what: "Ready judged assets divided by judged assets. Judged: the scan identified the cryptography and gave it a quantum verdict. Hybrid, post-quantum and symmetric (AES-256; AES-128 as Grover-weakened) count as ready. Unidentified assets and settings with no algorithm to judge (e.g. a password-hash setting) are left out of both numbers; the percentage is withheld when more assets are unidentified than judged.",
    why: "0% means every judged asset is breakable by a future quantum computer, not that the scan failed; the list below says which assets and what moves the score.",
    example: "46 judged, 0 ready: 0%. Moving 38 TLS endpoints to a hybrid key exchange makes it 82.6%.",
  },
  // src: backend/utilities/cbom_sources/posture.py:342-358, backend/utilities/cbom_sources/run_assets.py:120-148 — quantum-vulnerable assets per asset type and quantum finding, top 3, readiness after the fix; Show these lists the group (pqc_group) (#271)
  "cbom.run.readiness_actions": {
    what: "The largest groups of quantum-vulnerable assets (same asset type and same quantum finding), with the knowledge-base fix and the readiness this run would have if that group alone were fixed. Show these filters the findings table to the group.",
    why: "Tells you which change moves the score most, so the first migration step is the biggest one.",
    example: "Fix 38 TLS endpoints: No post-quantum key exchange · Readiness 0% → 82.6%.",
  },
  // src: backend/utilities/cbom_sources/waves.py:58-81,86-98 — wave counts of the run's assets; the rule per wave, the legend text built from it (#271)
  "cbom.run.waves": {
    what: "This run's assets per remediation wave; first matching rule wins. Wave 1: Critical or High weakness on an internet-facing or in-transit asset, or any quantum-vulnerable key exchange in transit (HNDL). Wave 2: other Critical or High. Wave 3: any other weakness, whatever its impact. Wave 4: quantum-vulnerable, no other weakness. Select findings below to set wave, owner, date or status.",
    why: "Turns the findings into an ordered plan with owners and dates.",
    example: "Wave 1: 4 · Wave 2: 11 · Wave 3: 30 · Wave 4: 52.",
  },
  // src: frontend/components/cbom/results/ComplianceScorecards.tsx:1-7, backend/utilities/cbom_sources/frameworks.py:36-66 — verdict counts and failing assets per requirement
  "cbom.run.compliance_readiness": {
    what: "Per framework the run is judged against (CNSA 2.0, FIPS 140-3 and others the run's checks evidence): requirements passed out of all its requirements, a verdict (Pass, Partial, Fail or Not assessed), the failing requirements and how many assets the worst one fails. Click a card for every requirement with its verdict and evidence.",
    why: "Shows at a glance which standard the crypto estate meets and which requirement keeps it from passing.",
    example: "CNSA 2.0 · Partial · 1/2 passed · 1 requirement failing · 12 assets fail the worst one.",
  },
  // src: frontend/components/cbom/results/RunSections.tsx:446-475 — CERT-In, RBI, SEBI CSCRF, NIST, CNSA 2.0
  "cbom.run.compliance": {
    what: "Per framework (CERT-In, RBI, SEBI CSCRF, NIST, CNSA 2.0): a verdict (Pass, Fail, Partial or Not assessed) from the compliance checks' requirement results, the clauses the findings touch and the assets affected; then each failing clause with its findings, how to fix them and the regulation's text behind Show text. Click an asset count to filter the findings table. Knowledge base and checks, no AI.",
    why: "Shows auditors what fails, where, and what to change, without reading every clause.",
    example: "NIST · Partial · 3/6 requirements pass · 1 clause · 3 assets: SHA-1 based SSH key exchange. How to fix: use curve25519-sha256.",
  },
  // src: frontend/components/cbom/results/views/TopRisksSummary.tsx:50-120, backend/utilities/cbom_sources/posture.py:43-47 — impact x criticality x exposure
  "cbom.run.top_risks": {
    what: "The run's riskiest assets, ranked by priority = impact weight x the source's business criticality x its internet exposure, from the run posture.",
    why: "Puts the fixes that cut the most risk first.",
    example: "Priority 21: RSA-1024 on api.bank.in:443, High, critical source, internet-facing, HNDL.",
  },
  // src: backend/utilities/cbom_sources/posture.py:43-47, backend/utilities/cbom_sources/posture.py:496-497 — impact x criticality x exposure
  "cbom.run.col.priority": {
    what: "Impact weight (Critical 10, High 7, Medium 4, Low 1) x business criticality (0.5 to 2) x exposure (1.5 internet-facing, else 1).",
    why: "Ranks the same weakness higher on critical, exposed systems.",
    example: "7 x 2 x 1.5 = 21.",
  },
  // src: frontend/components/cbom/results/views/TopRisksSummary.tsx:92 — the asset
  "cbom.run.col.asset": {
    what: "The cryptographic asset: an endpoint, key, certificate or library, with where it is.",
    why: "Names exactly what to change.",
    example: "api.bank.in:443 TLS.",
  },
  // src: backend/utilities/cbom_sources/posture.py:44 — the source's business criticality
  "cbom.run.col.criticality": {
    what: "The business criticality of the asset's source when the run started: low, medium, high or critical.",
    why: "Critical systems rank higher.",
    example: "critical.",
  },
  // src: backend/utilities/cbom_sources/posture.py:47, backend/utilities/cbom_sources/posture.py:398 — from facts or the source's override
  "cbom.run.col.exposure": {
    what: "Whether the asset is internet-facing, internal or unknown, from the collected facts or the source's override. Hover for the basis.",
    why: "Internet-facing assets are attacked first.",
    example: "Internet-facing (public load balancer).",
  },
  // src: backend/utilities/cbom_sources/posture.py:8-9 — harvest now, decrypt later
  "cbom.run.col.hndl": {
    what: "Harvest now, decrypt later: the asset's key exchange is quantum-vulnerable, so traffic recorded today could be decrypted by a future quantum computer.",
    why: "Long-lived secrets on these channels are already at risk.",
    example: "HNDL on vpn.bank.in (IKE with DH group 14).",
  },
  // src: frontend/components/cbom/results/RunFindingsTable.tsx:165-170 — the run's assets, Findings or All assets
  "cbom.run.findings": {
    what: "Findings: the assets of this run with a finding; select rows to change their status or plan a wave, click a row for its explanation. All assets: every asset collected, including clean ones and the parts it could not read (Not collected).",
    why: "Each row is something to fix, accept or plan for migration.",
    example: "RSA-2048 on api.bank.in:443 · High · quantum-vulnerable · Wave 1 · Not started.",
  },
  // src: frontend/components/cbom/results/RunFindingsTable.tsx:173-182 — view=findings or all
  "cbom.run.view": {
    what: "Switch between the assets with a finding and every asset the run collected (clean ones and Not collected rows included).",
    why: "All assets is the complete inventory; Findings is the work list.",
    example: "Findings (96) · All assets (1,284).",
  },
  // src: frontend/components/cbom/results/RunFindingsTable.tsx:216-220 — location, algorithm or finding
  "cbom.run.search": {
    what: "Shows only rows whose location, algorithm or finding text contains this text.",
    why: "Finds every asset of one host or algorithm quickly.",
    example: "\"api.bank.in\" keeps that host's endpoints and certificates.",
  },
  // src: frontend/components/cbom/results/RunFindingsTable.tsx:222-228 — Critical, High, Medium, Low
  "cbom.run.filter.impact": {
    what: "Shows only rows of one impact: Critical, High, Medium or Low.",
    why: "Focuses on the most serious findings.",
    example: "Critical.",
  },
  // src: frontend/components/cbom/results/RunFindingsTable.tsx:229-237,241 — asset type
  "cbom.run.filter.type": {
    what: "Shows only one type of asset: TLS endpoint, certificate, key, SSH host key, library and others.",
    why: "Plan migration one asset type at a time.",
    example: "Certificate.",
  },
  // src: frontend/components/cbom/results/RunFindingsTable.tsx:238-245,249 — quantum-vulnerable only
  "cbom.run.filter.quantum": {
    what: "Shows only quantum-vulnerable assets.",
    why: "This is your post-quantum migration list.",
    example: "Quantum-vulnerable.",
  },
  // src: frontend/components/cbom/results/RunFindingsTable.tsx:247-253,260 — one source
  "cbom.run.filter.source": {
    what: "Shows only the assets of one source of the run.",
    why: "Hand one source's list to its owner.",
    example: "dc-mumbai-linux.",
  },
  // src: frontend/components/cbom/results/RunFindingsTable.tsx:256-262,272 — Not started, In progress, Fixed, Ignored
  "cbom.run.filter.status": {
    what: "Shows only findings with one status: Not started, In progress, Fixed or Ignored.",
    why: "Track what is still open.",
    example: "Not started.",
  },
  // src: frontend/components/cbom/results/RunFindingsTable.tsx:324 — host, port, path
  "cbom.run.col.where": {
    what: "Where the asset is: host and port, file path, keystore or cloud resource.",
    why: "Takes you straight to the system to change.",
    example: "api.bank.in:443.",
  },
  // src: frontend/components/cbom/results/RunFindingsTable.tsx:311 — the finding text
  "cbom.run.col.finding": {
    what: "What is wrong with the asset, from the knowledge base.",
    why: "Explains why it is a finding before you open it.",
    example: "TLS 1.0 accepted; key exchange quantum-vulnerable.",
  },
  // src: frontend/components/cbom/results/RunFindingsTable.tsx:329 — the source
  "cbom.run.col.source": {
    what: "The source whose job collected this asset.",
    why: "Points to the owner of the system.",
    example: "dc-mumbai-linux.",
  },
  // src: backend/utilities/cbom_sources/waves.py:44-60 — suggested or assigned wave
  "cbom.run.col.wave": {
    what: "The remediation wave: the one your team assigned, or the suggested one (1 most urgent to 4 post-quantum migration), with owner and target date when set.",
    why: "Turns findings into an ordered plan.",
    example: "Wave 1 · Payments · 31 Dec.",
  },
  // src: contracts/cbom/status_buckets.json:2 — open, in progress, done, accepted risk
  "cbom.run.col.status": {
    what: "The finding's status from its remediation plan: Not started, In progress, Fixed or Ignored (risk accepted).",
    why: "Fixed and Ignored findings leave the open backlog.",
    example: "In progress.",
  },
  // src: backend/utilities/cbom_sources/qgrade.py:51-104 — Q0..Q4
  "cbom.run.col.qgrade": {
    what: "The asset's quantum risk grade, Q1 Critical to Q4 Low, or Q0 Unknown when a deciding fact or the team's Mosca settings are missing.",
    why: "Ranks post-quantum migration by how soon the data is at risk.",
    example: "Q1 Critical: quantum-vulnerable, internet-facing, X + Y > Z.",
  },
  // src: frontend/components/cbom/results/RunSections.tsx:456-472 — the rows of the current table page
  "cbom.run.risk_scores": {
    what: "The risk score (0 to 10) of the rows on the findings table's current page and filter, highest first, at most 24. It never counts the whole run.",
    why: "Shows whether this page's risk is concentrated in a few rows.",
    example: "F1: RSA-1024 signing key, 9.8.",
  },
  // src: frontend/components/cbom/results/RunSections.tsx:128-135 — CycloneDX JSON and XML, OSCAL
  "cbom.run.downloads": {
    what: "The run's CBOM as CycloneDX 1.6 JSON or XML (schema-valid), and OSCAL 1.2.3 assessment results for a GRC tool once the run has finished.",
    why: "Hands the inventory to auditors and other tools in standard formats.",
    example: "CycloneDX JSON (1,284) for the auditor's CBOM request.",
  },
  // src: frontend/components/cbom/results/RunFindingDialog.tsx:85 — asset type
  "cbom.run.f.type": {
    what: "The kind of asset: TLS endpoint, certificate, key, SSH host key, library and others.",
    why: "Each type has its own replacement path.",
    example: "TLS endpoint.",
  },
  // src: frontend/components/cbom/results/RunFindingDialog.tsx:81-83 — weak, moderate, strong, quantum-safe
  "cbom.run.f.strength": {
    what: "How strong the cryptography is today: weak, moderate, strong or quantum-safe.",
    why: "Weak is exploitable now.",
    example: "weak.",
  },
  // src: frontend/components/cbom/results/RunFindingDialog.tsx:89 — bits
  "cbom.run.f.key_size": {
    what: "The key length in bits, when the asset has one.",
    why: "Short keys can be broken without a quantum computer.",
    example: "1024 bits.",
  },
  // src: frontend/components/cbom/results/RunFindingDialog.tsx:85-89 — quantum verdict
  "cbom.run.f.quantum": {
    what: "Whether a quantum computer breaks it: quantum-vulnerable, quantum-safe or broken today.",
    why: "Quantum-vulnerable assets need a post-quantum replacement.",
    example: "Quantum-vulnerable.",
  },
  // src: frontend/components/cbom/results/RunFindingDialog.tsx:90-92 — impact as collected
  "cbom.run.f.impact": {
    what: "The impact the asset was judged with when it was collected: Critical, High, Medium, Low, or Info for clean inventory.",
    why: "Fix Critical and High first.",
    example: "High.",
  },
  // src: frontend/components/cbom/results/RunFindingDialog.tsx:93-97 — 0-10
  "cbom.run.f.risk": {
    what: "The asset's risk score, 0 to 10, from its impact, findings, strength and quantum verdict.",
    why: "Orders findings of the same impact.",
    example: "8.6 out of 10.",
  },
  // src: frontend/components/cbom/results/RunFindingDialog.tsx:98-102 — remediation status
  "cbom.run.f.status": {
    what: "The status of the asset's remediation plan: Not started, In progress, Fixed or Ignored.",
    why: "Shows whether anyone is working on it.",
    example: "In progress.",
  },
  // src: frontend/components/cbom/results/RunFindingDialog.tsx:106-112 — linked Jira ticket
  "cbom.run.f.ticket": {
    what: "The Jira ticket filed for this asset, if any.",
    why: "Follow the fix in your team's tracker.",
    example: "SEC-1423.",
  },
  // src: frontend/components/cbom/results/RunFindingDialog.tsx:116-123 — where it is
  "cbom.run.f.location": {
    what: "Exactly where the asset is: host and port, file path, keystore or cloud resource.",
    why: "Takes you to the system to change.",
    example: "web-07:/etc/ssl/intranet.pem.",
  },
  // src: frontend/components/cbom/results/RunFindingDialog.tsx:126-127 — the finding text
  "cbom.run.f.finding": {
    what: "What is wrong, from the knowledge base.",
    why: "Explains the risk in plain words.",
    example: "Key exchange uses RSA: quantum-vulnerable.",
  },
  // src: frontend/components/cbom/results/RunFindingDialog.tsx:129-130 — extra description
  "cbom.run.f.description": {
    what: "More detail about the asset and the finding.",
    why: "Context helps choose the right fix.",
    example: "Endpoint offers TLS 1.0-1.2 with RSA key exchange.",
  },
  // src: frontend/components/cbom/results/RunFindingDialog.tsx:134-170 — source, job, node
  "cbom.run.f.origin": {
    what: "The source, job and scan node (or cloud) that collected this asset, and when.",
    why: "Lets you trace and re-check the evidence.",
    example: "dc-mumbai-linux · job #4410 · node-dc1 · 13 Nov 23:10.",
  },
  // ────────────────────────────────────────────────────────────── CBOM Sources: in-tab run results and posture (components/cbom/sources/RunResults.tsx, RunPosture.tsx)
  // src: frontend/components/cbom/sources/RunResults.tsx:103-108 — each target's outcome
  "cbom.run.targets": {
    what: "Each target the run's jobs tried, with its outcome: read, unreachable, login failed and so on.",
    why: "Targets that could not be read are blind spots in this run.",
    example: "10.20.0.17 · unreachable (port 22 filtered).",
  },
  // src: backend/utilities/cbom_sources/posture.py:1-15 — HNDL, Mosca, risk score, compliance, from the knowledge base
  "cbom.run.posture": {
    what: "The run's posture from the knowledge base (no AI): harvest-now-decrypt-later exposure, the Mosca test X + Y > Z with your team's values, risk scores and the regulatory clauses touched.",
    why: "Turns the inventory into the questions a board and a regulator ask.",
    example: "14 HNDL endpoints; with X 10, Y 3, Z 10 the data is at risk now.",
  },
  // src: frontend/components/cbom/sources/RunPosture.tsx:108-112,170,144, backend/utilities/cbom_sources/posture.py:10-11 — X, Y, Z in years, 0-100, team admins
  "cbom.run.mosca": {
    what: "The team's Mosca values in whole years, 0 to 100: X how long data must stay secret, Y how long migration takes, Z years until a cryptographically relevant quantum computer. Team admins only; blank clears.",
    why: "X + Y > Z means data protected by quantum-vulnerable crypto is already at risk.",
    example: "X 10, Y 5, Z 12: 15 > 12, migration is overdue.",
  },
  // ────────────────────────────────────────────────────────────── CBOM run results: Ticketing tab (CB-38 PR-4)
  // src: backend/utilities/cbom_sources/run_tickets.py:1-22, frontend/components/cbom/results/RunTicketingTab.tsx:3-6,191 — one issue per asset across runs
  "cbom.run.tickets": {
    what: "Creates one Jira issue per selected finding with the team's Jira connection. An asset that already has an issue, from this run or an earlier run of the same source, keeps it and no duplicate is opened. Each result shows created, existing, failed or deferred (retry).",
    why: "Puts the fixes in the tracker your owners already work from.",
    example: "12 selected: 9 created (SEC-1501 to SEC-1509), 3 existing.",
  },
  // src: backend/utilities/cbom_sources/run_tickets.py:3-5, frontend/components/cbom/results/runTicketing.ts:26-33 — key or numeric id, team admin
  "cbom.run.tickets.project": {
    what: "The Jira project, by key or numeric id, for the tickets of every Sources run of the team. Only a team admin sets it; leave it empty to stop creating tickets. Jira credentials stay in Team settings.",
    why: "Tickets land where the owners of the infrastructure work.",
    example: "SEC, or 10000.",
  },
  // src: backend/utilities/cbom_sources/run_tickets.py:54, frontend/components/cbom/results/RunTicketingTab.tsx:107-110 — default Task
  "cbom.run.tickets.issue_type": {
    what: "The Jira issue type of the tickets, up to 64 characters. Task when left empty.",
    why: "Some projects only accept their own issue types, such as Bug or Vulnerability.",
    example: "Vulnerability.",
  },
  // src: frontend/components/cbom/results/RunTicketingTab.tsx:256-260, backend/utilities/cbom_sources/run_tickets.py:18-20 — findings without a ticket on this page
  "cbom.run.tickets.select": {
    what: "Selects every finding on this page that has no Jira issue yet. Clean inventory and coverage notes are not findings and cannot be ticketed.",
    why: "Ticket a page of findings in one step.",
    example: "100 on this page, 88 without a ticket: 88 selected.",
  },
  // ────────────────────────────────────────────────────────────── CBOM run results: quantum readiness chart of a run
  // src: frontend/components/cbom/results/model.ts:100-128, backend/utilities/cbom_sources/posture.py:3-7 — Safe = hybrid + quantum-safe + grover-weakened; Vulnerable = quantum-vulnerable
  "cbom.run.quantum": {
    what: "The run's assets with a quantum verdict, from the run's posture: Safe counts the hybrid, quantum-safe and grover-weakened classes, Vulnerable the quantum-vulnerable class. Assets with no verdict (unknown, not applicable) are left out. A run has no Broken today bar.",
    why: "Same counts as the Quantum ready card and the posture section, so the numbers on the page agree.",
    example: "Safe 412, Vulnerable 168.",
  },
  // ────────────────────────────────────────────────────────────── CBOM run results on the one results template (#239, #124)
  // src: frontend/components/cbom/results/RunDeliverablesMenu.tsx:20-45,83 — VEX, ES256 signature, evidence zip, PDF report
  "cbom.run.deliverables": {
    what: "The run's CycloneDX 1.6 VEX (exploitable, in triage, resolved or will-not-fix from the remediation plan), an ES256 signature of the CycloneDX JSON download (published key), an evidence pack (CycloneDX JSON and XML, OSCAL, VEX, signature, PDF, a signed sha256 manifest and an offline verifier) and a PDF report. While the run is collecting, each file says it holds what was collected so far.",
    why: "The documents an auditor or a regulator asks for, built from the same data as this page.",
    example: "Evidence pack for the RBI inspection: one zip with its signed sha256 manifest.",
  },
  // src: frontend/components/cbom/results/RunSections.tsx:163-192 — verifyCbomRunSignature; ES256, key published at GET /{team}/bom-signing-keys
  "cbom.run.verify": {
    what: "Checks a CycloneDX JSON file you downloaded from this run against the run's signature. The signature is ES256 with a published public key, so the same check also works offline (openssl or the verifier in the evidence pack); the result says whether the file is unchanged.",
    why: "Proves a file someone sends you is the run's real CBOM, not an edited copy.",
    example: "Verified: this file is the run's signed CycloneDX JSON, unchanged.",
  },
  // src: frontend/components/cbom/results/RunFindingDialog.tsx:138-150, frontend/components/cbom/results/model.ts:587-615 — the item's owasp_top_10, else the knowledge-base entries (findingChips)
  "cbom.run.f.owasp": {
    what: "The OWASP Top 10 categories this finding maps to: the scan's own mapping when it sent one, else the categories of the asset's knowledge-base entries. Most cryptographic findings fall under A02 Cryptographic Failures.",
    why: "Lets application security teams file the finding under the category they track.",
    example: "A02:2021 Cryptographic Failures.",
  },
  // src: frontend/components/cbom/results/RunFindingDialog.tsx:151-160, frontend/components/cbom/results/model.ts:587-615 — the item's compliance_controls, else the knowledge-base entries (findingChips)
  "cbom.run.f.compliance": {
    what: "The compliance controls this finding maps to, such as PCI DSS requirements, ISO 27001 clauses or RBI and CERT-In items: the scan's own mapping, else those of the asset's knowledge-base entries.",
    why: "Shows which audit requirement the fix closes.",
    example: "PCI DSS 4.2.1 (strong cryptography in transit).",
  },
  // src: frontend/components/cbom/results/RunFindingDialog.tsx:161-166, frontend/components/cbom/results/model.ts:587-615 — the item's suggested_fix, else the knowledge-base remediation summary (findingChips)
  "cbom.run.f.suggested_fix": {
    what: "The fix suggested for this finding: the scan's own suggestion when it gave one, else the remediation summary of the asset's knowledge-base entry (no AI).",
    why: "A starting point for the owner's change.",
    example: "Disable TLS 1.0 and 1.1; allow TLS 1.2 and 1.3 only.",
  },
} as const satisfies TipAreaText;

export default TEXT;
