/**
 * (i) tip text of the "cbom-results" area (ids: cbom.res.*, cbom.chart.*, cbom.cal.*, cbom.reg.*, cbom.q0.*, cbom.ai.*), loaded on demand by
 * content/infotips/load.ts. The label of each tip is in content/infotips/labels.ts; the rules for the text are in
 * content/infotips/index.ts (checked by content/infotips.test.ts).
 */
import type { TipAreaText } from "../types";

const TEXT = {
  // src: backend/utilities/dashboard/scan_list.py:1757-1783 — code-scan findings by your status; Sources findings by their remediation plan status
  "cbom.chart.remediation": {
    what: "Crypto findings by status: code-scan findings by the status your team set, CBOM Sources findings by their remediation plan status (open counts as Not started).",
    why: "Shows how far the team has got with fixing crypto findings.",
    example: "30 findings: 5 Fixed, 3 In progress, 22 Not started.",
  },
  // src: backend/utilities/cbom_sources/cbom_metrics.py:1-15, backend/utilities/dashboard/scan_list.py:1803 — findings by severity, inventory separately
  "cbom.chart.severity": {
    what: "Crypto findings by severity (Critical, High, Medium, Low) and the clean inventory rows as Informational.",
    why: "Critical and High findings are the ones to fix first.",
    example: "High 4, Medium 9, Informational 120.",
  },
  // src: backend/utilities/cbom_sources/cbom_metrics.py:116-121, backend/utilities/dashboard/scan_list.py:1804 — algorithm_type of every row
  "cbom.chart.algorithm_type": {
    what: "All crypto assets by the type the engine gave them (for example certificate, key or secret); assets without a type count as other.",
    why: "Shows which kinds of cryptography dominate your migration work.",
    example: "certificate 6, key 3, other 12.",
  },
  // src: backend/utilities/cbom_sources/cbom_metrics.py:99, backend/utilities/cbom_sources/cbom_metrics.py:122-128 — weak / moderate / strong / quantum-safe
  "cbom.chart.strength": {
    what: "All crypto assets by strength grade: weak (replace now), moderate, strong, quantum-safe. Assets without a grade are not shown.",
    why: "Weak and moderate assets are the near-term fixes.",
    example: "weak 5, moderate 12, strong 60, quantum_safe 2.",
  },
  // src: backend/utilities/cbom_sources/cbom_metrics.py:101, backend/utilities/cbom_sources/cbom_metrics.py:129-135 — quantum_safe / quantum_vulnerable / broken_today
  "cbom.chart.quantum": {
    what: "Assets with a quantum verdict: quantum-safe, quantum-vulnerable (breakable by a future quantum computer), and broken today (already insecure without one).",
    why: "Quantum-vulnerable assets are your post-quantum migration list.",
    example: "Safe 30, Vulnerable 12, Broken today 2.",
  },
  // src: backend/utilities/cbom_sources/cbom_metrics.py:1-15, backend/utilities/dashboard/scan_list.py:1808 — the 10 riskiest findings
  "cbom.chart.top_risks": {
    what: "The 10 riskiest crypto findings, with algorithm, type, strength, quantum safety, impact and where each was found (a code scan or a CBOM Sources collection).",
    why: "Start here when you have time for only a few fixes.",
    example: "RSA-1024 · asymmetric · weak · not quantum safe · High · payments-api.",
  },
  // ────────────────────────────────────────────────────────────── CBOM code-scan results (components/CbomResults.tsx)
  // src: backend/utilities/cbom_sources/cbom_metrics.py:166-174, backend/utilities/dashboard/scan.py:1207-1208 — every row of the inventory table: findings and clean inventory
  "cbom.res.kpi.assets": {
    what: "Every cryptographic asset this scan found: algorithms, keys, certificates, protocols and libraries in use, whether or not it is a finding.",
    why: "This is your cryptographic bill of materials; everything else on the page is a view of it.",
    example: "57 assets: 41 clean (such as AES-256-GCM) and 16 findings.",
  },
  // src: backend/utilities/cbom_sources/cbom_metrics.py:122-129 — crypto_strength weak
  "cbom.res.kpi.weak": {
    what: "Assets whose cryptographic strength is weak today: broken or deprecated algorithms and too-short keys.",
    why: "Weak crypto can be attacked now, without a quantum computer.",
    example: "MD5 password hashing in auth/legacy.py.",
  },
  // src: backend/utilities/cbom_sources/cbom_metrics.py:130-135 — the Quantum column's verdict
  "cbom.res.kpi.qv": {
    what: "Assets that a large quantum computer could break: public-key algorithms such as RSA, Diffie-Hellman and elliptic curves (ECDH, ECDSA).",
    why: "Data encrypted with them today can be recorded now and decrypted later (harvest now, decrypt later).",
    example: "RSA-2048 key exchange on api.bank.in:443: a future quantum computer could recover the key, so recorded traffic is at risk.",
  },
  // src: backend/utilities/cbom_sources/cbom_metrics.py:136-137 — algorithm_type certificate
  "cbom.res.kpi.certs": {
    what: "X.509 certificates found in the code and files of this scan.",
    why: "Certificates expire and carry keys and signature algorithms that need migrating.",
    example: "3: two in config/tls, one test certificate in fixtures.",
  },
  // src: backend/utilities/cbom_sources/cbom_metrics.py:138-139 — algorithm_type key or secret
  "cbom.res.kpi.keys": {
    what: "Keys and secrets found: private keys, symmetric keys and key material in code or files.",
    why: "A key committed to a repository should be treated as exposed and rotated.",
    example: "A PEM private key in deploy/certs/server.key.",
  },
  // src: backend/utilities/cbom_sources/cbom_metrics.py:29-43, backend/utilities/cbom_sources/cbom_metrics.py:175-179, frontend/utils/cbomReadiness.ts:19-21 — quantum-safe share of judged assets; n/a when none judged
  "cbom.res.kpi.ready": {
    what: "The share of judged assets that are quantum-safe: post-quantum, hybrid or symmetric with enough margin. Assets that are quantum-vulnerable or broken today count against it; assets without a quantum verdict (hashes, settings) are left out. n/a when no asset was judged.",
    why: "It tracks your post-quantum migration in one number.",
    example: "12 judged: 9 safe, 2 RSA, 1 DES: 9 / 12 = 75%.",
  },
  // src: aibom/src/aibom/score/posture.py:31-44, backend/utilities/cbom_sources/cbom_metrics.py:87-99 — the engine's one posture formula and the backend wrapper the API and PDF call
  "cbom.res.kpi.avg_risk": {
    what: "This scan's risk score, 0 to 100, with its grade and words: 4 x (10 per Critical + 5 per High + 2 per Medium + 1 per Low finding), at most 100, and capped by the worst severity found: no Critical keeps it at 69 or less, no Critical or High at 49 or less, Low only at 29 or less. Clean inventory is left out. The PDF report's headline shows the same number.",
    why: "One score for the whole scan that never claims a worse posture than its worst finding.",
    example: "1 High, 1 Medium and 2 Low: 4 x (5 + 2 + 2) = 36, grade C, Elevated risk.",
  },
  // src: backend/utilities/dashboard/scan.py:1233-1239 — finding rows by status
  "cbom.res.remediation": {
    what: "This scan's findings by the status your team set: Fixed, In progress, Not started, Ignored, with a count and a share each.",
    why: "Shows how far the fixing has got.",
    example: "16 findings: 4 Fixed (25%), 2 In progress, 10 Not started.",
  },
  // src: backend/utilities/cbom_sources/cbom_metrics.py:146-147 — owasp_top_10 values of the findings
  "cbom.res.owasp": {
    what: "How many findings map to each OWASP Top 10 category; most crypto findings fall under A02 Cryptographic Failures.",
    why: "Lets you report crypto findings in the framework your AppSec team uses.",
    example: "A02:2021 Cryptographic Failures: 14.",
  },
  // src: backend/utilities/cbom_sources/cbom_metrics.py:182-185 — findings by severity
  "cbom.res.severity": {
    what: "This scan's findings by impact: Critical, High, Medium and Low.",
    why: "Fix Critical and High first.",
    example: "Critical 1, High 5, Medium 7, Low 3.",
  },
  // src: backend/utilities/cbom_sources/cbom_metrics.py:148-149, backend/utilities/dashboard/scan.py:1213-1224 — controls the findings map to, and framework fails
  "cbom.res.compliance": {
    what: "Findings mapped to compliance controls and frameworks (for example CERT-In, RBI, NIST, PCI DSS): the 10 with the most findings.",
    why: "Shows which audit requirements the crypto weaknesses put at risk.",
    example: "PCI DSS 4.2.1 (strong cryptography in transit): 6.",
  },
  // src: backend/utilities/cbom_sources/cbom_metrics.py:116-120 — algorithm_type of every row
  "cbom.res.algo_types": {
    what: "Every asset by type of cryptography: symmetric cipher, asymmetric, hash, signature, key exchange, certificate, key, protocol and others.",
    why: "Shows where your crypto is concentrated and which migration work dominates.",
    example: "hash 18, symmetric 12, asymmetric 9, certificate 3.",
  },
  // src: backend/utilities/cbom_sources/cbom_metrics.py:121-129 — weak, moderate, strong, quantum_safe
  "cbom.res.strength": {
    what: "Every asset by strength today: weak, moderate, strong or quantum-safe.",
    why: "Weak and moderate assets are the near-term fixes.",
    example: "weak 4, moderate 6, strong 40, quantum-safe 2.",
  },
  // src: backend/utilities/cbom_sources/cbom_metrics.py:100-135 — quantum-safe, quantum-vulnerable, broken today
  "cbom.res.quantum": {
    what: "Every judged asset by its quantum verdict: quantum-safe, quantum-vulnerable (public-key crypto a quantum computer breaks), or broken today (already weak, such as MD5 or DES).",
    why: "Quantum-vulnerable assets are your post-quantum migration list.",
    example: "safe 30, quantum-vulnerable 9, broken today 3.",
  },
  // src: frontend/components/cbom/results/CbomDashboardCharts.tsx:94, backend/utilities/dashboard/bom_risk_score.py:101-120 — top 24 by score
  "cbom.res.risk_scores": {
    what: "The 24 highest-scoring findings, highest first (F1 is the highest). Each score is 0 to 10: the impact's base plus additions for weak strength, quantum vulnerability and the finding's codes.",
    why: "Shows whether risk is concentrated in a few findings or spread out.",
    example: "F1: RSA-1024 signing key, 9.8.",
  },
  // src: backend/utilities/dashboard/scan.py:1230-1231, backend/utilities/dashboard/remediation_metrics.py:17-90 — from the status of this scan's findings
  "cbom.res.remed.section": {
    what: "Measured from the status your team sets on this scan's findings. The targets are fixed goals shown for comparison.",
    why: "Shows whether fixes keep pace with what the scans find.",
    example: "Mark a finding Fixed in the table below and these numbers update.",
  },
  // src: frontend/components/cbom/results/views/ScanNotes.tsx:14-37 — the CycloneDX import report (code scans and runs)
  "cbom.res.import_notes": {
    what: "What happened when your uploaded CycloneDX CBOM was read: how many cryptographic assets were imported, and which components were skipped as not crypto, unreadable, duplicate or past the limit.",
    why: "Skipped components are missing from the results, so check them.",
    example: "40 of 42 cryptographic assets imported · CycloneDX 1.6 · 2 unreadable.",
  },
  // src: frontend/components/cbom/results/views/ScanNotes.tsx:40-65 — coverage notes of the scan (code scans and runs)
  "cbom.res.coverage": {
    what: "Which files and languages the scan read and what it skipped, with the reason.",
    why: "Skipped files are not in the inventory, so a clean result may be incomplete.",
    example: "312 files read; 14 skipped as larger than the size limit.",
  },
  // src: frontend/components/CbomResults.tsx:843 — an uploaded CBOM file
  "cbom.res.input": {
    what: "This scan read an uploaded CycloneDX CBOM file instead of source code.",
    why: "Results are only as complete as the file.",
    example: "CBOM file.",
  },
  // src: frontend/components/CbomResults.tsx:940 — finding rows; clean inventory is not listed here
  "cbom.res.findings": {
    what: "This scan's findings, one per row, each with a status your team sets. Clean assets (for example AES-GCM or SHA-256) are in the charts and the CycloneDX download, not in this table.",
    why: "Each row is something to fix, accept or plan for migration.",
    example: "RSA-2048 in src/crypto/keys.py:42, High, quantum-vulnerable, Not started.",
  },
  // src: frontend/components/CbomResults.tsx:266 — algorithm, description, location or id
  "cbom.res.search": {
    what: "Shows only the findings whose algorithm, description, location or id contains this text (upper or lower case does not matter).",
    why: "Find every use of one algorithm or file quickly.",
    example: "\"rsa\" keeps RSA-2048 and RSA-1024 findings.",
  },
  // src: frontend/components/CbomResults.tsx:994 — tiers on the 0-10 risk score
  "cbom.res.filter.risk": {
    what: "Shows only findings whose risk score (0 to 10) is in a tier: Critical 9 or more, High 7 to 9, Medium 5 to 7, Low under 5.",
    why: "Focus on the findings that score highest.",
    example: "High keeps a finding scored 7.6 and hides one scored 9.4.",
  },
  // src: frontend/components/CbomResults.tsx:1007 — exact crypto_strength
  "cbom.res.filter.strength": {
    what: "Shows only findings of one strength: weak, moderate, strong or quantum-safe.",
    why: "Weak findings are exploitable today.",
    example: "Weak.",
  },
  // src: frontend/components/CbomResults.tsx:1019 — exact algorithm_type
  "cbom.res.filter.type": {
    what: "Shows only findings of one algorithm type, from the types found in this scan.",
    why: "Plan migration work one type at a time.",
    example: "certificate.",
  },
  // src: frontend/components/cbom/quantumFilter.ts:10-29 — safe, broken today, vulnerable
  "cbom.res.filter.quantum": {
    what: "Shows only findings that are quantum-safe, broken today (weak even without a quantum computer, such as MD5) or quantum-vulnerable.",
    why: "Vulnerable gives your post-quantum migration list; Broken today the fixes that cannot wait.",
    example: "Vulnerable: the RSA and ECDH findings.",
  },
  // src: frontend/components/CbomResults.tsx:1063 — selects the rows shown
  "cbom.res.select_all": {
    what: "Selects every finding the table shows (after search and filters), for the actions above the table: change their status or file Jira tickets.",
    why: "Handle a group of similar findings in one step.",
    example: "Filter Type: certificate, select all, mark In progress.",
  },
  // src: frontend/components/CbomResults.tsx:1066 — algorithm name
  "cbom.res.col.algorithm": {
    what: "The algorithm, key, certificate or protocol found, as named in the code or file. Click it for the details and the suggested fix.",
    why: "Names exactly what to replace.",
    example: "RSA-2048.",
  },
  // src: frontend/components/CbomResults.tsx:1067 — algorithm_type
  "cbom.res.col.type": {
    what: "The kind of cryptography: symmetric, asymmetric, hash, signature, key exchange, certificate, key, protocol or other.",
    why: "Each type has its own replacement path.",
    example: "asymmetric.",
  },
  // src: frontend/components/CbomResults.tsx:1069, backend/utilities/cbom_sources/cbom_metrics.py:121-129 — weak, moderate, strong, quantum-safe
  "cbom.res.col.strength": {
    what: "How strong it is today: weak (broken or deprecated), moderate, strong, or quantum-safe.",
    why: "Weak is exploitable now; moderate is due for an upgrade.",
    example: "weak for SHA-1 signatures.",
  },
  // src: frontend/components/cbom/quantumFilter.ts:10-29 — safe, broken today, vulnerable
  "cbom.res.col.quantum": {
    what: "Whether a quantum computer breaks it: Quantum-safe, Vulnerable (RSA, Diffie-Hellman, elliptic curves) or Broken today (weak even without one).",
    why: "Vulnerable assets need a post-quantum replacement such as ML-KEM or ML-DSA.",
    example: "Vulnerable for ECDSA P-256 signing.",
  },
  // src: backend/utilities/dashboard/bom_risk_score.py:101-120 — 0-10 per finding
  "cbom.res.col.risk": {
    what: "This finding's risk, 0 to 10: the impact's base plus additions for weak strength, quantum vulnerability and its finding codes.",
    why: "Orders findings of the same impact by how much they matter.",
    example: "9.8 for an RSA-1024 signing key.",
  },
  // src: frontend/components/CbomResults.tsx:1073 — file and line
  "cbom.res.col.location": {
    what: "Where it was found: the file and line, or the component in an uploaded CBOM.",
    why: "Takes you straight to the code to change.",
    example: "src/crypto/keys.py:42.",
  },
  // src: backend/utilities/dashboard/scan.py:1256, backend/utilities/cbom_sources/cbom_metrics.py:186-188 — the 10 highest risk scores
  "cbom.res.top": {
    what: "The 10 findings with the highest risk scores in this scan.",
    why: "Start here when you have time for only a few fixes.",
    example: "RSA-1024 signing key, weak, not quantum-safe, Critical.",
  },
  // src: frontend/components/CbomResults.tsx:1206 — QuantumBadge yesNo: Yes, No, Broken today (weak and quantum-safe), or a dash when quantum readiness does not apply
  "cbom.res.col.quantum_safe": {
    what: "Whether the asset is quantum-safe: Yes, No (needs a post-quantum replacement), Broken today (weak even without a quantum computer, such as MD5), or a dash when quantum readiness does not apply to it.",
    why: "No means it needs a post-quantum replacement.",
    example: "No for RSA-2048; Broken today for MD5.",
  },
  // ────────────────────────────────────────────────────────────── CBOM crypto-asset charts (components/cbom/CbomCryptoCharts.tsx, CertCalendar.tsx)
  // src: frontend/components/cbom/CbomCryptoCharts.tsx:308-313 — algorithms by primitive
  "cbom.chart.algorithms": {
    what: "Cryptographic algorithms found, grouped by primitive: block cipher, hash, signature, key agreement, public-key encryption and others.",
    why: "Shows which primitives your migration has to cover and how often each is used.",
    example: "signature 14, hash 11, key agreement 6.",
  },
  // src: frontend/components/cbom/CbomCryptoCharts.tsx:346-351 — weak or deprecated crypto by category
  "cbom.chart.weak": {
    what: "Weak or deprecated cryptography by category, coloured by severity (High red, Medium orange).",
    why: "These can be attacked today and are the first fixes.",
    example: "Deprecated hash (SHA-1): 4 High.",
  },
  // src: frontend/components/cbom/CbomCryptoCharts.tsx:374-387 — PqcReadinessGauge counts every row of the page (quantumFilter.inventoryRows) by the Quantum column verdict (quantumCounts); distributions.pqc (NIST levels) only when the page has no rows
  "cbom.chart.pqc": {
    what: "The quantum-ready share of every crypto asset on the page (findings and clean inventory), by the same verdict as the table's Quantum column: quantum-safe counts as ready; quantum-vulnerable and broken today (weak even without a quantum computer) do not. Only when the page has no rows does it fall back to the NIST quantum security levels stored with the scan.",
    why: "One view of how much of your crypto survives a quantum computer.",
    example: "12 judged: 9 safe, 2 RSA (vulnerable), 1 DES (broken today): 9 / 12 = 75%.",
  },
  // src: frontend/components/cbom/CbomCryptoCharts.tsx:590-603 — NIST level 0 public-key assets
  "cbom.chart.qv": {
    what: "Public-key algorithms a cryptographically relevant quantum computer breaks (NIST level 0: no quantum resistance), each with where it is used. Near-identical assets (same algorithm, finding and fix) share one card with a count; open it for the asset list.",
    why: "Data protected by them can be harvested now and decrypted later.",
    example: "RSA-2048 key exchange on api.bank.in:443: a future quantum computer could recover the key; harvest-now-decrypt-later applies.",
  },
  // src: frontend/components/cbom/pqcMigrationGroup.ts:202-220 — each distinct fix text once, with the assets it covers (#271)
  "cbom.chart.qv_fixes": {
    what: "Each distinct fix once, numbered by how many assets it covers; every card above shows the number of its fix. The text comes from the offline knowledge base.",
    why: "One configuration change often fixes dozens of endpoints: reading it once makes the plan clear.",
    example: "Fix 1 · 28 assets · X25519 on TLS endpoint: offer a hybrid key-exchange group first.",
  },
  // src: frontend/components/cbom/CbomCryptoCharts.tsx:632-643 — no NIST level 0 assets
  "cbom.chart.qv_none": {
    what: "No algorithm in this inventory is broken by a quantum computer at its parameter size.",
    why: "Keep scanning: new code can add RSA or ECDH again.",
    example: "Only AES-256-GCM, SHA-384 and ML-KEM-768 found.",
  },
  // src: frontend/components/cbom/CbomCryptoCharts.tsx:700-712 — NIST replacement per algorithm against CNSA 2.0
  "cbom.chart.roadmap": {
    what: "The NIST-standardised replacement for each quantum-vulnerable algorithm, against the CNSA 2.0 timeline.",
    why: "Turns the inventory into a migration plan with dates regulators recognise.",
    example: "RSA-2048 signatures → ML-DSA-65; ECDH P-256 → ML-KEM-768.",
  },
  // src: frontend/components/cbom/CbomCryptoCharts.tsx:273-278,719, frontend/components/cbom/CbomCryptoCharts.tsx:716-725 — 2025 signing, 2030 networking, 2033 OS, 2035 all NSS
  "cbom.chart.cnsa": {
    what: "The NSA CNSA 2.0 dates by which systems should use quantum-resistant algorithms: software and firmware signing 2025, networking and traditional protocols 2030, operating systems 2033, all national security systems 2035.",
    why: "Many regulators and vendors plan against these dates.",
    example: "A VPN gateway falls under networking: 2030.",
  },
  // src: frontend/components/cbom/CbomCryptoCharts.tsx:743-750 — replacement per algorithm
  "cbom.chart.replacements": {
    what: "For each quantum-vulnerable algorithm found, the recommended post-quantum replacement and where the old one is used.",
    why: "Gives each owner a concrete target, not just a finding.",
    example: "ECDSA P-256 code signing → ML-DSA-65 (FIPS 204).",
  },
  // src: frontend/components/cbom/CbomCryptoCharts.tsx:906-913,949, aibom/src/aibom/cbom/weakness.py:38 — two bars, Valid and Expired; Near expiry is a badge in the list (aibom/src/aibom/cbom/weakness.py:38, 90 days)
  "cbom.chart.cert_expiry": {
    what: "X.509 certificates as two bars, Valid and Expired, with the certificates and related key or keystore material listed below; a certificate expiring within 90 days carries a Near expiry badge in the list.",
    why: "An expired certificate breaks a service; a long-lived one delays migration to post-quantum signatures.",
    example: "18 Valid and 2 Expired; 3 of the valid ones show Near expiry (within 90 days).",
  },
  // src: frontend/components/cbom/CbomCryptoCharts.tsx:1094-1099 — transport-security protocols in use
  "cbom.chart.protocols": {
    what: "Transport-security protocols and versions found in use: TLS, SSH, IPsec and others.",
    why: "Old versions such as TLS 1.0 or SSLv3 are exploitable today.",
    example: "TLS 1.2: 9, TLS 1.3: 4, TLS 1.0: 1.",
  },
  // src: frontend/components/cbom/CbomCryptoCharts.tsx:1142-1147 — CycloneDX asset classes
  "cbom.chart.asset_types": {
    what: "The crypto inventory by CycloneDX asset class: algorithm, certificate, protocol, related crypto material (keys, secrets).",
    why: "Mirrors the CBOM file you can download.",
    example: "algorithm 40, certificate 6, protocol 5, related material 3.",
  },
  // src: frontend/components/cbom/CertCalendar.tsx:100, frontend/components/cbom/CertCalendar.tsx:95-99 — month calendar, 30/60/90 days
  "cbom.cal.expiry": {
    what: "A month calendar of certificate expiry dates (UTC), coloured for 30, 60 and 90 days ahead. Choose a day to list its certificates; arrow keys move by day and week, Page Up and Page Down change the month.",
    why: "Renewals planned ahead avoid outages.",
    example: "Three certificates expire on 2 Dec: api.bank.in, mail.bank.in, vpn.bank.in.",
  },
  // ────────────────────────────────────────────────────────────── CBOM code results: crypto-agility column
  // src: backend/utilities/cbom_sources/agility.py:76-113 — configurable, code-fixed, vendor-fixed, hardware-fixed, unknown (CLASS_TEXT)
  "cbom.res.col.fix_class": {
    what: "Who can fix this finding and how: Configurable (a setting, policy, key or certificate), Code-fixed (your code or build changes), Vendor-fixed (only the vendor can change it), Hardware-fixed (firmware or a new device), or Unknown (a deciding fact was not read). Likely means the class is inferred.",
    why: "It tells you whether a fix is a config change this week or a vendor roadmap item.",
    example: "Code-fixed: KeyPairGenerator.initialize(1024) in src/crypto/keys.py.",
  },
  // ────────────────────────────────────────────────────────────── CBOM results: AI remediation assistant, crypto-agility and quantum-risk headings
  // src: frontend/components/cbom/results/AiRemediationPanel.tsx:1-5,72, frontend/components/cbom/results/aiPanelLogic.ts:22-35 — shown only when available; every answer validated against the knowledge base
  "cbom.ai.panel": {
    what: "Explain describes this finding in plain words; Plan gives ordered remediation steps; Ask a question answers about this finding only. Answers come from the configured model (AWS Bedrock, or an on-prem model) grounded in ZeroShield's knowledge base: every step cites it, and an answer that fails validation is withheld. The line beside it names the only outbound host.",
    why: "It turns a finding into concrete steps for your stack, without sending data anywhere but the named endpoint.",
    example: "Plan for RSA-2048 on api.bank.in:443: enable hybrid X25519MLKEM768, rotate to an ML-DSA certificate, cited KB steps.",
  },
  // src: frontend/components/cbom/results/aiPanelLogic.ts:7, frontend/components/cbom/results/AiRemediationPanel.tsx:86-95 — up to 500 characters, about this finding
  "cbom.ai.question": {
    what: "A question about this finding, up to 500 characters. The answer uses only this finding and the knowledge base.",
    why: "Lets you ask how a fix applies to your own setup.",
    example: "Which of these steps applies to an nginx reverse proxy?",
  },
  // ────────────────────────────────────────────────────────────── CBOM: quantum risk register, Q0 gaps and agility baseline (CB-23, CB-25; components/cbom/grade)
  // src: backend/utilities/cbom_sources/risk_register.py:1-11, frontend/app/[team_id]/cbom/page.tsx:844 — one row per estate asset, current grade
  "cbom.reg.section": {
    what: "Every asset of the team once, however many sources see it, with its current quantum risk grade: the team's Mosca inputs now, each source's data lifetime and exposure now, the current grade model. Worst grade first; filter and download the rows as CSV.",
    why: "The CISO view: one list to plan migration from and report on, not one list per run.",
    example: "2,140 assets: 37 Q1 Critical, 210 Q2 High, 18 Q0 Unknown.",
  },
  // src: backend/utilities/cbom_sources/risk_register.py:3-6 — the worst known grade over the asset's observations
  "cbom.reg.col.grade": {
    what: "The asset's quantum risk grade, Q1 Critical to Q4 Low, or Q0 Unknown when no observation could be graded. Seen by several sources, the worst known grade wins. Also a filter.",
    why: "Q1 and Q2 assets are where data is exposed first.",
    example: "Q1 Critical: an internet-facing RSA key exchange with X + Y > Z.",
  },
  // src: backend/utilities/cbom_sources/risk_register.py:146-148, backend/utilities/cbom_sources/heatmap.py:88-102 — HEAT.algorithm_family of the asset's algorithm
  "cbom.reg.col.family": {
    what: "The algorithm family of the asset, such as RSA, Elliptic curve, AES or Post-quantum, as the heatmap groups it. Also a filter.",
    why: "Migration work is planned per family: every RSA key needs the same replacement.",
    example: "RSA, for an RSA-2048 TLS key.",
  },
  // src: backend/utilities/cbom_sources/risk_register.py:146, backend/utilities/cbom_sources/qgrade.py:357-361, backend/utilities/cbom_sources/posture.py:47 — internet, internal or unknown, with the source's override
  "cbom.reg.col.exposure": {
    what: "Whether the asset is reachable from the internet, internal only, or unknown, from its address, the collector's facts and the source's exposure setting. Also a filter.",
    why: "Internet-facing assets are the ones whose traffic can be recorded today and decrypted later.",
    example: "Internet: 203.0.113.10:443.",
  },
  // src: backend/utilities/cbom_sources/risk_register.py:263-265 — source name, application, number of sources
  "cbom.reg.col.source": {
    what: "The source that saw the asset most recently, how many more see it, and its application when the source has one.",
    why: "Tells the owner where the asset lives and who reads it.",
    example: "Network TLS DC1 (+2 more), Netbanking.",
  },
  // src: backend/utilities/cbom_sources/risk_register.py:267 — observed_at of the latest observation
  "cbom.reg.col.last_observed": {
    what: "When a collection last read the asset. An asset missing from its source's latest collection is marked \"not read in the latest collection\".",
    why: "An old date means the grade rests on old data.",
    example: "14 Nov 2026, 09:12.",
  },
  // src: backend/utilities/cbom_sources/risk_register.py:51-53 — CSV_COLUMNS, filtered rows
  "cbom.reg.csv": {
    what: "The register rows that match the filters as a CSV file: key, grade and reason, asset, family, exposure, source, application, presence, sources and last observed.",
    why: "For the board pack, the regulator or a spreadsheet of owners.",
    example: "register.csv with the 37 Q1 Critical rows.",
  },
  // ────────────────────────────────────────────────────────────── CBOM: Q0 gaps of the quantum risk register (CB-23 PR-A)
  // src: backend/utilities/cbom_sources/q0register.py:1-16, frontend/components/cbom/grade/Q0Gaps.tsx:3-6 — evidence, scope, asset and inputs items
  "cbom.q0.section": {
    what: "Everything the quantum risk register cannot grade yet (Q0 Unknown), grouped by reason: evidence areas and vendors at E0, scope a collection could not read, assets the product could not grade, and missing Mosca inputs. Each opening is tracked until it closes.",
    why: "A Q0 item is a blind spot, never assumed safe; closing them is how the register becomes complete.",
    example: "Evidence at E0 (6): payment HSM vendor has not answered.",
  },
  // src: backend/utilities/cbom_sources/q0register.py:3-5, frontend/components/cbom/grade/Q0Gaps.tsx:110-118 — open while closed_at is empty
  "cbom.q0.status": {
    what: "Open: gaps that are still Q0 now. Closed: gaps that left Q0, each with its cause and the grade it closed to. A gap that comes back opens a new row.",
    why: "Closed gaps are the audit trail of what was resolved and how.",
    example: "Open (18) · Closed (42).",
  },
  // src: backend/utilities/cbom_sources/q0register.py:454 — from opened_at to closed_at, or to now
  "cbom.q0.col.age": {
    what: "How long the gap has been open, or was open before it closed, in days.",
    why: "Old gaps are the ones to chase first.",
    example: "47 days.",
  },
  // src: backend/utilities/cbom_sources/q0register.py:3-5 — opened_at of this opening
  "cbom.q0.col.opened": {
    what: "When this gap opened: the evidence turned E0, a collection could not read the scope, or the asset graded Q0.",
    why: "Ties the gap to the run or the change that caused it.",
    example: "28 Sep 2026, 10:04.",
  },
  // src: backend/utilities/cbom_sources/q0register.py:117-118 — closed_at, close_cause, closed_grade
  "cbom.q0.col.closed": {
    what: "When the gap closed; a dash while it is open.",
    why: "Shows when the blind spot was resolved.",
    example: "12 Nov 2026, 18:30.",
  },
  // src: backend/utilities/cbom_sources/q0register.py:18-25, frontend/components/cbom/grade/q0gaps.ts:83-89 — closing causes
  "cbom.q0.col.cause": {
    what: "Why the gap closed: evidence answered or renewed, the vendor or source removed, read again in a later collection, Mosca inputs set, or the grade model changed. Shown with the grade it closed to.",
    why: "Closures other than a grade-model change are sent to your integrations as drift events.",
    example: "Read again in a later collection, now Q3 Medium.",
  },
} as const satisfies TipAreaText;

export default TEXT;
