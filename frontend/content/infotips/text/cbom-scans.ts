/**
 * (i) tip text of the "cbom-scans" area (ids: cbom.cfg.*, cbom.table.*, cbom.kpi.*, cbom.list.*, cbom.estate.*, cbom.deliverables.*), loaded on demand by
 * content/infotips/load.ts. The label of each tip is in content/infotips/labels.ts; the rules for the text are in
 * content/infotips/index.ts (checked by content/infotips.test.ts).
 */
import type { TipAreaText } from "../types";

const TEXT = {
  // ────────────────────────────────────────────────────────────── CBOM: scan configuration (components/cbom-options-sidebar.tsx, cbom-ci-scan-settings-form.tsx)
  // src: RabbitMQ/worker/helpers/tools/cbom_agent/main.py:186-196 — deterministic engine, no language model
  "cbom.cfg.repository": {
    what: "Inventories the cryptography in your code: algorithms, key sizes, certificates, keys, protocols and crypto libraries, graded for strength and quantum safety, into a CycloneDX CBOM. The engine is rule-based; no AI model reads your code.",
    why: "You cannot plan a post-quantum migration without knowing where your cryptography is.",
    example: "Finds RSA-1024 in a Java KeyPairGenerator call and flags it weak and quantum-vulnerable.",
  },
  // src: RabbitMQ/worker/helpers/tools/cbom_agent/main.py:186-196, backend/utilities/scan/credit_estimate.py:14-24 — an uploaded CBOM is analysed for a flat 0.01
  "cbom.cfg.file": {
    what: "A CycloneDX CBOM you already have, as a JSON file, graded by the same rules. Analysing a file costs a flat 0.01 credits. Choosing a file clears the repository or zip.",
    why: "Grades a CBOM you already have without cloning code.",
    example: "cbom.json produced by another scanner.",
  },
  // src: RabbitMQ/worker/helpers/tools/cbom_agent/main.py:155-162, aibom/src/aibom/cbom/posture/safeio.py:22 — vendored and build directories are skipped unless asked
  "cbom.cfg.vendored": {
    what: "Also reads vendor/, dist/, build/ and node_modules/: third-party code and build output, skipped by default. Turn it on to see crypto your dependencies ship; it makes the scan larger and dearer.",
    why: "Third-party and build code ships with your product, so its crypto is your exposure too.",
    example: "A Go service with a vendor/ folder of crypto libraries.",
  },
  // src: RabbitMQ/worker/helpers/context/scan_context.py:22-28, RabbitMQ/worker/helpers/context/scan_context.py:44-47 — up to 1,000 commits, blobs over 2 MB not downloaded
  "cbom.cfg.history": {
    what: "Clones up to 1,000 commits of the branch (files over 2 MB are skipped) and reports key and certificate files that were committed and later deleted: they stay readable in the history.",
    why: "A key removed from the code is still exposed if it remains in git history.",
    example: "A server.key added in 2023 and removed a week later is still reported.",
  },
  // src: backend/utilities/scan/credit_estimate.py:25-27, RabbitMQ/worker/helpers/tools/cbom_agent/main.py:186-196 — 1 credit per 5 MB of binaries/images/firmware
  "cbom.cfg.binaries": {
    what: "Also reads compiled binaries, docker save / OCI image archives and firmware: linked crypto libraries, crypto constants, embedded keys and the packages inside images. Adds 1 credit per 5 MB of such content.",
    why: "Compiled code and images ship crypto libraries that source scans do not see.",
    example: "A 50 MB image archive in the zip adds 10 credits.",
  },
  // src: RabbitMQ/worker/helpers/tools/cbom_agent/main.py:186-196, backend/utilities/scan/credit_estimate.py:14-24, backend/utilities/scan/estimate_scan.py:210 — 1 credit per 0.5 MB source + binaries/5 MB, minimum 1; file 0.01
  "cbom.cfg.estimate": {
    what: "A repository or zip costs 2 credits per MB of source files (plus 1 per 5 MB of binaries when that option is on), at least 1 credit; an uploaded CBOM file 0.01. Nothing is charged until you start the scan.",
    why: "Shows the price before any credits are charged.",
    example: "300 KB of source: 1 credit (the minimum).",
  },

  // ────────────────────────────────────────────────────────────── CBOM: list page (app/[team_id]/cbom/page.tsx)
  // src: backend/utilities/dashboard/scan_list.py:1701-1755, backend/utilities/cbom_sources/cbom_metrics.py:164-171 — inventory rows of code scans + latest Sources collections, each asset once
  "cbom.kpi.assets": {
    what: "Cryptographic assets found: algorithms, keys, certificates, protocols and libraries, from successful code scans and the latest CBOM Sources collections. An asset seen by both is counted once, from its latest observation.",
    why: "This is your cryptographic bill of materials; everything else is a view of it.",
    example: "A TLS certificate found in the repository and on the live server counts 1.",
  },
  // src: backend/utilities/cbom_sources/cbom_metrics.py:122-128, aibom/src/aibom/cbom/weakness.py:93-108 — rows graded weak (broken digests, asymmetric keys under 2048 bits, ...)
  "cbom.kpi.weak": {
    what: "Assets graded weak: cryptography that is broken or too short today, for example MD5 or SHA-1 in signatures, or RSA, DSA and DH keys under 2048 bits.",
    why: "Weak cryptography can be attacked now, without a quantum computer.",
    example: "A password hash using MD5.",
  },
  // src: backend/utilities/cbom_sources/cbom_metrics.py:129-135, backend/utilities/cbom_sources/cbom_metrics.py:28-40 — verdict quantum-vulnerable
  "cbom.kpi.quantum_vulnerable": {
    what: "Assets a large quantum computer would break: public-key cryptography such as RSA, ECDSA, ECDH and DH, which need moving to post-quantum algorithms.",
    why: "Data protected by these can be recorded now and decrypted later (harvest now, decrypt later).",
    example: "An ECDHE key exchange without a post-quantum hybrid.",
  },
  // src: backend/utilities/cbom_sources/cbom_metrics.py:136-137 — algorithm_type certificate
  "cbom.kpi.certificates": {
    what: "X.509 certificates found in code, files or on live endpoints.",
    why: "Certificates expire and carry keys and signature algorithms that need migrating.",
    example: "The certificate served on api.example.com:443.",
  },
  // src: backend/utilities/cbom_sources/cbom_metrics.py:138-139 — algorithm_type key or secret
  "cbom.kpi.keys": {
    what: "Keys and secrets found: private keys, symmetric keys and other key material.",
    why: "Exposed keys must be rotated; long-lived keys need a migration plan.",
    example: "A PEM private key committed in config/.",
  },
  // src: backend/utilities/cbom_sources/cbom_metrics.py:28-46, backend/utilities/cbom_sources/cbom_metrics.py:174-178 — judged assets not vulnerable / judged; none judged shows no value
  "cbom.kpi.readiness": {
    what: "Share of assets with a quantum verdict that are safe: post-quantum, hybrid, or symmetric with enough margin (AES-128 counts as ready). Assets broken today count as not ready. Assets without a verdict (hashes, settings) are left out.",
    why: "Tracks your post-quantum migration in one number.",
    example: "10 judged assets, 3 quantum-vulnerable: 70%.",
  },
  // src: backend/utilities/cbom_sources/cbom_metrics.py:20-21, backend/utilities/cbom_sources/cbom_metrics.py:82-89 — 0-10 over findings: critical 9, high 7, medium 5, low 2
  "cbom.kpi.avg_risk": {
    what: "Average risk of the crypto findings, 0 to 10: Critical counts 9, High 7, Medium 5, Low 2. Clean inventory rows are not findings and are left out.",
    why: "One number to compare crypto risk over time.",
    example: "One High and one Low finding: (7 + 2) / 2 = 4.5.",
  },
  // src: backend/routers/cbom_deliverables.py:1-20 — PDFs built in memory from every completed CBOM scan; no language model; no credits charged by the route
  "cbom.deliverables": {
    what: "Team-wide regulatory PDFs (for example a certificate register or a post-quantum roadmap) built from every completed CBOM scan of the team. They are generated in-house, with no AI model, and download straight away.",
    why: "Auditors and regulators ask for these documents; they are built from the same data as the screens.",
    example: "Download the PQC roadmap for the board pack.",
  },
  // src: backend/utilities/db/scan_list_item.py:445-453, backend/utilities/cbom_sources/run_list.py:1-12 — code scan: findings by severity plus inventory; Sources run: counts as collected, QV = quantum-vulnerable assets
  "cbom.table.risks": {
    what: "This row's crypto findings by severity: Critical (red), High (orange), Medium (amber), Low (blue). A Sources run's counts are as collected: the impact each asset was judged with when it was read, before your remediation statuses. QV is the number of quantum-vulnerable assets.",
    why: "Shows at a glance how serious each scan's or run's crypto findings are.",
    example: "0 red, 2 orange, 5 amber, 1 blue, QV:3.",
  },
  // src: backend/utilities/cbom_sources/cbom_metrics.py:26, backend/utilities/cbom_sources/run_list.py:228 — 0-10: critical 9, high 7, medium 5, low 2; a Sources run uses the same average over its counts as collected
  "cbom.table.risk": {
    what: "This row's average finding risk, 0 to 10: Critical 9, High 7, Medium 5, Low 2; inventory rows are left out. A Sources run's score is the same average over its counts as collected.",
    why: "Lets you compare scans and runs by overall severity.",
    example: "Two Medium findings: 5.0.",
  },
  // ────────────────────────────────────────────────────────────── CBOM: list empty state and test-lab node warning
  // src: frontend/app/[team_id]/cbom/page.tsx:1014-1022 — the merged table of code scans and Sources runs is empty
  "cbom.list.empty": {
    what: "This table lists both CBOM code scans and CBOM Sources runs; this team has neither yet. A code scan reads a repository, zip or CBOM file; a Sources run reads servers, clusters, databases, cloud accounts and networks.",
    why: "Each feeds the same inventory, so start with whichever holds your most sensitive crypto.",
    example: "Create a CBOM scan of payments-api, then start a Sources run of the Mumbai servers.",
  },
  // ────────────────────────────────────────────────────────────── CBOM list: code scans and Sources runs in one table (CB-38 #117)
  // src: frontend/app/[team_id]/cbom/page.tsx:1112-1136, backend/utilities/cbom_sources/run_list.py:1-6 — code scans and Sources runs in one table
  "cbom.table.title": {
    what: "The scan's title, or for a CBOM Sources run \"Sources run #<id>\" with the names of its sources and a Sources run badge. Click it to open the results.",
    why: "Code scans and infrastructure runs land in one list, so the badge tells them apart.",
    example: "Sources run #42 · dc-mumbai-linux, aws-prod.",
  },
  // src: frontend/app/[team_id]/cbom/page.tsx:142-152, contracts/cbom/status_buckets.json:1 — code-scan statuses; a run's queued, running, done, partial, failed, cancelled
  "cbom.table.status": {
    what: "A code scan: Not started, Pending, Started (with progress), Retry, Success, Failure or Cancelled. A Sources run: Pending (queued), Started (running, with jobs done of total), Success (done), Partial (some jobs failed or expired; the results that were collected open like a success), Failure or Cancelled.",
    why: "A Partial run's results miss the sources whose jobs did not finish.",
    example: "Partial · 3/4 jobs: one database job expired.",
  },
  // src: frontend/app/[team_id]/cbom/page.tsx:1159-1190,1044, frontend/components/cbom/results/resultRows.ts:360-365 — repository, zip, or the run's sources and counts
  "cbom.table.source": {
    what: "For a code scan, the repository (or Zip file). For a Sources run, the sources it collected from, with how many assets it found and endpoints it probed.",
    why: "Tells you what each row covers before you open it.",
    example: "dc-mumbai-linux, aws-prod · 1,284 assets · 12 endpoints.",
  },
  // src: backend/utilities/cbom_sources/run_list.py:232-233, frontend/components/cbom/results/resultRows.ts:367-370 — charged; refunded shown below
  "cbom.table.credits": {
    what: "Credits charged for the scan or run. For a run, credits refunded for jobs that failed, expired or were cancelled are shown below in brackets.",
    why: "You pay only for the jobs that completed.",
    example: "12.4 (1 refunded).",
  },
  // src: backend/utilities/cbom_sources/estate_export.py:1-30, backend/routers/cbom_estate_export.py:1-9 — one
  // component per estate key; signed (JSF in the JSON, detached X-ZS-Signature) with X-Cbom-Sha256; filters application / source / type
  "cbom.estate.export": {
    what: "Your whole estate as one CycloneDX 1.6 file (JSON or XML): every asset once, however many sources see it, with its current quantum risk grade and VEX. It covers what the latest collections read, plus assets they could not read again (marked not read); removed assets are left out. The download API also filters by application, source or asset type.",
    why: "One file to hand to an auditor or import into another tool. It is signed with your deployment's published key (ES256, inside the JSON and in the X-ZS-Signature header), and its SHA-256 is shown after the download, so anyone can check it outside ZeroShield.",
    example: "cbom-estate-team3-2026-11-15.cdx.json · 2,140 assets · SHA-256 4f1c….",
  },
} as const satisfies TipAreaText;

export default TEXT;
