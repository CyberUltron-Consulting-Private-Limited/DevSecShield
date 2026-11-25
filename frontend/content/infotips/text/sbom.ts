/**
 * (i) tip text of the "sbom" area (ids: sbom.*), loaded on demand by
 * content/infotips/load.ts. The label of each tip is in content/infotips/labels.ts; the rules for the text are in
 * content/infotips/index.ts (checked by content/infotips.test.ts).
 */
import type { TipAreaText } from "../types";

const TEXT = {
  // ────────────────────────────────────────────────────────────── SCA + SBOM: scan configuration (components/sca-sbom-options-sidebar.tsx)
  // src: RabbitMQ/worker/helpers/tools/sca_sbom_agent/main.py:71-125, RabbitMQ/worker/helpers/tools/sca_sbom_agent/main.py:283-288 — repository or zip: Syft + cdxgen inventory, Grype vulnerabilities
  "sbom.cfg.repository": {
    what: "Builds the software bill of materials from your code (Syft and cdxgen, merged into CycloneDX) and matches every package against known vulnerabilities with Grype.",
    why: "Builds the list of every dependency you ship, the basis for finding known vulnerabilities.",
    example: "A Node repository: packages come from package-lock.json, CVEs from Grype.",
  },
  // src: RabbitMQ/worker/helpers/tools/sca_sbom_agent/main.py:185-226, RabbitMQ/worker/helpers/tools/sca_sbom_agent/main.py:289-290 — an uploaded JSON SBOM is analysed by the AI summariser instead of building an inventory
  "sbom.cfg.sbom_file": {
    what: "An SBOM you already have, as a JSON file. No code is cloned: the file's contents are analysed by the scan's AI model to list vulnerable dependencies. Choosing a file clears the repository or zip.",
    why: "Reuses an SBOM you already produce, so no code has to be cloned.",
    example: "bom.json exported by your build in CycloneDX JSON.",
  },
  // src: RabbitMQ/worker/helpers/tools/sca_sbom_agent/main.py:313-323, backend/utilities/scan/estimate_scan.py:210 — constant 0.01/0.836 credits, rounded to 0.01
  "sbom.cfg.estimate": {
    what: "An SCA + SBOM scan has a flat price of about 0.01 credits, whatever the size of the repository or file. Nothing is charged until you start the scan.",
    why: "Shows the price before any credits are charged.",
    example: "Any repository: 0.01 credits.",
  },

  // ────────────────────────────────────────────────────────────── SCA + SBOM: list page (app/[team_id]/sbom_sca/page.tsx)
  // src: backend/utilities/dashboard/scan_list.py:956-961, backend/utilities/dashboard/scan_list.py:1079, backend/utilities/dashboard/sbom_rows.py:20-22, RabbitMQ/worker/helpers/tools/sca_sbom_agent/merge_inventory.py:109-122 — the vulnerability rows of successful scans; the inventory_only rows (packages with no known vulnerability) are left out (#46)
  "sbom.kpi.total": {
    what: "The known vulnerabilities in the dependencies of this team's successful SCA + SBOM scans, added up. Packages found with no known vulnerability are part of the SBOM but are not counted here.",
    why: "Dependencies are a common way in for attackers; this sizes the problem.",
    example: "1 vulnerable package and 3 packages with no known vulnerability: 1.",
  },
  // src: backend/utilities/dashboard/scan_list.py:989-998, backend/utilities/dashboard/scan_list.py:1080 — impact critical
  "sbom.kpi.critical": {
    what: "Of those, the findings rated Critical.",
    why: "Critical vulnerabilities in dependencies are often exploited soon after disclosure.",
    example: "A remote-code-execution CVE in a direct dependency.",
  },
  // src: backend/utilities/dashboard/scan_list.py:1005-1018, backend/utilities/dashboard/scan_list.py:1081 — number of compliance control references of all findings
  "sbom.kpi.policy": {
    what: "How many compliance-control references (PCI DSS, ISO 27001 and others) the findings map to, added up over all findings.",
    why: "Shows how many audit requirements the dependency findings touch.",
    example: "One finding mapped to 2 controls and one to 3: 5.",
  },
  // src: backend/utilities/dashboard/scan_list.py:970,1082-1084, backend/utilities/dashboard/sbom_rows.py:52-87 — medium + high risk license categories over the SBOM components of successful scans (review 6028132826 M4)
  "sbom.kpi.license_risks": {
    what: "Packages in your SBOMs whose license is medium-risk (weak copyleft such as LGPL or MPL, Creative Commons, commercial) or high-risk (strong copyleft such as GPL, network copyleft such as AGPL, source-available such as SSPL or BUSL), whether or not they have a known vulnerability.",
    why: "Some licenses impose obligations on how you distribute your software.",
    example: "An LGPL-3.0 package and a GPL-3.0 package: 2.",
  },
  // src: backend/utilities/dashboard/scan_list.py:970,1082, backend/utilities/dashboard/sbom_rows.py:52-87, backend/utilities/dashboard/sbom_license.py:201 — strong copyleft, network copyleft, source-available, over the SBOM components (M4)
  "sbom.kpi.high_risk_licenses": {
    what: "Packages in your SBOMs under a strong copyleft (GPL), network copyleft (AGPL) or source-available (SSPL, BUSL) license, whether or not they have a known vulnerability.",
    why: "Strong copyleft or source-available licenses can force you to publish code or change your product.",
    example: "A package licensed GPL-2.0-only.",
  },
  // src: backend/utilities/dashboard/scan_list.py:1100-1102, backend/utilities/dashboard/risk_scale.py:76-95, frontend/utils/riskPosture.ts:22-28, frontend/app/[team_id]/sbom_sca/page.tsx:284-287 — risk_scale.posture over the known vulnerabilities of successful scans; inventory rows left out (#46)
  "sbom.kpi.avg_risk": {
    what: "The one risk score over the known vulnerabilities of successful scans, as on each scan's row, results page and PDF: 0-100: 4 × (10 per Critical, 5 per High, 2 per Medium, 1 per Low), capped by the worst severity (no Critical: 69 at most, no High either: 49, Low only: 29). Grades: A <15, B 15–29, C 30–49, D 50–69, F 70+. Packages without a known vulnerability are not counted.",
    why: "One number and grade to compare dependency risk over time, as every product shows it.",
    example: "15 High and no Critical vulnerabilities: 4 × 75 = 300, capped at 69, grade D (High risk).",
  },
  // src: backend/utilities/dashboard/scan_list.py:999-1002, backend/utilities/dashboard/sbom_license.py:382-392, RabbitMQ/worker/helpers/context/schema.py:34, RabbitMQ/worker/helpers/tools/sca_sbom_agent/main.py:137-158, RabbitMQ/worker/helpers/tools/sca_sbom_agent/parser.py:128-155 — reachability is a label the AI model sets from the Grype match text (id, severity, description, package, fix, locations); no source file is in its context
  "sbom.kpi.reachable": {
    what: "Vulnerabilities the AI model labelled Reachable. It judges from the vulnerability and package data (description, severity, where the package was found); it does not read your code, so treat the label as a hint.",
    why: "A vulnerability your code actually reaches is far more urgent than one it never calls.",
    example: "A CVE in a web framework's request parser may be labelled Reachable although your code never uses that parser.",
  },
  // src: backend/utilities/dashboard/scan_list.py:961, backend/utilities/dashboard/scan_list.py:1030-1037, backend/utilities/dashboard/finding_metrics.py:18-40 — stored findings by status; the stored findings of inventory rows are left out (#46)
  "sbom.chart.remediation": {
    what: "The stored vulnerability findings of SCA + SBOM scans by the status your team set: Fixed, In progress, Not started, Ignored. Packages with no known vulnerability are not counted.",
    why: "Shows how far the team has got with fixing dependency findings.",
    example: "40 findings: 10 Fixed, 5 In progress, 22 Not started, 3 Ignored.",
  },
  // src: backend/utilities/dashboard/scan_list.py:983-998, backend/utilities/dashboard/scan_list.py:1038-1043 — totals per impact over the vulnerability rows; inventory rows left out (#46)
  "sbom.chart.severity": {
    what: "Known vulnerabilities of successful scans by severity: Critical, High, Medium and Low. Packages with no known vulnerability are not counted.",
    why: "Critical and High vulnerabilities are the ones to look at first.",
    example: "Critical 2, High 9, Medium 15, Low 4 in a repository with about 300 packages.",
  },
  // src: backend/utilities/dashboard/scan_list.py:983, backend/utilities/dashboard/scan_list.py:999-1000, backend/utilities/dashboard/scan_list.py:1044-1056, backend/utilities/dashboard/sbom_license.py:382-392, RabbitMQ/worker/helpers/context/schema.py:34 — the AI model's label (no code in its context); missing counts as Not assessed; inventory rows left out (#46)
  "sbom.chart.reachability": {
    what: "Known vulnerabilities by the reachability label the AI model gave each one from the vulnerability and package data (it does not read your code): Reachable, Potentially reachable, Not reachable, or Not assessed. Packages with no known vulnerability are not counted.",
    why: "Helps you prioritise reachable vulnerabilities over unreachable ones.",
    example: "A CVE in a package found only in a test lock file is often labelled Not reachable.",
  },
  // src: backend/utilities/dashboard/scan_list.py:983-986, backend/utilities/dashboard/scan_list.py:1024-1028 — per creation date (UTC) of each successful scan; inventory rows left out (#46)
  "sbom.chart.trends": {
    what: "Known vulnerabilities of successful scans by severity, on the day (UTC) each scan was created. Packages with no known vulnerability are not counted.",
    why: "Shows whether dependency risk is growing or shrinking.",
    example: "Scans created on 5 Nov found 3 High in total: High shows 3 on 5 Nov.",
  },
  // src: backend/utilities/dashboard/scan_list.py:970, backend/utilities/dashboard/sbom_rows.py:52-87 — license family of each SBOM component (M4)
  "sbom.chart.licenses": {
    what: "The packages in your SBOMs grouped by license family: permissive, public domain, weak copyleft, Creative Commons, commercial, strong copyleft, network copyleft, source-available, or not declared.",
    why: "Shows which license obligations come with your dependencies.",
    example: "MIT and Apache-2.0 are permissive; GPL-3.0 is strong copyleft.",
  },
  // src: backend/utilities/dashboard/scan_list.py:960, backend/utilities/dashboard/scan_list.py:1060-1072, frontend/app/[team_id]/sbom_sca/page.tsx:448 — sorted by impact, first 20 shown; inventory rows left out (#46)
  "sbom.chart.top": {
    what: "The 20 most severe known vulnerabilities (Critical first), each with its reachability, direct or transitive dependency type, and license family.",
    why: "These are the dependency issues to fix first.",
    example: "lodash 4.17.15, reachable, direct, permissive, Critical.",
  },
  // src: backend/utilities/dashboard/scan_list.py:1022-1023, backend/utilities/dashboard/scan_list.py:1087-1097 — per level: average of weight/4*10
  "sbom.chart.risk_by_reach": {
    what: "The average risk score (0 to 10: Critical 10, High 7.5, Medium 5, Low 2.5) of the known vulnerabilities at each reachability level.",
    why: "Shows whether your riskiest vulnerabilities are also reachable.",
    example: "Reachable 8.8 means the reachable vulnerabilities are mostly Critical or High.",
  },
  // src: backend/utilities/dashboard/scan_list.py:1005-1018, backend/utilities/dashboard/scan_list.py:1099-1105 — references per standard: PCI DSS, ISO 27001-27004
  "sbom.chart.policy": {
    what: "How many compliance-control references the findings have per standard (PCI DSS, ISO 27001, 27002, 27003, 27004), and each standard's share of them.",
    why: "Shows which standards your dependency findings affect most.",
    example: "PCI DSS 12 of 20 references: 60%.",
  },
  // src: backend/utilities/db/scan_list_item.py:157-174 — counts per impact of a successful scan's vulnerability rows; inventory rows left out (#46)
  "sbom.table.vulns": {
    what: "This scan's known vulnerabilities by severity once it succeeded: Critical (red), High (orange), Medium (amber), Low (blue). Packages with no known vulnerability are not counted.",
    why: "Shows at a glance how serious this scan's results are.",
    example: "0 red, 3 orange, 6 amber, 2 blue for a repository with about 280 packages.",
  },
  // src: backend/utilities/db/scan_list_item.py:199,563-567, backend/utilities/dashboard/risk_scale.py:76-95, frontend/utils/riskPosture.ts:22-28, frontend/app/[team_id]/sbom_sca/page.tsx:115-118,991 — the row's risk_posture; — before success
  "sbom.table.risk": {
    what: "This scan's one risk score and grade, as on its results page and PDF: 0-100: 4 × (10 per Critical, 5 per High, 2 per Medium, 1 per Low), capped by the worst severity (no Critical: 69 at most, no High either: 49, Low only: 29). Grades: A <15, B 15–29, C 30–49, D 50–69, F 70+. \"incomplete\" when no package was inventoried or every match is on a guessed version; — when the scan did not succeed.",
    why: "Lets you compare scans by overall risk on the scale every product uses.",
    example: "1 Critical and 1 Low vulnerability: 4 × 11 = 44, grade C, shown 44 · C.",
  },
  // src: backend/utilities/db/scan_list_item.py:195-197 — repo_url, or zip upload, or SBOM file
  "sbom.table.source": {
    what: "The repository that was scanned (hover for the full URL), or Zip file for an uploaded archive. Empty for an uploaded SBOM file.",
    why: "Tells you which code or file the results belong to.",
    example: "payments-api.",
  },

  // ────────────────────────────────────────────────────────────── SCA + SBOM: results view (components/SbomResults.tsx)
  // src: backend/utilities/dashboard/scan.py:826, backend/utilities/dashboard/scan.py:857, backend/utilities/dashboard/sbom_rows.py:20-22, RabbitMQ/worker/helpers/tools/sca_sbom_agent/merge_inventory.py:109-122 — the vulnerability rows of this scan; inventory_only rows left out (#46)
  "sbom.res.kpi.total": {
    what: "This scan's known vulnerabilities in your dependencies. Packages found with no known vulnerability are in the bill of materials but are not counted here.",
    why: "Sizes this scan's dependency risk.",
    example: "1 vulnerable package and 3 packages with no known vulnerability: 1.",
  },
  // src: backend/utilities/dashboard/scan.py:840-842, backend/utilities/dashboard/scan.py:858 — impact critical
  "sbom.res.kpi.critical": {
    what: "Of those, the vulnerabilities rated Critical.",
    why: "Critical dependency vulnerabilities are often exploited soon after disclosure.",
    example: "A remote-code-execution CVE in a direct dependency.",
  },
  // src: backend/utilities/dashboard/scan.py:849-853 — number of compliance-control entries over all results
  "sbom.res.kpi.policy": {
    what: "How many compliance-control references (PCI DSS, ISO 27001 and others) this scan's vulnerabilities map to, added up.",
    why: "Shows how many audit requirements this scan's findings touch.",
    example: "One vulnerability mapped to 2 controls and one to 3: 5.",
  },
  // src: backend/utilities/dashboard/scan.py:869-872, backend/utilities/dashboard/sbom_rows.py:52-87 — medium + high risk license categories over this scan's SBOM components, the licences the downloaded SBOM lists (M4)
  "sbom.res.kpi.license_risks": {
    what: "Packages in this scan's SBOM whose license is medium-risk (weak copyleft such as LGPL or MPL, Creative Commons, commercial) or high-risk (strong copyleft such as GPL, network copyleft such as AGPL, source-available such as SSPL or BUSL), whether or not they have a known vulnerability. The licences are the ones the downloaded SBOM lists.",
    why: "Some licenses impose obligations on how you distribute your software.",
    example: "An LGPL-3.0 package and a GPL-3.0 package: 2.",
  },
  // src: backend/utilities/dashboard/scan.py:869,873, backend/utilities/dashboard/sbom_rows.py:52-87 — strong copyleft, network copyleft, source-available over the SBOM components (M4)
  "sbom.res.kpi.high_risk_licenses": {
    what: "Packages in this scan's SBOM under a strong copyleft (GPL), network copyleft (AGPL) or source-available (SSPL, BUSL) license, whether or not they have a known vulnerability.",
    why: "Strong copyleft or source-available licenses can force code publication or product changes.",
    example: "scapy under GPL-2.0-only.",
  },
  // src: backend/utilities/dashboard/scan.py:836,954, backend/utilities/dashboard/sbom_rows.py:30-34, RabbitMQ/worker/helpers/tools/sca_sbom_agent/grype_findings.py:254, frontend/components/SbomResults.tsx:335-344 — Grype matches on a version read from a manifest range (review 6028132826 M2)
  "sbom.res.kpi.unverified": {
    what: "Vulnerabilities matched on a version read from a range in a manifest (pillow>=10.0 read as 10.0) because no lock file or pin names the installed version. They are listed with the findings but not counted in the totals, the severities or the risk score.",
    why: "The installed version may well be newer and not affected: pin the version or commit a lock file, then rescan.",
    example: "pillow>=10.0 in requirements.txt with no requirements.lock: a pillow 10.0 advisory counts here, not in Critical.",
  },
  // src: backend/utilities/dashboard/scan.py:956-957, backend/utilities/dashboard/risk_scale.py:76-95, frontend/utils/riskPosture.ts:22-28, frontend/components/SbomResults.tsx:338-341 — risk_scale.posture over this scan's known vulnerabilities; inventory rows left out (#46)
  "sbom.res.kpi.avg_risk": {
    what: "This scan's one risk score over its known vulnerabilities, as on its list row and PDF: 0-100: 4 × (10 per Critical, 5 per High, 2 per Medium, 1 per Low), capped by the worst severity (no Critical: 69 at most, no High either: 49, Low only: 29). Grades: A <15, B 15–29, C 30–49, D 50–69, F 70+. Packages with no known vulnerability are not counted.",
    why: "One number and grade to compare this scan with others.",
    example: "1 Critical and 3 Low vulnerabilities: 4 × 13 = 52, grade D (High risk).",
  },
  // src: backend/utilities/dashboard/scan.py:843-846, RabbitMQ/worker/helpers/context/schema.py:34, RabbitMQ/worker/helpers/tools/sca_sbom_agent/main.py:137-158 — the AI model's label; no source file in its context
  "sbom.res.kpi.reachable": {
    what: "Vulnerabilities the AI model labelled Reachable. It judges from the vulnerability and package data (description, severity, where the package was found); it does not read your code, so treat the label as a hint.",
    why: "A vulnerability your code reaches is far more urgent than one it never calls.",
    example: "A CVE in a web framework's request parser may be labelled Reachable although your code never uses that parser.",
  },
  // src: backend/utilities/dashboard/scan.py:871-879, backend/utilities/dashboard/finding_metrics.py:18-40, frontend/components/SbomResults.tsx:246-250,338 — the scan's stored vulnerability findings by status, share of all; the stored findings of inventory rows are left out (#46)
  "sbom.res.remediation": {
    what: "This scan's stored vulnerability findings by the status your team set (Fixed, In progress, Not started, Ignored), each as a count and a share of all of them. Packages with no known vulnerability are not counted.",
    why: "Shows how far fixing has got for this scan.",
    example: "10 vulnerabilities: 2 Fixed (20%), 1 In progress, 7 Not started.",
  },
  // src: backend/utilities/dashboard/scan.py:826, backend/utilities/dashboard/scan.py:837-840, backend/utilities/dashboard/scan.py:952 — count per impact over the vulnerability rows; inventory rows left out (#46)
  "sbom.res.severity": {
    what: "How many of this scan's known vulnerabilities have each impact: Critical, High, Medium and Low. Packages with no known vulnerability are not counted.",
    why: "Critical and High vulnerabilities are the ones to look at first.",
    example: "Critical 1, High 3, Medium 6, Low 2.",
  },
  // src: backend/utilities/dashboard/scan.py:826, backend/utilities/dashboard/scan.py:841-842, backend/utilities/dashboard/scan.py:881-895, RabbitMQ/worker/helpers/context/schema.py:34 — the AI model's label; missing counts as Not assessed; inventory rows left out (#46)
  "sbom.res.reachability": {
    what: "This scan's known vulnerabilities by the reachability label the AI model gave each one from the vulnerability and package data (it does not read your code): Reachable, Potentially reachable, Not reachable, or Not assessed. Packages with no known vulnerability are not counted.",
    why: "Helps you prioritise reachable vulnerabilities.",
    example: "A CVE in a package found only in a test lock file is often labelled Not reachable.",
  },
  // src: backend/utilities/dashboard/scan.py:871, backend/utilities/dashboard/scan.py:897-912, backend/utilities/celery/create_findings.py:68-84 — vulnerability findings by impact on their created_at date (UTC); a scan's findings are all recorded when it finishes; inventory rows left out (#46)
  "sbom.res.trends": {
    what: "This scan's vulnerability findings by severity, on the date (UTC) each was recorded. A scan records all its findings when it finishes, so this usually shows a single day. Packages with no known vulnerability are not counted.",
    why: "Shows when the findings were recorded.",
    example: "12 findings recorded on 11 Nov: one point with Critical 1, High 3, Medium 6, Low 2.",
  },
  // src: backend/utilities/dashboard/scan.py:869, backend/utilities/dashboard/sbom_rows.py:52-87, RabbitMQ/worker/helpers/tools/sca_sbom_agent/registry_enrich.py:145,194 — license family per SBOM component (M4)
  "sbom.res.licenses": {
    what: "This scan's SBOM components by license family. The license is the one the downloaded SBOM lists (from the inventory tools, a built-in list of well-known packages, or the package registry, resolved once when the scan finished); otherwise Not declared.",
    why: "Shows which license obligations come with your dependencies.",
    example: "MIT and Apache-2.0 are permissive; GPL-3.0 is strong copyleft.",
  },
  // src: backend/utilities/dashboard/scan.py:853-856, backend/utilities/dashboard/scan.py:931-939 — per reachability label: mean of 10/7.5/5/2.5, 0 when none
  "sbom.res.risk_by_reach": {
    what: "For each reachability label, the average risk (0 to 10: Critical 10, High 7.5, Medium 5, Low 2.5) of this scan's vulnerabilities with that label; 0 when there are none.",
    why: "Shows whether the riskiest vulnerabilities are also reachable.",
    example: "Reachable 8.8: the vulnerabilities labelled Reachable are mostly Critical or High.",
  },
  // src: backend/utilities/dashboard/scan.py:826, backend/utilities/dashboard/scan.py:916-929, frontend/components/SbomResults.tsx:529-534,516 — sorted by impact, first 20; inventory rows left out (#46)
  "sbom.res.top": {
    what: "This scan's vulnerabilities, Critical first, the first 20, each with its reachability label, direct or transitive dependency, and license family.",
    why: "These are the dependency issues to fix first.",
    example: "lodash 4.17.15, reachable, direct, permissive, Critical.",
  },
  // src: frontend/components/SbomResults.tsx:611-627,1176 — case-insensitive match on title, description, impact, dependency and finding id of the loaded findings
  "sbom.res.search": {
    what: "Shows only the findings whose title, description, impact, dependency or finding id contains this text (upper or lower case does not matter).",
    why: "Finds the findings for one package quickly.",
    example: "\"lodash\" keeps every finding in a lodash version.",
  },
  // src: backend/utilities/db/findings.py:142, backend/utilities/dashboard/bom_risk_score.py:152-173, frontend/components/SbomResults.tsx:594-600,1212 — tiers on the 0-10 per-finding score
  "sbom.res.filter.risk": {
    what: "Shows only findings whose risk score (0 to 10) is in a tier: Critical 9 or more, High 7 to 9, Medium 5 to 7, Low under 5.",
    why: "Focuses the table on the riskiest findings.",
    example: "High keeps a finding scored 8.5 and hides one scored 9.4.",
  },
  // src: RabbitMQ/worker/helpers/context/schema.py:32-33, backend/utilities/db/findings.py:133-152 — the package (with version) as the analysis named it
  "sbom.res.table.dependency": {
    what: "The package, with its version, that the vulnerability is in. Hover for the full name when it is cut short.",
    why: "Names the package to upgrade or replace.",
    example: "lodash@4.17.15.",
  },
  // src: backend/utilities/dashboard/bom_risk_score.py:20-26, backend/utilities/dashboard/bom_risk_score.py:93-99, backend/utilities/dashboard/bom_risk_score.py:152-173 — impact base + 0.7 per CVE (max 3) + reachability + 0.5 high-risk license, 0-10, one decimal
  "sbom.res.table.risk": {
    what: "This finding's risk, 0 to 10: a base for its impact (Critical 7.5, High 5.5, Medium 3.5, Low 1.2), plus 0.7 per CVE (at most 3), plus its reachability label (Reachable 1.6, Potentially reachable 0.9, Not assessed 0.3), plus 0.5 for a high-risk license.",
    why: "Lets you compare findings by severity and context.",
    example: "High, 2 CVEs, labelled Reachable: 5.5 + 1.4 + 1.6 = 8.5.",
  },
  // src: backend/utilities/dashboard/sbom_license.py:382-392, RabbitMQ/worker/helpers/context/schema.py:34 — the AI model's label
  "sbom.res.table.reachability": {
    what: "The reachability label the AI model gave this vulnerability from the vulnerability and package data: Reachable, Potentially reachable, Not reachable or Not assessed. It does not read your code.",
    why: "Reachable vulnerabilities are the most urgent.",
    example: "Not reachable for a CVE in a test-only package.",
  },
  // src: backend/utilities/dashboard/sbom_license.py:330-375, RabbitMQ/worker/helpers/context/schema.py:35 — SPDX from the inventory, else the model's category (it may guess), else a curated package map, else not declared
  "sbom.res.table.license": {
    what: "The license family of the package. It comes from the SBOM when it records a license, else from the AI model's category (which may be its own judgement), else from a built-in list of well-known packages; otherwise Not declared.",
    why: "Tells you the obligations that come with the package.",
    example: "Permissive for a package licensed MIT.",
  },
  // src: frontend/components/SbomResults.tsx:1414, frontend/components/SbomResults.tsx:1429-1435, RabbitMQ/worker/helpers/context/schema.py:30-35 — shown when the scan has no stored findings: the analysis's own list
  "sbom.res.vuln.title": {
    what: "The vulnerabilities the analysis reported, shown when this scan has no stored findings. Click a title for the description and the suggested fix.",
    why: "Lists what the analysis found even when no findings were stored.",
    example: "Prototype pollution in lodash.",
  },
  // src: frontend/components/SbomResults.tsx:1434-1435 — one dependency, or the number of them
  "sbom.res.vuln.deps": {
    what: "The package the vulnerability is in, or the number of packages when it affects several.",
    why: "Names the package to upgrade or replace.",
    example: "\"3 dependencies\" for a CVE found in three lodash copies.",
  },
  // src: frontend/components/SbomResults.tsx:867-904,1411, backend/routers/scans.py:1192-1202 — rows without a stored finding id: one combined Jira issue from the summary
  "sbom.res.vuln.select": {
    what: "Selects rows of this list for a Jira ticket. These rows are not stored findings, so all the selected rows go into one combined Jira issue.",
    why: "Lets you file these vulnerabilities as Jira work.",
    example: "Select 4 rows, Create Jira ticket: one issue listing the 4 vulnerabilities.",
  },
} as const satisfies TipAreaText;

export default TEXT;
