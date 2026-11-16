/**
 * (i) tip text of the "sast" area (ids: sast.*), loaded on demand by
 * content/infotips/load.ts. The label of each tip is in content/infotips/labels.ts; the rules for the text are in
 * content/infotips/index.ts (checked by content/infotips.test.ts).
 */
import type { TipAreaText } from "../types";

const TEXT = {
  // ────────────────────────────────────────────────────────────── SAST: scan configuration (components/sast-options-sidebar.tsx)
  // src: RabbitMQ/worker/helpers/tools/sast_agent/main.py:51-92, RabbitMQ/worker/helpers/context/codebase_context.py:119-170 — built-in exclusions and your patterns go through the same matcher, on the file's path inside the repository (#37, #45)
  "sast.cfg.scope": {
    what: "Which files are analysed: the files of the chosen language, minus the language's built-in exclusions (such as node_modules, dist and build for JavaScript) and minus the patterns you add below. Exclusions are matched against each file's path inside the repository.",
    why: "Files outside the scope are neither analysed nor charged, so it decides both coverage and cost.",
    example: "Add \"tests\" to leave the tests folders out of a Python scan.",
  },
  // src: RabbitMQ/worker/helpers/context/codebase_context.py:119-170, RabbitMQ/worker/helpers/tools/sast_agent/main.py:91-92 — file_path_matches_pattern: the path inside the repository; every name counts, as whole names one after the other at any depth; literal apart from * and a ** name; one name starting with a dot matches the names ending with it (#37, #45)
  "sast.cfg.exclude": {
    what: "Each pattern is one or more folder or file names, one per box. A file is skipped when its path inside the repository has these whole names one after the other, at any depth. * stands for any characters within a name and a box holding ** for any number of folders; other characters are literal. One name starting with a dot matches the names ending with it. Skipped files are not analysed and not charged.",
    why: "Leaving out vendored or generated code cuts noise and credits; leaving out real code hides findings.",
    example: "\"vendor\" skips every vendor folder but not vendors; \"src\" / \"legacy\" skips src/legacy; \".min.js\" skips minified files.",
  },
  // src: RabbitMQ/worker/helpers/tools/sast_agent/main.py:51-83 — one file extension per language
  "sast.cfg.language": {
    what: "Only files with this language's extension are analysed: Python .py, JavaScript .js, Java .java, PHP .php, C .c, Ruby .rb, Rust .rs, Swift .swift, C# .cs, Kotlin .kt. Other files are ignored.",
    why: "Only files of the chosen language are read, so the wrong choice analyses nothing useful.",
    example: "For a Node service choose JavaScript; note that .ts and .jsx files are not analysed.",
  },
  // src: RabbitMQ/worker/helpers/tools/sast_agent/main.py:493-494, backend/utilities/scan/estimate_scan.py:210 — 1 credit per 0.5 MB of analysed files + 0.04/0.836, rounded to 0.01
  "sast.cfg.estimate": {
    what: "Measures the files in scope and prices the scan: 2 credits per MB of analysed source code, plus about 0.05 credits, rounded to 0.01. Nothing is charged until you start the scan.",
    why: "Shows the price before any credits are charged.",
    example: "3 MB of Python after exclusions: about 6.05 credits.",
  },

  // ────────────────────────────────────────────────────────────── SAST: list page (app/[team_id]/sast/page.tsx)
  // src: backend/utilities/dashboard/scan_list.py:672-673 — status NOT_STARTED
  "sast.kpi.not_started": {
    what: "SAST scans that were created but never started. They have used no credits.",
    why: "These scans were set up but never run, so they hold no results yet.",
    example: "You created \"payments-api\" but closed the page before estimating: it counts here.",
  },
  // src: backend/utilities/dashboard/scan_list.py:664-665, backend/routers/scans.py:599-610 — status pending: claimed by start, waiting for a worker
  "sast.kpi.pending": {
    what: "SAST scans that were started and are queued, waiting for a scan worker to pick them up.",
    why: "A growing number here means scans are waiting for a free worker.",
    example: "Three scans started together: one runs, two wait here.",
  },
  // src: backend/utilities/dashboard/scan_list.py:666-667, backend/utilities/celery/celery_connection.py:204-208 — status started: a worker is running it
  "sast.kpi.started": {
    what: "SAST scans a worker is running now. The table shows each one's progress.",
    why: "Results for these scans are not complete yet.",
    example: "A scan at 40% in the table counts here until it finishes.",
  },
  // src: backend/utilities/dashboard/scan_list.py:668-669, backend/utilities/celery/celery_connection.py:125-133, backend/utilities/dashboard/scan_list.py:690-779 — status success: results stored; findings charts use success only (Scans Per Day, Status and Remediation use every scan)
  "sast.kpi.success": {
    what: "SAST scans that finished and stored their findings. Only these feed the findings charts (severity, risk, category, language and top repositories).",
    why: "Only successful scans contribute findings to the charts on this page.",
    example: "A scan that found 0 issues still counts as a success.",
  },
  // src: backend/utilities/dashboard/scan_list.py:670-671, backend/utilities/celery/celery_connection.py:186-192 — status failure; credits refunded once
  "sast.kpi.failure": {
    what: "SAST scans that stopped with an error. Their credits were refunded automatically. Open one to read the reason and run it again.",
    why: "Failed scans have no results; rerun them after fixing the cause.",
    example: "A clone that failed because the token had expired.",
  },
  // src: backend/utilities/dashboard/scan_list.py:674-675 — created_at date equals today's UTC date
  "sast.kpi.created_today": {
    what: "SAST scans created since 00:00 UTC today, in any status.",
    why: "Shows how much scanning activity there has been today.",
    example: "A scan created at 04:00 IST on 11 Nov is 22:30 UTC on 10 Nov, so it counted for 10 Nov.",
  },
  // src: backend/utilities/dashboard/scan_list.py:676-677, backend/utilities/celery/celery_connection.py:200-215 — last_updated date equals today's UTC date; today it also moves on status polls without a change and on chat messages (#47)
  "sast.kpi.updated_today": {
    what: "SAST scans whose Last updated time is today (since 00:00 UTC). A status change counts, and so do a status check of a queued or running scan and a chat message about its results.",
    why: "Shows which scans had activity today, including ones that are still waiting.",
    example: "A scan queued since yesterday counts here once anyone opens the scan list today.",
  },
  // src: backend/utilities/dashboard/scan_list.py:781-809 — weights 4/3/2/1 over every finding of successful scans, average /4 *10
  "sast.avg_risk": {
    what: "Severity-weighted average of all findings from successful SAST scans, from 0 to 10. Each finding weighs Critical 4, High 3, Medium 2, Low 1; the average weight is divided by 4 and multiplied by 10. All-Critical gives 10, all-Low 2.5.",
    why: "One number to compare the overall severity of your code over time.",
    example: "1 Critical and 3 Low findings: (4+1+1+1)/4 = 1.75, so 1.75/4 x 10 = 4.4.",
  },
  // src: backend/utilities/dashboard/scan_list.py:690-709, backend/utilities/dashboard/scan_list.py:796-806 — totals per severity over successful scans
  "sast.chart.severity": {
    what: "How many findings of each severity (Critical, High, Medium, Low) all successful SAST scans found together. The severity is the one the analysis gave each finding.",
    why: "Critical and High findings are the ones to fix first.",
    example: "Critical 4, High 12, Medium 30, Low 9.",
  },
  // src: backend/utilities/dashboard/scan_list.py:735-747, backend/utilities/dashboard/scan_list.py:818-829 — "compliance" is each standard's share of the control references; overall = mean of the top 8 shares
  "sast.chart.policy": {
    what: "Findings are mapped to controls of standards such as PCI DSS or ISO 27001. Each row counts those references (violations) for one standard and shows its share of all references, top 8. It is not a pass rate. The overall score is the average of the shares shown.",
    why: "Shows which compliance requirements your code findings put at risk.",
    example: "60 references to PCI DSS and 40 to ISO 27001: PCI DSS 60%, ISO 27001 40%, overall 50%.",
  },
  // src: backend/utilities/dashboard/scan_list.py:756-779, backend/utilities/dashboard/scan_list.py:839 — one entry per successful scan, top 5 by its 0-10 score
  "sast.chart.top_repos": {
    what: "The 5 successful scans with the highest risk score (0 to 10, weighted the same way as the Average Risk Score), with their finding count and language. A repository scanned twice can appear twice.",
    why: "Points you to the repositories that need attention first.",
    example: "payments-api 8.1 with 14 issues, then auth-service 7.5 with 6.",
  },
  // src: backend/utilities/dashboard/scan_list.py:792-793 — every scan, keyed by the UTC date it was created
  "sast.chart.scans_per_day": {
    what: "How many SAST scans were created on each day (UTC), whatever their status.",
    why: "Shows how regularly your team scans.",
    example: "Five scans created on 10 Nov show a bar of 5.",
  },
  // src: backend/utilities/dashboard/scan_list.py:663-673 — five buckets: pending, started, success, failure, not_started; cancelled and retry scans are in none
  "sast.chart.status": {
    what: "SAST scans of this team by their current status: Success, Started, Pending, Failure and Not started. Cancelled scans and scans being retried are not shown.",
    why: "A pile of failures or pending scans signals a setup or capacity problem.",
    example: "20 scans: 15 Success, 1 Started, 4 Failure.",
  },
  // src: backend/utilities/dashboard/scan_list.py:690-709 — successful scans' findings by severity, on the scan's creation date
  "sast.chart.risks_over_time": {
    what: "Findings of successful SAST scans by severity, plotted on the day (UTC) each scan was created.",
    why: "Shows whether the severity of findings is going up or down.",
    example: "A scan created on 3 Nov that found 2 High issues adds 2 to High on 3 Nov.",
  },
  // src: backend/utilities/dashboard/scan_list.py:714-729, backend/utilities/dashboard/scan_list.py:812-815, backend/utilities/dashboard/scan_list.py:31-37 — OWASP Top 10 2021 labels, top 8
  "sast.chart.by_category": {
    what: "Findings grouped by OWASP Top 10 (2021) category, the 8 largest. A finding mapped to two categories counts in both.",
    why: "Recurring categories point to a coding pattern worth training on.",
    example: "Injection 12, Broken Access Control 7, Cryptographic Failures 3.",
  },
  // src: backend/utilities/dashboard/scan_list.py:749-753, backend/utilities/dashboard/scan_list.py:832-836 — finding count per configured app language, top 8
  "sast.chart.by_language": {
    what: "Findings per application language (the language chosen when each scan was configured), the 8 largest.",
    why: "Shows which code bases carry most of the findings.",
    example: "Python 30, Java 12.",
  },
  // src: backend/utilities/dashboard/scan_list.py:683-688 — distinct repo URLs and zip count of successful scans with results
  "sast.chart.sources": {
    what: "The distinct repository URLs, and the number of zip uploads, among successful SAST scans that returned results.",
    why: "Shows how much of your code estate is being scanned.",
    example: "2 zip uploads and https://github.com/acme/payments-api.",
  },
  // src: backend/utilities/dashboard/remediation_metrics.py:17-90, backend/utilities/db/schemas.py:15-17 — from each finding's status: not_started, in_progress, fixed, ignored
  "sast.remed.section": {
    what: "Measured from the status your team sets on each finding (Not started, In progress, Fixed, Ignored) across all SAST scans. The targets are fixed goals shown for comparison.",
    why: "Finding issues matters only if they get fixed; these show whether they do.",
    example: "Mark a finding Fixed in the results page and these numbers update.",
  },
  // src: backend/utilities/dashboard/remediation_metrics.py:43-80, frontend/app/[team_id]/sast/page.tsx:936 — mean of (fixed_at or ignored_at - created_at); target 3 days
  "sast.remed.mttr": {
    what: "Average time from when a finding was recorded to when it was marked Fixed or Ignored. The target is 3 days.",
    why: "A long time to fix keeps known weaknesses exploitable.",
    example: "One finding fixed after 2 days and one ignored after 4 days: 3.0 days.",
  },
  // src: backend/utilities/dashboard/remediation_metrics.py:47-49, backend/utilities/dashboard/scan_list.py:796-809, frontend/app/[team_id]/sast/page.tsx:960-962 — fixed critical / all critical findings; target 95%
  "sast.remed.critical_fixed": {
    what: "Critical findings marked Fixed, as a percentage of all Critical findings from successful SAST scans. Ignored findings do not count as fixed. The target is 95%.",
    why: "Critical findings are the most likely to be exploited.",
    example: "8 Critical findings, 6 marked Fixed: 75%.",
  },
  // src: backend/utilities/dashboard/remediation_metrics.py:38-40, frontend/app/[team_id]/sast/page.tsx:984 — critical or high and not fixed/ignored; target 10
  "sast.remed.backlog": {
    what: "Critical and High findings that are not yet marked Fixed or Ignored. The target is 10 or fewer.",
    why: "Open Critical and High findings are your current exposure.",
    example: "14 open Critical/High findings: 4 above target.",
  },
  // src: backend/utilities/dashboard/remediation_metrics.py:30, backend/utilities/dashboard/remediation_metrics.py:55-69, frontend/app/[team_id]/sast/page.tsx:1006 — fixed_at/ignored_at date >= today - 7 days (UTC): 8 dates; target 20
  "sast.remed.velocity": {
    what: "Findings marked Fixed or Ignored today or on the 7 dates before it (UTC), so over up to 8 calendar days. The target is 20 a week.",
    why: "Shows whether fixes keep up with new findings.",
    example: "On Wednesday 12 Nov: 12 fixed and 3 ignored since Wednesday 5 Nov gives 15/week.",
  },
  // src: frontend/app/[team_id]/sast/page.tsx:1169-1173,1346, backend/utilities/db/scan_list_item.py:38-41 — github/gitlab/bitbucket from repo_type, zip_file when a zip was used
  "sast.filter.type": {
    what: "Shows only scans of one source: GitHub, GitLab or Bitbucket repositories, or zip uploads.",
    why: "Narrows the list to one code source.",
    example: "Choose Zip file to list only scans of uploaded archives.",
  },
  // src: frontend/app/[team_id]/sast/page.tsx:107-115,1297, frontend/app/[team_id]/sast/page.tsx:98-105,1297 — tiers on the 0-10 per-scan risk score; scans without findings drop out
  "sast.filter.risk": {
    what: "Shows only scans whose risk score (0 to 10) is in a tier: Critical 9 or more, High 7 to 9, Medium 5 to 7, Low under 5. Scans without findings have no score and are hidden by any tier.",
    why: "Focuses the list on the riskiest scans.",
    example: "High keeps a scan scored 7.5 and hides one scored 9.2.",
  },
  // src: frontend/app/[team_id]/sast/page.tsx:1175-1190 — sorts the loaded rows
  "sast.filter.sort": {
    what: "Orders the table by creation date, risk score, coverage or credits, ascending or descending. Scans with no value for the chosen column go last when sorting high to low.",
    why: "Brings the scans you care about to the top.",
    example: "Risk descending puts the riskiest scan first.",
  },
  // src: backend/utilities/db/scan_list_item.py:77 — app_lang from the scan's settings
  "sast.table.language": {
    what: "The application language chosen for the scan. It decides which file extension was analysed.",
    why: "Only this language's files were analysed, so other code in the repository was not checked.",
    example: "python: only .py files were analysed.",
  },
  // src: backend/utilities/db/scan_list_item.py:9-26 — counts per impact of a successful scan
  "sast.table.vulns": {
    what: "Findings of this scan by severity: Critical (red), High (orange), Medium (amber), Low (blue). Counted only once the scan succeeded.",
    why: "Shows at a glance how serious this scan's findings are.",
    example: "2 red, 5 orange, 1 amber, 0 blue.",
  },
  // src: backend/utilities/db/scan_list_item.py:82, frontend/app/[team_id]/sast/page.tsx:99-105,1465 — per-scan weighted sum / count / 4 * 10
  "sast.table.risk": {
    what: "This scan's severity-weighted average, 0 to 10: Critical 4, High 3, Medium 2, Low 1, averaged over its findings, divided by 4 and multiplied by 10. Empty when it found nothing.",
    why: "Lets you compare scans by overall severity.",
    example: "2 High and 2 Low findings: (3+3+1+1)/4 = 2, so 5.0.",
  },
  // src: backend/utilities/db/scan_list_item.py:38-41 — repo_type or zip_file
  "sast.table.type": {
    what: "Where the code came from: GitHub, GitLab, Bitbucket or a zip upload.",
    why: "Tells you where the scanned code came from.",
    example: "GitLab.",
  },
  // src: backend/utilities/db/scan_list_item.py:76, frontend/app/[team_id]/sast/page.tsx:1609-1613,1467 — repo_url from the scan's settings; the SAST list item does not return zip_file_used, so a zip upload shows a dash until #49 is fixed
  "sast.table.source": {
    what: "The repository that was scanned (its last path segment; hover for the full URL). A scan of an uploaded zip file shows a dash.",
    why: "Tells you which code the findings belong to.",
    example: "payments-api for https://github.com/acme/payments-api.",
  },
  // src: backend/utilities/db/scan_list_item.py:24-31, RabbitMQ/worker/helpers/context/codebase_context.py:227-230 — included / (included + excluded) files with the language's extension
  "sast.table.coverage": {
    what: "Share of the language's source files that were analysed: analysed files divided by analysed plus excluded files. Exclusions are the language defaults and your patterns.",
    why: "Low coverage means much of the code was not analysed, so a clean result proves less.",
    example: "180 files analysed and 20 excluded: 90.0%.",
  },
  // src: RabbitMQ/worker/scan_worker.py:138-164, backend/utilities/db/scan_list_item.py:43 — start_time is taken before the context check and the clone, end after the analysis
  "sast.detail.duration": {
    what: "How long the scan worker spent on the scan, from start to results, including the clone.",
    why: "Unusually long scans may hit limits; watch for them on large repositories.",
    example: "4m 12s.",
  },
  // src: backend/utilities/db/scan_list_item.py:46-60 — sum of compliance_controls of the critical and high findings listed
  "sast.detail.policy": {
    what: "How many compliance controls (for example PCI DSS or ISO 27001 clauses) the Critical and High findings listed below map to, added up.",
    why: "Shows how many audit requirements this scan's serious findings touch.",
    example: "Two findings mapped to 3 and 2 controls: 5 violations.",
  },
  // src: backend/utilities/db/scan_list_item.py:46-60 — critical and high findings of the scan
  "sast.detail.top": {
    what: "The Critical and High findings of this scan, each with the number of compliance controls it maps to.",
    why: "These are the findings to fix first in this scan.",
    example: "SQL injection in orders.py, 3 policy violations.",
  },

  // ────────────────────────────────────────────────────────────── SAST: results view (components/SASTResults.tsx)
  // src: backend/utilities/dashboard/scan.py:181-192, frontend/components/SASTResults.tsx:220-233,279 — findings per OWASP category; each bar relative to the largest
  "sast.res.owasp": {
    what: "This scan's findings per OWASP Top 10 category. Each ring's length is relative to the largest category; hover a ring for its count. A finding mapped to two categories counts in both.",
    why: "Recurring categories point to a coding pattern to fix at the source.",
    example: "Injection 5 is the full ring; Cryptographic Failures 2 is 40% of it.",
  },
  // src: backend/utilities/dashboard/scan.py:170-176, backend/utilities/dashboard/scan.py:203-205 — count per impact
  "sast.res.risk": {
    what: "How many findings of this scan have each impact: Critical, High, Medium and Low.",
    why: "Critical and High findings are the ones to fix first.",
    example: "Critical 1, High 4, Medium 7, Low 2.",
  },
  // src: backend/utilities/dashboard/scan.py:207-215, frontend/components/SASTResults.tsx:240-243,364 — findings per CVE id, top 20
  "sast.res.cves": {
    what: "For each CVE the analysis linked to a finding, how many of this scan's findings reference it; the 20 most referenced.",
    why: "A CVE shared by many findings is one fix with a large effect.",
    example: "CVE-2021-44228 referenced by 3 findings.",
  },
  // src: backend/utilities/dashboard/scan.py:194-201, frontend/components/SASTResults.tsx:409 — findings per compliance control, all, largest first
  "sast.res.compliance": {
    what: "How many of this scan's findings map to each compliance control (for example a PCI DSS requirement), every control, largest first. A finding mapped to three controls counts once for each.",
    why: "Shows which audit requirements this scan's findings put at risk.",
    example: "PCI DSS 6.2.4: 4 findings.",
  },
  // src: backend/utilities/dashboard/scan.py:220-228, frontend/components/SASTResults.tsx:251-258,447, frontend/components/SASTResults.tsx:463-468,447 — control references grouped by standard (text before " - "), share of the total, top 12; icons mark the share
  "sast.res.policy": {
    what: "This scan's compliance-control references grouped by standard, with each standard's share of all references (top 12). It is a share, not a pass rate: the tick or cross only marks how large the share is.",
    why: "Shows which standards this scan affects most.",
    example: "6 PCI DSS and 4 ISO 27001 references: PCI DSS 60%, ISO 27001 40%.",
  },
  // src: backend/utilities/dashboard/scan.py:28-33, backend/utilities/dashboard/scan.py:216-218, frontend/components/SASTResults.tsx:262-266,487 — score by impact (10/7.5/5/2.5), keyed by title, top 24
  "sast.res.risk_scores": {
    what: "Each finding's risk score from its impact, on a 0 to 10 scale: Critical 10, High 7.5, Medium 5, Low 2.5. The 24 highest are shown as F1, F2…; hover for the title. Findings with the same title appear once.",
    why: "Shows whether risk is concentrated in a few findings.",
    example: "F1 \"SQL injection in orders.py\" 10.",
  },
  // src: backend/utilities/dashboard/scan.py:231-232, backend/utilities/dashboard/remediation_metrics.py:17-90 — from the status of this scan's findings
  "sast.res.remed.section": {
    what: "Measured from the status your team sets on this scan's findings (Not started, In progress, Fixed, Ignored). The targets are fixed goals shown for comparison.",
    why: "Shows whether this scan's findings are being fixed.",
    example: "Mark a finding Fixed in the table below and these numbers update.",
  },
  // src: backend/utilities/dashboard/remediation_metrics.py:43-80, frontend/components/SASTResults.tsx:552-554 — mean of (fixed_at or ignored_at - created_at); target 3 days
  "sast.res.remed.mttr": {
    what: "Average time from when this scan's findings were recorded to when they were marked Fixed or Ignored. The target is 3 days.",
    why: "A long time to fix keeps known weaknesses exploitable.",
    example: "One finding fixed after 2 days and one ignored after 4 days: 3.0 days.",
  },
  // src: backend/utilities/dashboard/remediation_metrics.py:47-49, backend/utilities/dashboard/scan.py:203-205, frontend/components/SASTResults.tsx:576-581 — fixed critical / all critical findings of the scan; target 95%
  "sast.res.remed.critical_fixed": {
    what: "This scan's Critical findings marked Fixed, as a percentage of all its Critical findings. Ignored findings do not count as fixed. The target is 95%.",
    why: "Critical findings are the most likely to be exploited.",
    example: "4 Critical findings, 3 marked Fixed: 75%.",
  },
  // src: backend/utilities/dashboard/remediation_metrics.py:38-40, frontend/components/SASTResults.tsx:601-602 — critical or high and not fixed/ignored; target 10
  "sast.res.remed.backlog": {
    what: "This scan's Critical and High findings that are not yet marked Fixed or Ignored. The target is 10 or fewer.",
    why: "Open Critical and High findings are this scan's current exposure.",
    example: "12 open Critical/High findings: 2 above target.",
  },
  // src: backend/utilities/dashboard/remediation_metrics.py:30, backend/utilities/dashboard/remediation_metrics.py:55-69, frontend/components/SASTResults.tsx:622-623 — fixed_at/ignored_at date >= today - 7 days (UTC): 8 dates; target 20
  "sast.res.remed.velocity": {
    what: "This scan's findings marked Fixed or Ignored today or on the 7 dates before it (UTC), so over up to 8 calendar days. The target is 20 a week.",
    why: "Shows whether fixes keep up.",
    example: "5 fixed and 1 ignored since last Wednesday: 6/week.",
  },
  // src: backend/utilities/dashboard/scan_metadata.py:79-99, RabbitMQ/worker/helpers/context/codebase_context.py:227-230 — included / (included + excluded) documents of the language
  "sast.res.coverage": {
    what: "Share of the chosen language's source files that were analysed: analysed files divided by analysed plus excluded files. Exclusions are the language's built-in ones and your patterns.",
    why: "Low coverage means much of the code was not analysed, so a clean result proves less.",
    example: "180 files analysed and 20 excluded: 90.0%.",
  },
  // src: backend/utilities/dashboard/scan_metadata.py:79-99 — len(included) / len(included) + len(excluded)
  "sast.res.files": {
    what: "Files analysed / files of the chosen language in the repository (analysed plus excluded). Files of other languages are not counted.",
    why: "Shows how much of the repository was analysed.",
    example: "180 / 200: 20 files were excluded by patterns.",
  },
  // src: frontend/components/SASTResults.tsx:717-728,1070 — case-insensitive match on title, description, impact, status, suggested fix and location of the loaded findings
  "sast.res.search": {
    what: "Shows only the findings whose title, description, impact, status, suggested fix or location contains this text (upper or lower case does not matter).",
    why: "Finds the findings for one file or topic quickly.",
    example: "\"orders.py\" keeps the findings located in orders.py.",
  },
  // src: backend/utilities/db/findings.py:44-49, backend/utilities/db/findings.py:96, frontend/components/SASTResults.tsx:699-705,1106 — the per-finding score is 1-4 (impact), the tiers are 0-10, so only Low matches; bug reported to the coordinator, issue not yet filed
  "sast.res.filter.risk": {
    what: "Shows only findings whose risk score is in a tier: Critical 9 or more, High 7 to 9, Medium 5 to 7, Low under 5. Today a SAST finding's score is 1 to 4, so Low keeps every finding and the other tiers none (a known bug); filter by Impact instead.",
    why: "Focuses the table on the riskiest findings.",
    example: "To list the Critical findings, choose Critical in the Impact filter.",
  },
  // src: frontend/components/SASTResults.tsx:1181-1182, frontend/components/SASTResults.tsx:1341-1363 — description cut to 80 characters; the dialog shows description, location, suggested fix and snippet
  "sast.res.description": {
    what: "The analysis's explanation of the issue, cut to 80 characters; hover for the whole text, or click the title for the description, location, code snippet and suggested fix.",
    why: "Explains what is wrong before you open the details.",
    example: "\"User input from the order form reaches a SQL query in orders.py without parame…\" (hover for the rest).",
  },
  // src: backend/utilities/db/findings.py:44-49, backend/utilities/db/findings.py:96, frontend/components/SASTResults.tsx:1222-1229 — risk_score_map: low 1 … critical 4
  "sast.res.table.risk": {
    what: "This finding's risk score, set by its impact: Critical 4, High 3, Medium 2, Low 1. The Risk scores per finding chart shows the same findings on a 0 to 10 scale.",
    why: "Lets you sort and compare findings by severity.",
    example: "4 for a Critical finding.",
  },
  // src: frontend/components/SASTResults.tsx:1174, frontend/components/SASTResults.tsx:650-655,1174 — number of CVE ids on the finding
  "sast.res.table.cves": {
    what: "How many CVE identifiers the analysis linked to this finding. Click the title to see them.",
    why: "Linked CVEs show the issue is known and documented.",
    example: "1 for a finding about a vulnerable Log4j call.",
  },
} as const satisfies TipAreaText;

export default TEXT;
