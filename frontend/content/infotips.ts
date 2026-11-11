/**
 * The text of every (i) info tip in the app, keyed by a stable id: `<surface>.<area>.<item>`.
 *
 * Rules (checked by content/infotips.test.ts):
 *  - "what" says what the field, metric or setting is and what the product really does with it (limits, units,
 *    credits, meaning of each value); "example" is one concrete example.
 *  - Every entry has a `// src:` comment directly above it naming the code it was checked against
 *    (`<repo-relative path>:<line>` or `:<from>-<to>`), so a reviewer can verify it. Behaviour that could not be
 *    verified in the code is left out of the text, never guessed.
 *  - An id shared by several products is used only where they run the same code.
 *
 * Components: <InfoTip id="…" /> and <FieldLabel infoId="…"> in components/ui/info-tip.tsx.
 */
export interface InfoTipEntry {
  /** What the (i) button is about; the button is named "About <label>". */
  label: string;
  /** What it is, in plain words, with the real limits, units and behaviour. */
  what: string;
  /** One concrete example. */
  example: string;
  /** Optional link: an app path ("/…") or an https URL. */
  learnMore?: { href: string; label?: string };
}

export const INFO_TIPS = {
  // ────────────────────────────────────────────────────────────── shared by the scan list pages (routers/scans.py)
  // src: backend/utilities/db/schemas.py:8-9, backend/routers/scans.py:150-155 — title 1-256 characters; creating stores a NOT_STARTED scan, no credits
  "scan.new.title": {
    label: "Scan title",
    what: "A name for the new scan, 1 to 256 characters, shown in the scan list. Creating the scan uses no credits: you choose what to scan, see the credit estimate and start it on the next page.",
    example: "payments-api main, November release.",
  },
  // src: backend/utilities/db/schemas.py:46-47, backend/routers/scans.py:801-831 — rename sets only the title (max 256)
  "scan.rename.title": {
    label: "Scan name",
    what: "The new name of this scan, up to 256 characters. Only the label changes: results, findings and credits stay as they are.",
    example: "payments-api before the PCI audit.",
  },
  // src: frontend/app/[team_id]/sast/page.tsx:1165 — case-insensitive match on the title, in the loaded list
  "scan.filter.search": {
    label: "Search by title",
    what: "Shows only the scans whose title contains this text (upper or lower case does not matter). It filters the list already loaded in this page.",
    example: "Typing \"api\" keeps \"payments-API main\" and \"api-gateway\".",
  },
  // src: backend/new_models.py:130, backend/routers/scans.py:585-596, backend/utilities/celery/celery_connection.py:186-192, backend/utilities/scan/cancel_scan.py:1-8 — the scan states and the refunds
  "scan.status": {
    label: "Scan status",
    what: "Not started: created, never run. Pending: queued for a scan worker. Started: running (the bar shows progress). Retry: the worker is retrying it. Success: finished, findings stored. Failure: stopped with an error; its credits were refunded. Cancelled: stopped by a user; its credits were refunded.",
    example: "A scan stuck in Pending is waiting for a free worker; it moves to Started when one picks it up.",
  },
  // src: backend/new_models.py:131, frontend/utils/datetime.ts:6-7 — stored in UTC, shown in IST
  "scan.table.created": {
    label: "Created at",
    what: "When the scan was created. Times are shown in India Standard Time (IST).",
    example: "9 Aug 2026, 07:30 pm IST.",
  },
  // src: backend/utilities/celery/celery_connection.py:182, backend/utilities/celery/celery_connection.py:200-215, frontend/utils/datetime.ts:6-7 — set when the scan pipeline reports progress or a result
  "scan.table.updated": {
    label: "Last updated",
    what: "The last time the scan pipeline changed this scan: it started, reported progress, finished, failed or was cancelled. Renaming does not change it. Shown in IST.",
    example: "A running scan's time moves forward each time its progress is refreshed.",
  },
  // src: backend/routers/scans.py:468, backend/utilities/db/scan_list_item.py:67, backend/utilities/celery/celery_connection.py:186-192, backend/utilities/scan/cancel_scan.py:1-8 — credit_consumed is the estimate, charged at start, refunded on failure or cancel
  "scan.table.credits": {
    label: "Credits",
    what: "Credits of this scan: the estimate made before it started, which is what the start charged. A scan that fails or is cancelled gets these credits back.",
    example: "12.4 means the scan was estimated and charged 12.4 credits.",
  },
  // src: backend/routers/scans.py:150-153, backend/utilities/db/scan_list_item.py:68-69 — owner_user_id is the user who created the scan
  "scan.table.owner": {
    label: "Owner",
    what: "The team member who created the scan.",
    example: "Priya Shah, priya@acme.com.",
  },
  // src: backend/utilities/scan/credit_estimate.py:1-15, backend/utilities/celery/celery_connection.py:186-192, backend/utilities/scan/cancel_scan.py:1-8 — start re-estimates when the input changed; failure and cancel refund
  "scan.cfg.run": {
    label: "Run scan",
    what: "Starts the scan and charges the estimated credits. If the input changed since the estimate (another file, repository, branch or option), the start estimates again before charging. Failed and cancelled scans are refunded.",
    example: "Estimate 3.2 credits, press Start scan: 3.2 credits leave the team balance.",
  },

  // ────────────────────────────────────────────────────────────── repository source (components/repository-card.tsx)
  // src: RabbitMQ/worker/helpers/context/scan_context.py:162-173, RabbitMQ/worker/helpers/context/git_hosts.py:8-14 — a zip or a clone of GitHub/GitLab/Bitbucket
  "repo.source": {
    label: "Repository",
    what: "Where the code comes from: a .zip you upload, or a repository on GitHub, GitLab or Bitbucket that the scan worker clones. Use one of them.",
    example: "Upload payments-api.zip, or connect https://github.com/acme/payments-api.",
  },
  // src: backend/utilities/scan/format_input.py:46-51, RabbitMQ/worker/helpers/context/scan_context.py:175-187, backend/utilities/scan/credit_estimate.py:8-10 — upload up to 50 MB; extracted with limits (2 GB, 50,000 files); the estimate is bound to the file size and SHA-256
  "repo.zip": {
    label: "Zip file",
    what: "A .zip of your source code, scanned instead of a repository: at most 50 MB, unpacking to at most 2 GB and 50,000 files. The credit estimate is for this exact file: a different file is estimated again when the scan starts.",
    example: "payments-api.zip made with \"git archive --format=zip HEAD\".",
  },
  // src: RabbitMQ/worker/helpers/context/git_hosts.py:8-14, RabbitMQ/worker/helpers/context/scan_context.py:92-139 — https on github.com / gitlab.com / bitbucket.org (or sub-domains), or a host listed in GIT_ALLOWED_HOSTS
  "repo.url": {
    label: "Repository URL",
    what: "The https address of the repository. GitHub, GitLab and Bitbucket (and their sub-domains) are accepted; a self-hosted Git server works only if your administrator listed it in GIT_ALLOWED_HOSTS.",
    example: "https://github.com/acme/payments-api.",
  },
  // src: RabbitMQ/worker/helpers/context/scan_context.py:31-49, RabbitMQ/worker/helpers/context/scan_context.py:89 — clone of that branch; default main
  "repo.branch": {
    label: "Branch",
    what: "The branch the scan worker clones and scans. Leave it empty to scan main.",
    example: "release/2026.11.",
  },
  // src: RabbitMQ/worker/helpers/context/scan_context.py:91-108 — GitHub token optional; a value that looks like a URL is ignored
  "repo.pat.github": {
    label: "GitHub token",
    what: "A personal access token that can read the repository. Optional for public repositories, required for private ones. It is used to clone; paste the token itself, not a URL.",
    example: "A fine-grained token with read-only Contents access to acme/payments-api.",
  },
  // src: RabbitMQ/worker/helpers/context/scan_context.py:110-139 — GitLab (user oauth2) and Bitbucket (user x-token-auth) require a token
  "repo.pat.required": {
    label: "Access token",
    what: "A token that can read the repository; required for GitLab and Bitbucket. The scan worker uses it to clone the repository.",
    example: "A GitLab project access token with the read_repository scope.",
  },

  // ────────────────────────────────────────────────────────────── SAST: scan configuration (components/sast-options-sidebar.tsx)
  // src: RabbitMQ/worker/helpers/tools/sast_agent/main.py:51-92, RabbitMQ/worker/helpers/context/codebase_context.py:114-141 — the scope is the language's files minus default and custom exclusions
  "sast.cfg.scope": {
    label: "Scan scope",
    what: "Which files are analysed: the files of the chosen language, minus the language's built-in exclusions (for JavaScript: node_modules, .next, dist, build, .cache, .nuxt, .output) and minus the patterns you add here.",
    example: "Add \"tests\" to leave every tests folder out.",
  },
  // src: RabbitMQ/worker/helpers/context/codebase_context.py:114-141, RabbitMQ/worker/helpers/tools/sast_agent/main.py:91-92 — a pattern is path segments; a file is skipped when its path contains them in order
  "sast.cfg.exclude": {
    label: "Exclude path patterns",
    what: "Each pattern is one or more folder or file names (one per box). A file is skipped when its path contains them in that order. A single name starting with a dot matches anywhere in the path. Skipped files are not analysed and not charged.",
    example: "\"vendor\" skips every vendor folder; \"src\" / \"legacy\" skips src/legacy; \".min.js\" skips minified files.",
  },
  // src: RabbitMQ/worker/helpers/tools/sast_agent/main.py:51-83 — one file extension per language
  "sast.cfg.language": {
    label: "Primary app language",
    what: "Only files with this language's extension are analysed: Python .py, JavaScript .js, Java .java, PHP .php, C .c, Ruby .rb, Rust .rs, Swift .swift, C# .cs, Kotlin .kt. Other files in the repository are ignored.",
    example: "For a Node service choose JavaScript; note that .ts and .jsx files are not analysed.",
  },
  // src: RabbitMQ/worker/helpers/tools/sast_agent/main.py:493-494, backend/utilities/scan/estimate_scan.py:210 — 1 credit per 0.5 MB of analysed files + 0.04/0.836, rounded to 0.01
  "sast.cfg.estimate": {
    label: "Estimate scan credits",
    what: "Measures the files in scope and prices the scan: 2 credits per MB of analysed source code, plus about 0.05 credits, rounded to 0.01. Nothing is charged until you start the scan.",
    example: "3 MB of Python after exclusions: about 6.05 credits.",
  },

  // ────────────────────────────────────────────────────────────── SAST: list page (app/[team_id]/sast/page.tsx)
  // src: backend/utilities/dashboard/scan_list.py:672-673 — status NOT_STARTED
  "sast.kpi.not_started": {
    label: "Not Started",
    what: "SAST scans that were created but never started. They have used no credits.",
    example: "You created \"payments-api\" but closed the page before estimating: it counts here.",
  },
  // src: backend/utilities/dashboard/scan_list.py:664-665, backend/routers/scans.py:585-596 — status pending: claimed by start, waiting for a worker
  "sast.kpi.pending": {
    label: "Pending",
    what: "SAST scans that were started and are queued, waiting for a scan worker to pick them up.",
    example: "Three scans started together: one runs, two wait here.",
  },
  // src: backend/utilities/dashboard/scan_list.py:666-667, backend/utilities/celery/celery_connection.py:204-208 — status started: a worker is running it
  "sast.kpi.started": {
    label: "Started",
    what: "SAST scans a worker is running now. The table shows each one's progress.",
    example: "A scan at 40% in the table counts here until it finishes.",
  },
  // src: backend/utilities/dashboard/scan_list.py:668-669, backend/utilities/celery/celery_connection.py:125-133 — status success: results stored
  "sast.kpi.success": {
    label: "Success",
    what: "SAST scans that finished and stored their findings. Only these feed the charts below.",
    example: "A scan that found 0 issues still counts as a success.",
  },
  // src: backend/utilities/dashboard/scan_list.py:670-671, backend/utilities/celery/celery_connection.py:186-192 — status failure; credits refunded once
  "sast.kpi.failure": {
    label: "Failure",
    what: "SAST scans that stopped with an error. Their credits were refunded automatically. Open one to read the reason and run it again.",
    example: "A clone that failed because the token had expired.",
  },
  // src: backend/utilities/dashboard/scan_list.py:674-675 — created_at date equals today's UTC date
  "sast.kpi.created_today": {
    label: "Created today",
    what: "SAST scans created since 00:00 UTC today, in any status.",
    example: "A scan created at 04:00 IST on 11 Nov is 22:30 UTC on 10 Nov, so it counted for 10 Nov.",
  },
  // src: backend/utilities/dashboard/scan_list.py:676-677, backend/utilities/celery/celery_connection.py:200-215 — last_updated date equals today's UTC date
  "sast.kpi.updated_today": {
    label: "Updated today",
    what: "SAST scans whose status or progress changed since 00:00 UTC today (started, progressed, finished, failed or cancelled).",
    example: "A scan created yesterday that finished at 01:00 UTC today counts here.",
  },
  // src: backend/utilities/dashboard/scan_list.py:781-809 — weights 4/3/2/1 over every finding of successful scans, average /4 *10
  "sast.avg_risk": {
    label: "Average Risk Score",
    what: "Severity-weighted average of all findings from successful SAST scans, from 0 to 10. Each finding weighs Critical 4, High 3, Medium 2, Low 1; the average weight is divided by 4 and multiplied by 10. All-Critical gives 10, all-Low 2.5.",
    example: "1 Critical and 3 Low findings: (4+1+1+1)/4 = 1.75, so 1.75/4 x 10 = 4.4.",
  },
  // src: backend/utilities/dashboard/scan_list.py:690-709, backend/utilities/dashboard/scan_list.py:796-806 — totals per severity over successful scans
  "sast.chart.severity": {
    label: "Risk Severity Distribution",
    what: "How many findings of each severity (Critical, High, Medium, Low) all successful SAST scans found together. The severity is the one the analysis gave each finding.",
    example: "Critical 4, High 12, Medium 30, Low 9.",
  },
  // src: backend/utilities/dashboard/scan_list.py:735-747, backend/utilities/dashboard/scan_list.py:818-829 — "compliance" is each standard's share of the control references; overall = mean of the top 8 shares
  "sast.chart.policy": {
    label: "Policy Compliance",
    what: "Findings are mapped to controls of standards such as PCI DSS or ISO 27001. Each row counts those references (violations) for one standard and shows its share of all references, top 8. It is not a pass rate. The overall score is the average of the shares shown.",
    example: "60 references to PCI DSS and 40 to ISO 27001: PCI DSS 60%, ISO 27001 40%, overall 50%.",
  },
  // src: backend/utilities/dashboard/scan_list.py:756-779, backend/utilities/dashboard/scan_list.py:839 — one entry per successful scan, top 5 by its 0-10 score
  "sast.chart.top_repos": {
    label: "Top Repositories by Risk",
    what: "The 5 successful scans with the highest risk score (0 to 10, weighted the same way as the Average Risk Score), with their finding count and language. A repository scanned twice can appear twice.",
    example: "payments-api 8.1 with 14 issues, then auth-service 7.5 with 6.",
  },
  // src: backend/utilities/dashboard/scan_list.py:792-793 — every scan, keyed by the UTC date it was created
  "sast.chart.scans_per_day": {
    label: "Scans Per Day",
    what: "How many SAST scans were created on each day (UTC), whatever their status.",
    example: "Five scans created on 10 Nov show a bar of 5.",
  },
  // src: backend/utilities/dashboard/scan_list.py:663-673 — counts by status
  "sast.chart.status": {
    label: "Scan Status Breakdown",
    what: "All SAST scans of this team by their current status: Success, Started, Pending, Failure and Not started.",
    example: "20 scans: 15 Success, 1 Started, 4 Failure.",
  },
  // src: backend/utilities/dashboard/scan_list.py:690-709 — successful scans' findings by severity, on the scan's creation date
  "sast.chart.risks_over_time": {
    label: "Risks Over Time",
    what: "Findings of successful SAST scans by severity, plotted on the day (UTC) each scan was created.",
    example: "A scan created on 3 Nov that found 2 High issues adds 2 to High on 3 Nov.",
  },
  // src: backend/utilities/dashboard/scan_list.py:714-729, backend/utilities/dashboard/scan_list.py:812-815, backend/utilities/dashboard/scan_list.py:31-37 — OWASP Top 10 2021 labels, top 8
  "sast.chart.by_category": {
    label: "Vulnerabilities by Category",
    what: "Findings grouped by OWASP Top 10 (2021) category, the 8 largest. A finding mapped to two categories counts in both.",
    example: "Injection 12, Broken Access Control 7, Cryptographic Failures 3.",
  },
  // src: backend/utilities/dashboard/scan_list.py:749-753, backend/utilities/dashboard/scan_list.py:832-836 — finding count per configured app language, top 8
  "sast.chart.by_language": {
    label: "Vulnerabilities by Language",
    what: "Findings per application language (the language chosen when each scan was configured), the 8 largest.",
    example: "Python 30, Java 12.",
  },
  // src: backend/utilities/dashboard/scan_list.py:683-688 — distinct repo URLs and zip count of successful scans with results
  "sast.chart.sources": {
    label: "Scan Sources",
    what: "The distinct repository URLs, and the number of zip uploads, among successful SAST scans that returned results.",
    example: "2 zip uploads and https://github.com/acme/payments-api.",
  },
  // src: backend/utilities/dashboard/remediation_metrics.py:17-90, backend/utilities/db/schemas.py:15-17 — from each finding's status: not_started, in_progress, fixed, ignored
  "sast.remed.section": {
    label: "Remediation Metrics",
    what: "Measured from the status your team sets on each finding (Not started, In progress, Fixed, Ignored) across all SAST scans. The targets are fixed goals shown for comparison.",
    example: "Mark a finding Fixed in the results page and these numbers update.",
  },
  // src: backend/utilities/dashboard/remediation_metrics.py:43-80, frontend/app/[team_id]/sast/page.tsx:935 — mean of (fixed_at or ignored_at - created_at); target 3 days
  "sast.remed.mttr": {
    label: "Mean Time to Remediate",
    what: "Average time from when a finding was recorded to when it was marked Fixed or Ignored. The target is 3 days.",
    example: "One finding fixed after 2 days and one ignored after 4 days: 3.0 days.",
  },
  // src: backend/utilities/dashboard/remediation_metrics.py:47-49, backend/utilities/dashboard/scan_list.py:796-809, frontend/app/[team_id]/sast/page.tsx:958-962 — fixed critical / all critical findings; target 95%
  "sast.remed.critical_fixed": {
    label: "Critical Issues Fixed",
    what: "Critical findings marked Fixed, as a percentage of all Critical findings from successful SAST scans. Ignored findings do not count as fixed. The target is 95%.",
    example: "8 Critical findings, 6 marked Fixed: 75%.",
  },
  // src: backend/utilities/dashboard/remediation_metrics.py:38-40, frontend/app/[team_id]/sast/page.tsx:984 — critical or high and not fixed/ignored; target 10
  "sast.remed.backlog": {
    label: "High Priority Backlog",
    what: "Critical and High findings that are not yet marked Fixed or Ignored. The target is 10 or fewer.",
    example: "14 open Critical/High findings: 4 above target.",
  },
  // src: backend/utilities/dashboard/remediation_metrics.py:30, backend/utilities/dashboard/remediation_metrics.py:55-69, frontend/app/[team_id]/sast/page.tsx:1006 — fixed or ignored on a UTC date within the last 7 days; target 20
  "sast.remed.velocity": {
    label: "Remediation Velocity",
    what: "Findings marked Fixed or Ignored during the last 7 days (UTC dates). The target is 20 a week.",
    example: "12 fixed and 3 ignored this week: 15/week.",
  },
  // src: frontend/app/[team_id]/sast/page.tsx:1169-1173, backend/utilities/db/scan_list_item.py:33-36 — github/gitlab/bitbucket from repo_type, zip_file when a zip was used
  "sast.filter.type": {
    label: "Scan type",
    what: "Shows only scans of one source: GitHub, GitLab or Bitbucket repositories, or zip uploads.",
    example: "Choose Zip file to list only scans of uploaded archives.",
  },
  // src: frontend/app/[team_id]/sast/page.tsx:105-113, frontend/app/[team_id]/sast/page.tsx:96-103 — tiers on the 0-10 per-scan risk score; scans without findings drop out
  "sast.filter.risk": {
    label: "Risk score filter",
    what: "Shows only scans whose risk score (0 to 10) is in a tier: Critical 9 or more, High 7 to 9, Medium 5 to 7, Low under 5. Scans without findings have no score and are hidden by any tier.",
    example: "High keeps a scan scored 7.5 and hides one scored 9.2.",
  },
  // src: frontend/app/[team_id]/sast/page.tsx:1175-1190 — sorts the loaded rows
  "sast.filter.sort": {
    label: "Sort",
    what: "Orders the table by creation date, risk score, coverage or credits, ascending or descending. Scans with no value for the chosen column go last when sorting high to low.",
    example: "Risk descending puts the riskiest scan first.",
  },
  // src: backend/utilities/db/scan_list_item.py:72 — app_lang from the scan's settings
  "sast.table.language": {
    label: "Language",
    what: "The application language chosen for the scan. It decides which file extension was analysed.",
    example: "python: only .py files were analysed.",
  },
  // src: backend/utilities/db/scan_list_item.py:4-21 — counts per impact of a successful scan
  "sast.table.vulns": {
    label: "Vulnerabilities",
    what: "Findings of this scan by severity: Critical (red), High (orange), Medium (amber), Low (blue). Counted only once the scan succeeded.",
    example: "2 red, 5 orange, 1 amber, 0 blue.",
  },
  // src: backend/utilities/db/scan_list_item.py:77, frontend/app/[team_id]/sast/page.tsx:97-103 — per-scan weighted sum / count / 4 * 10
  "sast.table.risk": {
    label: "Risk score",
    what: "This scan's severity-weighted average, 0 to 10: Critical 4, High 3, Medium 2, Low 1, averaged over its findings, divided by 4 and multiplied by 10. Empty when it found nothing.",
    example: "2 High and 2 Low findings: (3+3+1+1)/4 = 2, so 5.0.",
  },
  // src: backend/utilities/db/scan_list_item.py:33-36 — repo_type or zip_file
  "sast.table.type": {
    label: "Scan type",
    what: "Where the code came from: GitHub, GitLab, Bitbucket or a zip upload.",
    example: "GitLab.",
  },
  // src: backend/utilities/db/scan_list_item.py:71 — repo_url from the scan's settings; zip uploads have none
  "sast.table.source": {
    label: "Repository",
    what: "The repository that was scanned (its last path segment; hover for the full URL), or Zip file for an upload.",
    example: "payments-api for https://github.com/acme/payments-api.",
  },
  // src: backend/utilities/db/scan_list_item.py:39, RabbitMQ/worker/helpers/context/scan_context.py:89 — the branch from the scan's settings (main by default)
  "scan.table.branch": {
    label: "Branch",
    what: "The branch that was cloned and scanned. Empty for zip uploads.",
    example: "main.",
  },
  // src: backend/utilities/db/scan_list_item.py:24-31, RabbitMQ/worker/helpers/context/codebase_context.py:210-213 — included / (included + excluded) files with the language's extension
  "sast.table.coverage": {
    label: "Coverage",
    what: "Share of the language's source files that were analysed: analysed files divided by analysed plus excluded files. Exclusions are the language defaults and your patterns.",
    example: "180 files analysed and 20 excluded: 90.0%.",
  },
  // src: RabbitMQ/worker/scan_worker.py:138-164, backend/utilities/db/scan_list_item.py:38 — start_time is taken before the context check and the clone, end after the analysis
  "sast.detail.duration": {
    label: "Duration",
    what: "How long the scan worker spent on the scan, from start to results, including the clone.",
    example: "4m 12s.",
  },
  // src: backend/utilities/db/scan_list_item.py:41-55 — sum of compliance_controls of the critical and high findings listed
  "sast.detail.policy": {
    label: "Policy Violations",
    what: "How many compliance controls (for example PCI DSS or ISO 27001 clauses) the Critical and High findings listed below map to, added up.",
    example: "Two findings mapped to 3 and 2 controls: 5 violations.",
  },
  // src: backend/utilities/db/scan_list_item.py:41-55 — critical and high findings of the scan
  "sast.detail.top": {
    label: "Top vulnerabilities",
    what: "The Critical and High findings of this scan, each with the number of compliance controls it maps to.",
    example: "SQL injection in orders.py, 3 policy violations.",
  },

  // ────────────────────────────────────────────────────────────── IaC: scan configuration (components/iac-options-sidebar.tsx)
  // src: RabbitMQ/worker/helpers/tools/iac_agent/main.py:56-88, RabbitMQ/worker/helpers/context/codebase_context.py:56-82, RabbitMQ/worker/helpers/context/codebase_context.py:114-141 — only files matching a pattern (and the mode's extensions) are analysed
  "iac.cfg.include": {
    label: "Include path patterns",
    what: "Only files whose path matches one of these patterns, and has this format's extension, are analysed. Each pattern is one or more folder or file names (one per box) that must appear in the path in that order. Wildcards such as ** are not supported.",
    example: "\"charts\" includes everything under any charts folder; \"deploy\" / \"k8s\" includes deploy/k8s.",
  },

  // ────────────────────────────────────────────────────────────── SCA + SBOM: scan configuration (components/sca-sbom-options-sidebar.tsx)
  // src: RabbitMQ/worker/helpers/tools/sca_sbom_agent/main.py:71-125, RabbitMQ/worker/helpers/tools/sca_sbom_agent/main.py:283-288 — repository or zip: Syft + cdxgen inventory, Grype vulnerabilities
  "sbom.cfg.repository": {
    label: "Analyze Repository",
    what: "Builds the software bill of materials from your code (Syft and cdxgen, merged into CycloneDX) and matches every package against known vulnerabilities with Grype.",
    example: "A Node repository: packages come from package-lock.json, CVEs from Grype.",
  },
  // src: RabbitMQ/worker/helpers/tools/sca_sbom_agent/main.py:185-226, RabbitMQ/worker/helpers/tools/sca_sbom_agent/main.py:289-290 — an uploaded JSON SBOM is analysed by the AI summariser instead of building an inventory
  "sbom.cfg.sbom_file": {
    label: "SBOM file",
    what: "An SBOM you already have, as a JSON file. No code is cloned: the file's contents are analysed by the scan's AI model to list vulnerable dependencies. Choosing a file clears the repository or zip.",
    example: "bom.json exported by your build in CycloneDX JSON.",
  },
  // src: RabbitMQ/worker/helpers/tools/sca_sbom_agent/main.py:313-323, backend/utilities/scan/estimate_scan.py:210 — constant 0.01/0.836 credits, rounded to 0.01
  "sbom.cfg.estimate": {
    label: "Estimate scan credits",
    what: "An SCA + SBOM scan has a flat price of about 0.01 credits, whatever the size of the repository or file. Nothing is charged until you start the scan.",
    example: "Any repository: 0.01 credits.",
  },

  // ────────────────────────────────────────────────────────────── SCA + SBOM: list page (app/[team_id]/sbom_sca/page.tsx)
  // src: backend/utilities/dashboard/scan_list.py:958-960, backend/utilities/dashboard/scan_list.py:1079 — findings of successful scans
  "sbom.kpi.total": {
    label: "Total Vulnerabilities",
    what: "Vulnerable dependencies found by all successful SCA + SBOM scans of this team, added up.",
    example: "Two scans with 10 and 4 findings: 14.",
  },
  // src: backend/utilities/dashboard/scan_list.py:989-998, backend/utilities/dashboard/scan_list.py:1080 — impact critical
  "sbom.kpi.critical": {
    label: "Critical Vulnerabilities",
    what: "Of those, the findings rated Critical.",
    example: "A remote-code-execution CVE in a direct dependency.",
  },
  // src: backend/utilities/dashboard/scan_list.py:1005-1018, backend/utilities/dashboard/scan_list.py:1081 — number of compliance control references of all findings
  "sbom.kpi.policy": {
    label: "Policy Violations",
    what: "How many compliance-control references (PCI DSS, ISO 27001 and others) the findings map to, added up over all findings.",
    example: "One finding mapped to 2 controls and one to 3: 5.",
  },
  // src: backend/utilities/dashboard/scan_list.py:975-976, backend/utilities/dashboard/scan_list.py:1074-1082 — medium + high risk license categories
  "sbom.kpi.license_risks": {
    label: "License Risks",
    what: "Findings whose package has a medium-risk license (weak copyleft such as LGPL or MPL, Creative Commons, commercial) or a high-risk one (strong copyleft such as GPL, network copyleft such as AGPL, source-available such as SSPL or BUSL).",
    example: "A vulnerable package under LGPL-3.0 counts here.",
  },
  // src: backend/utilities/dashboard/scan_list.py:975, backend/utilities/dashboard/scan_list.py:1074, backend/utilities/dashboard/sbom_license.py:233-258 — strong copyleft, network copyleft, source-available
  "sbom.kpi.high_risk_licenses": {
    label: "High Risk Licenses",
    what: "Findings whose package is under a strong copyleft (GPL), network copyleft (AGPL) or source-available (SSPL, BUSL) license.",
    example: "A package licensed AGPL-3.0.",
  },
  // src: backend/utilities/dashboard/scan_list.py:1019-1021, backend/utilities/dashboard/scan_list.py:1077 — each finding scores weight/4*10, averaged
  "sbom.kpi.avg_risk": {
    label: "Avg Risk Score",
    what: "Average over all findings of successful scans, 0 to 10: Critical counts 10, High 7.5, Medium 5, Low 2.5.",
    example: "1 Critical and 1 Low: (10 + 2.5) / 2 = 6.3.",
  },
  // src: backend/utilities/dashboard/scan_list.py:999-1002, backend/utilities/dashboard/sbom_license.py:382-392, RabbitMQ/worker/helpers/context/schema.py:34 — reachability judged by the analysis
  "sbom.kpi.reachable": {
    label: "Reachable Issues",
    what: "Findings the analysis judged Reachable: your code appears to use the vulnerable part of the package.",
    example: "Your code calls the vulnerable yaml.load of an old PyYAML.",
  },
  // src: backend/utilities/dashboard/scan_list.py:1030-1037, backend/utilities/dashboard/finding_metrics.py:18-40 — stored findings by status
  "sbom.chart.remediation": {
    label: "Remediation Actions Required",
    what: "All stored findings of SCA + SBOM scans by the status your team set: Fixed, In progress, Not started, Ignored.",
    example: "40 findings: 10 Fixed, 5 In progress, 22 Not started, 3 Ignored.",
  },
  // src: backend/utilities/dashboard/scan_list.py:988-998, backend/utilities/dashboard/scan_list.py:1038-1043 — totals per impact
  "sbom.chart.severity": {
    label: "Severity Distribution",
    what: "Findings of successful scans by severity: Critical, High, Medium and Low.",
    example: "Critical 2, High 9, Medium 15, Low 4.",
  },
  // src: backend/utilities/dashboard/scan_list.py:1044-1056, backend/utilities/dashboard/sbom_license.py:382-392 — four reachability levels; missing or unknown counts as not assessed
  "sbom.chart.reachability": {
    label: "Reachability Distribution",
    what: "Findings by reachability: Reachable (your code uses the vulnerable code), Potentially reachable, Not reachable, and Not assessed (no judgement was possible).",
    example: "A vulnerable test-only package is often Not reachable.",
  },
  // src: backend/utilities/dashboard/scan_list.py:986, backend/utilities/dashboard/scan_list.py:1024-1028 — per creation date (UTC) of each successful scan
  "sbom.chart.trends": {
    label: "Vulnerability Trends Over Time",
    what: "Findings of successful scans by severity, on the day (UTC) each scan was created.",
    example: "Scans created on 5 Nov found 3 High in total: High shows 3 on 5 Nov.",
  },
  // src: backend/utilities/dashboard/scan_list.py:1003-1004, backend/utilities/dashboard/scan_list.py:1058, backend/utilities/dashboard/sbom_license.py:20-30 — license family of each finding's package
  "sbom.chart.licenses": {
    label: "Licenses Distribution",
    what: "Findings grouped by the license family of their package: permissive, public domain, weak copyleft, Creative Commons, commercial, strong copyleft, network copyleft, source-available, or not declared.",
    example: "MIT and Apache-2.0 are permissive; GPL-3.0 is strong copyleft.",
  },
  // src: backend/utilities/dashboard/scan_list.py:1060-1072, frontend/app/[team_id]/sbom_sca/page.tsx:455 — sorted by impact, first 20 shown
  "sbom.chart.top": {
    label: "Top Vulnerabilities by Risk Score",
    what: "The 20 most severe findings (Critical first), each with its reachability, direct or transitive dependency type, and license family.",
    example: "lodash 4.17.15, reachable, direct, permissive, Critical.",
  },
  // src: backend/utilities/dashboard/scan_list.py:1022-1023, backend/utilities/dashboard/scan_list.py:1087-1097 — per level: average of weight/4*10
  "sbom.chart.risk_by_reach": {
    label: "Average Risk Score per Reachability",
    what: "The average risk score (0 to 10: Critical 10, High 7.5, Medium 5, Low 2.5) of the findings at each reachability level.",
    example: "Reachable 8.8 means the reachable findings are mostly Critical or High.",
  },
  // src: backend/utilities/dashboard/scan_list.py:1005-1018, backend/utilities/dashboard/scan_list.py:1099-1105 — references per standard: PCI DSS, ISO 27001-27004
  "sbom.chart.policy": {
    label: "Policy Compliance Data",
    what: "How many compliance-control references the findings have per standard (PCI DSS, ISO 27001, 27002, 27003, 27004), and each standard's share of them.",
    example: "PCI DSS 12 of 20 references: 60%.",
  },
  // src: backend/utilities/db/scan_list_item.py:152-161 — counts per impact of a successful scan
  "sbom.table.vulns": {
    label: "Vulnerabilities",
    what: "This scan's vulnerable dependencies by severity: Critical (red), High (orange), Medium (amber), Low (blue). Counted once the scan succeeded.",
    example: "0 red, 3 orange, 6 amber, 1 blue.",
  },
  // src: backend/utilities/db/scan_list_item.py:171-173, backend/utilities/db/scan_list_item.py:112, backend/utilities/db/scan_list_item.py:410-412, frontend/app/[team_id]/sbom_sca/page.tsx:113-116, frontend/app/[team_id]/iac/page.tsx:123-126, frontend/app/[team_id]/dast/page.tsx:115-118 — weighted average on a 1-4 scale (SCA + SBOM, IaC, DAST; issue #35)
  "scan.table.risk4": {
    label: "Risk score",
    what: "This scan's average severity weight, from 1 to 4: Critical 4, High 3, Medium 2, Low 1, averaged over its findings. Empty when it found nothing.",
    example: "1 Critical and 1 Low finding: (4+1)/2 = 2.5.",
  },
  // src: frontend/app/[team_id]/sbom_sca/page.tsx:118-125, frontend/app/[team_id]/iac/page.tsx:128-135, frontend/app/[team_id]/dast/page.tsx:120-127 — tiers on the score shown in the Risk score column
  "scan.filter.risk": {
    label: "Risk score filter",
    what: "Shows only scans whose Risk score column value is in a tier: Critical 9 or more, High 7 to 9, Medium 5 to 7, Low under 5. Scans without findings are hidden by any tier.",
    example: "Low keeps every scan with a score under 5.",
  },
  // src: frontend/app/[team_id]/sbom_sca/page.tsx:699-712, frontend/app/[team_id]/iac/page.tsx:719-732, frontend/app/[team_id]/dast/page.tsx:637-650 — sorts the loaded rows; missing values count as -1
  "scan.filter.sort": {
    label: "Sort",
    what: "Orders the table by creation date, risk score or credits, high or low first. Scans with no value for the chosen column go last when sorting high first.",
    example: "Credits (high first) puts the most expensive scan on top.",
  },
  // src: backend/utilities/db/scan_list_item.py:179-181 — repo_url, or zip upload, or SBOM file
  "sbom.table.source": {
    label: "Repository",
    what: "The repository that was scanned (hover for the full URL), or Zip file for an uploaded archive. Empty for an uploaded SBOM file.",
    example: "payments-api.",
  },

  // ────────────────────────────────────────────────────────────── IaC: scan configuration (components/iac-options-sidebar.tsx)
  // src: backend/utilities/dashboard/scan_list.py:541-557, backend/utilities/db/scan_list_item.py:143 — stored as a label; the worker does not read it
  "iac.cfg.environment": {
    label: "Environment",
    what: "Which environment this infrastructure code is for: Development, Staging or Production. It is a label for your dashboards (the environment filter and heatmap); it does not change what the scan checks.",
    example: "Production for the Terraform that deploys your live VPC.",
  },
  // src: RabbitMQ/worker/helpers/tools/iac_agent/main.py:56-82 — one mode per context; each mode reads its file types
  "iac.cfg.contexts": {
    label: "IaC contexts",
    what: "The kinds of infrastructure code in the repository, one context each. Each kind reads its own files: Terraform .tf/.tfvars/.tfstate/.tf.json, Kubernetes and Helm .yaml/.yml, Ansible .yml/.yaml/.ini, CloudFormation .yaml/.yml/.json, Pulumi and CDK their program files.",
    example: "A repository with Terraform and Helm charts: add both contexts.",
  },
  // src: RabbitMQ/worker/helpers/tools/iac_agent/main.py:60-80 — terraform finds its files by extension; the others also need include patterns
  "iac.cfg.context_type": {
    label: "Context type",
    what: "The infrastructure format of this context. Terraform files are found anywhere by their extension; for the other formats only files matching the include patterns below are read.",
    example: "Kubernetes, with the include pattern \"k8s\".",
  },
  // src: RabbitMQ/worker/helpers/tools/iac_agent/main.py:207-227, backend/utilities/scan/estimate_scan.py:210 — 1 credit per 0.5 MB of matched files, rounded to 0.01
  "iac.cfg.estimate": {
    label: "Estimate scan credits",
    what: "Measures the infrastructure files the contexts match and prices the scan at 2 credits per MB, rounded to 0.01. Nothing is charged until you start the scan.",
    example: "400 KB of Terraform: about 0.78 credits.",
  },

  // ────────────────────────────────────────────────────────────── IaC: list page (app/[team_id]/iac/page.tsx)
  // src: backend/utilities/dashboard/scan_list.py:575 — successful IaC scans
  "iac.kpi.total_scans": {
    label: "Total scans",
    what: "IaC scans of this team that finished successfully.",
    example: "12 scans run, 2 failed: 10.",
  },
  // src: backend/utilities/dashboard/scan_list.py:456-480, backend/utilities/dashboard/scan_list.py:576 — findings of successful scans
  "iac.kpi.total_issues": {
    label: "Total issues",
    what: "Misconfigurations found by all successful IaC scans, added up.",
    example: "An S3 bucket without encryption is one issue.",
  },
  // src: backend/utilities/dashboard/scan_list.py:466-478, backend/utilities/dashboard/scan_list.py:577 — impact critical
  "iac.kpi.critical": {
    label: "Total critical",
    what: "Of those, the issues rated Critical.",
    example: "A security group open to 0.0.0.0/0 on SSH.",
  },
  // src: backend/utilities/dashboard/scan_list.py:564-569, backend/utilities/dashboard/remediation_metrics.py:43-80 — mean of fixed/ignored time minus creation, in days
  "iac.kpi.mttr": {
    label: "Avg MTTR (days)",
    what: "Mean time to remediate: the average time, in days, from when an issue was recorded to when it was marked Fixed or Ignored.",
    example: "One issue fixed after 1 day and one after 3 days: 2.0.",
  },
  // src: backend/utilities/dashboard/scan_list.py:509-518, backend/utilities/dashboard/scan_list.py:570 — per scan included / (included + excluded) files, averaged
  "iac.kpi.coverage": {
    label: "Coverage %",
    what: "For each successful scan, the share of candidate files that were analysed (analysed divided by analysed plus excluded), averaged over the scans.",
    example: "Two scans with 100% and 80%: 90.0%.",
  },
  // src: backend/utilities/dashboard/scan_list.py:493-507, backend/utilities/dashboard/scan_list.py:580 — compliance-control references with a standard
  "iac.kpi.policy": {
    label: "Policy violations",
    what: "How many compliance-control references (PCI DSS, ISO 27001 and others) the issues map to, added up.",
    example: "One issue mapped to 2 controls: 2.",
  },
  // src: backend/utilities/dashboard/scan_list.py:520-526, backend/utilities/dashboard/scan_list.py:571 — 0-10, weights 4/3/2/1, averaged over issues
  "iac.kpi.avg_risk": {
    label: "Avg risk score",
    what: "Severity-weighted average of all issues of successful scans, from 0 to 10: Critical 4, High 3, Medium 2, Low 1, the average weight divided by 4 and multiplied by 10.",
    example: "Half Critical, half Low: (4+1)/2 = 2.5, so 6.3.",
  },
  // src: backend/utilities/dashboard/scan_list.py:466-478, backend/utilities/dashboard/scan_list.py:584-589 — totals per impact
  "iac.chart.severity": {
    label: "Severity Distribution",
    what: "Issues of successful IaC scans by severity: Critical, High, Medium and Low.",
    example: "Critical 1, High 6, Medium 10, Low 3.",
  },
  // src: backend/utilities/dashboard/scan_list.py:464, backend/utilities/dashboard/scan_list.py:482-486 — per creation date (UTC)
  "iac.chart.over_time": {
    label: "Issues Over Time",
    what: "Issues of successful scans by severity, on the day (UTC) each scan was created.",
    example: "A scan created on 4 Nov with 3 High issues adds 3 to High on 4 Nov.",
  },
  // src: backend/utilities/dashboard/scan_list.py:488-491, backend/utilities/dashboard/scan_list.py:593-606 — issues per category; the six categories always shown
  "iac.chart.posture": {
    label: "Security Posture Overview",
    what: "Issues per security category: Network Security, Data Protection, Access Control, Logging and Monitoring, Secret Management, Audit and Compliance (and any other category found).",
    example: "Network Security 7 means seven issues about firewalls, ports or routing.",
  },
  // src: backend/utilities/dashboard/scan_list.py:615-622, backend/utilities/dashboard/finding_metrics.py:18-40 — stored findings by status
  "iac.chart.pipeline": {
    label: "Remediation Pipeline",
    what: "Issues by the status your team set on them: Fixed, In progress, Not started, Ignored, each as a share of all issues found.",
    example: "20 issues, 5 marked Fixed: Fixed 25%.",
  },
  // src: backend/utilities/dashboard/scan_list.py:493-507, backend/utilities/dashboard/scan_list.py:609, frontend/app/[team_id]/iac/page.tsx:478 — references per standard, share of all references
  "iac.chart.compliance": {
    label: "Compliance Framework Violations",
    what: "How many compliance-control references the issues have per standard, and that standard's share of all references. It is not a pass rate.",
    example: "PCI DSS 6 of 10 references: 60.0%.",
  },
  // src: backend/utilities/dashboard/scan_list.py:541-562 — successful scans with results counted per (environment, IaC type)
  "iac.chart.heatmap": {
    label: "Environment × Cloud Resource Heatmap",
    what: "How many successful scans covered each IaC type (rows) in each environment (columns). The environment is the one chosen when the scan was configured.",
    example: "Kubernetes × production = 3: three production scans had a Kubernetes context.",
  },
  // src: backend/utilities/dashboard/finding_metrics.py:89-125, backend/utilities/dashboard/scan_list.py:624-625 — per resolution date, average time to fix or ignore
  "iac.chart.mttr_per_day": {
    label: "MTTR Per Day",
    what: "For each day (UTC), the average time to remediate of the issues marked Fixed or Ignored that day, in days.",
    example: "Two issues fixed on 6 Nov after 1 and 2 days: 1.5 on 6 Nov.",
  },
  // src: backend/utilities/dashboard/scan_list.py:528-539 — one count per scan and IaC type, not per resource
  "iac.chart.providers": {
    label: "Resources by Provider",
    what: "How many successful scans included each IaC type (Terraform, Kubernetes, Helm, …). It counts scans per type, not individual cloud resources.",
    example: "Terraform 8, Kubernetes 3.",
  },
  // src: frontend/app/[team_id]/iac/page.tsx:714-717, backend/utilities/db/scan_list_item.py:143 — matches the scan's environment label
  "iac.filter.environment": {
    label: "Environment filter",
    what: "Shows only scans configured for one environment: Development, Staging or Production.",
    example: "Production lists only scans labelled Production.",
  },
  // src: backend/utilities/db/scan_list_item.py:137-138 — repo_url, or zip upload (IaC; the same fields for CBOM and AI BOM)
  "scan.table.source": {
    label: "Repository",
    what: "The repository that was scanned (its last path segment; hover for the full URL), or Zip file for an uploaded archive.",
    example: "infra-live for https://github.com/acme/infra-live.",
  },
  // src: backend/utilities/db/scan_list_item.py:140 — the IaC context types of the scan
  "iac.table.provider": {
    label: "Cloud provider",
    what: "The IaC types this scan read (its contexts), such as Terraform or Kubernetes.",
    example: "terraform, helm.",
  },
  // src: backend/utilities/db/scan_list_item.py:143 — environment label from the scan's settings
  "iac.table.environment": {
    label: "Environment",
    what: "The environment chosen when the scan was configured. It is a label only.",
    example: "staging.",
  },
  // src: backend/utilities/db/scan_list_item.py:89-104 — counts per impact of a successful scan
  "iac.table.vulns": {
    label: "Vulnerabilities",
    what: "This scan's issues by severity: Critical (red), High (orange), Medium (amber), Low (blue). Counted once the scan succeeded.",
    example: "1 red, 2 orange, 4 amber, 0 blue.",
  },

  // ────────────────────────────────────────────────────────────── DAST: scan configuration (components/dast-options-sidebar.tsx)
  // src: backend/utilities/dast/ssrf.py:1-12, backend/utilities/dast/ssrf.py:79-82 — http/https; scope = the target's host; private/metadata addresses refused unless the operator allows them
  "dast.cfg.target_url": {
    label: "Target URL",
    what: "The web application to test, starting with http:// or https://. Its host is the scan's scope: the login URL and additional URLs must be on the same host. Hosts that resolve to private, loopback or cloud-metadata addresses are refused unless your administrator allowed them.",
    example: "https://staging.shop.example.com.",
  },
  // src: RabbitMQ/dast_worker/helpers/agent/scan_config.py:17-75 — URL workers 10 / 5 / 2 and longer timeouts when slower
  "dast.cfg.speed": {
    label: "Scan speed",
    what: "How hard the scan pushes the target. Fast tests 10 URLs at a time with short timeouts, Medium 5, Slow 2 with the longest timeouts (gentlest on a fragile server). Your administrator can change the worker counts.",
    example: "Slow for a small staging server that falls over under load.",
  },
  // src: RabbitMQ/dast_worker/helpers/crawler/crawler.py:48-50, RabbitMQ/dast_worker/helpers/agent/main.py:373 — the crawler stops at max_urls; credits 0.08 per URL
  "dast.cfg.max_urls": {
    label: "Max URLs",
    what: "The most pages the crawler collects from the target before testing. Each URL tested costs 0.08 credits, so this also caps the price (additional URLs come on top).",
    example: "100 URLs: at most 8 credits.",
  },
  // src: RabbitMQ/dast_worker/helpers/agent/main.py:72-73, RabbitMQ/dast_worker/helpers/checks/nuclei/basic_templates.py:11-37 — all five fields required; a headless browser signs in with them
  "dast.cfg.auth": {
    label: "Authentication",
    what: "How the scanner signs in: a headless browser opens the login URL, types the username and password into the fields found by their XPaths and clicks the submit button. All fields are required, so the pages behind the login are tested too.",
    example: "Login URL https://shop.example.com/login with a test account.",
  },
  // src: backend/utilities/dast/ssrf.py:79-82, RabbitMQ/dast_worker/helpers/checks/nuclei/basic_templates.py:11-21 — opened first; must be on the target's host
  "dast.cfg.login_url": {
    label: "Login URL",
    what: "The page with the sign-in form. It must be on the same host as the target URL.",
    example: "https://shop.example.com/login.",
  },
  // src: RabbitMQ/dast_worker/helpers/checks/nuclei/construct_temp.py:10-27, RabbitMQ/dast_worker/helpers/checks/nuclei/basic_templates.py:21-31 — XPath of the input clicked and typed into
  "dast.cfg.xpath_user": {
    label: "Username field XPath",
    what: "An XPath that finds the username (or email) input on the login page. In the browser: right-click the field, Inspect, then Copy > Copy XPath.",
    example: "//input[@name='email'].",
  },
  // src: RabbitMQ/dast_worker/helpers/checks/nuclei/construct_temp.py:10-27, RabbitMQ/dast_worker/helpers/checks/nuclei/basic_templates.py:31-37 — XPath of the password input
  "dast.cfg.xpath_pass": {
    label: "Password field XPath",
    what: "An XPath that finds the password input on the login page.",
    example: "//input[@type='password'].",
  },
  // src: RabbitMQ/dast_worker/helpers/checks/nuclei/construct_temp.py:10-27 — XPath of the button clicked to submit
  "dast.cfg.xpath_submit": {
    label: "Submit button XPath",
    what: "An XPath that finds the button the scanner clicks to sign in.",
    example: "//button[@type='submit'].",
  },
  // src: RabbitMQ/dast_worker/helpers/agent/context.py:4-10, backend/utilities/scan/format_input.py:165-181 — sent to the worker for the sign-in; redacted from the scan's stored settings
  "dast.cfg.username": {
    label: "Username",
    what: "The account the scanner signs in with. Use a test account: the scan submits forms and tries attacks while signed in.",
    example: "dast-test@shop.example.com.",
  },
  // src: RabbitMQ/dast_worker/helpers/agent/context.py:4-10, backend/utilities/scan/credit_estimate.py:29-30 — sent to the worker; never part of the stored estimate digest
  "dast.cfg.password": {
    label: "Password",
    what: "The password of that test account. It is sent to the scan worker for the sign-in and is not shown again.",
    example: "The password of dast-test@shop.example.com.",
  },
  // src: RabbitMQ/dast_worker/helpers/crawler/crawler.py:60-63, backend/utilities/dast/ssrf.py:79-82 — always added to the crawl; must be on the target's host
  "dast.cfg.additional_urls": {
    label: "Additional URLs to scan",
    what: "Pages to test even if the crawler does not find them (they are added to the crawl). They must be on the target's host. Each one costs 0.08 credits like any other URL.",
    example: "https://shop.example.com/admin/reports (linked from nowhere).",
  },
  // src: RabbitMQ/dast_worker/helpers/crawler/crawler.py:51-56, RabbitMQ/dast_worker/helpers/crawler/crawler.py:108-123 — include or exclude, not both; * matches anything, searched anywhere in the URL
  "dast.cfg.url_patterns": {
    label: "URL patterns",
    what: "Either Include (test only crawled URLs that match) or Exclude (skip URLs that match), not both. In a pattern * matches anything, and the pattern may match any part of the URL. Additional URLs are always tested.",
    example: "Exclude https://shop.example.com/logout* so the scan does not sign itself out.",
  },
  // src: RabbitMQ/dast_worker/helpers/agent/main.py:350-375, backend/utilities/scan/estimate_scan.py:193 — the estimate crawls the target now; 0.08 credits per URL found
  "dast.cfg.estimate": {
    label: "Estimate scan credits",
    what: "Crawls the target now (real requests to your site) to count the URLs the scan would test, and prices them at 0.08 credits each. Nothing is charged until you start the scan.",
    example: "The crawl finds 60 URLs: 4.8 credits.",
  },

  // ────────────────────────────────────────────────────────────── DAST: automatic profiles (components/dast/DastProfilesTab.tsx, DastScheduleFields.tsx)
  // src: backend/utilities/dast/schemas.py:40-56, backend/utilities/dast/dispatch.py:115-121 — profile title; each run is titled "<title> (<trigger>)"
  "dast.profile.title": {
    label: "Profile title",
    what: "A name for this saved DAST setup. Each run it starts appears in the scan list as \"<title> (<how it started>)\".",
    example: "Shop staging nightly.",
  },
  // src: backend/routers/dast_profiles.py:112-155, backend/routers/dast_profiles.py:253-274, backend/utilities/dast/beat.py:71, backend/routers/cicd.py:88, backend/utilities/dast/dispatch.py:84-121 — saved settings run by schedule, Run now or CI; each run is a new scan charged up front
  "dast.profile.form": {
    label: "DAST profile",
    what: "Saved DAST settings (target, sign-in, limits, schedule) that can run without you: on its schedule, with Run now, or from your CI pipeline. Each run becomes a new scan in the list and is charged Max URLs x 0.08 credits when it starts.",
    example: "A profile for staging that runs every night at 02:00 IST.",
  },
  // src: backend/routers/dast_profiles.py:253-274, backend/utilities/dast/dispatch.py:89-90, backend/utilities/dast/schedule.py:1 — Run now; skipped while a run is in flight; next run in IST
  "dast.profile.list": {
    label: "Saved profiles",
    what: "Your team's DAST profiles with their schedule, next run (IST) and last scan. Run now starts a new scan at once; a run is skipped while the profile's previous run is still in progress.",
    example: "\"Shop staging · daily 02:00 IST · next 12 Nov 2026, 02:00 am IST\".",
  },
  // src: frontend/components/dast/DastScheduleFields.tsx:190-215, backend/utilities/dast/schemas.py:37 — the five selects write the cron expression
  "dast.profile.cron_builder": {
    label: "Visual cron builder",
    what: "Pick minute, hour, day, month and weekday from lists; the builder writes the matching cron expression below. Every means any value.",
    example: "Minute 0, Hour 9, Weekday Monday gives 0 9 * * 1.",
  },
  // src: backend/utilities/dast/schemas.py:46, backend/utilities/dast/credits.py:4-6, backend/utilities/dast/dispatch.py:103 — 1-10,000; every run is charged max_urls x 0.08 up front
  "dast.profile.max_urls": {
    label: "Max URLs",
    what: "The most pages a run crawls and tests, from 1 to 10,000. An automatic run is charged Max URLs x 0.08 credits when it starts (no estimate crawl), whatever it then finds.",
    example: "200 URLs: each run costs 16 credits.",
  },
  // src: backend/utilities/dast/dispatch.py:84-88, backend/utilities/dast/schemas.py:55 — runs refused without consent
  "dast.profile.consent": {
    label: "Authorization",
    what: "Confirms you are allowed to attack-test this target. A DAST scan sends real attack payloads; without this confirmation the profile cannot be saved or run.",
    example: "Tick it for your own staging site, never for a third-party site.",
  },
  // src: backend/utilities/dast/schedule.py:1-24, backend/utilities/dast/dispatch.py:89-90 — next_run_at computed in Asia/Kolkata; a run in flight makes the next one skip
  "dast.profile.schedule": {
    label: "Schedule",
    what: "When the profile runs by itself: off, hourly, every N hours, daily, weekdays, weekly, monthly, once, or a cron expression. Times are India Standard Time. A run is skipped if the previous one is still in progress.",
    example: "Weekdays at 02:00 IST.",
  },
  // src: backend/utilities/dast/schemas.py:33, backend/utilities/dast/schedule.py:1 — 1 to 24 hours
  "dast.profile.interval": {
    label: "Every N hours",
    what: "Hours between runs, from 1 to 24 (IST clock).",
    example: "6 runs four times a day.",
  },
  // src: backend/utilities/dast/schemas.py:34, backend/utilities/dast/schedule.py:1 — 0-6 weekday
  "dast.profile.weekday": {
    label: "Weekday",
    what: "The day of the week a weekly schedule runs on (IST).",
    example: "Sunday.",
  },
  // src: backend/utilities/dast/schemas.py:35 — 1 to 28, so every month has the day
  "dast.profile.monthday": {
    label: "Day of month",
    what: "The day a monthly schedule runs on, from 1 to 28 so that every month has it (IST).",
    example: "1 runs on the first of each month.",
  },
  // src: backend/utilities/dast/schemas.py:36, backend/utilities/dast/schedule.py:1 — a single run at that IST time
  "dast.profile.once_at": {
    label: "Run at",
    what: "The date and time (IST) of a single run.",
    example: "15 Nov 2026, 23:00.",
  },
  // src: backend/utilities/dast/schemas.py:32, backend/utilities/dast/schedule.py:26-34 — HH:MM, clamped to 00:00-23:59
  "dast.profile.times": {
    label: "Fire times",
    what: "The times of day (24-hour HH:MM, IST) the schedule runs. You can add several.",
    example: "02:00 and 14:00.",
  },
  // src: backend/utilities/dast/schemas.py:37, backend/utilities/dast/schedule.py:1 — 5-field cron evaluated in IST, 0 = Sunday
  "dast.profile.cron": {
    label: "Cron expression",
    what: "A 5-field cron expression (minute, hour, day of month, month, day of week) evaluated in IST, with 0 = Sunday. The builder above fills it for you.",
    example: "0 9 * * 1-5 runs at 09:00 IST Monday to Friday.",
  },

  // ────────────────────────────────────────────────────────────── DAST: list page (app/[team_id]/dast/page.tsx)
  // src: backend/utilities/dashboard/scan_list.py:216, backend/utilities/dashboard/scan_list.py:291 — successful DAST scans
  "dast.kpi.total_scans": {
    label: "Total scans",
    what: "DAST scans of this team that finished successfully, manual and automatic.",
    example: "A nightly profile that ran 7 times adds 7.",
  },
  // src: backend/utilities/dashboard/scan_list.py:251-256, backend/utilities/dashboard/scan_list.py:284-295 — stored findings of DAST scans by impact
  "dast.kpi.severity": {
    label: "Findings by severity",
    what: "Findings of all DAST scans with this severity (Critical, High, Medium or Low), counted from the stored findings. A finding without a severity counts as Low.",
    example: "Total high 4: four High findings across all runs.",
  },
  // src: backend/utilities/dashboard/scan_list.py:104, backend/utilities/dashboard/scan_list.py:257-259, backend/utilities/dashboard/scan_list.py:288 — 10 / 7.5 / 5 / 2.5 per finding, averaged
  "dast.kpi.avg_risk": {
    label: "Avg risk score",
    what: "Average over all DAST findings, 0 to 10: each Critical counts 10, High 7.5, Medium 5, Low 2.5.",
    example: "One High and one Low: (7.5 + 2.5) / 2 = 5.0.",
  },
  // src: backend/utilities/dashboard/scan_list.py:251-256, backend/utilities/dashboard/scan_list.py:299 — totals per impact
  "dast.chart.severity": {
    label: "Severity Distribution",
    what: "All DAST findings by severity: Critical, High, Medium, Low.",
    example: "Critical 0, High 4, Medium 9, Low 12.",
  },
  // src: backend/utilities/dashboard/scan_list.py:234-248 — successful scans' findings on the scan's creation date (UTC)
  "dast.chart.over_time": {
    label: "Issues Over Time",
    what: "Findings of successful DAST scans by severity, on the day (UTC) each scan was created.",
    example: "A nightly run on 7 Nov with 2 Medium findings adds 2 to Medium on 7 Nov.",
  },
  // src: backend/utilities/dashboard/scan_list.py:88-101, backend/utilities/dashboard/scan_list.py:271-273, backend/utilities/dashboard/scan_list.py:301 — 12 categories
  "dast.chart.posture": {
    label: "Security Posture Overview",
    what: "Findings in 12 web-security categories: injection, XSS and client side, authentication, authorization, session and state, file and resource, server-side execution, information disclosure, crypto and transport, security headers, API security, denial of service.",
    example: "Security headers 8: eight findings about missing or weak headers.",
  },
  // src: backend/utilities/dashboard/scan_list.py:69-80, backend/utilities/dashboard/scan_list.py:266-269, backend/utilities/dashboard/scan_list.py:302 — the ten OWASP 2021 keys
  "dast.chart.owasp": {
    label: "OWASP Top 10",
    what: "Findings per OWASP Top 10 (2021) category, A01 to A10. A finding mapped to two categories counts in both.",
    example: "A03 Injection 3, A05 Security Misconfiguration 6.",
  },
  // src: backend/utilities/dashboard/scan_list.py:81-87, backend/utilities/dashboard/scan_list.py:274-276, backend/utilities/dashboard/scan_list.py:303-306 — five categories, mean of 10/7.5/5/2.5
  "dast.chart.risk_by_category": {
    label: "Average Risk Score per Category",
    what: "The average risk score (Critical 10, High 7.5, Medium 5, Low 2.5) of the findings in five categories: injection, XSS and client side, authentication, authorization, session and state.",
    example: "Injection 8.8: the injection findings are mostly Critical or High.",
  },
  // src: backend/utilities/dashboard/scan_list.py:103, backend/utilities/dashboard/scan_list.py:278-282, backend/utilities/dashboard/scan_list.py:307-310 — by the scanner's confidence; missing counts as low
  "dast.chart.risk_by_confidence": {
    label: "Average Risk Score per Confidence",
    what: "The average risk score of findings grouped by how sure the scanner is that each one is real: high, medium or low confidence (unknown counts as low).",
    example: "High confidence 7.5: the certain findings are mostly High.",
  },
  // src: backend/utilities/dashboard/scan_list.py:102, backend/utilities/dashboard/scan_list.py:261-264, backend/utilities/dashboard/scan_list.py:311 — references to PCI DSS, ISO 27001-27004
  "dast.chart.compliance": {
    label: "Compliance Violations",
    what: "How many compliance-control references the findings have for PCI DSS and ISO 27001, 27002, 27003 and 27004.",
    example: "PCI DSS 5: findings map to five PCI DSS controls in total.",
  },
  // src: backend/utilities/db/scan_list_item.py:381-390 — counts per impact of a successful scan
  "dast.table.vulns": {
    label: "Vulnerabilities",
    what: "This scan's findings by severity: Critical (red), High (orange), Medium (amber), Low (blue). Counted once the scan succeeded.",
    example: "0 red, 1 orange, 3 amber, 5 blue.",
  },
  // src: backend/utilities/db/scan_list_item.py:429 — target_url from the settings of the scan
  "dast.table.target": {
    label: "Target URL",
    what: "The site this scan tested.",
    example: "https://staging.shop.example.com.",
  },
  // src: backend/utilities/db/scan_list_item.py:392-402, RabbitMQ/dast_worker/helpers/crawler/crawler.py:40-71 — URLs the crawler kept for testing
  "dast.table.urls": {
    label: "URLs scanned",
    what: "How many URLs the scan tested: the pages the crawler kept after your patterns, plus the additional URLs.",
    example: "48 URLs tested.",
  },
  // src: backend/utilities/db/scan_list_item.py:432, RabbitMQ/dast_worker/helpers/crawler/crawler.py:79-106 — tested / (tested + dropped by the patterns)
  "dast.table.coverage": {
    label: "Coverage %",
    what: "Tested URLs as a share of all crawled URLs, after your include or exclude patterns dropped some. 100% when no pattern removed anything.",
    example: "45 tested, 5 excluded by a pattern: 90.0%.",
  },
} as const satisfies Record<string, InfoTipEntry>;

export type InfoTipId = keyof typeof INFO_TIPS;
