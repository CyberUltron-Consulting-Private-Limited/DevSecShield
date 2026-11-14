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
 *  - Where a product bug is being fixed in parallel, the text describes the fixed behaviour and the `// src:` note
 *    names the issue ("fixed by #47"); such an entry is true once that fix is merged, which PR #38 waits for.
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
  // src: backend/new_models.py:131, frontend/utils/datetime.ts:6-7 — stored in UTC, shown in IST; the browser reads the API's offset-less UTC time as local time until #48 is fixed (T3b)
  "scan.table.created": {
    label: "Created at",
    what: "When the scan was created. Times are shown in India Standard Time (IST).",
    example: "9 Aug 2026, 07:30 pm IST.",
  },
  // src: backend/utilities/celery/celery_connection.py:182, backend/utilities/celery/celery_connection.py:200-215, frontend/utils/datetime.ts:6-7 — set on a status or progress change; status polls without a change and chat messages stop moving it with #47 (T3a); IST with #48 (T3b)
  "scan.table.updated": {
    label: "Last updated",
    what: "The last time this scan's status or progress changed: it was queued, started, progressed, finished, failed or was cancelled. Opening the scan list or chatting with the results does not change it. Shown in India Standard Time (IST).",
    example: "A scan that finished yesterday still shows yesterday after you chat with its results today.",
  },
  // src: backend/routers/scans.py:461-472, backend/new_models.py:122, backend/utilities/db/scan_list_item.py:67, backend/utilities/celery/celery_connection.py:186-192, backend/utilities/scan/cancel_scan.py:1-8 — credit_consumed is the estimate (set by /estimate before any charge; credit_charged is separate), charged at start, refunded on failure or cancel
  "scan.table.credits": {
    label: "Credits",
    what: "The scan's credit estimate. It is charged when the scan starts and refunded if the scan fails or is cancelled. A scan that was only estimated, and never started, has not been charged.",
    example: "12.4 on a finished scan: 12.4 credits left the balance when it started.",
  },
  // src: backend/routers/scans.py:150-153, backend/utilities/db/scan_list_item.py:68-69 — owner_user_id is the user who created the scan
  "scan.table.owner": {
    label: "Owner",
    what: "The team member who created the scan.",
    example: "Priya Shah, priya@acme.com.",
  },
  // src: backend/routers/scans.py:620-637, backend/routers/scans.py:474-479, backend/utilities/celery/celery_connection.py:186-192, backend/utilities/scan/cancel_scan.py:1-8 — start re-estimates; a changed price answers 409 estimate_changed and charges nothing; failure and cancel refund
  "scan.cfg.run": {
    label: "Run scan",
    what: "Starts the scan and charges the estimated credits. The start prices the scan again first: if the price changed (another file, repository, branch or option), nothing is charged and you see the new price; press Start scan again to accept it. Failed and cancelled scans are refunded.",
    example: "Estimate 3.2 credits, press Start scan: 3.2 credits leave the team balance.",
  },

  // ────────────────────────────────────────────────────────────── repository source (components/repository-card.tsx)
  // src: RabbitMQ/worker/helpers/context/scan_context.py:162-173, RabbitMQ/worker/helpers/context/git_hosts.py:8-14 — a zip or a clone of GitHub/GitLab/Bitbucket
  "repo.source": {
    label: "Repository",
    what: "Where the code comes from: a .zip you upload, or a repository on GitHub, GitLab or Bitbucket that the scan worker clones. Use one of them.",
    example: "Upload payments-api.zip, or connect https://github.com/acme/payments-api.",
  },
  // src: backend/utilities/scan/format_input.py:44-52, RabbitMQ/worker/helpers/context/scan_context.py:175-216, backend/utilities/scan/credit_estimate.py:8-10 — upload capped at 50 MB (413); unpacked at most 2 GB and 50,000 zip entries (folders count); the estimate is bound to the file's size and SHA-256
  "repo.zip": {
    label: "Zip file",
    what: "A .zip of your source code, scanned instead of a repository: at most 50 MB to upload, and it may unpack to at most 2 GB and 50,000 entries (files and folders). The credit estimate is for this exact file: a different file is priced again when the scan starts.",
    example: "payments-api.zip made with \"git archive --format=zip -o payments-api.zip HEAD\".",
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
  // src: RabbitMQ/worker/helpers/tools/sast_agent/main.py:51-92, RabbitMQ/worker/helpers/context/codebase_context.py:114-141 — the language's files minus built-in and custom exclusions; matched on whole names inside the repository (not the /tmp clone path) once #45 and #37 are fixed (T3a)
  "sast.cfg.scope": {
    label: "Scan scope",
    what: "Which files are analysed: the files of the chosen language, minus the language's built-in exclusions (folders such as node_modules, dist and build for JavaScript; vendor and tmp for Ruby) and minus the patterns you add here. Exclusions are matched on folder and file names inside your repository.",
    example: "Add \"tests\" to leave every tests folder out.",
  },
  // src: RabbitMQ/worker/helpers/context/codebase_context.py:114-141, RabbitMQ/worker/helpers/tools/sast_agent/main.py:91-92 — whole names, every segment used, path inside the repository: the behaviour #37 and #45 fix (T3a)
  "sast.cfg.exclude": {
    label: "Exclude path patterns",
    what: "Each pattern is one or more folder or file names, one per box, matched as whole names on the path inside your repository. One name skips every folder or file with that name, at any depth; several names skip the path where they appear one after another. Skipped files are not analysed and not charged.",
    example: "\"vendor\" skips every vendor folder but not vendors; \"src\" / \"legacy\" skips src/legacy.",
  },
  // src: RabbitMQ/worker/helpers/tools/sast_agent/main.py:51-83 — one file extension per language; Ruby files are analysed once #45 (the built-in "tmp" exclusion matched the /tmp clone path) is fixed (T3a)
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
  // src: backend/utilities/dashboard/scan_list.py:668-669, backend/utilities/celery/celery_connection.py:125-133, backend/utilities/dashboard/scan_list.py:690-779 — status success: results stored; findings charts use success only (Scans Per Day, Status and Remediation use every scan)
  "sast.kpi.success": {
    label: "Success",
    what: "SAST scans that finished and stored their findings. Only these feed the findings charts (severity, risk, category, language and top repositories).",
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
  // src: backend/utilities/dashboard/scan_list.py:676-677, backend/utilities/celery/celery_connection.py:200-215 — last_updated date equals today's UTC date; polls without a change and chat stop moving last_updated with #47 (T3a)
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
  // src: backend/utilities/dashboard/scan_list.py:663-673 — five buckets: pending, started, success, failure, not_started; cancelled and retry scans are in none
  "sast.chart.status": {
    label: "Scan Status Breakdown",
    what: "SAST scans of this team by their current status: Success, Started, Pending, Failure and Not started. Cancelled scans and scans being retried are not shown.",
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
  // src: backend/utilities/dashboard/remediation_metrics.py:30, backend/utilities/dashboard/remediation_metrics.py:55-69, frontend/app/[team_id]/sast/page.tsx:1006 — fixed_at/ignored_at date >= today - 7 days (UTC): 8 dates; target 20
  "sast.remed.velocity": {
    label: "Remediation Velocity",
    what: "Findings marked Fixed or Ignored today or on the 7 dates before it (UTC), so over up to 8 calendar days. The target is 20 a week.",
    example: "On Wednesday 12 Nov: 12 fixed and 3 ignored since Wednesday 5 Nov gives 15/week.",
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
  // src: backend/utilities/db/scan_list_item.py:71, frontend/app/[team_id]/sast/page.tsx:1609-1613 — repo_url from the scan's settings; a zip upload shows "Zip file" once #49 returns zip_file_used for SAST rows (T3a)
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
  // src: RabbitMQ/worker/helpers/tools/iac_agent/main.py:56-88, RabbitMQ/worker/helpers/context/codebase_context.py:56-82, RabbitMQ/worker/helpers/context/codebase_context.py:114-141, RabbitMQ/worker/helpers/context/codebase_context.py:228-233 — no pattern: every file of the formats; patterns and extensions of all formats are merged (Terraform adds .tf patterns): bug reported to the coordinator, issue not yet filed; whole-name matching inside the repository: #37 (T3a)
  "iac.cfg.include": {
    label: "Include path patterns",
    what: "Only files of this format whose path inside your repository matches one of these patterns are analysed. Each pattern is one or more whole folder or file names, one per box, that appear one after another. No pattern means every file of the format, but the patterns of all formats in the scan are combined: next to Terraform, give each other format a pattern.",
    example: "\"charts\" includes every charts folder; \"deploy\" / \"k8s\" includes deploy/k8s.",
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
  // src: backend/utilities/dashboard/scan_list.py:958-960, backend/utilities/dashboard/scan_list.py:1079, RabbitMQ/worker/helpers/tools/sca_sbom_agent/merge_inventory.py:109-122 — vulnerabilities of successful scans; inventory-only rows (packages with no known vulnerability) leave the counts with #46 (T3a)
  "sbom.kpi.total": {
    label: "Total Vulnerabilities",
    what: "Known vulnerabilities in your dependencies found by all successful SCA + SBOM scans of this team, added up. Packages with no known vulnerability are listed in each scan's SBOM but not counted here.",
    example: "Two scans with 10 and 4 vulnerabilities: 14, however many packages they listed.",
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
  // src: backend/utilities/dashboard/scan_list.py:975-976, backend/utilities/dashboard/scan_list.py:1074-1082 — medium + high risk license categories, over findings only once #46 drops inventory-only rows (T3a)
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
  // src: backend/utilities/dashboard/scan_list.py:1019-1021, backend/utilities/dashboard/scan_list.py:1077 — each finding scores weight/4*10, averaged, Python round(x, 1); over vulnerabilities only once #46 drops inventory-only rows (T3a)
  "sbom.kpi.avg_risk": {
    label: "Avg Risk Score",
    what: "Average over all vulnerabilities found by successful scans, 0 to 10: Critical counts 10, High 7.5, Medium 5, Low 2.5. Rounded to one decimal.",
    example: "1 High and 1 Low: (7.5 + 2.5) / 2 = 5.0.",
  },
  // src: backend/utilities/dashboard/scan_list.py:999-1002, backend/utilities/dashboard/sbom_license.py:382-392, RabbitMQ/worker/helpers/context/schema.py:34, RabbitMQ/worker/helpers/tools/sca_sbom_agent/main.py:137-158, RabbitMQ/worker/helpers/tools/sca_sbom_agent/parser.py:128-155 — reachability is a label the AI model sets from the Grype match text (id, severity, description, package, fix, locations); no source file is in its context
  "sbom.kpi.reachable": {
    label: "Reachable Issues",
    what: "Vulnerabilities the AI model labelled Reachable. It judges from the vulnerability and package data (description, severity, where the package was found); it does not read your code, so treat the label as a hint.",
    example: "A CVE in a web framework's request parser may be labelled Reachable although your code never uses that parser.",
  },
  // src: backend/utilities/dashboard/scan_list.py:1030-1037, backend/utilities/dashboard/finding_metrics.py:18-40 — stored findings by status
  "sbom.chart.remediation": {
    label: "Remediation Actions Required",
    what: "All stored findings of SCA + SBOM scans by the status your team set: Fixed, In progress, Not started, Ignored.",
    example: "40 findings: 10 Fixed, 5 In progress, 22 Not started, 3 Ignored.",
  },
  // src: backend/utilities/dashboard/scan_list.py:988-998, backend/utilities/dashboard/scan_list.py:1038-1043 — totals per impact; Low stops counting inventory-only packages with #46 (T3a)
  "sbom.chart.severity": {
    label: "Severity Distribution",
    what: "Findings of successful scans by severity: Critical, High, Medium and Low.",
    example: "Critical 2, High 9, Medium 15, Low 4.",
  },
  // src: backend/utilities/dashboard/scan_list.py:1044-1056, backend/utilities/dashboard/sbom_license.py:382-392, RabbitMQ/worker/helpers/context/schema.py:34 — the AI model's label (no code in its context); missing counts as Not assessed; inventory-only packages (stored Not reachable) leave the chart with #46 (T3a)
  "sbom.chart.reachability": {
    label: "Reachability Distribution",
    what: "Vulnerabilities by the reachability label the AI model gave each one from the vulnerability and package data (it does not read your code): Reachable, Potentially reachable, Not reachable, or Not assessed (no label).",
    example: "A CVE in a package found only in a test lock file is often labelled Not reachable.",
  },
  // src: backend/utilities/dashboard/scan_list.py:986, backend/utilities/dashboard/scan_list.py:1024-1028 — per creation date (UTC) of each successful scan; Low stops counting inventory-only packages with #46 (T3a)
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
  // src: backend/utilities/db/scan_list_item.py:152-161 — counts per impact of a successful scan; inventory-only packages (stored as Low) leave the counts with #46 (T3a)
  "sbom.table.vulns": {
    label: "Vulnerabilities",
    what: "This scan's vulnerable dependencies by severity: Critical (red), High (orange), Medium (amber), Low (blue). Counted once the scan succeeded.",
    example: "0 red, 3 orange, 6 amber, 1 blue.",
  },
  // src: backend/utilities/db/scan_list_item.py:171-173, frontend/app/[team_id]/sbom_sca/page.tsx:113-116 — weighted average scaled to 0-10 (/4*10, as SAST) with #35 (T3b); no score (None) when there is no vulnerability with #46 (T3a)
  "sbom.table.risk": {
    label: "Risk score",
    what: "This scan's severity-weighted average, 0 to 10: Critical 10, High 7.5, Medium 5, Low 2.5, averaged over its vulnerabilities. Empty when it found none.",
    example: "1 High and 1 Low: (7.5 + 2.5) / 2 = 5.0.",
  },
  // src: frontend/app/[team_id]/sbom_sca/page.tsx:118-125 — tiers on the 0-10 Risk score column once #35 scales it (T3b); scans without vulnerabilities have no score once #46 returns None (T3a)
  "sbom.filter.risk": {
    label: "Risk score filter",
    what: "Shows only scans whose risk score (0 to 10) is in a tier: Critical 9 or more, High 7 to 9, Medium 5 to 7, Low under 5. Scans without vulnerabilities have no score and are hidden by any tier.",
    example: "High keeps a scan scored 7.5 and hides one scored 9.2.",
  },
  // src: frontend/app/[team_id]/sbom_sca/page.tsx:699-712 — sorts the loaded rows; missing values count as -1
  "sbom.filter.sort": {
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

  // ────────────────────────────────────────────────────────────── results views, shared (components/SASTResults.tsx, SbomResults.tsx, finding-selection-menu.tsx)
  // src: backend/utilities/dashboard/scan_metadata.py:73-101, backend/utilities/dashboard/scan_metadata.py:120-124 — repo_url from the scan's settings
  "results.meta.repository": {
    label: "Repository",
    what: "The address of the repository this scan cloned. Hover for the full address when it is cut short.",
    example: "https://github.com/acme/payments-api.",
  },
  // src: backend/utilities/dashboard/scan_metadata.py:76-77, backend/utilities/dashboard/scan_metadata.py:122-123, RabbitMQ/worker/helpers/context/scan_context.py:89 — the branch from the scan's settings (SAST shows main when none was given)
  "results.meta.branch": {
    label: "Branch",
    what: "The branch that was cloned and scanned. A zip upload or an uploaded SBOM file has no branch, so the card is not shown for them.",
    example: "release/2026.11.",
  },
  // src: backend/utilities/dashboard/scan_metadata.py:75, backend/utilities/dashboard/scan_metadata.py:13, frontend/components/SbomResults.tsx:1104 — zip_file_used, sbom_file_used (SCA + SBOM), else a repository
  "results.meta.source": {
    label: "Source",
    what: "Where the scanned input came from: a repository that was cloned, a ZIP upload, or (SCA + SBOM only) an SBOM file you uploaded.",
    example: "ZIP upload for a scan started from payments-api.zip.",
  },
  // src: backend/utilities/db/findings.py:29-42, backend/utilities/celery/create_findings.py:10-48, backend/routers/scans.py:1189-1240 — the scan's stored findings, one per row, each with a status the team sets
  "results.findings": {
    label: "Findings",
    what: "This scan's findings, one per row, each with a status your team sets. Click a title for the details; select rows to file Jira tickets; use Action to set a finding's status.",
    example: "\"SQL injection in orders.py\", High, Not started.",
  },
  // src: frontend/components/SASTResults.tsx:724-725, frontend/components/SbomResults.tsx:630-631 — exact match on the finding's impact
  "results.filter.impact": {
    label: "Impact filter",
    what: "Shows only the findings of one impact (severity): Critical, High, Medium or Low. It filters the findings already loaded in this page.",
    example: "Choose Critical to see only the Critical findings.",
  },
  // src: frontend/components/SASTResults.tsx:786-791, frontend/components/SbomResults.tsx:840-846, backend/routers/scans.py:1137-1160 — selects the rows shown (after search and filters); the selection menu files them in Jira
  "results.select_all": {
    label: "Select all",
    what: "Selects every finding the table shows (after search and filters). The selected findings can then be filed in Jira from the Actions menu above the table.",
    example: "Filter Impact to Critical, select all, then Actions > Create Jira ticket.",
  },
  // src: backend/routers/scans.py:1189-1240, backend/utilities/db/finding_state.py:20-35, backend/utilities/dashboard/remediation_metrics.py:17-90 — fixed sets fixed_at and closes the Jira issue; ignored sets ignored_at; the remediation metrics read these
  "results.finding.action": {
    label: "Action",
    what: "Sets a finding's status. Fixed records when it was fixed and closes its Jira issue, if it has one. Ignored records when it was dismissed. In progress and Not started only change the status. The remediation metrics are computed from these statuses.",
    example: "Mark a false positive Ignored: it leaves the high-priority backlog.",
  },
  // src: backend/new_models.py:130, backend/utilities/db/schemas.py:15-17, backend/routers/scans.py:1216-1235 — finding_status not_started (new), in_progress, fixed, ignored
  "results.table.status": {
    label: "Status",
    what: "The status your team set on this finding: Not started (every finding starts here), In progress, Fixed or Ignored. Change it with Action.",
    example: "In progress while a fix is in review.",
  },
  // src: RabbitMQ/worker/helpers/context/schema.py:18, backend/utilities/db/findings.py:87-105, backend/utilities/db/findings.py:129-153 — impact as stored with the finding
  "results.table.impact": {
    label: "Impact",
    what: "The severity the scan's analysis gave this finding: Critical, High, Medium or Low.",
    example: "High for a vulnerable dependency with a known remote exploit.",
  },
  // src: frontend/components/SASTResults.tsx:643-648, frontend/components/SbomResults.tsx:149-154 — number of entries in the finding's owasp_top_10
  "results.table.owasp": {
    label: "OWASP Top 10",
    what: "How many OWASP Top 10 categories this finding maps to. Click the title to see which.",
    example: "1: A03:2021 Injection.",
  },
  // src: frontend/components/SASTResults.tsx:643-648, frontend/components/SbomResults.tsx:149-154 — number of entries in the finding's compliance_controls
  "results.table.compliance": {
    label: "Compliance controls",
    what: "How many compliance controls (for example PCI DSS requirements or ISO 27001 clauses) this finding maps to. Click the title to see which.",
    example: "3: PCI DSS 6.2.4, ISO 27001 A.8.28 and ISO 27002 8.28.",
  },
  // src: frontend/components/finding-selection-menu.tsx:44-119, backend/routers/scans.py:1108-1160 — one Jira issue per selected stored finding (a finding with an issue keeps it); needs a successful scan, the scan's Jira project and the team's Jira connection
  "results.selection.actions": {
    label: "Actions for the selection",
    what: "Acts on the selected findings. Create Jira ticket files one Jira issue per finding in the project set on this scan's Ticketing integrations tab; a finding that already has an issue is not filed again. Some results pages also set the status of all selected findings here.",
    example: "Select 3 Critical findings, Create Jira ticket: 3 issues in project SEC.",
  },

  // ────────────────────────────────────────────────────────────── SAST: results view (components/SASTResults.tsx)
  // src: backend/utilities/dashboard/scan.py:181-192, frontend/components/SASTResults.tsx:218-231 — findings per OWASP category; each bar relative to the largest
  "sast.res.owasp": {
    label: "OWASP Top 10 metrics",
    what: "This scan's findings per OWASP Top 10 category. Each ring's length is relative to the largest category; hover a ring for its count. A finding mapped to two categories counts in both.",
    example: "Injection 5 is the full ring; Cryptographic Failures 2 is 40% of it.",
  },
  // src: backend/utilities/dashboard/scan.py:170-176, backend/utilities/dashboard/scan.py:203-205 — count per impact
  "sast.res.risk": {
    label: "Risk metrics",
    what: "How many findings of this scan have each impact: Critical, High, Medium and Low.",
    example: "Critical 1, High 4, Medium 7, Low 2.",
  },
  // src: backend/utilities/dashboard/scan.py:207-215, frontend/components/SASTResults.tsx:238-241 — findings per CVE id, top 20
  "sast.res.cves": {
    label: "CVEs per vulnerability",
    what: "For each CVE the analysis linked to a finding, how many of this scan's findings reference it; the 20 most referenced.",
    example: "CVE-2021-44228 referenced by 3 findings.",
  },
  // src: backend/utilities/dashboard/scan.py:194-201, frontend/components/SASTResults.tsx:234-236 — findings per compliance control, all, largest first
  "sast.res.compliance": {
    label: "Compliance Controls Failed count",
    what: "How many of this scan's findings map to each compliance control (for example a PCI DSS requirement), every control, largest first. A finding mapped to three controls counts once for each.",
    example: "PCI DSS 6.2.4: 4 findings.",
  },
  // src: backend/utilities/dashboard/scan.py:220-228, frontend/components/SASTResults.tsx:249-256, frontend/components/SASTResults.tsx:457-462 — control references grouped by standard (text before " - "), share of the total, top 12; icons mark the share
  "sast.res.policy": {
    label: "Policy Violations",
    what: "This scan's compliance-control references grouped by standard, with each standard's share of all references (top 12). It is a share, not a pass rate: the tick or cross only marks how large the share is.",
    example: "6 PCI DSS and 4 ISO 27001 references: PCI DSS 60%, ISO 27001 40%.",
  },
  // src: backend/utilities/dashboard/scan.py:28-33, backend/utilities/dashboard/scan.py:216-218, frontend/components/SASTResults.tsx:260-264 — score by impact (10/7.5/5/2.5), keyed by title, top 24
  "sast.res.risk_scores": {
    label: "Risk scores per finding",
    what: "Each finding's risk score from its impact, on a 0 to 10 scale: Critical 10, High 7.5, Medium 5, Low 2.5. The 24 highest are shown as F1, F2…; hover for the title. Findings with the same title appear once.",
    example: "F1 \"SQL injection in orders.py\" 10.",
  },
  // src: backend/utilities/dashboard/scan.py:231-232, backend/utilities/dashboard/remediation_metrics.py:17-90 — from the status of this scan's findings
  "sast.res.remed.section": {
    label: "Remediation Metrics",
    what: "Measured from the status your team sets on this scan's findings (Not started, In progress, Fixed, Ignored). The targets are fixed goals shown for comparison.",
    example: "Mark a finding Fixed in the table below and these numbers update.",
  },
  // src: backend/utilities/dashboard/remediation_metrics.py:43-80, frontend/components/SASTResults.tsx:545-547 — mean of (fixed_at or ignored_at - created_at); target 3 days
  "sast.res.remed.mttr": {
    label: "Mean Time to Remediate",
    what: "Average time from when this scan's findings were recorded to when they were marked Fixed or Ignored. The target is 3 days.",
    example: "One finding fixed after 2 days and one ignored after 4 days: 3.0 days.",
  },
  // src: backend/utilities/dashboard/remediation_metrics.py:47-49, backend/utilities/dashboard/scan.py:203-205, frontend/components/SASTResults.tsx:569-574 — fixed critical / all critical findings of the scan; target 95%
  "sast.res.remed.critical_fixed": {
    label: "Critical Issues Fixed",
    what: "This scan's Critical findings marked Fixed, as a percentage of all its Critical findings. Ignored findings do not count as fixed. The target is 95%.",
    example: "4 Critical findings, 3 marked Fixed: 75%.",
  },
  // src: backend/utilities/dashboard/remediation_metrics.py:38-40, frontend/components/SASTResults.tsx:594-595 — critical or high and not fixed/ignored; target 10
  "sast.res.remed.backlog": {
    label: "High Priority Backlog",
    what: "This scan's Critical and High findings that are not yet marked Fixed or Ignored. The target is 10 or fewer.",
    example: "12 open Critical/High findings: 2 above target.",
  },
  // src: backend/utilities/dashboard/remediation_metrics.py:30, backend/utilities/dashboard/remediation_metrics.py:55-69, frontend/components/SASTResults.tsx:615-616 — fixed_at/ignored_at date >= today - 7 days (UTC): 8 dates; target 20
  "sast.res.remed.velocity": {
    label: "Remediation Velocity",
    what: "This scan's findings marked Fixed or Ignored today or on the 7 dates before it (UTC), so over up to 8 calendar days. The target is 20 a week.",
    example: "5 fixed and 1 ignored since last Wednesday: 6/week.",
  },
  // src: backend/utilities/dashboard/scan_metadata.py:79-99, RabbitMQ/worker/helpers/context/codebase_context.py:210-213 — included / (included + excluded) documents of the language
  "sast.res.coverage": {
    label: "Code coverage",
    what: "Share of the chosen language's source files that were analysed: analysed files divided by analysed plus excluded files. Exclusions are the language's built-in ones and your patterns.",
    example: "180 files analysed and 20 excluded: 90.0%.",
  },
  // src: backend/utilities/dashboard/scan_metadata.py:79-99 — len(included) / len(included) + len(excluded)
  "sast.res.files": {
    label: "Files scanned",
    what: "Files analysed / files of the chosen language in the repository (analysed plus excluded). Files of other languages are not counted.",
    example: "180 / 200: 20 files were excluded by patterns.",
  },
  // src: frontend/components/SASTResults.tsx:710-721 — case-insensitive match on title, description, impact, status, suggested fix and location of the loaded findings
  "sast.res.search": {
    label: "Search findings",
    what: "Shows only the findings whose title, description, impact, status, suggested fix or location contains this text (upper or lower case does not matter).",
    example: "\"orders.py\" keeps the findings located in orders.py.",
  },
  // src: backend/utilities/db/findings.py:44-49, backend/utilities/db/findings.py:96, frontend/components/SASTResults.tsx:692-698 — the per-finding score is 1-4 (impact), the tiers are 0-10, so only Low matches; bug reported to the coordinator, issue not yet filed
  "sast.res.filter.risk": {
    label: "Risk score filter",
    what: "Shows only findings whose risk score is in a tier: Critical 9 or more, High 7 to 9, Medium 5 to 7, Low under 5. Today a SAST finding's score is 1 to 4, so Low keeps every finding and the other tiers none (a known bug); filter by Impact instead.",
    example: "To list the Critical findings, choose Critical in the Impact filter.",
  },
  // src: frontend/components/SASTResults.tsx:1181-1182, frontend/components/SASTResults.tsx:1341-1363 — description cut to 80 characters; the dialog shows description, location, suggested fix and snippet
  "sast.res.description": {
    label: "Description",
    what: "The analysis's explanation of the issue, cut to 80 characters; hover for the whole text, or click the title for the description, location, code snippet and suggested fix.",
    example: "\"User input from the order form reaches a SQL query in orders.py without parame…\" (hover for the rest).",
  },
  // src: backend/utilities/db/findings.py:44-49, backend/utilities/db/findings.py:96, frontend/components/SASTResults.tsx:1222-1229 — risk_score_map: low 1 … critical 4
  "sast.res.table.risk": {
    label: "Risk score",
    what: "This finding's risk score, set by its impact: Critical 4, High 3, Medium 2, Low 1. The Risk scores per finding chart shows the same findings on a 0 to 10 scale.",
    example: "4 for a Critical finding.",
  },
  // src: frontend/components/SASTResults.tsx:1187, frontend/components/SASTResults.tsx:643-648 — number of CVE ids on the finding
  "sast.res.table.cves": {
    label: "CVE count",
    what: "How many CVE identifiers the analysis linked to this finding. Click the title to see them.",
    example: "1 for a finding about a vulnerable Log4j call.",
  },

  // ────────────────────────────────────────────────────────────── SCA + SBOM: results view (components/SbomResults.tsx)
  // src: backend/utilities/dashboard/scan.py:857-858, RabbitMQ/worker/helpers/tools/sca_sbom_agent/merge_inventory.py:109-122 — len(results) of this scan; inventory-only rows (packages with no known vulnerability) leave the counts with #46 (T3a, per-scan dashboard included)
  "sbom.res.kpi.total": {
    label: "Total vulnerabilities",
    what: "Known vulnerabilities this scan found in your dependencies. Packages with no known vulnerability are listed in the bill of materials below but not counted here.",
    example: "12 vulnerabilities in a repository with 340 packages.",
  },
  // src: backend/utilities/dashboard/scan.py:840-842, backend/utilities/dashboard/scan.py:858 — impact critical
  "sbom.res.kpi.critical": {
    label: "Critical",
    what: "Of those, the vulnerabilities rated Critical.",
    example: "A remote-code-execution CVE in a direct dependency.",
  },
  // src: backend/utilities/dashboard/scan.py:849-853 — number of compliance-control entries over all results
  "sbom.res.kpi.policy": {
    label: "Policy violations",
    what: "How many compliance-control references (PCI DSS, ISO 27001 and others) this scan's vulnerabilities map to, added up.",
    example: "One vulnerability mapped to 2 controls and one to 3: 5.",
  },
  // src: backend/utilities/dashboard/scan.py:860-864, backend/utilities/dashboard/scan.py:95-97 — medium + high risk license categories; vulnerabilities only with #46 (T3a)
  "sbom.res.kpi.license_risks": {
    label: "License risks",
    what: "Vulnerabilities whose package has a medium-risk license (weak copyleft such as LGPL or MPL, Creative Commons, commercial) or a high-risk one (strong copyleft such as GPL, network copyleft such as AGPL, source-available such as SSPL or BUSL).",
    example: "A vulnerable package under LGPL-3.0 counts here.",
  },
  // src: backend/utilities/dashboard/scan.py:865-869, backend/utilities/dashboard/scan.py:96 — strong copyleft, network copyleft, source-available
  "sbom.res.kpi.high_risk_licenses": {
    label: "High-risk licenses",
    what: "Vulnerabilities whose package is under a strong copyleft (GPL), network copyleft (AGPL) or source-available (SSPL, BUSL) license.",
    example: "A vulnerable package licensed AGPL-3.0.",
  },
  // src: backend/utilities/dashboard/scan.py:28-33, backend/utilities/dashboard/scan.py:853-859 — mean of 10/7.5/5/2.5 per result, Python round(x, 1); vulnerabilities only with #46 (T3a)
  "sbom.res.kpi.avg_risk": {
    label: "Avg risk score",
    what: "Average over this scan's vulnerabilities, 0 to 10: Critical counts 10, High 7.5, Medium 5, Low 2.5. Rounded to one decimal.",
    example: "1 High and 1 Low: (7.5 + 2.5) / 2 = 5.0.",
  },
  // src: backend/utilities/dashboard/scan.py:843-846, RabbitMQ/worker/helpers/context/schema.py:34, RabbitMQ/worker/helpers/tools/sca_sbom_agent/main.py:137-158 — the AI model's label; no source file in its context
  "sbom.res.kpi.reachable": {
    label: "Reachable issues",
    what: "Vulnerabilities the AI model labelled Reachable. It judges from the vulnerability and package data (description, severity, where the package was found); it does not read your code, so treat the label as a hint.",
    example: "A CVE in a web framework's request parser may be labelled Reachable although your code never uses that parser.",
  },
  // src: backend/utilities/dashboard/scan.py:871-879, backend/utilities/dashboard/finding_metrics.py:18-40, frontend/components/SbomResults.tsx:246-250 — stored findings of the scan by status, share of all; vulnerabilities only with #46 (T3a)
  "sbom.res.remediation": {
    label: "Remediation actions",
    what: "This scan's findings by the status your team set (Fixed, In progress, Not started, Ignored), each as a count and a share of all its findings.",
    example: "10 findings: 2 Fixed (20%), 1 In progress, 7 Not started.",
  },
  // src: backend/utilities/dashboard/scan.py:837-839, backend/utilities/dashboard/scan.py:953 — count per impact; Low stops counting inventory-only packages with #46 (T3a)
  "sbom.res.severity": {
    label: "Severity distribution",
    what: "How many of this scan's vulnerabilities have each impact: Critical, High, Medium and Low.",
    example: "Critical 1, High 3, Medium 6, Low 2.",
  },
  // src: backend/utilities/dashboard/scan.py:843-844, backend/utilities/dashboard/scan.py:881-896, RabbitMQ/worker/helpers/context/schema.py:34 — the AI model's label; missing counts as Not assessed; inventory-only rows leave it with #46 (T3a)
  "sbom.res.reachability": {
    label: "Reachability distribution",
    what: "This scan's vulnerabilities by the reachability label the AI model gave each one from the vulnerability and package data (it does not read your code): Reachable, Potentially reachable, Not reachable, or Not assessed (no label).",
    example: "A CVE in a package found only in a test lock file is often labelled Not reachable.",
  },
  // src: backend/utilities/dashboard/scan.py:898-912, backend/utilities/celery/create_findings.py:68-84 — findings by impact on their created_at date (UTC); a scan's findings are all recorded when it finishes
  "sbom.res.trends": {
    label: "Vulnerability trends over time",
    what: "This scan's findings by severity, on the date (UTC) each was recorded. A scan records all its findings when it finishes, so this usually shows a single day.",
    example: "12 findings recorded on 11 Nov: one point with Critical 1, High 3, Medium 6, Low 2.",
  },
  // src: backend/utilities/dashboard/scan.py:847-848, backend/utilities/dashboard/scan.py:914, backend/utilities/dashboard/sbom_license.py:330-375 — license family per result (SPDX from the inventory, else the model's category, else a curated package map, else not declared)
  "sbom.res.licenses": {
    label: "Licenses Distribution",
    what: "This scan's vulnerabilities by the license family of their package. The license comes from the SBOM when it records one, else from the AI model's category, else from a built-in list of well-known packages; otherwise Not declared.",
    example: "MIT and Apache-2.0 are permissive; GPL-3.0 is strong copyleft.",
  },
  // src: backend/utilities/dashboard/scan.py:853-856, backend/utilities/dashboard/scan.py:931-939 — per reachability label: mean of 10/7.5/5/2.5, 0 when none
  "sbom.res.risk_by_reach": {
    label: "Average risk score per reachability",
    what: "For each reachability label, the average risk (0 to 10: Critical 10, High 7.5, Medium 5, Low 2.5) of this scan's vulnerabilities with that label; 0 when there are none.",
    example: "Reachable 8.8: the vulnerabilities labelled Reachable are mostly Critical or High.",
  },
  // src: backend/utilities/dashboard/scan.py:916-929, frontend/components/SbomResults.tsx:525-530 — sorted by impact, first 20
  "sbom.res.top": {
    label: "Top vulnerabilities by risk score",
    what: "This scan's vulnerabilities, Critical first, the first 20, each with its reachability label, direct or transitive dependency, and license family.",
    example: "lodash 4.17.15, reachable, direct, permissive, Critical.",
  },
  // src: frontend/components/SbomResults.tsx:607-623 — case-insensitive match on title, description, impact, dependency and finding id of the loaded findings
  "sbom.res.search": {
    label: "Search findings",
    what: "Shows only the findings whose title, description, impact, dependency or finding id contains this text (upper or lower case does not matter).",
    example: "\"lodash\" keeps every finding in a lodash version.",
  },
  // src: backend/utilities/db/findings.py:142, backend/utilities/dashboard/bom_risk_score.py:152-173, frontend/components/SbomResults.tsx:590-596 — tiers on the 0-10 per-finding score
  "sbom.res.filter.risk": {
    label: "Risk score filter",
    what: "Shows only findings whose risk score (0 to 10) is in a tier: Critical 9 or more, High 7 to 9, Medium 5 to 7, Low under 5.",
    example: "High keeps a finding scored 8.5 and hides one scored 9.4.",
  },
  // src: RabbitMQ/worker/helpers/context/schema.py:32-33, backend/utilities/db/findings.py:133-152 — the package (with version) as the analysis named it
  "sbom.res.table.dependency": {
    label: "Dependency",
    what: "The package, with its version, that the vulnerability is in. Hover for the full name when it is cut short.",
    example: "lodash@4.17.15.",
  },
  // src: backend/utilities/dashboard/bom_risk_score.py:20-26, backend/utilities/dashboard/bom_risk_score.py:93-99, backend/utilities/dashboard/bom_risk_score.py:152-173 — impact base + 0.7 per CVE (max 3) + reachability + 0.5 high-risk license, 0-10, one decimal
  "sbom.res.table.risk": {
    label: "Risk score",
    what: "This finding's risk, 0 to 10: a base for its impact (Critical 7.5, High 5.5, Medium 3.5, Low 1.2), plus 0.7 per CVE (at most 3), plus its reachability label (Reachable 1.6, Potentially reachable 0.9, Not assessed 0.3), plus 0.5 for a high-risk license.",
    example: "High, 2 CVEs, labelled Reachable: 5.5 + 1.4 + 1.6 = 8.5.",
  },
  // src: backend/utilities/dashboard/sbom_license.py:382-392, RabbitMQ/worker/helpers/context/schema.py:34 — the AI model's label
  "sbom.res.table.reachability": {
    label: "Reachability",
    what: "The reachability label the AI model gave this vulnerability from the vulnerability and package data: Reachable, Potentially reachable, Not reachable or Not assessed. It does not read your code.",
    example: "Not reachable for a CVE in a test-only package.",
  },
  // src: backend/utilities/dashboard/sbom_license.py:330-375, RabbitMQ/worker/helpers/context/schema.py:35 — SPDX from the inventory, else the model's category (it may guess), else a curated package map, else not declared
  "sbom.res.table.license": {
    label: "License",
    what: "The license family of the package. It comes from the SBOM when it records a license, else from the AI model's category (which may be its own judgement), else from a built-in list of well-known packages; otherwise Not declared.",
    example: "Permissive for a package licensed MIT.",
  },
  // src: frontend/components/SbomResults.tsx:583, frontend/components/SbomResults.tsx:1429-1435, RabbitMQ/worker/helpers/context/schema.py:30-35 — shown when the scan has no stored findings: the analysis's own list
  "sbom.res.vuln.title": {
    label: "Vulnerability",
    what: "The vulnerabilities the analysis reported, shown when this scan has no stored findings. Click a title for the description and the suggested fix.",
    example: "Prototype pollution in lodash.",
  },
  // src: frontend/components/SbomResults.tsx:1434-1435 — one dependency, or the number of them
  "sbom.res.vuln.deps": {
    label: "Dependencies",
    what: "The package the vulnerability is in, or the number of packages when it affects several.",
    example: "\"3 dependencies\" for a CVE found in three lodash copies.",
  },
  // src: frontend/components/SbomResults.tsx:863-900, backend/routers/scans.py:1165-1175 — rows without a stored finding id: one combined Jira issue from the summary
  "sbom.res.vuln.select": {
    label: "Select rows",
    what: "Selects rows of this list for a Jira ticket. These rows are not stored findings, so all the selected rows go into one combined Jira issue.",
    example: "Select 4 rows, Create Jira ticket: one issue listing the 4 vulnerabilities.",
  },
} as const satisfies Record<string, InfoTipEntry>;

export type InfoTipId = keyof typeof INFO_TIPS;
