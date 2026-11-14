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
 *  - The text describes what the product does today. Where an open issue will change that behaviour, the `// src:`
 *    note names the issue (e.g. "#47"), so the fix updates the tip in the same PR.
 *  - Optional "why": why it matters (risk, consequence); shown between the text and the example.
 *
 * Components: <InfoTip id="…" /> and <FieldLabel infoId="…"> in components/ui/info-tip.tsx.
 */
export interface InfoTipEntry {
  /** What the (i) button is about; the button is named "About <label>". */
  label: string;
  /** What it is, in plain words, with the real limits, units and behaviour. */
  what: string;
  /** Optional: why it matters (the risk or consequence), one or two sentences. */
  why?: string;
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
  // src: backend/new_models.py:131, frontend/utils/datetime.ts:6-7 — stored in UTC; the text names no time zone because an IST browser reads the API's offset-less UTC time as local time until #48 is fixed
  "scan.table.created": {
    label: "Created at",
    what: "When the scan was created: the date and time it was added to this list, before it was started.",
    example: "9 Aug 2026, 07:30 pm.",
  },
  // src: backend/utilities/celery/celery_connection.py:182, backend/utilities/celery/celery_connection.py:200-215, frontend/utils/datetime.ts:6-7 — today's behaviour: set on every status poll of a pending or started scan (also without a change) and on every chat message; #47 narrows it to real changes
  "scan.table.updated": {
    label: "Last updated",
    what: "The last time the platform touched this scan: a status or progress change, a status check while it is queued or running (the list checks those each time it loads), or a chat message about its results.",
    example: "A scan queued since yesterday shows today's time once anyone opens the list today.",
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
  // src: RabbitMQ/worker/helpers/tools/sast_agent/main.py:51-92, RabbitMQ/worker/helpers/context/codebase_context.py:114-141 — today's behaviour: built-in exclusions and your patterns go through the same matcher on the file's full path (#37, #45)
  "sast.cfg.scope": {
    label: "Scan scope",
    what: "Which files are analysed: the files of the chosen language, minus the language's built-in exclusions (such as node_modules, dist and build for JavaScript) and minus the patterns you add below. Exclusions are matched against each file's full path.",
    example: "Add \"tests\" to leave the tests folders out of a Python scan.",
  },
  // src: RabbitMQ/worker/helpers/context/codebase_context.py:114-141, RabbitMQ/worker/helpers/tools/sast_agent/main.py:91-92 — today's behaviour of file_path_matches_pattern: one name matches a path segment starting with it; two names one after the other; a third and later name is dropped; names are regular expressions (#37)
  "sast.cfg.exclude": {
    label: "Exclude path patterns",
    what: "Each pattern is one or two folder or file names, one per box. One name skips every file whose path has a folder or file name starting with it; two names skip paths where they appear one after the other (a third name is ignored). Names are read as regular expressions, so a dot matches any character. Skipped files are not analysed and not charged.",
    example: "\"vendor\" skips vendor/ and vendors/; \"src\" / \"legacy\" skips src/legacy.",
  },
  // src: RabbitMQ/worker/helpers/tools/sast_agent/main.py:51-83 — one file extension per language; Ruby's built-in "tmp" exclusion matches the /tmp clone path, so Ruby scans analyse no file until #45 is fixed
  "sast.cfg.language": {
    label: "Primary app language",
    what: "Only files with this language's extension are analysed: Python .py, JavaScript .js, Java .java, PHP .php, C .c, Ruby .rb, Rust .rs, Swift .swift, C# .cs, Kotlin .kt. Other files are ignored. Ruby scans currently analyse no files: Ruby's built-in tmp exclusion matches the folder the repository is cloned into.",
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
  // src: backend/utilities/dashboard/scan_list.py:676-677, backend/utilities/celery/celery_connection.py:200-215 — last_updated date equals today's UTC date; today it also moves on status polls without a change and on chat messages (#47)
  "sast.kpi.updated_today": {
    label: "Updated today",
    what: "SAST scans whose Last updated time is today (since 00:00 UTC). A status change counts, and so do a status check of a queued or running scan and a chat message about its results.",
    example: "A scan queued since yesterday counts here once anyone opens the scan list today.",
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
  // src: backend/utilities/db/scan_list_item.py:71, frontend/app/[team_id]/sast/page.tsx:1609-1613 — repo_url from the scan's settings; the SAST list item does not return zip_file_used, so a zip upload shows a dash until #49 is fixed
  "sast.table.source": {
    label: "Repository",
    what: "The repository that was scanned (its last path segment; hover for the full URL). A scan of an uploaded zip file shows a dash.",
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
  // src: RabbitMQ/worker/helpers/tools/iac_agent/main.py:56-88, RabbitMQ/worker/helpers/context/codebase_context.py:56-82, RabbitMQ/worker/helpers/context/codebase_context.py:114-141, RabbitMQ/worker/helpers/context/codebase_context.py:228-233 — no pattern: every file of the formats; patterns and extensions of all formats are merged; one name matches a path segment starting with it, a third and later name is dropped (#37)
  "iac.cfg.include": {
    label: "Include path patterns",
    what: "Only files of this format whose full path matches a pattern are analysed. A pattern is one or two folder or file names, one per box; one name matches any folder or file name starting with it. No pattern means every file of the format, but the patterns of all formats in the scan are combined: next to Terraform, give each other format a pattern.",
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
  // src: backend/utilities/dashboard/scan_list.py:958-960, backend/utilities/dashboard/scan_list.py:1079, RabbitMQ/worker/helpers/tools/sca_sbom_agent/merge_inventory.py:109-122 — len of all result rows of successful scans; each package with no known vulnerability is stored as a Low row (inventory_only) until #46 is fixed
  "sbom.kpi.total": {
    label: "Total Vulnerabilities",
    what: "All result rows of this team's successful SCA + SBOM scans, added up: each known vulnerability, plus each package found with no known vulnerability (stored as a Low row).",
    example: "1 vulnerable package and 3 packages with no known vulnerability: 4.",
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
  // src: backend/utilities/dashboard/scan_list.py:975-976, backend/utilities/dashboard/scan_list.py:1074-1082 — medium + high risk license categories over all result rows, packages with no known vulnerability included (#46)
  "sbom.kpi.license_risks": {
    label: "License Risks",
    what: "Result rows of successful scans, vulnerable packages or not, whose license is medium-risk (weak copyleft such as LGPL or MPL, Creative Commons, commercial) or high-risk (strong copyleft such as GPL, network copyleft such as AGPL, source-available such as SSPL or BUSL).",
    example: "A package under LGPL-3.0 counts here even with no known vulnerability.",
  },
  // src: backend/utilities/dashboard/scan_list.py:975, backend/utilities/dashboard/scan_list.py:1074, backend/utilities/dashboard/sbom_license.py:233-258 — strong copyleft, network copyleft, source-available
  "sbom.kpi.high_risk_licenses": {
    label: "High Risk Licenses",
    what: "Findings whose package is under a strong copyleft (GPL), network copyleft (AGPL) or source-available (SSPL, BUSL) license.",
    example: "A package licensed AGPL-3.0.",
  },
  // src: backend/utilities/dashboard/scan_list.py:1019-1021, backend/utilities/dashboard/scan_list.py:1077 — each row scores weight/4*10, averaged, Python round(x, 1); packages with no known vulnerability are Low rows (#46)
  "sbom.kpi.avg_risk": {
    label: "Avg Risk Score",
    what: "Average over all result rows of successful scans, 0 to 10: Critical counts 10, High 7.5, Medium 5, Low 2.5. Packages with no known vulnerability are Low rows, so many of them pull the average towards 2.5. Rounded to one decimal.",
    example: "1 Critical and 3 packages with no known vulnerability: (10 + 3 × 2.5) / 4 = 4.4.",
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
  // src: backend/utilities/dashboard/scan_list.py:988-998, backend/utilities/dashboard/scan_list.py:1038-1043 — totals per impact over all result rows; Low includes packages with no known vulnerability (#46)
  "sbom.chart.severity": {
    label: "Severity Distribution",
    what: "Result rows of successful scans by severity: Critical, High, Medium and Low. Low also counts every package found with no known vulnerability.",
    example: "Critical 2, High 9, Medium 15, Low 310 in a repository with about 300 packages.",
  },
  // src: backend/utilities/dashboard/scan_list.py:1044-1056, backend/utilities/dashboard/sbom_license.py:382-392, RabbitMQ/worker/helpers/context/schema.py:34 — the AI model's label (no code in its context); missing counts as Not assessed; packages with no known vulnerability are stored Not reachable (#46)
  "sbom.chart.reachability": {
    label: "Reachability Distribution",
    what: "Result rows by the reachability label the AI model gave each one from the vulnerability and package data (it does not read your code): Reachable, Potentially reachable, Not reachable, or Not assessed. Not reachable also counts packages with no known vulnerability.",
    example: "A CVE in a package found only in a test lock file is often labelled Not reachable.",
  },
  // src: backend/utilities/dashboard/scan_list.py:986, backend/utilities/dashboard/scan_list.py:1024-1028 — per creation date (UTC) of each successful scan; Low includes packages with no known vulnerability (#46)
  "sbom.chart.trends": {
    label: "Vulnerability Trends Over Time",
    what: "Result rows of successful scans by severity, on the day (UTC) each scan was created. Low also counts packages with no known vulnerability.",
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
  // src: backend/utilities/db/scan_list_item.py:152-161 — counts per impact of a successful scan's result rows; packages with no known vulnerability are Low rows (#46)
  "sbom.table.vulns": {
    label: "Vulnerabilities",
    what: "This scan's result rows by severity once it succeeded: Critical (red), High (orange), Medium (amber), Low (blue). Blue also counts every package found with no known vulnerability.",
    example: "0 red, 3 orange, 6 amber, 280 blue for a repository with about 280 packages.",
  },
  // src: backend/utilities/db/scan_list_item.py:171-173, frontend/app/[team_id]/sbom_sca/page.tsx:113-116 — today's scale: weights 4/3/2/1 averaged over result rows, 0 without rows (#35, #46)
  "sbom.table.risk": {
    label: "Risk score",
    what: "This scan's severity-weighted average on a 1 to 4 scale: Critical 4, High 3, Medium 2, Low 1, averaged over its result rows (packages with no known vulnerability count as Low). 0 when the scan has no rows or did not succeed.",
    example: "1 High and 1 Low: (3 + 1) / 2 = 2.",
  },
  // src: backend/utilities/db/scan_list_item.py:90-112, backend/utilities/db/scan_list_item.py:379-412, frontend/app/[team_id]/iac/page.tsx:123-126, frontend/app/[team_id]/dast/page.tsx:115-118 — today's scale for IaC and DAST: weights 4/3/2/1 averaged over findings, 0 without findings (#35)
  "scan.table.risk": {
    label: "Risk score",
    what: "This scan's severity-weighted average on a 1 to 4 scale: Critical 4, High 3, Medium 2, Low 1, averaged over its findings. 0 when it found nothing or did not succeed.",
    example: "1 High and 1 Low finding: (3 + 1) / 2 = 2.",
  },
  // src: frontend/app/[team_id]/sbom_sca/page.tsx:118-125, frontend/app/[team_id]/iac/page.tsx:128-135, frontend/app/[team_id]/dast/page.tsx:120-127, frontend/app/[team_id]/ai_bom/page.tsx:114-121, frontend/app/[team_id]/llm/page.tsx:123-130, frontend/app/[team_id]/cbom/page.tsx:120-127 — tiers on the Risk score column; the column is 1-4 for SCA + SBOM, IaC and DAST today (#35), 0-10 for AI BOM, LLM and CBOM; a null score matches no tier
  "scan.filter.risk": {
    label: "Risk score filter",
    what: "Shows only scans whose Risk score is in a tier: Critical 9 or more, High 7 to 9, Medium 5 to 7, Low under 5. Where this table's score runs from 1 to 4 (SCA + SBOM, IaC, DAST), every scored scan is in Low. A scan without a score (shown as a dash) is hidden by any tier.",
    example: "On the LLM list, High keeps a scan scored 7.5 and hides one scored 9.2.",
  },
  // src: frontend/app/[team_id]/sbom_sca/page.tsx:699-712, frontend/app/[team_id]/iac/page.tsx:719-732, frontend/app/[team_id]/dast/page.tsx:637-650, frontend/app/[team_id]/ai_bom/page.tsx:601-614, frontend/app/[team_id]/llm/page.tsx:568-581, frontend/app/[team_id]/cbom/page.tsx:668-681 — sorts the loaded rows; missing values count as -1
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
  // src: RabbitMQ/worker/helpers/tools/iac_agent/main.py:56-88, RabbitMQ/worker/helpers/context/codebase_context.py:228-233 — the format decides the extensions; Terraform adds its own .tf patterns; the other formats' include patterns narrow their files (merged across formats: see iac.cfg.include)
  "iac.cfg.context_type": {
    label: "Context type",
    what: "The infrastructure format of this context; it decides which file extensions are read. Terraform needs no pattern: its files are found by extension anywhere. For the other formats, the include patterns below narrow which files are read.",
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

  // ────────────────────────────────────────────────────────────── AI BOM: scan configuration (components/ai-bom-options-sidebar.tsx)
  // src: RabbitMQ/worker/helpers/tools/ai_bom_agent/main.py:391-394, RabbitMQ/worker/helpers/tools/ai_bom_agent/main.py:426-447 — repository: model and source files; AI BOM file: AI summariser
  "aibom.cfg.repository": {
    label: "Analyze Repository",
    what: "Finds the AI in your code: model files, embedding models, Hugging Face models, AI SDKs and external AI providers, datasets, and their licenses, and builds a CycloneDX AI bill of materials.",
    example: "A service that imports the OpenAI SDK and loads a local .onnx model.",
  },
  // src: RabbitMQ/worker/helpers/tools/ai_bom_agent/main.py:122-150 — an existing AI-BOM JSON analysed by the AI model (map-reduce)
  "aibom.cfg.file": {
    label: "AI BOM file",
    what: "An AI bill of materials you already have, as a JSON file. No code is cloned: the file's contents are analysed by the scan's AI model to list risks. Choosing a file clears the repository or zip.",
    example: "aibom.cdx.json exported from another tool.",
  },
  // src: RabbitMQ/worker/helpers/tools/ai_bom_agent/main.py:426-447, backend/utilities/scan/estimate_scan.py:210 — 2 credits per MB of model/source files + ~0.05; a file is ~0.01
  "aibom.cfg.estimate": {
    label: "Estimate scan credits",
    what: "A repository or zip costs 2 credits per MB of model and source files plus about 0.05; an uploaded AI BOM file about 0.01. Rounded to 0.01. Nothing is charged until you start the scan.",
    example: "4 MB of Python and model files: about 8.05 credits.",
  },

  // ────────────────────────────────────────────────────────────── AI BOM: list page (app/[team_id]/ai_bom/page.tsx)
  // src: backend/utilities/dashboard/scan_list.py:1853-1860 — detections of successful scans
  "aibom.kpi.assets": {
    label: "AI Assets",
    what: "Every AI component detection in successful AI BOM scans: models, datasets, AI libraries and external AI providers, added up across scans.",
    example: "The OpenAI SDK found in 4 files counts 4 here.",
  },
  // src: backend/utilities/dashboard/scan_list.py:1821, backend/utilities/dashboard/scan_list.py:1884-1886, backend/utilities/dashboard/scan_list.py:1956 — distinct (provider, name) of model components
  "aibom.kpi.models": {
    label: "Models",
    what: "Distinct models (local model files, Hugging Face models, embedding models), counted once per provider and name across all scans.",
    example: "bert-base-uncased found in two repositories counts 1.",
  },
  // src: backend/utilities/dashboard/scan_list.py:1890-1892, backend/utilities/dashboard/scan_list.py:1957 — distinct dataset names
  "aibom.kpi.datasets": {
    label: "Datasets",
    what: "Distinct datasets the code loads, counted once per name.",
    example: "squad loaded by two notebooks counts 1.",
  },
  // src: backend/utilities/dashboard/scan_list.py:1887-1889, backend/utilities/dashboard/scan_list.py:1958 — distinct providers of external_provider detections
  "aibom.kpi.providers": {
    label: "External Providers",
    what: "Distinct external AI services your code calls, such as OpenAI or Anthropic, counted once each.",
    example: "OpenAI used in 4 files and Anthropic in 1: 2.",
  },
  // src: backend/utilities/dashboard/scan_list.py:1894-1896 — impact critical or high
  "aibom.kpi.high_risk": {
    label: "High Risk",
    what: "AI asset detections rated Critical or High.",
    example: "A model downloaded without a pinned revision, rated High.",
  },
  // src: backend/utilities/dashboard/scan_list.py:1898-1904, backend/utilities/dashboard/aibom_license.py:83-92 — libraries without a usable license
  "aibom.kpi.unlicensed": {
    label: "Unlicensed",
    what: "AI libraries with no usable open-source license declared. Models and external providers are not counted here.",
    example: "An internal AI package with no license field.",
  },
  // src: backend/utilities/dashboard/scan_list.py:1906-1910, backend/utilities/dashboard/scan_list.py:1960-1963 — assets with a declared license and a model card / total
  "aibom.kpi.governance": {
    label: "Governance Readiness",
    what: "Share of AI asset detections that have both a declared license and a model card: the documentation an AI governance review asks for.",
    example: "10 assets, 4 with license and model card: 40%.",
  },
  // src: backend/utilities/dashboard/scan_list.py:1965-1971 — 0-10, weights 4/3/2/1
  "aibom.kpi.avg_risk": {
    label: "Avg Risk Score",
    what: "Severity-weighted average of all AI asset findings, 0 to 10: Critical 4, High 3, Medium 2, Low 1, the average weight divided by 4 and multiplied by 10.",
    example: "2 High and 2 Low: (3+3+1+1)/4 = 2, so 5.0.",
  },
  // src: backend/utilities/dashboard/scan_list.py:1979-2018, backend/utilities/dashboard/finding_metrics.py:18-40 — stored findings of successful scans by status
  "aibom.chart.remediation": {
    label: "Remediation Actions Required",
    what: "Stored findings of successful AI BOM scans by the status your team set: Fixed, In progress, Not started, Ignored.",
    example: "12 findings: 3 Fixed, 9 Not started.",
  },
  // src: backend/utilities/dashboard/scan_list.py:1862-1866 — impact per detection
  "aibom.chart.severity": {
    label: "Severity Distribution",
    what: "AI asset detections by severity: Critical, High, Medium, Low.",
    example: "High 3, Medium 7, Low 20.",
  },
  // src: backend/utilities/dashboard/scan_list.py:1868-1869 — component_type per detection
  "aibom.chart.asset_type": {
    label: "Asset Type Distribution",
    what: "Detections by kind of AI component: local model file, Hugging Face model, embedding model, dataset, AI library, external provider and others.",
    example: "external_provider 5, huggingface_model 2.",
  },
  // src: backend/utilities/dashboard/scan_list.py:1871-1872 — resolved provider per detection
  "aibom.chart.provider": {
    label: "Provider Distribution",
    what: "Detections by the AI vendor or source behind them, such as openai, anthropic or huggingface.",
    example: "openai 6, huggingface 3.",
  },
  // src: backend/utilities/dashboard/scan_list.py:1874-1875 — resolved license per detection
  "aibom.chart.license": {
    label: "License Distribution",
    what: "Detections by license, as declared or resolved for each component (for example MIT, Apache-2.0, a proprietary API's terms, or not declared).",
    example: "Apache-2.0 8, NOASSERTION 3.",
  },
  // src: backend/utilities/dashboard/scan_list.py:1930-1936, backend/utilities/dashboard/scan_list.py:1973-1977 — the 10 most severe detections
  "aibom.chart.top_risks": {
    label: "Top AI Risks",
    what: "The 10 most severe AI asset detections (Critical first), with their type, provider, license and impact.",
    example: "gpt-4o · external_provider · openai · proprietary · High.",
  },
  // src: backend/utilities/db/scan_list_item.py:484-505 — counts per impact of a successful scan
  "aibom.table.risks": {
    label: "Risks",
    what: "This scan's AI asset findings by severity: Critical (red), High (orange), Medium (amber), Low (blue). Counted once the scan succeeded.",
    example: "0 red, 2 orange, 5 amber, 11 blue.",
  },
  // src: backend/utilities/db/scan_list_item.py:521-524 — weighted 4/3/2/1 average, /4 *10
  "aibom.table.risk": {
    label: "Risk score",
    what: "This scan's severity-weighted average, 0 to 10: Critical 4, High 3, Medium 2, Low 1, averaged over its findings, divided by 4 and multiplied by 10.",
    example: "1 High and 1 Low: (3+1)/2 = 2, so 5.0.",
  },

  // ────────────────────────────────────────────────────────────── MCP: scan configuration (components/mcp-options-sidebar.tsx)
  // src: backend/utilities/db/schemas.py:159-169, RabbitMQ/worker/helpers/tools/mcp_agent/context.py:5-9 — the MCP server endpoint the worker connects to
  "mcp.cfg.server_url": {
    label: "MCP server URL",
    what: "The address of the MCP (Model Context Protocol) server to test. The scan connects to it, lists its tools, prompts and resources, and checks each one for risks such as prompt injection or dangerous capabilities.",
    example: "https://mcp.example.com/mcp.",
  },
  // src: backend/utilities/db/schemas.py:161, RabbitMQ/worker/helpers/tools/mcp_agent/context.py:7 — httpstreamable or sse
  "mcp.cfg.server_mode": {
    label: "Server mode",
    what: "The transport the server speaks: Streamable HTTP (the current MCP standard) or SSE (Server-Sent Events, the older one). Pick what the server documents.",
    example: "Streamable HTTP for a server whose endpoint ends in /mcp.",
  },
  // src: backend/utilities/db/schemas.py:163, backend/utilities/dashboard/scan_list.py:1326-1329 — a label used by the Environment Risk Analysis chart
  "mcp.cfg.environment": {
    label: "Environment",
    what: "Which environment the server belongs to: Development, Staging or Production. A label for the dashboard's Environment Risk Analysis; it does not change the tests.",
    example: "Production for the server your agents use live.",
  },
  // src: backend/utilities/db/schemas.py:162, RabbitMQ/worker/helpers/tools/mcp_agent/context.py:8-9 — JSON object of HTTP headers sent with every request
  "mcp.cfg.headers": {
    label: "Headers (JSON)",
    what: "Extra HTTP headers sent with every request to the server, as a JSON object, typically for authentication.",
    example: "{\"Authorization\": \"Bearer <token>\"}.",
  },
  // src: RabbitMQ/worker/helpers/tools/mcp_agent/main.py:253-285, backend/utilities/scan/estimate_scan.py:210 — connects now; 0.005 credits per tool, prompt and resource
  "mcp.cfg.estimate": {
    label: "Estimate scan credits",
    what: "Connects to the server now, lists its tools, prompts and resources, and prices each at 0.005 credits, rounded to 0.01. Nothing is charged until you start the scan.",
    example: "40 tools, 4 prompts, 6 resources: 0.25 credits.",
  },

  // ────────────────────────────────────────────────────────────── MCP: list page (app/[team_id]/mcp/page.tsx)
  // src: backend/utilities/dashboard/scan_list.py:1371 — every MCP scan in any status
  "mcp.kpi.total_scans": {
    label: "Total Scans",
    what: "All MCP scans of this team, in any status.",
    example: "8 scans: 6 succeeded, 1 running, 1 failed.",
  },
  // src: backend/utilities/dashboard/scan_list.py:1320-1325, backend/utilities/dashboard/scan_list.py:1372 — critical findings of all scans
  "mcp.kpi.critical": {
    label: "Critical Issues",
    what: "Findings rated Critical across the tools, prompts and resources of all MCP scans.",
    example: "A tool that runs shell commands from model input.",
  },
  // src: backend/utilities/dashboard/scan_list.py:1346-1349, backend/utilities/dashboard/scan_list.py:1368 — each finding weight/4*10, averaged
  "mcp.kpi.avg_risk": {
    label: "Avg Risk Score",
    what: "Average over all MCP findings, 0 to 10: Critical counts 10, High 7.5, Medium 5, Low 2.5.",
    example: "One Critical and one Medium: 7.5.",
  },
  // src: backend/utilities/dashboard/scan_list.py:1293-1294, backend/utilities/dashboard/scan_list.py:1369 — status started
  "mcp.kpi.active": {
    label: "Active Scans",
    what: "MCP scans a worker is running now.",
    example: "2 while two servers are being tested.",
  },
  // src: backend/utilities/dashboard/scan_list.py:1243-1248, backend/utilities/dashboard/scan_list.py:1375 — findings marked fixed in the last 7 x 24 h
  "mcp.kpi.resolved": {
    label: "Resolved (7d)",
    what: "MCP findings marked Fixed in the last 7 days (the last 168 hours). Ignored findings are not counted.",
    example: "5 findings fixed this week.",
  },
  // src: backend/utilities/dashboard/scan_list.py:1291-1300 — started / success / failure; everything else (incl. pending) counts as not started
  "mcp.chart.status": {
    label: "Scan Status Distribution",
    what: "MCP scans by status: Started, Success, Failure, and Not started (which also counts queued and cancelled scans).",
    example: "6 Success, 1 Started, 1 Failure.",
  },
  // src: backend/utilities/dashboard/scan_list.py:1348-1351, backend/routers/scans.py:88 — per server: average of weight/4*10; scans come newest first, so the earliest scan's value is kept
  "mcp.chart.risk_trend": {
    label: "Risk Score Trend",
    what: "For each MCP server, the average risk score (0 to 10: Critical 10, High 7.5, Medium 5, Low 2.5) of its scan's findings. A server scanned several times shows one value, from its earliest scan (the list is read newest first and later rows overwrite).",
    example: "mcp.example.com 6.3.",
  },
  // src: backend/utilities/dashboard/scan_list.py:1352-1356 — findings by severity on the scan's creation date (UTC)
  "mcp.chart.risks_over_time": {
    label: "Risks Over Time",
    what: "MCP findings by severity, on the day (UTC) each scan was created.",
    example: "A scan created on 9 Nov with 3 High findings adds 3 to High on 9 Nov.",
  },
  // src: backend/utilities/dashboard/scan_list.py:1307-1325 — totals per impact
  "mcp.chart.severity": {
    label: "Severity Distribution",
    what: "All MCP findings by severity: Critical, High, Medium, Low.",
    example: "Critical 1, High 5, Medium 9, Low 2.",
  },
  // src: backend/utilities/dashboard/scan_list.py:1326-1329 — findings counted by the scan's environment label
  "mcp.chart.environment": {
    label: "Environment Risk Analysis",
    what: "How many findings come from servers labelled Development, Staging or Production (the environment chosen when each scan was configured).",
    example: "Production 7 means seven findings on production servers.",
  },
  // src: backend/utilities/dashboard/scan_list.py:1330-1345 — compliance-control references per standard
  "mcp.chart.compliance": {
    label: "Compliance Framework Distribution",
    what: "How many compliance-control references the MCP findings have per standard.",
    example: "ISO 27001 9, PCI DSS 3.",
  },
  // src: backend/utilities/dashboard/scan_list.py:1378, backend/utilities/dashboard/finding_metrics.py:18-40 — stored findings by status
  "mcp.chart.remediation": {
    label: "Remediation Status",
    what: "MCP findings by the status your team set: Not started, In progress, Fixed, Ignored.",
    example: "Fixed 5, Not started 12.",
  },
  // src: backend/utilities/dashboard/scan_list.py:1256-1259, backend/utilities/dashboard/scan_list.py:1286-1289, backend/utilities/dashboard/scan_list.py:1346-1347 — by the resource category of each finding
  "mcp.chart.asset_category": {
    label: "Asset Category Vulnerabilities",
    what: "Findings by what the affected tool, prompt or resource gives access to: web, file system, code execution, database, search, vector store, document store.",
    example: "Code execution 3: three findings on tools that can run code.",
  },
  // src: backend/utilities/dashboard/scan_list.py:1357-1359, RabbitMQ/worker/scan_worker.py:157-164 — duration_of_scan per server
  "mcp.chart.duration": {
    label: "Scan Duration Trends",
    what: "How long each server's MCP scan took, in seconds, from the worker starting to results. A server scanned several times shows its earliest scan.",
    example: "mcp.example.com 95.",
  },
  // src: backend/utilities/dashboard/scan_list.py:1261-1264, backend/utilities/dashboard/scan_list.py:1348-1349, backend/utilities/dashboard/scan_list.py:1363-1366 — average weight/4*10 per category
  "mcp.chart.posture": {
    label: "Security Posture Overview",
    what: "The average risk score (0 to 10: Critical 10, High 7.5, Medium 5, Low 2.5) of the findings in each asset category; 0 where there are none.",
    example: "File system 8.8: its findings are mostly Critical or High.",
  },
  // src: backend/utilities/dashboard/finding_metrics.py:89-125, backend/utilities/dashboard/scan_list.py:1379-1380 — per resolution date
  "mcp.chart.mttr": {
    label: "Mean Time to Remediate per Day",
    what: "For each day (UTC), the average time between a finding being recorded and being marked Fixed or Ignored, for the findings resolved that day.",
    example: "Two findings fixed on 8 Nov after 1 and 3 days: 2 days on 8 Nov.",
  },
  // src: backend/utilities/dashboard/scan_list.py:1389-1400 — per scan date: findings and those marked ignored
  "mcp.chart.effectiveness": {
    label: "Scan Effectiveness Trend",
    what: "Per scan date, the findings the scans produced and how many of them your team marked Ignored (treated as false positives).",
    example: "10 findings on 5 Nov, 2 ignored.",
  },
  // src: backend/utilities/dashboard/scan_list.py:1382-1388 — 100 minus the framework's share of that day's references
  "mcp.chart.compliance_trend": {
    label: "Compliance Framework Score Trend",
    what: "Per scan date and standard: 100 minus that standard's share of the day's compliance-control references. A relative measure, not an audit score.",
    example: "PCI DSS has 3 of 10 references on 5 Nov: 70.",
  },
  // src: backend/utilities/dashboard/scan_list.py:1401-1420 — resolved findings by days from creation to fixed/ignored, 30-day buckets
  "mcp.chart.age": {
    label: "Vulnerability Age Distribution",
    what: "Resolved findings (Fixed or Ignored) grouped by how many days they stayed open, in 30-day buckets up to 210 days. Open findings are not shown.",
    example: "A finding fixed after 45 days counts in 30-60 days.",
  },
  // src: frontend/app/[team_id]/mcp/page.tsx:711-715 — sorts the loaded rows by created_at
  "scan.filter.sort_created": {
    label: "Sort",
    what: "Orders the table by creation date, newest or oldest first.",
    example: "Newest puts the scan you created last on top.",
  },
  // src: backend/utilities/db/scan_list_item.py:277 — host part of the server URL
  "mcp.table.server": {
    label: "Server",
    what: "A short name for the MCP server, taken from its URL's host.",
    example: "example for https://mcp.example.com.",
  },
  // src: backend/utilities/db/scan_list_item.py:200-261, frontend/app/[team_id]/mcp/page.tsx:1007-1011 — today's scale: weights 4/3/2/1 averaged over findings, 0 without findings (#35)
  "mcp.table.risk": {
    label: "Risk Score",
    what: "This scan's severity-weighted average on a 1 to 4 scale: Critical 4, High 3, Medium 2, Low 1, averaged over its findings. 0 when it found nothing or did not succeed.",
    example: "1 High and 1 Low finding: (3 + 1) / 2 = 2.",
  },
  // src: backend/utilities/db/scan_list_item.py:199-210, backend/utilities/db/scan_list_item.py:279-284 — tools, prompts and resources the server exposed
  "mcp.table.discovery": {
    label: "Discovery",
    what: "What the scan found on the server: T tools, P prompts, R resources.",
    example: "T: 40 P: 4 R: 6.",
  },
  // src: backend/utilities/db/scan_list_item.py:244-256 — tools/prompts/resources rated high or critical
  "mcp.table.risky": {
    label: "Risky assets",
    what: "Tools, prompts and resources the scan rated High or Critical risk.",
    example: "3: two tools and one resource.",
  },
  // src: backend/utilities/db/scan_list_item.py:212-240 — counts per impact of a successful scan
  "mcp.table.vulns": {
    label: "Vulnerabilities",
    what: "This scan's findings by severity: Critical (red), High (orange), Medium (amber), Low (blue). Counted once the scan succeeded.",
    example: "1 red, 2 orange, 0 amber, 4 blue.",
  },

  // ────────────────────────────────────────────────────────────── LLM red teaming: scan configuration (components/llm-options-sidebar.tsx)
  // src: backend/utilities/db/schemas.py:176-186 — openai, anthropic, gemini or custom
  "llm.cfg.model_type": {
    label: "Model Type",
    what: "Where the model under test is hosted: OpenAI, Anthropic, Google Gemini, or Custom (any HTTP endpoint you describe below).",
    example: "Custom for your own chatbot API.",
  },
  // src: backend/utilities/db/schemas.py:178, backend/utilities/db/scan_list_item.py:350 — the provider's model id
  "llm.cfg.model_name": {
    label: "Model Name",
    what: "The model id the provider expects, exactly as in its API, or a name for your custom model. It also labels the scan in the Model Risk Comparison chart.",
    example: "gpt-4o-mini.",
  },
  // src: backend/utilities/db/schemas.py:181 — secret field, never printed
  "llm.cfg.api_key": {
    label: "API Key",
    what: "The provider API key the red-team prompts are sent with. Every test prompt is billed by your provider on this key. It is never printed in logs.",
    example: "An OpenAI key from a project with a spending limit.",
  },
  // src: backend/utilities/db/schemas.py:179, RabbitMQ/worker/helpers/tools/llm_agent/main.py:142-155 — answers per prompt; not part of the credit price
  "llm.cfg.generations": {
    label: "Generations per benchmark",
    what: "How many answers the model is asked to give for each attack prompt. More generations catch inconsistent behaviour but send more requests to your provider; the credit price does not change.",
    example: "3 sends each prompt three times.",
  },
  // src: backend/utilities/db/schemas.py:185 — the endpoint of a custom model
  "llm.cfg.model_uri": {
    label: "Model URI",
    what: "The URL the scan calls to talk to your custom model (POST by default).",
    example: "https://chat.example.com/api/v1/complete.",
  },
  // src: backend/utilities/db/schemas.py:182 — HTTP headers of the custom request
  "llm.cfg.headers": {
    label: "Headers (JSON)",
    what: "HTTP headers sent with every request to the custom model, as a JSON object, usually for authentication.",
    example: "{\"Authorization\": \"Bearer <token>\"}.",
  },
  // src: backend/utilities/db/schemas.py:183 — the JSON body with the prompt placeholder
  "llm.cfg.request_template": {
    label: "Request Template",
    what: "The JSON body sent to your model, with a placeholder where each attack prompt goes.",
    example: "{\"message\": \"$INPUT\"}.",
  },
  // src: backend/utilities/db/schemas.py:184 — where the answer is in the response
  "llm.cfg.response_field": {
    label: "Response JSON Field",
    what: "The field of your model's JSON response that holds the answer text, which the detectors then judge.",
    example: "reply for a response {\"reply\": \"…\"}.",
  },
  // src: backend/utilities/db/schemas.py:180, RabbitMQ/worker/helpers/tools/llm_agent/main.py:142-155 — garak probes; 0.002 credits each
  "llm.cfg.probes": {
    label: "Security Benchmarks",
    what: "The attack families (garak probes) to run against the model, such as jailbreaks, prompt injection, data leakage or toxicity. Each selected benchmark costs 0.002 credits.",
    example: "promptinject and dan for a customer-facing chatbot.",
  },
  // src: RabbitMQ/worker/helpers/tools/llm_agent/main.py:142-155, backend/utilities/scan/estimate_scan.py:210 — number of probes x 0.002
  "llm.cfg.estimate": {
    label: "Estimate scan credits",
    what: "Prices the scan at 0.002 credits per selected benchmark, rounded to 0.01. Your model provider bills its own usage separately. Nothing is charged until you start the scan.",
    example: "10 benchmarks: 0.02 credits.",
  },

  // ────────────────────────────────────────────────────────────── LLM red teaming: list page (app/[team_id]/llm/page.tsx)
  // src: backend/utilities/dashboard/scan_list.py:1500-1518 — the same status counters as SAST (UTC day for today); last_updated also moves on status polls and chat messages (#47)
  "llm.kpi.status": {
    label: "Scan counts by status",
    what: "LLM scans of this team per status (Not started, Pending, Started, Success, Failure), and how many were created or updated since 00:00 UTC today. A status check of a running scan or a chat message also counts as an update.",
    example: "Updated today 2: two scans started or finished today (UTC).",
  },
  // src: backend/utilities/dashboard/scan_list.py:1553-1555, backend/utilities/dashboard/scan_list.py:1638 — successful scans
  "llm.kpi.success": {
    label: "Scans (success)",
    what: "LLM scans that finished successfully. Only these feed the risk cards and charts.",
    example: "5 scans succeeded.",
  },
  // src: backend/utilities/dashboard/scan_list.py:1619-1626 — weight/4*10 per finding, averaged
  "llm.kpi.avg_risk": {
    label: "Avg Risk Score",
    what: "Average over all findings of successful LLM scans, 0 to 10: Critical counts 10, High 7.5, Medium 5, Low 2.5.",
    example: "One Critical and one Low: 6.3.",
  },
  // src: backend/utilities/dashboard/scan_list.py:1564-1567, backend/utilities/dashboard/scan_list.py:1617-1618 — findings of successful scans
  "llm.kpi.vulns": {
    label: "Vulnerabilities",
    what: "Findings of successful LLM scans: all of them (Total Vulns), and those rated Critical (Critical Vulns).",
    example: "Total 12, Critical 2.",
  },
  // src: backend/utilities/dashboard/scan_list.py:1532-1543, backend/utilities/dashboard/scan_list.py:1628-1631 — 10 minus the number of OWASP LLM categories with a finding
  "llm.kpi.owasp": {
    label: "OWASP Score",
    what: "10 minus the number of OWASP Top 10 for LLM categories that have at least one finding. 10 means no category was hit; it does not weigh how many findings each has.",
    example: "Findings in LLM01 and LLM06 only: 8.",
  },
  // src: backend/utilities/dashboard/scan_list.py:1602-1606, backend/utilities/dashboard/scan_list.py:1633-1635 — (tests - hits) / tests over successful scans
  "llm.kpi.passed_rate": {
    label: "Passed Rate",
    what: "Share of attack attempts the models resisted, over all successful scans: attempts that did not trigger a detector divided by all attempts.",
    example: "1,000 attempts, 80 hits: 92.0%.",
  },
  // src: backend/utilities/dashboard/scan_list.py:1564-1567 — findings by impact
  "llm.chart.risk_level": {
    label: "Risk Level Distribution",
    what: "Findings of successful LLM scans by severity: Critical, High, Medium, Low.",
    example: "High 4, Medium 6, Low 2.",
  },
  // src: backend/utilities/dashboard/scan_list.py:1592-1601 — per probe: passed and failed attempts
  "llm.chart.attack_vectors": {
    label: "Attack Vector Test Results",
    what: "For each benchmark (garak probe), how many attack attempts the models resisted (passed) and how many succeeded (failed), over all successful scans.",
    example: "dan: 45 passed, 5 failed.",
  },
  // src: backend/utilities/dashboard/scan_list.py:1581-1590, backend/utilities/dashboard/scan_list.py:1653-1656 — per model name: findings-weighted 0-10 score
  "llm.chart.model_risk": {
    label: "Model Risk Comparison",
    what: "The average risk score (0 to 10, weights Critical 4, High 3, Medium 2, Low 1) of each model's findings, across its successful scans.",
    example: "gpt-4o-mini 5.0, my-chatbot 7.5.",
  },
  // src: backend/utilities/dashboard/scan_list.py:1544-1551, backend/utilities/dashboard/scan_list.py:1607-1613, backend/utilities/dashboard/scan_list.py:1659-1665 — average of each scan's resistance scores
  "llm.chart.posture": {
    label: "AI Security Posture Overview",
    what: "Average of the scans' resistance scores in six areas: jailbreak resistance, injection resistance, hallucination resistance, bias resistance, content safety and data privacy. 0 where no scan reported one.",
    example: "Jailbreak resistance 7.2.",
  },
  // src: backend/utilities/dashboard/scan_list.py:1532-1543, backend/utilities/dashboard/scan_list.py:1568-1580, backend/utilities/dashboard/scan_list.py:1666-1669 — findings per OWASP LLM category
  "llm.chart.owasp": {
    label: "OWASP Top 10 LLM Metrics",
    what: "Findings per OWASP Top 10 for LLM Applications category (LLM01 Prompt Injection to LLM10). A finding mapped to two categories counts in both.",
    example: "LLM01 6, LLM06 2.",
  },
  // src: backend/utilities/dashboard/scan_list.py:1502-1519 — every LLM scan by its UTC creation date
  "llm.chart.scans_per_day": {
    label: "Scans Per Day",
    what: "How many LLM scans were created on each day (UTC), whatever their status.",
    example: "3 scans created on 10 Nov.",
  },
  // src: backend/utilities/dashboard/scan_list.py:1500-1512 — counts by status
  "llm.chart.status": {
    label: "Scan Status Breakdown",
    what: "All LLM scans of this team by their current status.",
    example: "5 Success, 1 Failure.",
  },
  // src: backend/utilities/db/scan_list_item.py:366 — model type from the scan's settings
  "llm.table.model_type": {
    label: "Model type",
    what: "Where the tested model is hosted: openai, anthropic, gemini or custom.",
    example: "openai.",
  },
  // src: backend/utilities/db/scan_list_item.py:350, backend/utilities/db/scan_list_item.py:367 — model name from the settings or the results
  "llm.table.model_name": {
    label: "Model name",
    what: "The model id that was tested.",
    example: "gpt-4o-mini.",
  },
  // src: backend/utilities/db/scan_list_item.py:369 — number of selected probes
  "llm.table.probes": {
    label: "Probes",
    what: "How many security benchmarks (garak probes) the scan was configured with.",
    example: "10 probes selected.",
  },
  // src: backend/utilities/db/scan_list_item.py:338-346, backend/utilities/db/scan_list_item.py:372 — distinct MITRE ATLAS tactics of the findings
  "llm.table.mitre": {
    label: "MITRE",
    what: "How many different MITRE ATLAS tactics (the adversarial-AI attack stages) the scan's findings map to.",
    example: "3: initial access, ML model access and exfiltration.",
  },
  // src: backend/utilities/db/scan_list_item.py:293-310 — counts per impact of a successful scan
  "llm.table.vulns": {
    label: "Vulnerabilities",
    what: "This scan's findings by severity: Critical (red), High (orange), Medium (amber), Low (blue). Counted once the scan succeeded.",
    example: "1 red, 0 orange, 3 amber, 2 blue.",
  },
  // src: backend/utilities/db/scan_list_item.py:330-336 — 0-10 weighted per scan
  "llm.table.risk": {
    label: "Risk score",
    what: "This scan's severity-weighted average, 0 to 10: Critical 4, High 3, Medium 2, Low 1, averaged over its findings, divided by 4 and multiplied by 10.",
    example: "1 Critical and 1 Medium: (4+2)/2 = 3, so 7.5.",
  },

  // ────────────────────────────────────────────────────────────── CBOM: scan configuration (components/cbom-options-sidebar.tsx, cbom-ci-scan-settings-form.tsx)
  // src: RabbitMQ/worker/helpers/tools/cbom_agent/main.py:186-196 — deterministic engine, no language model
  "cbom.cfg.repository": {
    label: "Analyze Repository",
    what: "Inventories the cryptography in your code: algorithms, key sizes, certificates, keys, protocols and crypto libraries, graded for strength and quantum safety, into a CycloneDX CBOM. The engine is rule-based; no AI model reads your code.",
    example: "Finds RSA-1024 in a Java KeyPairGenerator call and flags it weak and quantum-vulnerable.",
  },
  // src: RabbitMQ/worker/helpers/tools/cbom_agent/main.py:186-196, backend/utilities/scan/credit_estimate.py:14-24 — an uploaded CBOM is analysed for a flat 0.01
  "cbom.cfg.file": {
    label: "CBOM file",
    what: "A CycloneDX CBOM you already have, as a JSON file, graded by the same rules. Analysing a file costs a flat 0.01 credits. Choosing a file clears the repository or zip.",
    example: "cbom.json produced by another scanner.",
  },
  // src: RabbitMQ/worker/helpers/tools/cbom_agent/main.py:155-162, aibom/src/aibom/cbom/posture/safeio.py:22 — vendored and build directories are skipped unless asked
  "cbom.cfg.vendored": {
    label: "Scan vendored and build directories",
    what: "Also reads vendor/, dist/, build/ and node_modules/: third-party code and build output, skipped by default. Turn it on to see crypto your dependencies ship; it makes the scan larger and dearer.",
    example: "A Go service with a vendor/ folder of crypto libraries.",
  },
  // src: RabbitMQ/worker/helpers/context/scan_context.py:22-28, RabbitMQ/worker/helpers/context/scan_context.py:44-47 — up to 1,000 commits, blobs over 2 MB not downloaded
  "cbom.cfg.history": {
    label: "Scan git history for keys",
    what: "Clones up to 1,000 commits of the branch (files over 2 MB are skipped) and reports key and certificate files that were committed and later deleted: they stay readable in the history.",
    example: "A server.key added in 2023 and removed a week later is still reported.",
  },
  // src: backend/utilities/scan/credit_estimate.py:25-27, RabbitMQ/worker/helpers/tools/cbom_agent/main.py:186-196 — 1 credit per 5 MB of binaries/images/firmware
  "cbom.cfg.binaries": {
    label: "Scan binaries, container images and firmware",
    what: "Also reads compiled binaries, docker save / OCI image archives and firmware: linked crypto libraries, crypto constants, embedded keys and the packages inside images. Adds 1 credit per 5 MB of such content.",
    example: "A 50 MB image archive in the zip adds 10 credits.",
  },
  // src: RabbitMQ/worker/helpers/tools/cbom_agent/main.py:186-196, backend/utilities/scan/credit_estimate.py:14-24, backend/utilities/scan/estimate_scan.py:210 — 1 credit per 0.5 MB source + binaries/5 MB, minimum 1; file 0.01
  "cbom.cfg.estimate": {
    label: "Estimate scan credits",
    what: "A repository or zip costs 2 credits per MB of source files (plus 1 per 5 MB of binaries when that option is on), at least 1 credit; an uploaded CBOM file 0.01. Nothing is charged until you start the scan.",
    example: "300 KB of source: 1 credit (the minimum).",
  },

  // ────────────────────────────────────────────────────────────── CBOM: list page (app/[team_id]/cbom/page.tsx)
  // src: backend/utilities/dashboard/scan_list.py:1701-1755, backend/utilities/cbom_sources/cbom_metrics.py:160-167 — inventory rows of code scans + latest Sources collections, each asset once
  "cbom.kpi.assets": {
    label: "Crypto Assets",
    what: "Cryptographic assets found: algorithms, keys, certificates, protocols and libraries, from successful code scans and the latest CBOM Sources collections. An asset seen by both is counted once, from its latest observation.",
    example: "A TLS certificate found in the repository and on the live server counts 1.",
  },
  // src: backend/utilities/cbom_sources/cbom_metrics.py:118-124, aibom/src/aibom/cbom/weakness.py:93-108 — rows graded weak (broken digests, asymmetric keys under 2048 bits, ...)
  "cbom.kpi.weak": {
    label: "Weak Algorithms",
    what: "Assets graded weak: cryptography that is broken or too short today, for example MD5 or SHA-1 in signatures, or RSA, DSA and DH keys under 2048 bits.",
    example: "A password hash using MD5.",
  },
  // src: backend/utilities/cbom_sources/cbom_metrics.py:125-131, backend/utilities/cbom_sources/cbom_metrics.py:28-40 — verdict quantum-vulnerable
  "cbom.kpi.quantum_vulnerable": {
    label: "Quantum Vulnerable",
    what: "Assets a large quantum computer would break: public-key cryptography such as RSA, ECDSA, ECDH and DH, which need moving to post-quantum algorithms.",
    example: "An ECDHE key exchange without a post-quantum hybrid.",
  },
  // src: backend/utilities/cbom_sources/cbom_metrics.py:132-133 — algorithm_type certificate
  "cbom.kpi.certificates": {
    label: "Certificates",
    what: "X.509 certificates found in code, files or on live endpoints.",
    example: "The certificate served on api.example.com:443.",
  },
  // src: backend/utilities/cbom_sources/cbom_metrics.py:134-135 — algorithm_type key or secret
  "cbom.kpi.keys": {
    label: "Keys",
    what: "Keys and secrets found: private keys, symmetric keys and other key material.",
    example: "A PEM private key committed in config/.",
  },
  // src: backend/utilities/cbom_sources/cbom_metrics.py:28-46, backend/utilities/cbom_sources/cbom_metrics.py:170-174 — judged assets not vulnerable / judged; none judged shows no value
  "cbom.kpi.readiness": {
    label: "Quantum Readiness",
    what: "Share of assets with a quantum verdict that are safe: post-quantum, hybrid, or symmetric with enough margin (AES-128 counts as ready). Assets broken today count as not ready. Assets without a verdict (hashes, settings) are left out.",
    example: "10 judged assets, 3 quantum-vulnerable: 70%.",
  },
  // src: backend/utilities/cbom_sources/cbom_metrics.py:20-21, backend/utilities/cbom_sources/cbom_metrics.py:78-85 — 0-10 over findings: critical 9, high 7, medium 5, low 2
  "cbom.kpi.avg_risk": {
    label: "Avg Risk Score",
    what: "Average risk of the crypto findings, 0 to 10: Critical counts 9, High 7, Medium 5, Low 2. Clean inventory rows are not findings and are left out.",
    example: "One High and one Low finding: (7 + 2) / 2 = 4.5.",
  },
  // src: backend/utilities/dashboard/scan_list.py:1757-1783 — code-scan findings by your status; Sources findings by their remediation plan status
  "cbom.chart.remediation": {
    label: "Remediation Actions Required",
    what: "Crypto findings by status: code-scan findings by the status your team set, CBOM Sources findings by their remediation plan status (open counts as Not started).",
    example: "30 findings: 5 Fixed, 3 In progress, 22 Not started.",
  },
  // src: backend/utilities/cbom_sources/cbom_metrics.py:1-15, backend/utilities/dashboard/scan_list.py:1803 — findings by severity, inventory separately
  "cbom.chart.severity": {
    label: "Severity Distribution",
    what: "Crypto findings by severity (Critical, High, Medium, Low) and the clean inventory rows as Informational.",
    example: "High 4, Medium 9, Informational 120.",
  },
  // src: backend/utilities/cbom_sources/cbom_metrics.py:112-117, backend/utilities/dashboard/scan_list.py:1804 — algorithm_type of every row
  "cbom.chart.algorithm_type": {
    label: "Algorithm Type Distribution",
    what: "All crypto assets by the type the engine gave them (for example certificate, key or secret); assets without a type count as other.",
    example: "certificate 6, key 3, other 12.",
  },
  // src: backend/utilities/cbom_sources/cbom_metrics.py:95, backend/utilities/cbom_sources/cbom_metrics.py:118-124 — weak / moderate / strong / quantum-safe
  "cbom.chart.strength": {
    label: "Crypto Strength Distribution",
    what: "All crypto assets by strength grade: weak (replace now), moderate, strong, quantum-safe. Assets without a grade are not shown.",
    example: "weak 5, moderate 12, strong 60, quantum_safe 2.",
  },
  // src: backend/utilities/cbom_sources/cbom_metrics.py:97, backend/utilities/cbom_sources/cbom_metrics.py:125-131 — quantum_safe / quantum_vulnerable / broken_today
  "cbom.chart.quantum": {
    label: "Quantum Readiness",
    what: "Assets with a quantum verdict: quantum-safe, quantum-vulnerable (breakable by a future quantum computer), and broken today (already insecure without one).",
    example: "Safe 30, Vulnerable 12, Broken today 2.",
  },
  // src: backend/utilities/cbom_sources/cbom_metrics.py:1-15, backend/utilities/dashboard/scan_list.py:1808 — the 10 riskiest findings
  "cbom.chart.top_risks": {
    label: "Top Cryptographic Risks",
    what: "The 10 riskiest crypto findings, with algorithm, type, strength, quantum safety, impact and where each was found (a code scan or a CBOM Sources collection).",
    example: "RSA-1024 · asymmetric · weak · not quantum safe · High · payments-api.",
  },
  // src: backend/routers/cbom_deliverables.py:1-20 — PDFs built in memory from every completed CBOM scan; no language model; no credits charged by the route
  "cbom.deliverables": {
    label: "Deliverables",
    what: "Team-wide regulatory PDFs (for example a certificate register or a post-quantum roadmap) built from every completed CBOM scan of the team. They are generated in-house, with no AI model, and download straight away.",
    example: "Download the PQC roadmap for the board pack.",
  },
  // src: backend/routers/scans.py:100-118, backend/utilities/dashboard/scan_list.py:1786-1790 — the latest completed collection of each Sources source
  "cbom.sources_runs": {
    label: "CBOM Sources results",
    what: "Completed CBOM Sources runs whose assets are counted on this page: when each finished, how many assets it found and how many network endpoints it probed.",
    example: "Sources run #12 · 3 sources · 140 assets · 25 endpoints probed.",
  },
  // src: backend/utilities/db/scan_list_item.py:445-453, backend/utilities/cbom_sources/cbom_metrics.py:1-15 — findings by severity plus inventory
  "cbom.table.risks": {
    label: "Risks",
    what: "This scan's crypto findings by severity: Critical (red), High (orange), Medium (amber), Low (blue), plus clean inventory rows (Informational).",
    example: "0 red, 2 orange, 5 amber, 1 blue, 80 informational.",
  },
  // src: backend/utilities/db/scan_list_item.py:452-453, backend/utilities/cbom_sources/cbom_metrics.py:20-21 — 0-10: critical 9, high 7, medium 5, low 2
  "cbom.table.risk": {
    label: "Risk score",
    what: "This scan's average finding risk, 0 to 10: Critical 9, High 7, Medium 5, Low 2. Inventory rows are left out.",
    example: "Two Medium findings: 5.0.",
  },

  // ────────────────────────────────────────────────────────────── Team dashboard (app/[team_id]/page.tsx, backend/utilities/dashboard/team.py)
  // src: backend/utilities/dashboard/team.py:86-97, backend/utilities/dashboard/team.py:113-134 — every scan of the team plus its CBOM Sources runs
  "team.section.activity": {
    label: "Your Team's Recent Activity",
    what: "Scans of every product in this team, plus CBOM Sources collection runs, counted together.",
    example: "A SAST scan and a CBOM Sources run both count as one scan each.",
  },
  // src: backend/utilities/dashboard/team.py:173-190 — stored findings of all scans + Sources findings not already found by a code scan
  "team.kpi.findings": {
    label: "Total findings",
    what: "Findings stored for all scans of this team, in any product, plus CBOM Sources findings that no code scan already reported.",
    example: "40 SAST + 12 SCA + 8 CBOM findings: 60.",
  },
  // src: backend/utilities/dashboard/team.py:13, backend/utilities/dashboard/team.py:114-134, backend/utilities/dashboard/team.py:196 — STARTED/RETRY scans + running Sources runs
  "team.kpi.started": {
    label: "Started scans",
    what: "Scans running now (started or retrying), plus CBOM Sources runs in progress.",
    example: "2 while a DAST scan and a Sources run are working.",
  },
  // src: backend/utilities/dashboard/team.py:13, backend/utilities/dashboard/team.py:114-134, backend/utilities/dashboard/team.py:197 — SUCCESS scans + done/partial Sources runs
  "team.kpi.completed": {
    label: "Completed scans",
    what: "Scans that finished successfully, plus CBOM Sources runs that finished (fully or partly).",
    example: "30 completed scans across all products.",
  },
  // src: backend/utilities/dashboard/team.py:13, backend/utilities/dashboard/team.py:114-134, backend/utilities/dashboard/team.py:198 — NOT_STARTED/PENDING scans + queued Sources runs
  "team.kpi.not_started": {
    label: "Not started",
    what: "Scans created but not running yet (never started, or queued for a worker), plus queued CBOM Sources runs.",
    example: "A scan you created and never estimated counts here.",
  },
  // src: backend/utilities/dashboard/team.py:174-177, backend/utilities/dashboard/team.py:190 — status fixed (or a fixed date) + Sources findings whose remediation is done
  "team.kpi.fixed": {
    label: "Fixed findings",
    what: "Findings your team marked Fixed, plus CBOM Sources findings whose remediation is done.",
    example: "15 of 60 findings fixed.",
  },
  // src: backend/utilities/dashboard/team.py:191-193 — fixed / total * 100
  "team.kpi.remediation": {
    label: "Remediation",
    what: "Fixed findings as a percentage of all findings of the team.",
    example: "15 fixed of 60: 25.0%.",
  },
  // src: backend/utilities/dashboard/team.py:226-236 — scans created in the last 30 days by type; Sources runs count as CBOM
  "team.chart.activity": {
    label: "Scan activity by type",
    what: "Scans created in the last 30 days, per product (SAST, SCA + SBOM, IaC, DAST, CBOM, AI BOM, MCP, LLM). CBOM Sources runs count as CBOM.",
    example: "SAST 12, DAST 4, CBOM 3.",
  },
  // src: backend/utilities/dashboard/team.py:237-290 — high and critical findings of scans created in the last 30 days
  "team.chart.severity30": {
    label: "Vulnerabilities by severity (last 30 days)",
    what: "High and Critical findings of the scans created in the last 30 days (Medium and Low are not counted here). A CBOM asset seen twice counts once.",
    example: "Critical 3, High 17.",
  },
  // src: backend/utilities/dashboard/team.py:199-205, frontend/app/[team_id]/page.tsx:94 — scans by creation date
  "team.chart.daily": {
    label: "Daily scan volume",
    what: "How many scans the team created each day, all products together, in any status.",
    example: "7 scans on 10 Nov.",
  },
  // src: backend/utilities/dashboard/team.py:13, backend/utilities/dashboard/team.py:114-134 — four buckets over scans and Sources runs
  "team.chart.status": {
    label: "Scan status distribution",
    what: "All scans and CBOM Sources runs by state: Not started (including queued), Running (including retrying), Completed, Failed.",
    example: "Completed 30, Failed 2, Running 1.",
  },
  // src: backend/utilities/dashboard/team.py:135-170 — findings of all products and their status changes over time
  "team.section.findings": {
    label: "Findings & Remediation",
    what: "Findings of all products and what your team did with them, day by day (dates in UTC).",
    example: "A spike of fixes after a remediation sprint.",
  },
  // src: backend/utilities/dashboard/team.py:141-163 — per day: findings created (by current status), plus fixes and ignores on their own dates
  "team.chart.remediations_per_day": {
    label: "Remediations status per day",
    what: "For each day: the findings recorded that day by their current status, plus the findings marked Fixed and Ignored that day.",
    example: "10 Nov: 8 new (5 Not started, 3 In progress), 4 fixed.",
  },
  // src: backend/utilities/dashboard/team.py:150-153 — by creation date
  "team.chart.findings_per_day": {
    label: "Findings per day",
    what: "How many findings were recorded each day, across all products.",
    example: "25 findings on the day a large SAST scan finished.",
  },
  // src: backend/utilities/dashboard/team.py:157-159 — by fixed date
  "team.chart.fixes_per_day": {
    label: "Fixes per day",
    what: "How many findings were marked Fixed each day.",
    example: "6 fixes on 9 Nov.",
  },
  // src: backend/utilities/dashboard/team.py:160-162 — by ignored date
  "team.chart.false_positives": {
    label: "False positive trends",
    what: "How many findings were marked Ignored each day: the findings your team judged false positives or accepted risks.",
    example: "3 ignored on 8 Nov.",
  },
  // src: backend/utilities/dashboard/team.py:89, frontend/app/[team_id]/page.tsx:817-830 — CI/CD integrations by creation date
  "team.section.integrations": {
    label: "Your Team's Integrations",
    what: "CI/CD integrations your team created, by creation date.",
    example: "2 integrations created on 1 Nov.",
  },

  // ────────────────────────────────────────────────────────────── Team settings (app/[team_id]/settings/page.tsx)
  // src: backend/routers/team.py:86, backend/utilities/team/invitations.py:219, backend/routers/team.py:173 — creator is admin, invitees join as member
  "settings.members": {
    label: "Team members",
    what: "Everyone in this team and their role. Admin: the team's creator (and other admins) can edit the team, invite, remove members and delete it. Member: runs scans and works on findings. Tick members to remove them.",
    example: "you@acme.com admin, dev@acme.com member.",
  },
  // src: backend/utilities/team/invitations.py:1-9, backend/utilities/team/invitations.py:33 — single-use link, 7 days, no password mailed
  "settings.invite": {
    label: "Invite by email",
    what: "Mails the address a single-use invitation link, valid for 7 days. No password is sent: a new person chooses one on the invitation page, an existing user signs in and accepts. Nobody joins until they accept.",
    example: "dev@acme.com joins as a member after clicking the link.",
  },
  // src: backend/utilities/team/invitations.py:1-9, backend/utilities/team/invitations.py:33, backend/routers/team.py:466-490 — open invitations; resend replaces the link; revoke cancels it
  "settings.invitations": {
    label: "Pending invitations",
    what: "Invitations not yet accepted, with their status and expiry (7 days after sending). Resend mails a new link (the old one stops working); Revoke cancels it.",
    example: "dev@acme.com · pending · expires 18 Nov.",
  },
  // src: backend/utilities/db/schemas.py:24-37, backend/utilities/integrations/jira.py:100-160 — Jira Cloud REST v3 with email + API token
  "settings.jira": {
    label: "Jira",
    what: "Connects the team to Jira (REST API v3, as used by Jira Cloud) so scans can create Jira issues from findings. Each scan chooses its project and whether tickets are created automatically.",
    example: "https://acme.atlassian.net with a bot account's API token.",
  },
  // src: backend/utilities/integrations/jira.py:100-110 — basic auth email + token
  "settings.jira.email": {
    label: "Jira email",
    what: "The email of the Jira account the tickets are created as. It needs access to the projects you will pick.",
    example: "security-bot@acme.com.",
  },
  // src: backend/utilities/db/schemas.py:27, backend/utilities/integrations/jira.py:107 — the site URL; REST paths are added to it
  "settings.jira.url": {
    label: "Jira URL",
    what: "The address of your Jira site, without a path.",
    example: "https://acme.atlassian.net.",
  },
  // src: backend/utilities/db/schemas.py:26, backend/utilities/integrations/jira.py:100-110 — secret field, never printed; basic auth with the email
  "settings.jira.token": {
    label: "Jira API token",
    what: "An API token of that Jira account (Atlassian account settings > Security > API tokens). It is stored for the team and never printed in logs.",
    example: "A token created for the security-bot account.",
  },
  // src: backend/utilities/db/schemas.py:20-22, backend/routers/team.py:193-215 — admin only
  "settings.team.name": {
    label: "Team name",
    what: "The team's name, shown in the team switcher. Only admins can change it.",
    example: "Payments platform.",
  },
  // src: backend/utilities/db/schemas.py:20-22, backend/routers/team.py:193-215 — optional text
  "settings.team.description": {
    label: "Description",
    what: "An optional note about what this team covers.",
    example: "Scans for the payments services and their infrastructure.",
  },
  // src: backend/routers/team.py:297-330 — admin only; the default team cannot be deleted; scans and CBOM Sources data are deleted
  "settings.danger": {
    label: "Danger zone",
    what: "Deleting the team removes its scans, findings and CBOM Sources data for everyone. Only admins can do it, and your default team cannot be deleted.",
    example: "Delete a team created for a finished project.",
  },

  // ────────────────────────────────────────────────────────────── Per-scan ticketing (components/ticketing-integrations-settings.tsx)
  // src: backend/utilities/db/schemas.py:39-45, backend/utilities/integrations/jira.py:148 — project used for issues created from this scan
  "ticketing.jira_project": {
    label: "Jira project ID",
    what: "The Jira project where tickets for this scan's findings are created, using the Jira connection in team Settings.",
    example: "10001 (the numeric id of project SEC).",
  },
  // src: backend/utilities/db/schemas.py:39-41, backend/utilities/celery/celery_connection.py:236-239, backend/utilities/integrations/jira_ticketing.py:20, backend/utilities/integrations/jira_ticketing.py:170-200 — one task per finding when the scan succeeds, cap 50
  "ticketing.auto_create": {
    label: "Create tickets automatically",
    what: "When on, one Jira task is created per finding as soon as this scan succeeds (at most 50 per scan). Marking a finding Fixed closes its ticket.",
    example: "Turn it on for a nightly scan your team triages in Jira.",
  },

  // ────────────────────────────────────────────────────────────── Account (app/[team_id]/account/page.tsx)
  // src: backend/routers/auth.py:333-345 — the current password is checked before the change
  "account.current_password": {
    label: "Current password",
    what: "Your present password, to prove it is you before the change.",
    example: "The password you signed in with today.",
  },
  // src: backend/utilities/auth/auth_utils.py:203-243, frontend/utils/password_rules.ts:1-8 — 8 to 128 characters, at most 512 bytes
  "account.new_password": {
    label: "New password",
    what: "8 to 128 characters (an emoji counts as one), at most 512 bytes. After the change every other browser and device is signed out; this one stays signed in.",
    example: "A passphrase such as \"correct-horse-battery-staple\".",
  },
  // src: frontend/app/[team_id]/account/page.tsx:55-67 — must equal the new password
  "account.confirm_password": {
    label: "New password again",
    what: "Type the new password once more, so a typo does not lock you out.",
    example: "The same passphrase as above.",
  },
  // src: backend/routers/auth.py:1-8 — logout revokes every token issued before it
  "account.sessions": {
    label: "Sessions",
    what: "Sign out everywhere ends every session of your account, on every browser and device, this one included.",
    example: "Use it after signing in on a shared computer.",
  },

  // ────────────────────────────────────────────────────────────── Admin (app/admin/page.tsx, superusers only)
  // src: backend/routers/admin.py:200-262 — superuser account; temporary password; a single-use choose-your-password link is mailed
  "admin.create_user": {
    label: "Create admin user",
    what: "Creates a superuser account. The password you set is temporary: the user must choose their own at first sign-in, and is mailed a single-use link to do it (the password itself is never mailed).",
    example: "ops@zeroshield.example with a temporary password.",
  },
  // src: backend/routers/admin.py:220-235 — one account per email
  "admin.email": {
    label: "Email",
    what: "The new admin's sign-in email. It must not belong to an existing account.",
    example: "ops@zeroshield.example.",
  },
  // src: backend/routers/admin.py:219-222, backend/utilities/auth/auth_utils.py:203-243 — temporary; 8-128 characters
  "admin.password": {
    label: "Password",
    what: "A temporary password, 8 to 128 characters; the user replaces it at first sign-in.",
    example: "A random 16-character string.",
  },
  // src: backend/routers/admin.py:236-246 — stored on the account
  "admin.name": {
    label: "Name",
    what: "The new admin's first and last name, shown in team member lists and scan owners.",
    example: "Asha Rao.",
  },
  // src: backend/routers/admin.py:153-199, backend/routers/admin.py:355-424 — every user, teams, superuser switch
  "admin.users": {
    label: "Users",
    what: "Every account on this installation, its teams and whether it has admin (superuser) access. The switch grants or removes that access.",
    example: "Turn off Admin Access for someone who changed role.",
  },
  // src: backend/routers/admin.py:97-152, backend/routers/admin.py:291-354 — every team; the credit balance is set (not added), never negative
  "admin.teams": {
    label: "Teams",
    what: "Every team with its members, credit balance and scan count. Editing the balance sets it to the number you enter (it does not add to it); it cannot be negative.",
    example: "Set 5000 to give a team 5,000 credits in total.",
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
  // src: backend/utilities/dashboard/scan.py:857-858, RabbitMQ/worker/helpers/tools/sca_sbom_agent/merge_inventory.py:109-122 — len(results) of this scan; packages with no known vulnerability are Low rows (#46)
  "sbom.res.kpi.total": {
    label: "Total vulnerabilities",
    what: "This scan's result rows: each known vulnerability in your dependencies, plus each package found with no known vulnerability (stored as a Low row).",
    example: "1 vulnerable package and 3 packages with no known vulnerability: 4.",
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
  // src: backend/utilities/dashboard/scan.py:860-864, backend/utilities/dashboard/scan.py:95-97 — medium + high risk license categories over all result rows (#46)
  "sbom.res.kpi.license_risks": {
    label: "License risks",
    what: "This scan's result rows, vulnerable packages or not, whose license is medium-risk (weak copyleft such as LGPL or MPL, Creative Commons, commercial) or high-risk (strong copyleft such as GPL, network copyleft such as AGPL, source-available such as SSPL or BUSL).",
    example: "A package under LGPL-3.0 counts here even with no known vulnerability.",
  },
  // src: backend/utilities/dashboard/scan.py:865-869, backend/utilities/dashboard/scan.py:96 — strong copyleft, network copyleft, source-available
  "sbom.res.kpi.high_risk_licenses": {
    label: "High-risk licenses",
    what: "Vulnerabilities whose package is under a strong copyleft (GPL), network copyleft (AGPL) or source-available (SSPL, BUSL) license.",
    example: "A vulnerable package licensed AGPL-3.0.",
  },
  // src: backend/utilities/dashboard/scan.py:28-33, backend/utilities/dashboard/scan.py:853-859 — mean of 10/7.5/5/2.5 per result row, Python round(x, 1); packages with no known vulnerability are Low rows (#46)
  "sbom.res.kpi.avg_risk": {
    label: "Avg risk score",
    what: "Average over this scan's result rows, 0 to 10: Critical counts 10, High 7.5, Medium 5, Low 2.5. Packages with no known vulnerability are Low rows. Rounded to one decimal.",
    example: "1 Critical and 3 packages with no known vulnerability: (10 + 3 × 2.5) / 4 = 4.4.",
  },
  // src: backend/utilities/dashboard/scan.py:843-846, RabbitMQ/worker/helpers/context/schema.py:34, RabbitMQ/worker/helpers/tools/sca_sbom_agent/main.py:137-158 — the AI model's label; no source file in its context
  "sbom.res.kpi.reachable": {
    label: "Reachable issues",
    what: "Vulnerabilities the AI model labelled Reachable. It judges from the vulnerability and package data (description, severity, where the package was found); it does not read your code, so treat the label as a hint.",
    example: "A CVE in a web framework's request parser may be labelled Reachable although your code never uses that parser.",
  },
  // src: backend/utilities/dashboard/scan.py:871-879, backend/utilities/dashboard/finding_metrics.py:18-40, frontend/components/SbomResults.tsx:246-250 — stored result rows of the scan by status, share of all; packages with no known vulnerability included (#46)
  "sbom.res.remediation": {
    label: "Remediation actions",
    what: "This scan's result rows by the status your team set (Fixed, In progress, Not started, Ignored), each as a count and a share of all its rows.",
    example: "10 rows: 2 Fixed (20%), 1 In progress, 7 Not started.",
  },
  // src: backend/utilities/dashboard/scan.py:837-839, backend/utilities/dashboard/scan.py:953 — count per impact; Low includes packages with no known vulnerability (#46)
  "sbom.res.severity": {
    label: "Severity distribution",
    what: "How many of this scan's result rows have each impact: Critical, High, Medium and Low. Low also counts packages with no known vulnerability.",
    example: "Critical 1, High 3, Medium 6, Low 2.",
  },
  // src: backend/utilities/dashboard/scan.py:843-844, backend/utilities/dashboard/scan.py:881-896, RabbitMQ/worker/helpers/context/schema.py:34 — the AI model's label; missing counts as Not assessed; packages with no known vulnerability are stored Not reachable (#46)
  "sbom.res.reachability": {
    label: "Reachability distribution",
    what: "This scan's result rows by the reachability label the AI model gave each one from the vulnerability and package data (it does not read your code): Reachable, Potentially reachable, Not reachable, or Not assessed. Not reachable also counts packages with no known vulnerability.",
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
  // ────────────────────────────────────────────────────────────── CBOM Sources: shared by the tabs, and Servers (components/cbom/sources/ServersTab.tsx)
  // src: frontend/components/cbom/sources/ServersTab.tsx:173-174, backend/utilities/cbom_sources/kinds.py:26 — 1-64 letters, digits, spaces, dots, dashes, underscores
  "cbsrc.common.name": {
    label: "Source name",
    what: "A name for this source, 1 to 64 letters, digits, spaces, dots, dashes or underscores. It labels the source in lists, run results, the CBOM and reports.",
    why: "Every asset a run finds records the source it came from, so a clear name tells an auditor where a weak key or certificate lives.",
    example: "dc-mumbai-linux for the Linux servers of the Mumbai data centre.",
  },
  // src: frontend/components/cbom/sources/ServersTab.tsx:963-972, backend/utilities/cbom_sources/jobs.py:302 — jobs of the source run on this node
  "cbsrc.common.node": {
    label: "Scan node",
    what: "The scan node, inside your network, that connects to these targets and collects their crypto. Every job of this source (connection tests and collection) runs on it.",
    why: "Only a node that can reach the targets on the right port can read them; a node in the wrong network segment makes every target unreachable.",
    example: "node-dc1 in the 10.20.0.0/16 segment for servers in 10.20.5.0/24.",
  },
  // src: frontend/components/cbom/sources/ServersTab.tsx:976-982, frontend/components/cbom/sources/ServersTab.tsx:176-177 — 1,000 lines; ranges up to /16; 262,144 addresses per source
  "cbsrc.servers.targets": {
    label: "Targets",
    what: "The servers to read: IP addresses, CIDR ranges or hostnames, one per line, up to 1,000 lines. A range may be at most a /16 and a source at most 262,144 addresses. Import CSV adds the first column of a file.",
    why: "Only listed targets are scanned, so a server left out is a blind spot in the CBOM.",
    example: "10.20.0.0/24, 10.20.5.17 and app-01.bank.local: 256 + 1 + 1 targets.",
  },
  // src: frontend/components/cbom/sources/teamNeverScan.ts:96-97 — per-source exclusions; never-scan always wins
  "cbsrc.common.never_scan": {
    label: "Never scan",
    what: "Addresses, ranges or hostnames this source must never touch, one per line or comma-separated. A hostname also covers every address it resolves to from the scan node. The team never-scan list on the Network tab applies as well. Never-scan always wins over targets.",
    why: "Keeps fragile or out-of-scope systems (a core banking host, a partner's range) out of every job.",
    example: "10.20.0.1, 10.20.0.254 keeps the two gateways out of 10.20.0.0/24.",
  },
  // src: frontend/components/cbom/sources/ServersTab.tsx:120-123 — SSH 22, WinRM over HTTPS 5986, LDAPS 636 by default
  "cbsrc.servers.port": {
    label: "Port",
    what: "The port the scan node connects to: SSH for Linux (default 22), WinRM over HTTPS for Windows (5986), LDAPS for Active Directory (636).",
    why: "A port that is closed or filtered from the node fails the connection test for every server.",
    example: "2222 when your Linux servers run sshd on a non-standard port.",
  },
  // src: frontend/components/cbom/sources/ServersTab.tsx:1072-1078, backend/utilities/cbom_sources/kinds.py:27 — up to 64 characters; DOMAIN\\user accepted for Windows and AD
  "cbsrc.servers.login": {
    label: "Login user",
    what: "The account the scan node logs in as, up to 64 characters. For Linux a read-only account on each server (zs-cbom by default); for Windows and Active Directory a local or domain account, DOMAIN\\user accepted.",
    why: "A dedicated read-only account limits what a leaked credential could do and makes the scan easy to spot in audit logs.",
    example: "zs-cbom on Linux; BANK\\svc-zscbom for Active Directory.",
  },
  // src: frontend/components/cbom/sources/ServersTab.tsx:1093-1110 — trust on first use or pinned known_hosts; a password forces pinning
  "cbsrc.servers.host_key_policy": {
    label: "Host key policy",
    what: "How the node checks each server's SSH host key before logging in. Trust on first use remembers the key on first contact and refuses and alerts if it changes. Pin fingerprints accepts only the keys you paste. A password credential requires pinned keys.",
    why: "The host key check stops a machine impersonating the server from capturing the credential.",
    example: "Pin fingerprints with the output of ssh-keyscan for servers you already trust.",
  },
  // src: frontend/components/cbom/sources/ServersTab.tsx:1114-1120 — public keys only
  "cbsrc.servers.known_hosts": {
    label: "known_hosts lines",
    what: "The SSH host keys to accept, in known_hosts format: the output of ssh-keyscan or your existing known_hosts file. Public keys only; upload a file or paste the lines.",
    why: "A server whose key is not listed is refused, so a spoofed server never receives the login.",
    example: "10.20.0.11 ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAA...",
  },
  // src: frontend/components/cbom/sources/ServersTab.tsx:1153-1160, backend/utilities/cbom_sources/kinds.py:21 — PEM up to 64 KB, checked before the login is sent
  "cbsrc.servers.ca_pem": {
    label: "CA certificate",
    what: "Optional PEM certificate of the CA that issued the WinRM (HTTPS) or LDAPS certificate of the servers. The server's certificate is checked against it before the login is sent. Needed when an internal CA issued it.",
    why: "Without the right CA the TLS check fails and the node never sends the password.",
    example: "The root certificate of BANK-ISSUING-CA, as -----BEGIN CERTIFICATE-----...",
  },
  // src: frontend/components/cbom/sources/ServersTab.tsx:127-133, frontend/components/cbom/sources/ServersTab.tsx:1200-1212 — node key, SSH CA, SSH certificate, vault reference or password; vault and SSH CA for admins only
  "cbsrc.servers.credential": {
    label: "Credential",
    what: "How the node proves who it is. Node-generated SSH key (recommended, the private key never leaves the node), SSH CA certificate (signed per job for minutes), your own SSH certificate, a vault reference, or a password. Only team admins choose vault or SSH CA.",
    why: "The credential is the most sensitive thing a source holds; options that keep secrets off ZeroShield reduce what a breach could expose.",
    example: "Linux: Node-generated SSH key, then install the shown public key for zs-cbom.",
  },
  // src: frontend/components/cbom/sources/ServersTab.tsx:1266-1277, backend/utilities/cbom_sources/kinds.py:20 — secrets up to 256 KB, encrypted at rest
  "cbsrc.servers.ssh_certificate": {
    label: "SSH certificate",
    what: "An OpenSSH user certificate signed by your own SSH CA, used together with the private key below. Encrypted at rest and sent only to the scan node that runs the job.",
    why: "A short-lived certificate expires on its own, so a copied credential stops working.",
    example: "ssh-ed25519-cert-v01@openssh.com AAAA... zs-cbom valid for 8 hours.",
  },
  // src: frontend/components/cbom/sources/ServersTab.tsx:1278-1289, backend/utilities/cbom_sources/kinds.py:20 — secrets up to 256 KB, encrypted at rest
  "cbsrc.servers.private_key": {
    label: "Private key",
    what: "The private key that goes with the SSH certificate, in OpenSSH or PEM format. Encrypted at rest, never shown again, sent only to the scan node that runs the job.",
    why: "Without the matching private key the certificate cannot be used to log in.",
    example: "-----BEGIN OPENSSH PRIVATE KEY----- ....",
  },
  // src: frontend/components/cbom/sources/ServersTab.tsx:1296-1306 — the CA's active key signs the node's key for each job
  "cbsrc.servers.ssh_ca": {
    label: "SSH CA",
    what: "The ZeroShield SSH CA (created on Fleet > SSH CA) whose active key signs the scan node's own key for each job; the certificate lives for minutes. Rotating the CA needs no change here.",
    why: "Servers trust one CA instead of a key per node, and no long-lived credential exists to steal.",
    example: "prod-ssh-ca, trusted on the servers through TrustedUserCAKeys.",
  },
  // src: frontend/components/cbom/sources/ServersTab.tsx:175, frontend/components/cbom/sources/ServersTab.tsx:1309-1312 — zs-<team>-<name>, one per line
  "cbsrc.servers.principals": {
    label: "Principals",
    what: "The principals written into each job's certificate, one per line, in the form zs-<team id>-<name>. A server accepts the certificate only for a login whose principals file lists one of them.",
    why: "Principals decide which servers accept the certificate, so prod and test servers can trust different ones.",
    example: "zs-12-prod, listed in /etc/ssh/zs-cbom/principals/zs-cbom on the production servers.",
  },
  // src: frontend/components/cbom/sources/ServersTab.tsx:1314-1318 — source-address of the certificate; /16 or narrower (IPv6 /48)
  "cbsrc.servers.source_addresses": {
    label: "Addresses the servers see the node as",
    what: "The source-address restriction written into each certificate: the addresses or networks (/16 or narrower, IPv6 /48) the servers see the node connect from. Blank uses the node's own addresses.",
    why: "A certificate copied off the node cannot be used from anywhere else.",
    example: "10.20.1.15, or 10.20.1.0/28 when the node sits behind a NAT pool.",
  },
  // src: frontend/components/cbom/sources/ServersTab.tsx:135-140 — HashiCorp Vault, CyberArk, AWS Secrets Manager, Azure Key Vault
  "cbsrc.common.vault_provider": {
    label: "Vault",
    what: "The secrets manager the scan node reads the credential from when a job runs: HashiCorp Vault, CyberArk, AWS Secrets Manager or Azure Key Vault.",
    why: "The password stays in your vault and is never stored by ZeroShield.",
    example: "CyberArk, where the svc-zscbom password is already rotated daily.",
  },
  // src: frontend/components/cbom/sources/ServersTab.tsx:1344-1351 — only the reference is stored
  "cbsrc.common.vault_path": {
    label: "Secret path",
    what: "Where the secret lives in your vault. The scan node reads it when the job runs; ZeroShield stores only this reference. Only a team admin can add or change it.",
    why: "A wrong path fails every job of the source at the login step.",
    example: "secret/data/cbom/linux-prod for HashiCorp Vault KV v2.",
  },
  // src: frontend/components/cbom/sources/ServersTab.tsx:1367-1376, backend/utilities/cbom_sources/kinds.py:20 — encrypted at rest; blank on edit keeps the saved one
  "cbsrc.common.password": {
    label: "Password",
    what: "The account's password. Encrypted at rest by ZeroShield, sent only to the scan node that runs the job and never shown again. When editing, leave it blank to keep the saved one.",
    why: "Changing the targets, port, login or node clears a stored password, so it is never sent to a host it was not meant for.",
    example: "The password of svc-zscbom, rotated every 90 days.",
  },
  // src: frontend/components/cbom/sources/ServersTab.tsx:141-170, frontend/components/cbom/sources/ServersTab.tsx:1384-1398 — Tier 1 read-only commands; Tier 2 adds an exact sudo allowlist
  "cbsrc.servers.tier": {
    label: "Privilege tier",
    what: "Tier 1 runs read-only commands as the login user: packages, crypto configs, readable keys, certificates and keystores. Tier 2 adds an exact sudo allowlist (no wildcards) to see which process loads which crypto library, socket owners, the effective SSH config and disk encryption.",
    why: "Tier 2 finds crypto in use at runtime that config files alone do not show, at the cost of a sudoers entry.",
    example: "Tier 2 shows that java on port 8443 loads libssl 1.1.1 with TLS 1.0 enabled.",
  },
  // src: frontend/components/cbom/sources/ServersTab.tsx:1231-1240 — the public key for the login user
  "cbsrc.servers.node_key_install": {
    label: "Install the node's key",
    what: "Copy this public key into authorized_keys of the login user on every server of this source.",
    why: "Until the key is installed, the connection test reports Login failed for each server.",
    example: "ssh-copy-id is not needed: echo 'ssh-ed25519 AAAA...' >> ~zs-cbom/.ssh/authorized_keys.",
  },
  // src: backend/utilities/cbom_sources/kinds.py:171 — 1 to 64, default 8
  "cbsrc.servers.parallel": {
    label: "Servers in parallel",
    what: "How many servers the scan node reads at the same time, 1 to 64 (default 8).",
    why: "Higher finishes large ranges sooner but adds load on the node and the network.",
    example: "8 reads a /24 of 254 servers in about 32 rounds.",
  },
  // src: backend/utilities/cbom_sources/kinds.py:172 — 10 to 3,600 s, default 300
  "cbsrc.servers.timeout": {
    label: "Timeout per server",
    what: "How long the node may spend on one server, 10 to 3,600 seconds (default 300). A server that takes longer is reported as timed out and the job moves on.",
    why: "One hung server cannot stall the whole run.",
    example: "600 for servers with very large keystores to read.",
  },
  // src: frontend/components/cbom/sources/ServersTab.tsx:1514-1545 — team network window, any time, or a custom copy
  "cbsrc.common.window": {
    label: "Scan window",
    what: "When collection may run: the team scan window set on the Network tab, any time, or a custom copy of the weekly hours for this source. Connection tests always run straight away.",
    why: "Keeps scans out of business hours or change freezes on production systems.",
    example: "Network window (team): weekdays 22:00 to 06:00 IST.",
  },
  // src: frontend/components/cbom/sources/ServersTab.tsx:919-923, frontend/components/cbom/sources/ServersTab.tsx:117-124 — Linux, Windows or Active Directory sources
  "cbsrc.servers.form": {
    label: "Add servers",
    what: "A server source is one list of Linux servers, Windows servers or an Active Directory, read through one scan node with a read-only account. Pick the type, then where the servers are and how to log in.",
    why: "Servers hold most of the keys, certificates and crypto libraries an inventory has to cover.",
    example: "Linux: 10.20.0.0/24 through node-dc1, login zs-cbom with the node's SSH key.",
  },
  // src: frontend/components/cbom/sources/ServersTab.tsx:513-546 — each source with its target count after exclusions
  "cbsrc.servers.list": {
    label: "Configured server sources",
    what: "The server sources of this team with their type, target count after exclusions, scan node, privilege tier and last connection test.",
    why: "Sources here are what a run on the Review & Run tab collects from.",
    example: "dc-mumbai-linux · Linux · 256 targets · node-dc1 · Tier 1 · Passed.",
  },
  // src: frontend/components/cbom/sources/ServersTab.tsx:141-170, frontend/components/cbom/sources/ServersTab.tsx:1594-1598 — the command lists; nothing is installed
  "cbsrc.servers.what_runs": {
    label: "Exactly what runs on each server",
    what: "The exact commands the node runs on each server for the chosen type and tier. Nothing is installed; output is parsed on the node.",
    why: "Your change board can review every command before approving the scan.",
    example: "Tier 1 runs openssl version -a and cat /etc/ssh/sshd_config, among others.",
  },
  // src: backend/utilities/cbom_sources/jobs.py:302, backend/utilities/cbom_sources/jobs.py:670-674 — up to 5 sampled targets
  "cbsrc.servers.test": {
    label: "Connection test",
    what: "The result of the last connection test: up to 5 sampled targets, each checked for reachability, login and privilege. Passed when every sample is ready, Partly ready when some are.",
    why: "It proves the node, network path and credential work before a full run spends credits.",
    example: "4 of 5 samples ready: 10.20.0.9 refused the login.",
  },
  // src: frontend/components/cbom/sources/ServersTab.tsx:117-124 — the source kind
  "cbsrc.col.type": {
    label: "Type",
    what: "The kind of source: what it reads and how.",
    why: "Each type uses a different protocol, port and credential.",
    example: "Linux servers over SSH; Active Directory over LDAPS.",
  },
  // src: backend/utilities/cbom_sources/jobs.py:302 — targets after exclusions
  "cbsrc.col.targets": {
    label: "Targets",
    what: "How many addresses or names this source covers after its never-scan list and the team never-scan list are removed.",
    why: "Collection credits and run time grow with the number of targets.",
    example: "254 for 10.20.0.0/24 minus the two gateways.",
  },
  // src: frontend/components/cbom/sources/ServersTab.tsx:963-972 — the scan node that runs the source's jobs
  "cbsrc.col.node": {
    label: "Node",
    what: "The scan node that runs this source's jobs.",
    why: "An offline node means the source cannot be tested or collected.",
    example: "node-dc1 · Online.",
  },
  // src: frontend/components/cbom/sources/ServersTab.tsx:1384-1398 — Tier 1 or Tier 2
  "cbsrc.col.tier": {
    label: "Tier",
    what: "The privilege tier of a Linux source: Tier 1 without sudo, Tier 2 with the exact sudo allowlist.",
    why: "Tier 2 sees runtime crypto use that Tier 1 cannot.",
    example: "Tier 2 on the application servers, Tier 1 elsewhere.",
  },
  // src: backend/utilities/cbom_sources/jobs.py:670-684 — passed, partial, failed, could not test
  "cbsrc.col.last_test": {
    label: "Last test",
    what: "The result of the latest connection test: Not tested, Testing, Passed (every sample ready), Partly ready, Failed or Could not test, with its summary below.",
    why: "A source that has not passed a test is likely to fail its collection jobs.",
    example: "Partly ready · 3 of 5 samples ready.",
  },
  // src: backend/utilities/cbom_sources/jobs.py:302 — sampled target
  "cbsrc.test.server": {
    label: "Server",
    what: "One of the targets sampled for the connection test.",
    why: "Samples stand in for the whole range, so fix their failures before running.",
    example: "10.20.0.17.",
  },
  // src: frontend/components/cbom/sources/ServersTab.tsx:1764-1766 — yes, no, or waiting
  "cbsrc.test.reachable": {
    label: "Reachable",
    what: "Whether the scan node could open a connection to the server on the configured port.",
    why: "No here points at routing, a firewall or the wrong port, not the credential.",
    example: "No: port 22 is filtered between node-dc1 and 10.20.0.17.",
  },
  // src: frontend/components/cbom/sources/ServersTab.tsx:1764-1767 — yes, no, or waiting
  "cbsrc.test.login": {
    label: "Login",
    what: "Whether the login user could authenticate with the configured credential.",
    why: "No here means the key, certificate or password is not accepted on that server.",
    example: "No: the node's key is not in authorized_keys of zs-cbom.",
  },
  // src: frontend/components/cbom/sources/ServersTab.tsx:1755, frontend/components/cbom/sources/ServersTab.tsx:1768 — sudo allowlist (Linux Tier 2) or Windows group
  "cbsrc.test.privilege": {
    label: "Privilege",
    what: "Linux Tier 2: whether the sudo allowlist works. Windows: whether the account may open a WinRM shell (Remote Management Users with WinRM access). Not needed for Linux Tier 1.",
    why: "Without it, runtime crypto use is not collected even though the login works.",
    example: "No: the sudoers file was not installed on 10.20.0.17.",
  },
  // src: frontend/components/cbom/sources/ServersTab.tsx:1769-1774 — the sample's status and note
  "cbsrc.test.result": {
    label: "Result",
    what: "The sample's overall status with the node's note, for example Ready, Unreachable or Login failed.",
    why: "The note names the exact cause to fix.",
    example: "Login failed · Permission denied (publickey).",
  },
  // ────────────────────────────────────────────────────────────── CBOM Sources: source metadata (components/cbom/sources/SourceMetadata.tsx)
  // src: backend/utilities/cbom_sources/kinds.py:55-56, backend/utilities/cbom_sources/kinds.py:67, backend/utilities/cbom_sources/waves.py:120 — up to 128 characters; the default remediation owner
  "cbsrc.meta.owner": {
    label: "Owner",
    what: "The team or person who answers for this source, up to 128 characters. Remediation waves use it as the owner of this source's findings.",
    why: "A finding without an owner is rarely fixed; this routes it to the right people.",
    example: "Payments platform team.",
  },
  // src: backend/utilities/cbom_sources/kinds.py:55-56, backend/utilities/cbom_sources/kinds.py:68 — up to 128 characters
  "cbsrc.meta.application": {
    label: "Application",
    what: "The business application this source serves, up to 128 characters, shown with its findings in reports and the roadmap.",
    why: "Migration is planned per application, so findings grouped by it are easier to schedule.",
    example: "UPI switch.",
  },
  // src: backend/utilities/cbom_sources/kinds.py:55-56, backend/utilities/cbom_sources/kinds.py:69 — public, internal, confidential or restricted
  "cbsrc.meta.classification": {
    label: "Data classification",
    what: "How sensitive the data this source handles is: Public, Internal, Confidential or Restricted.",
    why: "Sensitive data protected by quantum-vulnerable crypto is the first thing to migrate.",
    example: "Restricted for systems holding card or Aadhaar data.",
  },
  // src: backend/utilities/cbom_sources/kinds.py:70, backend/utilities/cbom_sources/posture.py:10-11 — 0 to 100 years; Mosca's X
  "cbsrc.meta.lifetime": {
    label: "Data must stay secret for (years)",
    what: "How many years this source's data must stay confidential, 0 to 100: Mosca's X. With the team's migration time (Y) and quantum timeline (Z), X + Y > Z means the data is already at risk.",
    why: "Long-lived data encrypted with RSA or ECDH today can be recorded now and decrypted later (harvest now, decrypt later).",
    example: "10 for loan records kept a decade: with Y = 3 and Z = 10, 13 > 10, so it is at risk now.",
  },
  // src: backend/utilities/cbom_sources/kinds.py:57, backend/utilities/cbom_sources/kinds.py:71 — up to 32 characters, as the CMDB names it
  "cbsrc.meta.environment": {
    label: "Environment",
    what: "The environment of this source as your CMDB names it, up to 32 characters. A CMDB import fills it in.",
    why: "Lets you plan production fixes separately from test systems.",
    example: "production.",
  },
  // src: backend/utilities/cbom_sources/kinds.py:54, backend/utilities/cbom_sources/posture.py:39, backend/utilities/cbom_sources/posture.py:99 — overrides the derived exposure; internet x1.5
  "cbsrc.meta.exposure": {
    label: "Internet exposure",
    what: "Overrides the internet exposure worked out from the collected facts: From collected facts (no override), Internet-facing, Internal or Unknown. Internet-facing multiplies the risk score of this source's findings by 1.5.",
    why: "Systems reachable from the internet are attacked first, so their weak crypto ranks higher.",
    example: "Internet-facing for the API gateway servers behind the public load balancer.",
  },
  // src: backend/utilities/cbom_sources/kinds.py:53, backend/utilities/cbom_sources/posture.py:36, backend/utilities/cbom_sources/posture.py:192-193 — low 0.5, medium 1, high 1.5, critical 2
  "cbsrc.meta.criticality": {
    label: "Business criticality",
    what: "How critical the systems of the selected sources are to the business. It scales the risk score of their findings: Low x0.5, Medium x1 (the default), High x1.5, Critical x2.",
    why: "The same weak cipher matters more on a payment switch than on a test box.",
    example: "Critical: a High finding (7) on an internet-facing source scores 7 x 2 x 1.5 = 21.",
  },
  // src: backend/utilities/cbom_sources/kinds.py:59-62 — metadata never cancels a job or resets the test
  "cbsrc.meta.bulk": {
    label: "Owners, applications and data",
    what: "Set the owner, application, data classification, data lifetime, environment and criticality of several sources at once. These describe the source, so saving them never cancels a job or resets its connection test.",
    why: "Ownership and sensitivity drive risk scores and remediation waves for every run that follows.",
    example: "Select the 4 Mumbai sources and set Owner to Payments platform team.",
  },
  // src: frontend/components/cbom/sources/SourceMetadata.tsx:200-210 — which sources the bulk edit changes
  "cbsrc.meta.select": {
    label: "Select sources",
    what: "Choose the sources the values below are written to; the first box selects every source.",
    why: "Only selected sources change; the others keep their values.",
    example: "Tick dc-mumbai-linux and dc-mumbai-windows, then Apply.",
  },
  // ────────────────────────────────────────────────────────────── CBOM Sources: Kubernetes, databases, HSMs and key managers (components/cbom/sources/ClustersDatabasesTab.tsx)
  // src: frontend/components/cbom/sources/ClustersDatabasesTab.tsx:373 — read through a scan node
  "cbsrc.k8sdb.intro": {
    label: "Kubernetes clusters and databases",
    what: "Kubernetes clusters, databases, HSMs and key managers, each read through a scan node inside your network.",
    why: "Clusters and databases terminate much of your TLS and store keys and certificates that servers alone do not show.",
    example: "prod-payments cluster and pg-core-01 database, both through node-dc1.",
  },
  // src: frontend/components/cbom/sources/ClustersDatabasesTab.tsx:425-470 — clusters, databases, HSMs and key managers of the team
  "cbsrc.k8sdb.list": {
    label: "Configured clusters and databases",
    what: "The cluster, database, HSM and key manager sources of this team with their endpoint, access level or login, scan node and last connection test.",
    why: "These sources are what a run collects from on the Review & Run tab.",
    example: "pg-core-01 · PostgreSQL · pg-core-01.bank.local:5432 · zs_cbom · Passed.",
  },
  // src: frontend/components/cbom/sources/ClustersDatabasesTab.tsx:466 — API server URL, host and port, module or KMIP host
  "cbsrc.col.endpoint": {
    label: "Endpoint",
    what: "Where the source is reached: the cluster's API server URL, the database host and port, the PKCS#11 module, or the KMIP server.",
    why: "The scan node must reach this endpoint for the source's jobs to succeed.",
    example: "https://10.30.0.5:6443 for a cluster.",
  },
  // src: frontend/components/cbom/sources/ClustersDatabasesTab.tsx:467 — tier for clusters, login for databases
  "cbsrc.col.access": {
    label: "Access / login",
    what: "How the source is read: the access tier of a cluster (Tier 1 without Secrets, Tier 2 with) or the login of a database.",
    why: "It shows how much each source's credential can see.",
    example: "Tier 1 for prod-payments; zs_cbom for pg-core-01.",
  },
  // src: frontend/components/cbom/sources/ClustersDatabasesTab.tsx:906-911 — read through the Kubernetes API with a read-only ClusterRole
  "cbsrc.k8s.form": {
    label: "Kubernetes cluster",
    what: "A Kubernetes cluster read through its API with a read-only ClusterRole: versions, API server and ingress TLS, cert-manager certificates, keys in ConfigMaps and service mesh mTLS policy.",
    why: "Clusters hold many certificates that rotate on their own and are easy to lose track of.",
    example: "prod-payments, https://10.30.0.5:6443, Tier 1, through node-dc1.",
  },
  // src: frontend/components/cbom/sources/ClustersDatabasesTab.tsx:914-915 — 1-64 characters
  "cbsrc.k8s.name": {
    label: "Cluster name",
    what: "A name for this cluster, 1 to 64 letters, digits, spaces, dots, dashes or underscores, shown in lists, run results and reports.",
    why: "Each asset found records it as its source.",
    example: "prod-payments.",
  },
  // src: frontend/components/cbom/sources/ClustersDatabasesTab.tsx:917-928 — the Kubernetes API endpoint
  "cbsrc.k8s.api_url": {
    label: "API server URL",
    what: "The HTTPS address of the cluster's Kubernetes API server, as in the server field of your kubeconfig.",
    why: "The scan node talks only to this URL; it must be reachable from the node.",
    example: "https://10.30.0.5:6443.",
  },
  // src: frontend/components/cbom/sources/ClustersDatabasesTab.tsx:930-936, backend/utilities/cbom_sources/kinds.py:21 — PEM up to 64 KB; optional with certificate-authority-data
  "cbsrc.k8s.ca": {
    label: "Cluster CA certificate",
    what: "The PEM certificate of the cluster's CA, used to verify the API server before the token is sent. Optional when the kubeconfig embeds certificate-authority-data.",
    why: "Without verification a spoofed API server could capture the service account token.",
    example: "The ca.crt from /etc/kubernetes/pki on a control plane node.",
  },
  // src: frontend/components/cbom/sources/ClustersDatabasesTab.tsx:982-991 — kubeconfig or token from vault
  "cbsrc.k8s.credential": {
    label: "Cluster credential",
    what: "Upload kubeconfig: encrypted at rest and sent only to the scan node. Token from vault: the node fetches it when the job runs (team admins only).",
    why: "A token kept in your vault never rests on ZeroShield.",
    example: "A kubeconfig for the service account zs-cbom bound to the ClusterRole below.",
  },
  // src: frontend/components/cbom/sources/ClustersDatabasesTab.tsx:887-891, frontend/components/cbom/sources/ClustersDatabasesTab.tsx:999-1010 — exec and auth-provider plugins refused
  "cbsrc.k8s.kubeconfig": {
    label: "Kubeconfig file",
    what: "The kubeconfig of the zs-cbom service account. It is sent once, encrypted at rest and sent only to the scan node that runs the job. Configs that use exec or auth-provider plugins are refused.",
    why: "Plugins would run commands on the scan node; a static token keeps the node's footprint read-only.",
    example: "zs-cbom.kubeconfig with a token for the zs-cbom service account.",
  },
  // src: frontend/components/cbom/sources/ClustersDatabasesTab.tsx:1045-1046 — up to 128 characters; blank uses current-context
  "cbsrc.k8s.context": {
    label: "Context",
    what: "Which context of the kubeconfig to use, up to 128 characters. Blank uses its current-context.",
    why: "A kubeconfig with several clusters would otherwise read whichever was last selected.",
    example: "prod-payments-admin.",
  },
  // src: frontend/components/cbom/sources/ClustersDatabasesTab.tsx:1065-1086 — Tier 1 without Secrets; Tier 2 reads TLS Secrets, private keys dropped unparsed
  "cbsrc.k8s.tier": {
    label: "Access tier",
    what: "Tier 1 reads versions, API server and ingress TLS, Secret names, cert-manager Certificates, certificates in ConfigMaps and mesh mTLS policy. Tier 2 also reads the certificates of TLS Secrets; their private keys are dropped unparsed and never stored or sent.",
    why: "Tier 2 covers certificates kept only in Secrets, but its token can read Secret values.",
    example: "Tier 2 finds the expiring ingress certificate stored in secret payments-tls.",
  },
  // src: frontend/components/cbom/sources/ClustersDatabasesTab.tsx:1088-1096 — Kubernetes cannot grant Secret names without values
  "cbsrc.k8s.tier2_warning": {
    label: "Tier 2 can read Secret values",
    what: "Kubernetes cannot grant access to Secret names without their values, so a Tier 2 token can read them. Only metadata such as fingerprints is sent to ZeroShield.",
    why: "The token is as sensitive as the Secrets it can read; protect it accordingly.",
    example: "Try Tier 2 on a staging cluster before production.",
  },
  // src: frontend/components/cbom/sources/ClustersDatabasesTab.tsx:1129-1131 — link the cloud account that runs it
  "cbsrc.k8s.managed": {
    label: "Managed cluster",
    what: "Tick for EKS, AKS or GKE clusters to link the cloud account source that runs the cluster.",
    why: "The cloud account holds the encryption-at-rest settings of the cluster's Secrets.",
    example: "EKS cluster prod-payments, linked to the AWS account aws-prod.",
  },
  // src: frontend/components/cbom/sources/ClustersDatabasesTab.tsx:1134-1139 — stored as a link until cloud collection reads it
  "cbsrc.k8s.cloud": {
    label: "Cloud account",
    what: "The cloud account source that runs this managed cluster. Secret encryption at rest is read from this account once cloud collection is available; until then it is stored as a link.",
    why: "Ties the cluster's findings to the account where the fix is made.",
    example: "aws-prod · AWS account.",
  },
  // src: frontend/components/cbom/sources/ClustersDatabasesTab.tsx:1379-1383, backend/utilities/cbom_sources/kinds.py:347-356 — read-only login
  "cbsrc.db.form": {
    label: "Database",
    what: "A database server read with a read-only login: its TLS setup, certificates and encryption settings. Run the grant shown below once as an admin.",
    why: "Databases hold the most sensitive data; weak TLS or unencrypted storage there is a top finding.",
    example: "pg-core-01.bank.local:5432, login zs_cbom, Require TLS with the bank CA.",
  },
  // src: frontend/components/cbom/sources/ClustersDatabasesTab.tsx:1387-1388 — 1-64 characters
  "cbsrc.db.name": {
    label: "Name",
    what: "A name for this database source, 1 to 64 characters, shown in lists, run results and reports.",
    why: "Each asset found records it as its source.",
    example: "pg-core-01.",
  },
  // src: frontend/components/cbom/sources/ClustersDatabasesTab.tsx:61-68, backend/utilities/cbom_sources/kinds.py:344 — PostgreSQL, MySQL/MariaDB, SQL Server, Oracle, MongoDB, Redis
  "cbsrc.db.engine": {
    label: "Engine",
    what: "The database engine: PostgreSQL, MySQL / MariaDB, SQL Server, Oracle, MongoDB or Redis. It sets the default port, the grant to run and how the login is protected.",
    why: "Each engine exposes its crypto settings differently, so the wrong engine reads nothing.",
    example: "SQL Server, default port 1433.",
  },
  // src: backend/utilities/cbom_sources/kinds.py:349 — up to 253 characters
  "cbsrc.db.host": {
    label: "Host",
    what: "The database server's hostname or IP address, up to 253 characters, as the scan node reaches it.",
    why: "Use the name in the server's certificate so the TLS check passes.",
    example: "pg-core-01.bank.local.",
  },
  // src: backend/utilities/cbom_sources/kinds.py:344, backend/utilities/cbom_sources/kinds.py:350 — 1-65535; engine default when blank
  "cbsrc.db.port": {
    label: "Port",
    what: "The database port, 1 to 65535. Blank uses the engine's default: PostgreSQL 5432, MySQL 3306, SQL Server 1433, Oracle 1521, MongoDB 27017, Redis 6379.",
    why: "A wrong port fails the connection test before the login is tried.",
    example: "6432 when PostgreSQL sits behind PgBouncer.",
  },
  // src: backend/utilities/cbom_sources/kinds.py:351, backend/utilities/cbom_sources/kinds.py:27 — up to 64 characters; optional for engines that run without authentication
  "cbsrc.db.login": {
    label: "Login",
    what: "The read-only login the node connects with, up to 64 characters. Optional for MongoDB and Redis servers that run without authentication.",
    why: "A dedicated login with only the grants below limits what a leaked password can do.",
    example: "zs_cbom.",
  },
  // src: backend/utilities/cbom_sources/kinds.py:356 — up to 128 characters; required for Oracle
  "cbsrc.db.database": {
    label: "Database or service name",
    what: "For Oracle, the service (PDB) the login and grants belong to (required). For other engines, the database to connect to first (optional); server-wide settings are read from there.",
    why: "Oracle logins exist per service, so a wrong name fails the login.",
    example: "ORCLPDB1 for Oracle; postgres for PostgreSQL.",
  },
  // src: frontend/components/cbom/sources/ClustersDatabasesTab.tsx:1444-1452 — password or password from vault
  "cbsrc.db.credential": {
    label: "Database credential",
    what: "Password: encrypted at rest and sent only to the scan node. Password from vault: the node fetches it when the job runs (team admins only).",
    why: "A vault reference keeps the password out of ZeroShield entirely.",
    example: "Password from vault at secret/zs-cbom/db/pg-core-01.",
  },
  // src: backend/utilities/cbom_sources/kinds.py:20, backend/utilities/cbom_sources/kinds.py:262-271 — encrypted at rest; MySQL, Redis and SQL Server need TLS with a CA
  "cbsrc.db.password": {
    label: "Database password",
    what: "The password of the login. Encrypted at rest, never shown again, sent only to the scan node. MySQL, Redis and SQL Server logins also need Require TLS and the CA certificate, so the password only goes to the real server.",
    why: "Those engines would otherwise send the password in a form an impostor can read.",
    example: "The password of zs_cbom, with the bank CA uploaded below.",
  },
  // src: backend/utilities/cbom_sources/kinds.py:354 — on by default
  "cbsrc.db.require_tls": {
    label: "Require TLS to the database",
    what: "On (the default): the node connects only over TLS. Off: it may connect without TLS and records that the server allows plaintext.",
    why: "TLS keeps the login and the data in transit away from anyone on the network path.",
    example: "Leave on; turn off only for a legacy server you are documenting as plaintext.",
  },
  // src: frontend/components/cbom/sources/ClustersDatabasesTab.tsx:1489-1505, backend/utilities/cbom_sources/kinds.py:355 — PEM up to 64 KB; required with a password for MySQL, Redis, SQL Server
  "cbsrc.db.ca": {
    label: "Database CA certificate",
    what: "The PEM certificate of the CA that signed the database server's certificate. The node checks the server against it before sending a password. Required with a password for MySQL, Redis and SQL Server; optional otherwise.",
    why: "It proves the node is talking to the real database, not an impostor collecting credentials.",
    example: "bank-root-ca.pem.",
  },
  // src: frontend/components/cbom/sources/ClustersDatabasesTab.tsx:1775-1779, frontend/components/cbom/sources/ClustersDatabasesTab.tsx:1615-1626 — attributes only, never key values
  "cbsrc.km.form": {
    label: "HSM or key manager",
    what: "An HSM or token read through PKCS#11, or a KMIP key manager. Keys are inventoried by their attributes only: type, size, flags, state and dates. No key value ever leaves the device.",
    why: "Keys in HSMs sign payments and certificates; their algorithms and sizes decide the post-quantum migration work.",
    example: "hsm-payments-01, a Luna HSM read through module luna.",
  },
  // src: frontend/components/cbom/sources/ClustersDatabasesTab.tsx:1782-1783 — 1-64 characters
  "cbsrc.km.name": {
    label: "Name",
    what: "A name for this HSM or key manager source, 1 to 64 characters, shown in lists, run results and reports.",
    why: "Each key found records it as its source.",
    example: "hsm-payments-01.",
  },
  // src: frontend/components/cbom/sources/ClustersDatabasesTab.tsx:1786-1795 — PKCS#11 or KMIP
  "cbsrc.km.provider": {
    label: "Kind of key manager",
    what: "HSM or token (PKCS#11): read through the vendor library on the scan node. KMIP server: read over TLS with a client certificate.",
    why: "It decides how the node connects and which credential it needs.",
    example: "KMIP for a Thales CipherTrust Manager.",
  },
  // src: frontend/components/cbom/sources/ClustersDatabasesTab.tsx:1801-1808 — mapped in ZS_PKCS11_MODULES on the node
  "cbsrc.km.module": {
    label: "Module name",
    what: "The name the scan node's operator maps to a PKCS#11 library in ZS_PKCS11_MODULES on the node. ZeroShield never sends a library path.",
    why: "Only libraries the node's operator approved can be loaded.",
    example: "luna, mapped to /usr/safenet/lunaclient/lib/libCryptoki2_64.so.",
  },
  // src: frontend/components/cbom/sources/ClustersDatabasesTab.tsx:1810-1811 — up to 32 characters; blank reads every initialised token
  "cbsrc.km.token": {
    label: "Token label",
    what: "The label of the token or partition to read, up to 32 characters. Blank reads every initialised token the module shows.",
    why: "Limits the read to the partition you mean when an HSM is shared.",
    example: "payments-partition.",
  },
  // src: frontend/components/cbom/sources/ClustersDatabasesTab.tsx:1816-1822 — PIN, PIN from vault; optional
  "cbsrc.km.pin_source": {
    label: "PIN source",
    what: "The crypto user PIN, typed here (encrypted at rest) or fetched from your vault when the job runs. Optional: without it only public objects are read.",
    why: "Private and secret keys are only listed after a login with the PIN.",
    example: "PIN from vault for the crypto user of payments-partition.",
  },
  // src: frontend/components/cbom/sources/ClustersDatabasesTab.tsx:1827, backend/utilities/cbom_sources/kinds.py:20 — encrypted at rest
  "cbsrc.km.pin": {
    label: "User PIN",
    what: "The PIN of the crypto user or partition role. Encrypted at rest, never shown again, sent only to the scan node; the session it opens is read-only.",
    why: "Without it the inventory misses the private keys, which matter most.",
    example: "The crypto user PIN of payments-partition.",
  },
  // src: backend/utilities/cbom_sources/kinds.py:26 — up to 253 characters
  "cbsrc.km.host": {
    label: "KMIP host",
    what: "The KMIP server's hostname or IP address as the scan node reaches it.",
    why: "Use the name in the server's certificate so the TLS check passes.",
    example: "kms01.bank.local.",
  },
  // src: frontend/components/cbom/sources/ClustersDatabasesTab.tsx:1847 — default 5696
  "cbsrc.km.port": {
    label: "KMIP port",
    what: "The KMIP port, default 5696.",
    why: "A wrong port fails the connection test before TLS starts.",
    example: "5696.",
  },
  // src: frontend/components/cbom/sources/ClustersDatabasesTab.tsx:1851-1857 — optional PEM; verifies the KMIP server
  "cbsrc.km.ca": {
    label: "Server CA certificate",
    what: "Optional PEM certificate of the CA that issued the KMIP server's certificate. With it the node verifies the server; TLS client authentication never reveals the client key either way.",
    why: "Verifying the server proves the inventory comes from your real key manager.",
    example: "The CipherTrust root CA certificate.",
  },
  // src: frontend/components/cbom/sources/ClustersDatabasesTab.tsx:1860, backend/utilities/cbom_sources/kinds.py:20 — PEM, encrypted at rest
  "cbsrc.km.client_cert": {
    label: "Client certificate",
    what: "The PEM client certificate the node presents to the KMIP server. Encrypted at rest and sent only to the scan node.",
    why: "KMIP servers admit only clients with a certificate they trust.",
    example: "zs-cbom-client.crt issued by the KMIP server's CA.",
  },
  // src: frontend/components/cbom/sources/ClustersDatabasesTab.tsx:1861, backend/utilities/cbom_sources/kinds.py:20 — PEM, unencrypted; encrypted at rest
  "cbsrc.km.client_key": {
    label: "Client private key",
    what: "The unencrypted PEM private key of the client certificate. Encrypted at rest by ZeroShield, never shown again, sent only to the scan node.",
    why: "Give the KMIP client read-only rights so this key can list objects but not export them.",
    example: "-----BEGIN PRIVATE KEY----- ....",
  },
  // ────────────────────────────────────────────────────────────── CBOM Sources: Cloud & Identity (components/cbom/sources/CloudIdentityTab.tsx)
  // src: frontend/components/cbom/sources/CloudIdentityTab.tsx:70-74 — AWS by role, Azure by app registration, Google Cloud by service account
  "cbsrc.cloud.connect": {
    label: "Connect a cloud account",
    what: "Connect an AWS account (ZeroShield assumes a read-only role with your external ID, no keys exchanged), an Azure subscription (Key Vault metadata through an app registration) or Google Cloud (KMS, CA Service and Secret Manager metadata through a service account).",
    why: "Cloud KMS keys, certificates and secrets are a large part of the crypto estate and are invisible to network scans.",
    example: "AWS account 111122223333 with the ZeroShieldCBOMReader role in eu-west-1 and ap-south-1.",
  },
  // src: frontend/components/cbom/sources/CloudIdentityTab.tsx:500-512 — the checks of the last validation
  "cbsrc.cloud.validation": {
    label: "Validation",
    what: "The checks of the last validation of the selected account: each read-only call ZeroShield tried and whether it passed, failed, was skipped or hit an error.",
    why: "An account that fails a check is collected only partly, so fix the role or permission it names.",
    example: "kms:ListKeys in ap-south-1 · Fail: the role is missing kms:ListKeys.",
  },
  // src: frontend/components/cbom/sources/CloudIdentityTab.tsx:516-519 — 4 credits per account per run
  "cbsrc.cloud.list": {
    label: "Connected cloud accounts",
    what: "The cloud accounts of this team. Accounts that pass validation are scanned read-only from ZeroShield's cloud, 4 credits per account per run.",
    why: "Only accounts listed here are part of a run's cloud inventory.",
    example: "payments-prod · AWS · One account · 2 regions · Valid.",
  },
  // src: frontend/components/cbom/sources/CloudIdentityTab.tsx:543 — the provider's account or tenant
  "cbsrc.cloud.col.account": {
    label: "Account",
    what: "The cloud provider and the account, subscription or project identifier.",
    why: "Tells you where to make a fix in the provider's console.",
    example: "AWS 111122223333.",
  },
  // src: frontend/components/cbom/sources/CloudIdentityTab.tsx:1003-1012 — one account or a whole AWS Organization
  "cbsrc.cloud.col.scope": {
    label: "Scope",
    what: "What the connection covers: one account, or every member account of an AWS Organization through a StackSet.",
    why: "An Organization connection picks up new member accounts without another setup.",
    example: "Whole AWS Organization · 37 accounts.",
  },
  // src: frontend/components/cbom/sources/CloudIdentityTab.tsx:1143-1150 — regions read in each run
  "cbsrc.cloud.col.regions": {
    label: "Regions",
    what: "For an AWS account, how many regions are read in each run; resources in other regions are not inventoried. A dash for Azure and Google Cloud.",
    why: "Keys and certificates in a forgotten region are a common blind spot.",
    example: "2: eu-west-1 and ap-south-1.",
  },
  // src: frontend/components/cbom/sources/CloudIdentityTab.tsx:547 — time of the last validation
  "cbsrc.cloud.col.validated": {
    label: "Last validated",
    what: "When the account was last validated (ZeroShield tried each read-only call), or Never.",
    why: "A role changed since then may make the next run fail.",
    example: "12 Nov 2026, 10:42 am IST.",
  },
  // src: frontend/components/cbom/sources/CloudIdentityTab.tsx:123-128, frontend/components/cbom/sources/CloudIdentityTab.tsx:548 — result of the last validation
  "cbsrc.cloud.col.status": {
    label: "Status",
    what: "The result of the last validation: Not tested, Testing, Passed (every check passed), Partly ready (some checks failed), Failed or Could not test. Hover the badge for its summary.",
    why: "Only valid accounts are scanned fully in a run.",
    example: "Partly ready: KMS passed, ACM was denied.",
  },
  // src: frontend/components/cbom/sources/CloudIdentityTab.tsx:614 — CAs, CLM tools and your domains
  "cbsrc.cloud.certificates": {
    label: "Certificates",
    what: "Where your certificates come from: certificate authorities and CLM tools you connect, and the domains you own (searched in Certificate Transparency logs where available).",
    why: "Certificates issued outside your managed CAs are the ones that expire unnoticed.",
    example: "AD CS through node-dc1, and bank.in searched in CT logs.",
  },
  // src: frontend/components/cbom/sources/CloudIdentityTab.tsx:84-95, frontend/components/cbom/sources/CloudIdentityTab.tsx:141, backend/utilities/cbom_sources/kinds.py:478 — AD CS, Vault and EJBCA read by a scan node; others stored only
  "cbsrc.cloud.cas": {
    label: "Certificate authorities and CLM",
    what: "Microsoft AD CS, HashiCorp Vault PKI and EJBCA are read by a scan node inside your network. AWS Private CA, Venafi, Keyfactor, DigiCert and others are saved for the certificate collector; they are not validated or collected yet.",
    why: "Your CA knows every certificate it issued, including ones on hosts no scan reaches.",
    example: "AD CS on ca01.bank.local, read by node-dc1 over WinRM.",
  },
  // src: frontend/components/cbom/sources/CloudIdentityTab.tsx:663, frontend/components/cbom/sources/CloudIdentityTab.tsx:142 — public OIDC and SAML metadata, free
  "cbsrc.cloud.idps": {
    label: "Identity providers",
    what: "Signing keys and certificates of your identity providers, read by ZeroShield's cloud from each provider's public OIDC and SAML metadata. Free.",
    why: "An IdP signing with RSA-2048 or SHA-1 signs every login; it is a key migration target.",
    example: "Okta at https://bank.okta.com: 2 signing keys, RS256, one expiring in 30 days.",
  },
  // src: frontend/components/cbom/sources/CloudIdentityTab.tsx:1003-1012 — CloudFormation stack or StackSet
  "cbsrc.aws.scope": {
    label: "Scope",
    what: "One account: create a CloudFormation stack in that account. Whole AWS Organization: deploy a StackSet from the management account to every member account.",
    why: "It decides which template you deploy and which accounts are inventoried.",
    example: "Whole AWS Organization for 37 accounts managed by Control Tower.",
  },
  // src: frontend/components/cbom/sources/CloudIdentityTab.tsx:1039-1070 — off by default; template parameters follow the switches
  "cbsrc.aws.optional_reads": {
    label: "Optional reads",
    what: "Extra permissions you may grant the read-only role, off by default. The template's parameters follow these switches; changing one later means updating the stack and validating again.",
    why: "Each adds coverage but also a permission that could, in a misconfigured account, return a secret.",
    example: "Turn on Read Glue connections to see which connections skip TLS.",
  },
  // src: frontend/components/cbom/sources/CloudIdentityTab.tsx:1040-1054 — kms:Decrypt for Lambda environments; only their shape is kept
  "cbsrc.aws.lambda_cmk": {
    label: "Decrypt Lambda environment variables",
    what: "Lets the role decrypt Lambda environment variables so ZeroShield can check them for keys and passwords; only their shape is kept, never the values. Off: each function's environment is listed as not inspected.",
    why: "Hard-coded keys in Lambda environments are a frequent finding.",
    example: "On: a function with DB_PASSWORD set in plain text is flagged.",
  },
  // src: frontend/components/cbom/sources/CloudIdentityTab.tsx:1056-1068 — TLS enforcement and password storage of each connection
  "cbsrc.aws.glue": {
    label: "Read Glue connections",
    what: "Reports whether each Glue connection enforces TLS and where its password is stored. ZeroShield asks with HidePassword and keeps only those settings.",
    why: "If Data Catalog password encryption is off, this permission could return a password in plain text.",
    example: "jdbc-core-banking: TLS not enforced, password in the connection.",
  },
  // src: backend/utilities/cbom_sources/kinds.py:29, frontend/components/cbom/sources/CloudIdentityTab.tsx:1124-1138 — arn:aws:iam::<12 digits>:role/<name>
  "cbsrc.aws.role_arn": {
    label: "Role ARN",
    what: "The ARN of the read-only role the stack created (the RoleArn output). For an Organization, the role in the management account.",
    why: "ZeroShield assumes this role with your external ID; nothing else gives it access.",
    example: "arn:aws:iam::111122223333:role/ZeroShieldCBOMReader.",
  },
  // src: frontend/components/cbom/sources/CloudIdentityTab.tsx:133, frontend/components/cbom/sources/CloudIdentityTab.tsx:1143-1160 — AWS region codes; the first one is used for the test read
  "cbsrc.aws.regions": {
    label: "Regions",
    what: "The AWS regions to read, as region codes; press Enter or Add region after each. The first region is used for the validation read.",
    why: "Resources in regions not listed are not inventoried.",
    example: "ap-south-1 and ap-south-2 for the Mumbai and Hyderabad regions.",
  },
  // src: frontend/components/cbom/sources/CloudIdentityTab.tsx:1177-1183 — up to 64 characters; blank uses aws-<account id>
  "cbsrc.aws.name": {
    label: "Name",
    what: "A name for this account, up to 64 characters. Blank uses aws-<account id>.",
    why: "Each asset found records it as its source.",
    example: "payments-prod.",
  },
  // src: frontend/components/cbom/sources/CloudIdentityTab.tsx:1347-1348 — up to 64 characters
  "cbsrc.azure.name": {
    label: "Name",
    what: "A name for this Azure connection, 1 to 64 characters, shown in lists, run results and reports.",
    why: "Each asset found records it as its source.",
    example: "azure-prod.",
  },
  // src: backend/utilities/cbom_sources/kinds.py:28, frontend/components/cbom/sources/CloudIdentityTab.tsx:1350-1360 — a GUID
  "cbsrc.azure.tenant": {
    label: "Directory (tenant) ID",
    what: "The GUID of your Microsoft Entra directory (tenant), from the app registration's Overview page.",
    why: "The app registration signs in to this tenant only.",
    example: "72f988bf-86f1-41af-91ab-2d7cd011db47.",
  },
  // src: backend/utilities/cbom_sources/kinds.py:28, frontend/components/cbom/sources/CloudIdentityTab.tsx:1362-1372 — a GUID
  "cbsrc.azure.client": {
    label: "Application (client) ID",
    what: "The GUID of the app registration that the reader script gave Key Vault Reader access.",
    why: "ZeroShield signs in as this app; its roles decide what can be read.",
    example: "0f3c6a2e-1b5d-4c8e-9a7f-2d4e6b8c0a1f.",
  },
  // src: frontend/components/cbom/sources/CloudIdentityTab.tsx:1375-1386 — client secret or certificate
  "cbsrc.azure.credential": {
    label: "Credential",
    what: "Client secret: from Certificates & secrets in the app registration. Certificate: a PEM certificate with its private key; ZeroShield signs a client assertion with it.",
    why: "A certificate credential never sends a reusable secret over the network.",
    example: "Certificate, with the same certificate uploaded to the app registration.",
  },
  // src: frontend/components/cbom/sources/CloudIdentityTab.tsx:144, frontend/components/cbom/sources/CloudIdentityTab.tsx:1389-1397 — encrypted at rest; changing tenant, client ID or credential clears it
  "cbsrc.azure.secret": {
    label: "Client secret or certificate",
    what: "The client secret, or the PEM certificate with its private key. Encrypted at rest by ZeroShield and never shown again; changing the tenant, client ID or credential type clears it.",
    why: "It is the only credential of the connection; rotate it in Azure and paste the new one here.",
    example: "A client secret value created today, valid for 6 months.",
  },
  // src: frontend/components/cbom/sources/CloudIdentityTab.tsx:1400-1410 — one GUID per line, optional
  "cbsrc.azure.subs": {
    label: "Subscription IDs",
    what: "Optional: the subscriptions to read, one GUID per line. Blank reads every subscription the app can see.",
    why: "Narrowing it keeps a shared app registration from inventorying another unit's subscriptions.",
    example: "11111111-2222-3333-4444-555555555555.",
  },
  // src: frontend/components/cbom/sources/CloudIdentityTab.tsx:1512-1513 — up to 64 characters
  "cbsrc.gcp.name": {
    label: "Name",
    what: "A name for this Google Cloud connection, 1 to 64 characters, shown in lists, run results and reports.",
    why: "Each asset found records it as its source.",
    example: "gcp-payments.",
  },
  // src: frontend/components/cbom/sources/CloudIdentityTab.tsx:1515-1525 — numeric; blank lists projects instead
  "cbsrc.gcp.org": {
    label: "Organization ID",
    what: "The numeric ID of your Google Cloud organization. Leave blank to list the projects below instead.",
    why: "With an organization ID every project under it is read, including new ones.",
    example: "123456789012.",
  },
  // src: frontend/components/cbom/sources/CloudIdentityTab.tsx:1527-1536 — one per line; needed without an organization ID
  "cbsrc.gcp.projects": {
    label: "Project IDs",
    what: "The project IDs to read, one per line. Needed when there is no organization ID.",
    why: "Projects not listed are not inventoried.",
    example: "payments-prod and core-banking-dr.",
  },
  // src: frontend/components/cbom/sources/CloudIdentityTab.tsx:1538-1548 — up to 254 characters
  "cbsrc.gcp.email": {
    label: "Service account",
    what: "The email of the service account that the gcloud script granted the viewer roles to.",
    why: "ZeroShield reads as this account; its roles decide what is visible.",
    example: "zs-cbom@payments-prod.iam.gserviceaccount.com.",
  },
  // src: frontend/components/cbom/sources/CloudIdentityTab.tsx:144, frontend/components/cbom/sources/CloudIdentityTab.tsx:1550-1562 — encrypted at rest; changing the service account clears it
  "cbsrc.gcp.key": {
    label: "Service account key (JSON)",
    what: "The JSON key of the service account, pasted or uploaded. Encrypted at rest by ZeroShield and never shown again; changing the service account clears it.",
    why: "Anyone with this key can act as the service account, so it should hold viewer roles only.",
    example: "The .json file from IAM > Service accounts > Keys.",
  },
  // src: frontend/components/cbom/sources/CloudIdentityTab.tsx:1564-1575 — .json up to 64 KB
  "cbsrc.gcp.key_file": {
    label: "Upload the key file",
    what: "Pick the .json key file instead of pasting it; it fills the key field above. Up to 64 KB.",
    why: "Uploading avoids copy-paste errors in the long key.",
    example: "zs-cbom-payments-prod-3f2a.json.",
  },
  // src: frontend/components/cbom/sources/CloudIdentityTab.tsx:139, frontend/components/cbom/sources/CloudIdentityTab.tsx:1672-1677 — up to 200 domains; saved, not yet searched
  "cbsrc.cert.domains": {
    label: "Domains to search in Certificate Transparency logs",
    what: "Domains you own, up to 200. They are saved for the certificate collector; ZeroShield does not query Certificate Transparency logs on this deployment yet.",
    why: "CT logs list every public certificate issued for your domains, including ones nobody registered with IT.",
    example: "bank.in and bankonline.co.in.",
  },
  // src: frontend/components/cbom/sources/CloudIdentityTab.tsx:1786-1795 — searched every run from ZeroShield's cloud; credits per domain
  "cbsrc.ct.discovery": {
    label: "Certificate Transparency",
    what: "Every run, ZeroShield's cloud searches public Certificate Transparency logs for certificates issued for these domains, including hosts no scan node reaches. Expiring, expired, revoked and weak certificates, and certificates from CAs you have not listed, are flagged. Charged per domain searched, per run.",
    why: "A certificate issued by a CA you do not use can mean a mis-issuance or a shadow IT service.",
    example: "bank.in: 412 certificates found, 3 from an unexpected CA.",
  },
  // src: frontend/components/cbom/sources/CloudIdentityTab.tsx:1721, frontend/components/cbom/sources/CloudIdentityTab.tsx:1797-1830 — up to 1,000 domains; a leading *. is dropped
  "cbsrc.ct.domains": {
    label: "Domains",
    what: "The domains to search, up to 1,000. A leading *. is dropped; add each registered domain once.",
    why: "Each domain is one search per run, so list the ones you own.",
    example: "bank.in.",
  },
  // src: frontend/components/cbom/sources/CloudIdentityTab.tsx:1849-1852 — search subdomains too
  "cbsrc.ct.subdomains": {
    label: "Include subdomains",
    what: "Also search certificates for every subdomain of the listed domains.",
    why: "Most forgotten certificates sit on subdomains such as uat-api.bank.in.",
    example: "On: certificates for netbanking.bank.in are found too.",
  },
  // src: frontend/components/cbom/sources/CloudIdentityTab.tsx:1722, frontend/components/cbom/sources/CloudIdentityTab.tsx:1854-1856 — up to 50; matched on name, organisation or CN
  "cbsrc.ct.issuers": {
    label: "Certificate authorities you use",
    what: "Optional, up to 50: the CAs you expect. A certificate from any other CA is flagged as unexpected. Matched against the CA's name, organisation or CN: the whole value or its first words (at least 3 characters).",
    why: "Unexpected issuers point at mis-issuance or teams buying certificates outside policy.",
    example: "DigiCert and Let's Encrypt.",
  },
  // src: frontend/components/cbom/sources/CloudIdentityTab.tsx:2173-2190 — Sectigo or other
  "cbsrc.ca.product": {
    label: "Product",
    what: "Which certificate product this connection is for, when the row covers several.",
    why: "It names the source in reports.",
    example: "Sectigo Certificate Manager.",
  },
  // src: frontend/components/cbom/sources/CloudIdentityTab.tsx:2195-2196 — up to 64 characters
  "cbsrc.ca.name": {
    label: "Name",
    what: "A name for this CA connection, 1 to 64 characters, shown in lists, run results and reports.",
    why: "Each certificate found records it as its source.",
    example: "AD CS Mumbai.",
  },
  // src: frontend/components/cbom/sources/CloudIdentityTab.tsx:2201-2203, backend/utilities/cbom_sources/kinds.py:478 — AD CS, Vault, EJBCA are read through a node
  "cbsrc.ca.node": {
    label: "Scan node",
    what: "The scan node, in a segment that reaches the certificate authority, that reads it.",
    why: "Internal CAs are rarely reachable from the internet, so a node inside the network reads them.",
    example: "node-dc1, which reaches ca01.bank.local on 5986.",
  },
  // src: frontend/components/cbom/sources/CloudIdentityTab.tsx:2222-2223 — reached over WinRM HTTPS (5986)
  "cbsrc.ca.host": {
    label: "CA server",
    what: "The AD CS server's hostname, reached over WinRM HTTPS (5986). Run the Windows setup script from the Servers tab on it first.",
    why: "The CA database lists every certificate it issued, including ones on hosts no scan reaches.",
    example: "ca01.bank.local.",
  },
  // src: frontend/components/cbom/sources/CloudIdentityTab.tsx:2225-2226, backend/utilities/cbom_sources/kinds.py:27 — up to 64 characters
  "cbsrc.ca.login": {
    label: "Read-only Windows account",
    what: "A read-only Windows account on the CA server, in Remote Management Users; DOMAIN\\user is accepted.",
    why: "A non-admin account limits what a leaked password can do on your CA.",
    example: "BANK\\svc-zscbom.",
  },
  // src: frontend/components/cbom/sources/CloudIdentityTab.tsx:2228-2236 — encrypted at rest; changing server, account, CA or node clears it
  "cbsrc.ca.password": {
    label: "Password",
    what: "The password of the read-only account. Encrypted at rest and sent only to the scan node; changing the server, account, CA or node clears it.",
    why: "Clearing it on change keeps the password from going to a host it was not meant for.",
    example: "The password of svc-zscbom.",
  },
  // src: frontend/components/cbom/sources/CloudIdentityTab.tsx:2242-2258 — read through a connected AWS account's role
  "cbsrc.ca.aws": {
    label: "AWS account",
    what: "The connected AWS account whose read-only role reads AWS Private CA. No new credential is needed.",
    why: "Private CAs in AWS issue internal certificates that never appear in CT logs.",
    example: "payments-prod · 111122223333.",
  },
  // src: frontend/components/cbom/sources/CloudIdentityTab.tsx:2263-2273 — HTTPS, up to 512 characters
  "cbsrc.ca.api_url": {
    label: "API address",
    what: "The HTTPS address of the CA or CLM API, up to 512 characters.",
    why: "The scan node or the certificate collector calls only this address.",
    example: "https://vault.corp.example.com:8200 for Vault PKI.",
  },
  // src: frontend/components/cbom/sources/CloudIdentityTab.tsx:2278-2286 — read-only policy; encrypted at rest
  "cbsrc.ca.vault_token": {
    label: "Vault token",
    what: "A Vault token bound to the read-only policy shown below. Encrypted at rest and sent only to the scan node; changing the address, CA or node clears it.",
    why: "The policy lets it list PKI mounts and transit keys without signing or decrypting.",
    example: "A periodic token created with vault token create -policy=zs-cbom-read.",
  },
  // src: frontend/components/cbom/sources/CloudIdentityTab.tsx:2287-2295 — the read-only HCL policy
  "cbsrc.ca.vault_policy": {
    label: "Policy for the token",
    what: "The Vault policy to bind to the token: read and list on PKI and transit metadata only.",
    why: "Review it before creating the token; it grants no sign, issue or decrypt rights.",
    example: "vault policy write zs-cbom-read zs-cbom-read.hcl.",
  },
  // src: frontend/components/cbom/sources/CloudIdentityTab.tsx:2303 — PEM, encrypted at rest
  "cbsrc.ca.client_cert": {
    label: "Client certificate",
    what: "The PEM client certificate the scan node presents to the EJBCA REST API. Encrypted at rest and sent only to the scan node.",
    why: "EJBCA admits only clients whose certificate maps to an administrator role.",
    example: "zs-cbom-reader.crt issued by the EJBCA ManagementCA.",
  },
  // src: frontend/components/cbom/sources/CloudIdentityTab.tsx:2304-2312 — PEM, unencrypted; encrypted at rest
  "cbsrc.ca.client_key": {
    label: "Client private key",
    what: "The unencrypted PEM private key of the client certificate. Encrypted at rest and sent only to the scan node; changing the address, CA or node clears it.",
    why: "Give the matching EJBCA role read-only rights so the key cannot issue certificates.",
    example: "-----BEGIN PRIVATE KEY----- ....",
  },
  // src: frontend/components/cbom/sources/CloudIdentityTab.tsx:2319-2326 — optional PEM; verified before signing in
  "cbsrc.ca.ca_pem": {
    label: "CA of the server certificate",
    what: "Optional PEM certificate of the CA that issued the server's TLS (or WinRM) certificate. The node verifies the server with it before signing in.",
    why: "Needed when the server uses a private CA; without it the TLS check fails.",
    example: "bank-root-ca.pem.",
  },
  // src: frontend/components/cbom/sources/CloudIdentityTab.tsx:2330-2338 — encrypted at rest; changing the address clears it
  "cbsrc.ca.api_key": {
    label: "API key",
    what: "The CLM tool's API key. Encrypted at rest by ZeroShield and never shown again; changing the address clears it.",
    why: "Use a key scoped to read-only access to the certificate inventory.",
    example: "A Venafi API key with the certificate:discover scope.",
  },
  // src: frontend/components/cbom/sources/CloudIdentityTab.tsx:2453-2454 — up to 64 characters
  "cbsrc.idp.name": {
    label: "Name",
    what: "A name for this identity provider, 1 to 64 characters, shown in lists, run results and reports.",
    why: "Each signing key found records it as its source.",
    example: "Okta workforce.",
  },
  // src: frontend/components/cbom/sources/CloudIdentityTab.tsx:2457-2465 — a GUID
  "cbsrc.idp.tenant": {
    label: "Directory (tenant) ID",
    what: "The GUID of your Microsoft Entra directory (tenant).",
    why: "The app registration signs in to this tenant only.",
    example: "72f988bf-86f1-41af-91ab-2d7cd011db47.",
  },
  // src: frontend/components/cbom/sources/CloudIdentityTab.tsx:2470-2479 — HTTPS, up to 512 characters
  "cbsrc.idp.base_url": {
    label: "Okta domain or base URL",
    what: "Okta: your Okta domain. Keycloak: the base URL of the server. HTTPS, up to 512 characters.",
    why: "Signing keys are read from this address's public metadata.",
    example: "https://bank.okta.com.",
  },
  // src: frontend/components/cbom/sources/CloudIdentityTab.tsx:2482-2484 — up to 128 characters
  "cbsrc.idp.realm": {
    label: "Realm",
    what: "The Keycloak realm whose clients and keys are read, up to 128 characters.",
    why: "Each realm has its own signing keys.",
    example: "corp.",
  },
  // src: frontend/components/cbom/sources/CloudIdentityTab.tsx:2487-2489 — Entra application ID or Keycloak client ID
  "cbsrc.idp.client": {
    label: "Client ID",
    what: "Entra ID: the application (client) ID of the app registration with Application.Read.All. Keycloak: the confidential client with read-only access to clients and keys.",
    why: "With it ZeroShield also reads the app registrations' certificates and secrets metadata.",
    example: "zs-cbom-reader.",
  },
  // src: frontend/components/cbom/sources/CloudIdentityTab.tsx:142, frontend/components/cbom/sources/CloudIdentityTab.tsx:2399, frontend/components/cbom/sources/CloudIdentityTab.tsx:2491-2498 — optional; encrypted at rest
  "cbsrc.idp.secret": {
    label: "Client secret or API token",
    what: "Optional. The Okta API token or the client secret. Signing keys are read from public metadata without it; with it, more is read. Encrypted at rest and never shown again.",
    why: "Without it, only the provider's published signing keys are inventoried.",
    example: "A read-only Okta API token.",
  },
  // src: frontend/components/cbom/sources/CloudIdentityTab.tsx:2538-2560 — HTTPS, up to 1,000 characters
  "cbsrc.idp.saml_url": {
    label: "SAML metadata URL",
    what: "The HTTPS address of an identity provider's SAML metadata, up to 1,000 characters. Its signing and encryption certificates are read from it.",
    why: "Covers identity providers without a dedicated connector, such as ADFS.",
    example: "https://adfs.bank.in/FederationMetadata/2007-06/FederationMetadata.xml.",
  },
  // src: frontend/components/cbom/sources/CloudIdentityTab.tsx:2538-2560 — HTTPS, up to 1,000 characters
  "cbsrc.idp.oidc_url": {
    label: "OIDC discovery URL",
    what: "The HTTPS address of an OpenID Connect discovery document, up to 1,000 characters. Its JWKS signing keys are read from it.",
    why: "Covers any OIDC provider, including in-house ones.",
    example: "https://sso.bank.in/.well-known/openid-configuration.",
  },
  // ────────────────────────────────────────────────────────────── CBOM Sources: Network TLS (components/cbom/sources/NetworkTab.tsx)
  // src: frontend/components/cbom/sources/NetworkTab.tsx:450-458 — the team emergency stop
  "cbsrc.net.stopped": {
    label: "All network scanning is stopped",
    what: "A team admin stopped all network scanning. Scan nodes skip network ranges and discovery sweeps until a team admin resumes it; other sources are not affected.",
    why: "The emergency stop exists so the SOC can halt probing at once if a device misbehaves.",
    example: "Stopped 12 minutes ago after a PLC on 10.50.0.0/24 raised an alarm.",
  },
  // src: frontend/components/cbom/sources/NetworkTab.tsx:469, frontend/components/cbom/sources/NetworkTab.tsx:471-500 — allowed ranges, never scan, SNI names, ports
  "cbsrc.net.scope": {
    label: "Scope",
    what: "What the network scan may touch and how: the allowed ranges and their scan nodes, the never-scan list, hostnames for SNI and the ports and protocols to probe.",
    why: "Nothing outside the allowed ranges is ever probed, and never-scan always wins.",
    example: "10.20.0.0/16 through node-dc1, except 10.20.99.0/24 (OT), on ports 443, 8443 and 22.",
  },
  // src: frontend/components/cbom/sources/NetworkTab.tsx:471-500, frontend/components/cbom/sources/NetworkTab.tsx:1153-1160 — nothing is scanned until a range is allowed
  "cbsrc.net.ranges": {
    label: "Allowed ranges",
    what: "The address ranges the network scan may probe, each with the scan node that reaches it. Nothing is scanned until you allow a range.",
    why: "An explicit allow list keeps scans inside the networks you approved.",
    example: "10.20.0.0/16 through node-dc1, Full mode.",
  },
  // src: frontend/components/cbom/sources/NetworkTab.tsx:1153 — a /16 or smaller, one IP, or a-b
  "cbsrc.net.col.range": {
    label: "Range",
    what: "The addresses: a CIDR range of /16 or smaller, one IP address, or a first-last range.",
    why: "Each address in it may be probed on every listed port.",
    example: "10.20.5.0/24.",
  },
  // src: frontend/components/cbom/sources/NetworkTab.tsx:530, frontend/components/cbom/sources/NetworkTab.tsx:1176-1190 — Full or Fragile (version check only)
  "cbsrc.net.col.mode": {
    label: "Mode",
    what: "Full: complete TLS and SSH handshakes on every listed port. Fragile: a version check only, for OT or devices that may not cope with many handshakes.",
    why: "Old PLCs and medical devices can crash under repeated handshakes.",
    example: "Fragile for the SCADA network 10.50.0.0/24.",
  },
  // src: frontend/components/cbom/sources/NetworkTab.tsx:115, frontend/components/cbom/sources/NetworkTab.tsx:580-680 — up to 500 entries; always wins in every job of the team
  "cbsrc.net.never_scan": {
    label: "Never scan",
    what: "Addresses and ranges, up to 500, that no job of this team may touch. The node refuses them even if a job asks; a server, database, registry or Kubernetes API whose name resolves to a listed address is skipped as a whole. Add each with a reason.",
    why: "It protects OT networks, core routers and partner systems from any probe, whatever a source says.",
    example: "10.20.99.0/24 · OT plant network.",
  },
  // src: frontend/components/cbom/sources/NetworkTab.tsx:591, frontend/components/cbom/sources/NetworkTab.tsx:659-668 — up to 120 characters
  "cbsrc.net.col.reason": {
    label: "Reason",
    what: "Why the range is excluded, up to 120 characters, so others know not to remove it.",
    why: "An exclusion without a reason tends to be deleted during clean-ups.",
    example: "OT plant network, no active scanning per IT-OT policy.",
  },
  // src: frontend/components/cbom/sources/NetworkTab.tsx:114, frontend/components/cbom/sources/NetworkTab.tsx:689-698 — up to 10,000 names
  "cbsrc.net.sni": {
    label: "Hostnames for SNI",
    what: "Hostnames, up to 10,000, sent as SNI in TLS handshakes so servers that host several sites return each site's certificate.",
    why: "Without SNI a shared server shows only its default certificate and the others go uninventoried.",
    example: "www.bank.in and api.bank.in on the same load balancer address.",
  },
  // src: frontend/components/cbom/sources/NetworkTab.tsx:76-90, frontend/components/cbom/sources/NetworkTab.tsx:113, frontend/components/cbom/sources/NetworkTab.tsx:700-770 — up to 64 ports; TLS, StartTLS, SSH, RDP, IKE, OT
  "cbsrc.net.ports": {
    label: "Ports and protocols",
    what: "The ports probed on each address, up to 64, each with its protocol: TLS, StartTLS for LDAP, SMTP, IMAP, PostgreSQL or MySQL, SQL Server, SSH, RDP, IKE, and OT protocols (OPC UA, Modbus). Add a port, its protocol and an optional label.",
    why: "A service on a port that is not listed is never seen.",
    example: "7443 · TLS · admin console.",
  },
  // src: frontend/components/cbom/sources/NetworkTab.tsx:770-772 — passive read of what clients negotiate
  "cbsrc.net.zeek": {
    label: "Zeek ssl.log from a SPAN port",
    what: "Also read Zeek's ssl.log from a SPAN port to see the protocol versions and cipher suites clients actually negotiate.",
    why: "A server may allow TLS 1.0 but only passive data shows whether anything still uses it.",
    example: "Shows 3% of connections to core-api still use TLS 1.0 with CBC ciphers.",
  },
  // src: frontend/components/cbom/sources/NetworkTab.tsx:781 — window, rates, SOC contacts
  "cbsrc.net.safety": {
    label: "Safety",
    what: "When network scans may run, how fast they may go, and who your SOC should call.",
    why: "Probing at the wrong hour or speed can set off alarms or disturb fragile devices.",
    example: "Weekday nights only, 50 connections per second per node.",
  },
  // src: frontend/components/cbom/sources/NetworkTab.tsx:783-830 — weekly hours in a time zone; work pauses at the end
  "cbsrc.net.window": {
    label: "Scan window",
    what: "The weekly hours, in the chosen time zone, when network scans and sources set to the team window may run. Work pauses at the end of the window and resumes in the next one.",
    why: "Keeps probes out of business hours and change freezes.",
    example: "Weekday nights, 22:00 to 06:00 Asia/Kolkata: 40 hours a week.",
  },
  // src: frontend/components/cbom/sources/NetworkTab.tsx:109 — 1 to 500
  "cbsrc.net.rate_conn": {
    label: "Connections/s per node",
    what: "The most new connections per second each scan node opens, 1 to 500.",
    why: "Lower values avoid tripping IDS alerts and connection limits on firewalls.",
    example: "50 for a branch network behind a small firewall.",
  },
  // src: frontend/components/cbom/sources/NetworkTab.tsx:110 — 1 to 32
  "cbsrc.net.rate_parallel": {
    label: "Parallel per server",
    what: "The most connections a node keeps open to one server at a time, 1 to 32.",
    why: "Protects small servers from being overloaded by parallel handshakes.",
    example: "4 for older appliances that limit concurrent TLS sessions.",
  },
  // src: frontend/components/cbom/sources/NetworkTab.tsx:111 — 1 to 200
  "cbsrc.net.rate_handshakes": {
    label: "Handshakes per endpoint",
    what: "The most TLS or SSH handshakes made to one endpoint (address and port), 1 to 200. More handshakes test more protocol versions and cipher suites.",
    why: "A full cipher-suite enumeration needs many handshakes; fewer is gentler but less complete.",
    example: "60 enumerates TLS 1.0 to 1.3 suites on a typical web server.",
  },
  // src: frontend/components/cbom/sources/NetworkTab.tsx:861-915 — each node's source IPs and your contacts
  "cbsrc.net.soc": {
    label: "Tell your SOC",
    what: "The source IP addresses of each scan node, to give your SOC so the scans are recognised, and the contacts they can reach.",
    why: "An unannounced scan looks like an attack and may be blocked mid-run.",
    example: "node-dc1 scans from 10.20.1.15.",
  },
  // src: frontend/components/cbom/sources/NetworkTab.tsx:879 — the node
  "cbsrc.net.col.node": {
    label: "Scan node",
    what: "The scan node whose source addresses are listed.",
    why: "Each node scans from its own addresses.",
    example: "node-dc1.",
  },
  // src: frontend/components/cbom/sources/NetworkTab.tsx:880 — addresses the node reported
  "cbsrc.net.col.source_ips": {
    label: "Source IPs",
    what: "The addresses the node reported it connects from, to whitelist or recognise in your SOC tools.",
    why: "Behind NAT the address seen by targets may differ; check with your network team.",
    example: "10.20.1.15, fd00:20::15.",
  },
  // src: frontend/components/cbom/sources/NetworkTab.tsx:118, frontend/components/cbom/sources/NetworkTab.tsx:894-902 — up to 254 characters
  "cbsrc.net.soc_email": {
    label: "SOC email",
    what: "Your SOC's email address, up to 254 characters, recorded with the team's network settings as the contact for these scans.",
    why: "Gives operators one place to send questions about a scan they see.",
    example: "soc@bank.in.",
  },
  // src: frontend/components/cbom/sources/NetworkTab.tsx:119, frontend/components/cbom/sources/NetworkTab.tsx:905-913 — a phone number, up to 64 characters
  "cbsrc.net.emergency": {
    label: "Emergency stop contact",
    what: "A phone number, up to 64 characters, for whoever can stop the scans at once.",
    why: "If a device misbehaves during a scan, someone must be reachable to stop it.",
    example: "+91 22 5555 0100 (NOC, 24x7).",
  },
  // src: frontend/components/cbom/sources/NetworkTab.tsx:1171-1174 — the node that reaches the range
  "cbsrc.net.range_form_node": {
    label: "Scan node",
    what: "The scan node that probes this range. It must reach every address in it on the listed ports.",
    why: "A node in another segment sees every address as silent.",
    example: "node-dc1 for 10.20.0.0/16.",
  },
  // src: frontend/components/cbom/sources/NetworkTab.tsx:116, frontend/components/cbom/sources/NetworkTab.tsx:1392-1393 — BIND export up to 8 MB; A, AAAA, CNAME names
  "cbsrc.net.sni_zone": {
    label: "Import a DNS zone file",
    what: "Add hostnames from a BIND zone export, up to 8 MB: the names of its A, AAAA and CNAME records.",
    why: "A zone file lists names nobody remembers to type in.",
    example: "bank.in.zone exported from the DNS server.",
  },
  // src: frontend/components/cbom/sources/NetworkTab.tsx:1395-1396 — text or CSV; first column
  "cbsrc.net.sni_list": {
    label: "Import a plain list",
    what: "Add hostnames from a text or CSV file; the first column of each row is used.",
    why: "Reuse an existing asset list instead of typing names.",
    example: "hosts.csv exported from the CMDB.",
  },
  // src: frontend/components/cbom/sources/NetworkTab.tsx:114, frontend/components/cbom/sources/NetworkTab.tsx:1399-1406 — one per line, up to 10,000; duplicates dropped
  "cbsrc.net.sni_text": {
    label: "Hostnames",
    what: "One hostname per line, up to 10,000; duplicates are dropped.",
    why: "Each name is sent as SNI so the right certificate is returned.",
    example: "www.bank.in, api.bank.in, mail.bank.in.",
  },
  // ────────────────────────────────────────────────────────────── CBOM Sources: Evidence (components/cbom/sources/EvidenceTab.tsx)
  // src: frontend/components/cbom/sources/shared.tsx:127-132, frontend/components/cbom/sources/EvidenceTab.tsx:275-284 — areas at Q0
  "cbsrc.ev.q0": {
    label: "Q0 Unknown",
    what: "Areas with no usable answer: never answered, answered without evidence where evidence is needed, or with evidence older than 12 months.",
    why: "Q0 areas are open gaps in the CBOM and are listed as such on Review & Run.",
    example: "3 areas: the payment HSM vendor has not answered.",
  },
  // src: frontend/components/cbom/sources/shared.tsx:127-132, frontend/components/cbom/sources/EvidenceTab.tsx:275-284 — areas at Q1
  "cbsrc.ev.q1": {
    label: "Q1 Self-attested",
    what: "Areas answered by their owner or vendor without supporting evidence.",
    why: "A self-attested answer is better than nothing but would not satisfy an auditor.",
    example: "The card vendor says its terminals use AES-256, with no document.",
  },
  // src: frontend/components/cbom/sources/shared.tsx:127-132, frontend/components/cbom/sources/EvidenceTab.tsx:275-284 — areas at Q2
  "cbsrc.ev.q2": {
    label: "Q2 Documented",
    what: "Areas answered with a dated evidence document, such as a policy, certificate or report.",
    why: "Documented answers can be shown to an auditor and re-checked when the document is renewed.",
    example: "Key management policy v3 (PDF), dated March 2026.",
  },
  // src: frontend/components/cbom/sources/shared.tsx:127-132, frontend/components/cbom/sources/EvidenceTab.tsx:275-284 — areas at Q3
  "cbsrc.ev.q3": {
    label: "Q3 Verified",
    what: "Areas whose evidence your team has checked and confirmed.",
    why: "Verified evidence carries the same weight as a scan result.",
    example: "The HSM's FIPS 140-3 certificate checked against the NIST CMVP list.",
  },
  // src: frontend/components/cbom/sources/EvidenceTab.tsx:268-272, frontend/components/cbom/sources/EvidenceTab.tsx:287-312 — owner questionnaires with a confidence level
  "cbsrc.ev.areas": {
    label: "Areas that cannot be scanned",
    what: "Parts of your crypto estate no scan can read, such as vendor services and offline key ceremonies. Each has an owner questionnaire, a confidence level and an optional evidence link; a missing answer stays a visible gap.",
    why: "A CBOM that only lists what scans can see overstates your readiness.",
    example: "Card personalisation bureau: owner Cards ops, Q1, due 30 Nov.",
  },
  // src: frontend/components/cbom/sources/EvidenceTab.tsx:307 — the evidence area
  "cbsrc.ev.col.area": {
    label: "Area",
    what: "The part of the estate the questionnaire covers.",
    why: "Each area is one gap until it is answered.",
    example: "Offline root CA key ceremony.",
  },
  // src: frontend/components/cbom/sources/EvidenceTab.tsx:308, frontend/components/cbom/sources/EvidenceTab.tsx:768 — who answers
  "cbsrc.ev.col.owner": {
    label: "Owner",
    what: "The person or team asked to answer for this area.",
    why: "An area without an owner is never answered.",
    example: "PKI team.",
  },
  // src: frontend/components/cbom/sources/shared.tsx:127-132 — Q0 Unknown to Q3 Verified
  "cbsrc.ev.col.confidence": {
    label: "Confidence",
    what: "How much the answer can be trusted: Q0 Unknown, Q1 Self-attested, Q2 Documented (evidence document), Q3 Verified (evidence checked by your team).",
    why: "Reports and the run's coverage weigh answers by this level.",
    example: "Q2 Documented.",
  },
  // src: frontend/components/cbom/sources/EvidenceTab.tsx:310, frontend/components/cbom/sources/EvidenceTab.tsx:848-873 — the evidence document and its date
  "cbsrc.ev.col.evidence": {
    label: "Evidence",
    what: "The supporting document's title and link, and its date. Evidence older than 12 months drops back to Q0 until renewed.",
    why: "Dated evidence shows the answer was true recently, not years ago.",
    example: "HSM FIPS certificate (PDF), 4 Feb 2026.",
  },
  // src: frontend/components/cbom/sources/EvidenceTab.tsx:311, frontend/components/cbom/sources/EvidenceTab.tsx:881 — when the owner should answer by
  "cbsrc.ev.col.due": {
    label: "Due",
    what: "When the owner should answer by.",
    why: "Overdue areas are the gaps to chase before an audit.",
    example: "30 Nov 2026.",
  },
  // src: frontend/components/cbom/sources/EvidenceTab.tsx:397-400 — single-use links, no login, 14 days
  "cbsrc.ev.vendors": {
    label: "Vendors",
    what: "Vendors asked to answer a questionnaire through a single-use link, with no login; the link expires in 14 days. A vendor who does not answer stays Q0.",
    why: "Third-party services use crypto you cannot scan but still answer for in an audit.",
    example: "Acme Payments, link sent 2 Nov, answered 6 Nov, Q2.",
  },
  // src: frontend/components/cbom/sources/EvidenceTab.tsx:424 — vendor name
  "cbsrc.ev.col.vendor": {
    label: "Vendor",
    what: "The vendor asked to answer.",
    why: "Each vendor is one evidence area of its own.",
    example: "Acme Payments.",
  },
  // src: frontend/components/cbom/sources/EvidenceTab.tsx:425 — the single-use link
  "cbsrc.ev.col.link": {
    label: "Link status",
    what: "The state of the vendor's single-use link: not sent, sent and waiting, answered, or expired (after 14 days).",
    why: "An expired link needs a new one before the vendor can answer.",
    example: "Expired: press New link and send the vendor the fresh link.",
  },
  // src: frontend/components/cbom/sources/EvidenceTab.tsx:508, frontend/components/cbom/sources/EvidenceTab.tsx:640-670 — read-only preview
  "cbsrc.ev.preview": {
    label: "Questionnaire preview",
    what: "Read-only view of exactly what an owner or vendor is asked for the chosen area.",
    why: "Check the questions before sending a link to a vendor.",
    example: "Preview Card personalisation bureau: 5 questions and an evidence link.",
  },
  // src: frontend/components/cbom/sources/EvidenceTab.tsx:511-513 — which area to preview
  "cbsrc.ev.preview_area": {
    label: "Area",
    what: "The evidence area whose questionnaire is shown below.",
    why: "Each area asks different questions.",
    example: "Offline root CA key ceremony.",
  },
  // src: frontend/components/cbom/sources/EvidenceTab.tsx:783-816, frontend/components/cbom/sources/EvidenceTab.tsx:644-662 — yes/no/unknown or a free-text answer
  "cbsrc.ev.question": {
    label: "Question",
    what: "One question of the area's questionnaire, answered with a choice or in free text.",
    why: "Each answer feeds the area's confidence; an unanswered question keeps it a gap.",
    example: "Are keys generated inside a FIPS 140-3 Level 3 HSM? Yes.",
  },
  // src: frontend/components/cbom/sources/EvidenceTab.tsx:664-666 — Q2 and Q3 need one
  "cbsrc.ev.preview_link": {
    label: "Link to supporting evidence",
    what: "Where the person answering links a policy, certificate or report. Documented (Q2) and Verified (Q3) need one.",
    why: "Without evidence an answer stays Self-attested at best.",
    example: "https://intranet.bank.in/pki/ceremony-2026.pdf.",
  },
  // src: frontend/components/cbom/sources/EvidenceTab.tsx:768-770 — the person or team who answers
  "cbsrc.ev.owner": {
    label: "Owner",
    what: "Who answers for this area: a person or team. The area may suggest a usual owner.",
    why: "Named owners are who auditors ask, and who remediation is routed to.",
    example: "PKI team (usually: Information security).",
  },
  // src: frontend/components/cbom/sources/EvidenceTab.tsx:822-829 — Documented and Verified need a document and date
  "cbsrc.ev.confidence": {
    label: "Confidence",
    what: "The confidence of this area's answer: Q0 Unknown, Q1 Self-attested, Q2 Documented or Q3 Verified. Documented and Verified need an evidence document and its date.",
    why: "It decides how the area counts in coverage and reports.",
    example: "Q3 after you checked the vendor's certificate yourself.",
  },
  // src: frontend/components/cbom/sources/EvidenceTab.tsx:848-849 — up to 200 characters
  "cbsrc.ev.title": {
    label: "Evidence title",
    what: "A short title for the evidence document, up to 200 characters.",
    why: "Auditors find the document by its title in the evidence pack.",
    example: "Key management policy v3 (PDF).",
  },
  // src: frontend/components/cbom/sources/EvidenceTab.tsx:851-858 — http or https, up to 1,000 characters
  "cbsrc.ev.url": {
    label: "Evidence link",
    what: "An http:// or https:// link to the document, up to 1,000 characters.",
    why: "The link lets a reviewer open the evidence in one click.",
    example: "https://intranet.bank.in/policies/kms-v3.pdf.",
  },
  // src: frontend/components/cbom/sources/EvidenceTab.tsx:861-873 — evidence older than 12 months drops to Q0
  "cbsrc.ev.date": {
    label: "Evidence date",
    what: "The date of the document, not later than today. Evidence older than 12 months drops back to Q0 until renewed.",
    why: "Crypto policies change; old evidence may describe a setup that no longer exists.",
    example: "14 Mar 2026.",
  },
  // src: frontend/components/cbom/sources/EvidenceTab.tsx:881-882 — when the owner should answer by
  "cbsrc.ev.due": {
    label: "Due date",
    what: "When the owner should answer by.",
    why: "A due date turns an open gap into a tracked task.",
    example: "30 Nov 2026.",
  },
  // src: frontend/components/cbom/sources/EvidenceTab.tsx:954-955 — required
  "cbsrc.ev.vendor_name": {
    label: "Vendor name",
    what: "The vendor's name, as shown in lists and reports.",
    why: "Each vendor becomes an evidence area of its own.",
    example: "Acme Payments Pvt Ltd.",
  },
  // src: frontend/components/cbom/sources/EvidenceTab.tsx:964-965 — for your records only
  "cbsrc.ev.vendor_email": {
    label: "Contact email",
    what: "Optional: the vendor contact's email, for your records only. ZeroShield does not email the vendor; you send the link yourself.",
    why: "Keeps who was asked next to the answer.",
    example: "security@acmepayments.in.",
  },
  // src: frontend/components/cbom/sources/EvidenceTab.tsx:1054-1060 — Q1 when answered, Q2 with a link, Q3 once verified
  "cbsrc.ev.vendor_confidence": {
    label: "Confidence",
    what: "The confidence of the vendor's answer. Set Q1 when answered, Q2 when the vendor gave an evidence link, Q3 once you have verified the evidence.",
    why: "It decides how much the vendor's answer counts.",
    example: "Q2: the vendor linked its PCI PIN attestation.",
  },
  // ────────────────────────────────────────────────────────────── CBOM Sources: Review & Run (components/cbom/sources/ReviewRunTab.tsx)
  // src: frontend/components/cbom/sources/ReviewRunTab.tsx:235-309, frontend/components/cbom/sources/ReviewRunTab.tsx:319 — one row per source group
  "cbsrc.rr.coverage": {
    label: "Coverage",
    what: "Every kind of source and what a run would collect from it: how much is in scope, what reaches it (scan nodes, ZeroShield's cloud or questionnaires), failed tests, the credits it costs per run and whether it is ready.",
    why: "Shows at a glance which parts of the estate the next run covers and which it leaves out.",
    example: "Servers · 3 sources, 612 targets · node-dc1 · No failed tests · 6.12 · Ready.",
  },
  // src: frontend/components/cbom/sources/ReviewRunTab.tsx:325 — the source group
  "cbsrc.rr.col.source": {
    label: "Source",
    what: "The group of sources: servers, Kubernetes, databases, cloud, network, identity, evidence or code scans.",
    why: "A run is started per group with the boxes under Start a scan.",
    example: "Databases.",
  },
  // src: frontend/components/cbom/sources/ReviewRunTab.tsx:326 — what the group covers
  "cbsrc.rr.col.in_scope": {
    label: "In scope",
    what: "How much of the group a run would cover: sources, targets, accounts or areas.",
    why: "Zero in scope means the group adds nothing to the CBOM yet.",
    example: "2 sources, 4 databases.",
  },
  // src: frontend/components/cbom/sources/ReviewRunTab.tsx:327 — scan nodes or ZeroShield's cloud
  "cbsrc.rr.col.through": {
    label: "Reached through",
    what: "What does the collecting: the scan nodes for in-network sources, or ZeroShield's cloud for cloud accounts, CT logs and identity providers.",
    why: "An offline node here means that group's jobs wait.",
    example: "node-dc1, node-dr1.",
  },
  // src: frontend/components/cbom/sources/ReviewRunTab.tsx:243, frontend/components/cbom/sources/ReviewRunTab.tsx:267, frontend/components/cbom/sources/ReviewRunTab.tsx:309 — estimated credits per run for the group
  "cbsrc.rr.col.credits": {
    label: "Credits",
    what: "The credits one run of this group is estimated to charge; code scans are charged per scan and evidence costs nothing.",
    why: "Credits come off the team balance when the run starts and are refunded for jobs that fail or expire.",
    example: "4.00 for one AWS account (4 credits per account per run).",
  },
  // src: frontend/components/cbom/sources/ReviewRunTab.tsx:328 — ready, needs attention or not set up
  "cbsrc.rr.col.status": {
    label: "Status",
    what: "Ready, a count of issues to fix (for example an offline node or a failed test), Not configured, or for evidence the number of gaps.",
    why: "Groups that are not ready are skipped and listed below with the fix.",
    example: "1 issue: a source has a failed connection test.",
  },
  // src: frontend/components/cbom/sources/ReviewRunTab.tsx:358 — sources the plan would skip
  "cbsrc.rr.skipped": {
    label: "Will be skipped unless you fix it",
    what: "Sources the next run would skip, each with the reason: an offline or missing node, a failed or missing test, a missing credential, or a closed scan window.",
    why: "A skipped source is a gap in the CBOM; fixing it before starting saves a second run.",
    example: "dc-mumbai-windows: the connection test failed (Login failed).",
  },
  // src: frontend/components/cbom/sources/ReviewRunTab.tsx:394-405 — jobs, run record, proof trail, evidence gaps
  "cbsrc.rr.after": {
    label: "What you get after the scan",
    what: "What a run produces: collection jobs per source for your scan nodes, a run record with the credits charged and refunded, a proof trail (audit log, node source IPs, the AWS role's CloudTrail calls) and evidence gaps listed as Q0.",
    why: "The proof trail lets your SOC and auditors confirm exactly what was touched.",
    example: "Run #42: 9 jobs, 1,284 assets, 12.40 credits charged, 1.00 refunded.",
  },
  // src: frontend/components/cbom/sources/ReviewRunTab.tsx:636, frontend/components/cbom/sources/ReviewRunTab.tsx:52-58 — choose groups, estimate the credits, start
  "cbsrc.rr.start": {
    label: "Start a scan",
    what: "Choose which groups to collect, estimate the credits, confirm the SOC agreement for network scans, then start the run.",
    why: "Credits are charged when the run starts; the estimate shows the cost and what will be skipped first.",
    example: "Servers and Cloud: 10.12 credits for 4 sources.",
  },
  // src: frontend/components/cbom/sources/ReviewRunTab.tsx:52-58, frontend/components/cbom/sources/ReviewRunTab.tsx:640-646 — one box per group; how many sources are ready
  "cbsrc.rr.include": {
    label: "Include in the run",
    what: "Tick each group of sources to collect in this run; the count shows how many of its sources are ready.",
    why: "Leave out groups whose systems are in a change freeze.",
    example: "Servers · 3 ready.",
  },
  // src: frontend/components/cbom/sources/ReviewRunTab.tsx:705-716 — required when Network is included
  "cbsrc.rr.soc_ack": {
    label: "SOC agreement",
    what: "Confirm that your SOC has agreed the network ranges and scan windows. Required when the run includes Network.",
    why: "Active network probing without SOC agreement is often treated as an incident.",
    example: "Tick after the SOC acknowledged ranges 10.20.0.0/16 and the 22:00-06:00 window.",
  },
  // src: frontend/components/cbom/sources/ReviewRunTab.tsx:424 — the 50 most recent runs
  "cbsrc.rr.runs": {
    label: "Runs",
    what: "The 50 most recent collection runs of this team, newest first, with their status, jobs, assets and credits. Open Results for a run's findings, or Compare two finished runs.",
    why: "Comparing runs shows what changed: new weak keys, fixed ones, expired certificates.",
    example: "Run #42 · Done · 9 done · 1,284 assets · 12.40 charged / 1.00 refunded.",
  },
  // src: frontend/components/cbom/sources/ReviewRunTab.tsx:450 — run number
  "cbsrc.rr.col.run": {
    label: "Run",
    what: "The run's number, unique within ZeroShield.",
    why: "Reports and exports name the run by this number.",
    example: "#42, the run started on 13 Nov.",
  },
  // src: frontend/components/cbom/sources/ReviewRunTab.tsx:451 — when the run was created
  "cbsrc.rr.col.started": {
    label: "Started",
    what: "When the run was started.",
    why: "Findings reflect the estate at this time.",
    example: "13 Nov 2026, 11:05 pm IST.",
  },
  // src: frontend/components/cbom/sources/shared.tsx:114-121 — queued, running, done, partial, failed, cancelled
  "cbsrc.rr.col.run_status": {
    label: "Status",
    what: "Queued, Running, Done (every job succeeded), Partial (some jobs failed or expired), Failed or Cancelled.",
    why: "A Partial run's results miss the sources whose jobs failed.",
    example: "Partial: 8 of 9 jobs done, 1 expired.",
  },
  // src: frontend/components/cbom/sources/ReviewRunTab.tsx:160-164 — job counts by status
  "cbsrc.rr.col.jobs": {
    label: "Jobs",
    what: "The run's collection jobs (one per source) counted by status.",
    why: "Waiting jobs usually mean an offline scan node.",
    example: "8 done · 1 failed.",
  },
  // src: frontend/components/cbom/sources/ReviewRunTab.tsx:470-472 — assets collected
  "cbsrc.rr.col.assets": {
    label: "Assets",
    what: "How many crypto assets the run collected: certificates, keys, protocols, libraries and other items.",
    why: "A sudden drop between runs can mean a source stopped reporting.",
    example: "1,284.",
  },
  // src: frontend/components/cbom/sources/ReviewRunTab.tsx:473-475, backend/utilities/cbom_sources/jobs.py:85-107 — charged and refunded
  "cbsrc.rr.col.run_credits": {
    label: "Credits",
    what: "Credits charged when the run started, and credits refunded for jobs that failed, expired or were cancelled.",
    why: "You pay only for jobs that completed.",
    example: "12.40 charged / 1.00 refunded.",
  },
  // src: frontend/components/cbom/sources/ReviewRunTab.tsx:828-830 — scan node or ZeroShield cloud
  "cbsrc.rr.job.runs_on": {
    label: "Runs on",
    what: "Where the job ran: a scan node, or ZeroShield's cloud for cloud accounts, CT logs and identity providers.",
    why: "Points you at the node to check when a job fails.",
    example: "node-dc1.",
  },
  // src: frontend/components/cbom/sources/shared.tsx:96-103 — waiting, running, done, failed, cancelled, expired
  "cbsrc.rr.job.status": {
    label: "Status",
    what: "Waiting (for its node or window), Running, Done, Failed, Cancelled or Expired (never claimed in time; refunded). The note below says why it waits.",
    why: "Expired and failed jobs are refunded and their source has no new results in this run.",
    example: "Waiting · outside the scan window; starts at 22:00.",
  },
  // src: frontend/components/cbom/sources/ReviewRunTab.tsx:838 — assets the job collected
  "cbsrc.rr.job.assets": {
    label: "Assets",
    what: "How many assets this job collected from its source.",
    why: "Zero from a source that had assets before deserves a look.",
    example: "212 from dc-mumbai-linux.",
  },
  // src: frontend/components/cbom/sources/ReviewRunTab.tsx:839-842 — charged for the job; refunded marker
  "cbsrc.rr.job.credits": {
    label: "Credits",
    what: "The credits charged for this job, marked refunded when it failed, expired or was cancelled.",
    why: "Shows which part of the run's cost came back.",
    example: "2.56 refunded.",
  },
  // src: frontend/components/cbom/sources/ReviewRunTab.tsx:843 — how many times the job was tried
  "cbsrc.rr.job.attempts": {
    label: "Attempts",
    what: "How many times a node tried this job. A job is retried after a transient failure.",
    why: "Many attempts point at a flaky network path or an overloaded node.",
    example: "2: the first try timed out, the second finished.",
  },
  // src: frontend/components/cbom/sources/ReviewRunTab.tsx:844-846 — the job's last error
  "cbsrc.rr.job.error": {
    label: "Error",
    what: "The last error the job reported, if any.",
    why: "It names the exact failure to fix before the next run.",
    example: "connect timeout to 10.20.0.17:22.",
  },
  // src: frontend/components/cbom/sources/ReviewRunTab.tsx:862-872 — sources skipped at start
  "cbsrc.rr.skipped_start": {
    label: "Skipped when the run started",
    what: "Sources that were not queued when the run started, each with the reason.",
    why: "They are not in this run's results and were not charged.",
    example: "dc-mumbai-windows: the scan node was offline.",
  },
  // src: frontend/components/cbom/sources/ReviewRunTab.tsx:874-878 — what changed since the previous run
  "cbsrc.rr.changes": {
    label: "Changes",
    what: "What changed in this run compared with the previous run of the same sources: assets added, removed or changed.",
    why: "Drift shows new weak crypto as soon as it appears.",
    example: "+3 certificates, -1 SSH host key, 2 changed.",
  },
  // ────────────────────────────────────────────────────────────── CBOM Sources: Review & Run, run details
  // src: frontend/components/cbom/sources/ReviewRunTab.tsx:825-827 — one job per source
  "cbsrc.rr.job.source": {
    label: "Source",
    what: "The source this job collected from; each source in the run has one job.",
    why: "Open the source's tab to fix a failed job.",
    example: "dc-mumbai-linux.",
  },
  // ────────────────────────────────────────────────────────────── CBOM Sources: Scan nodes (components/cbom/sources/ScanNodesTab.tsx)
  // src: frontend/components/cbom/sources/ScanNodesTab.tsx:265 — nodes of the team
  "cbsrc.nodes.count": {
    label: "Scan nodes",
    what: "How many scan nodes this team has registered or is registering.",
    why: "Each network segment you want to scan needs a node inside it.",
    example: "3: one per data centre and one in the DMZ.",
  },
  // src: backend/utilities/cbom_sources/planning.py:21, backend/utilities/cbom_sources/planning.py:35-44 — heartbeat within the last 120 s
  "cbsrc.nodes.online": {
    label: "Online",
    what: "Nodes that sent a heartbeat in the last 2 minutes and can take jobs now.",
    why: "Jobs for sources behind an offline node wait and expire.",
    example: "2 of 3 online.",
  },
  // src: backend/utilities/cbom_sources/planning.py:21, backend/utilities/cbom_sources/planning.py:35-44 — registered, no heartbeat for 120 s
  "cbsrc.nodes.offline": {
    label: "Offline",
    what: "Registered nodes with no heartbeat for more than 2 minutes: stopped, unable to reach ZeroShield, or their host is down.",
    why: "An offline node silently removes its whole segment from the next run.",
    example: "node-dr1 offline since the DR site's proxy changed.",
  },
  // src: frontend/components/cbom/sources/ScanNodesTab.tsx:268 — servers and addresses routed through these nodes
  "cbsrc.nodes.assigned": {
    label: "Targets assigned",
    what: "Servers and addresses routed through these nodes by your sources and network ranges.",
    why: "Shows how much depends on each node staying online.",
    example: "4,612 targets across 3 nodes.",
  },
  // src: frontend/components/cbom/sources/ScanNodesTab.tsx:271-273 — one per segment; outbound only
  "cbsrc.nodes.list": {
    label: "Registered scan nodes",
    what: "Your scan nodes: small read-only collectors inside your network, one per network segment. Each connects out to ZeroShield on one HTTPS port only and opens no inbound ports.",
    why: "Nodes are how ZeroShield reads systems that are not reachable from the internet.",
    example: "node-dc1 · DC1-core · Online · Docker container.",
  },
  // src: frontend/components/cbom/sources/ScanNodesTab.tsx:312 — node name
  "cbsrc.nodes.col.node": {
    label: "Node",
    what: "The node's name, as chosen when it was added.",
    why: "Sources and ranges pick their node by this name.",
    example: "node-dc1.",
  },
  // src: frontend/components/cbom/sources/ScanNodesTab.tsx:313, frontend/components/cbom/sources/ScanNodesTab.tsx:430-433 — the network segment it sits in
  "cbsrc.nodes.col.segment": {
    label: "Segment",
    what: "The network segment the node sits in.",
    why: "A source must use a node in a segment that reaches its targets.",
    example: "DC1-core.",
  },
  // src: frontend/components/cbom/sources/shared.tsx:62-67 — online, offline, waiting to register, token expired
  "cbsrc.nodes.col.status": {
    label: "Status",
    what: "Online (heartbeat in the last 2 minutes), Offline, Waiting to register (installed with a token that was not used yet) or Token expired (create a new registration token).",
    why: "Only online nodes take jobs.",
    example: "Token expired: the install command was not run within 24 hours.",
  },
  // src: frontend/components/cbom/sources/ScanNodesTab.tsx:64-70, frontend/components/cbom/sources/ScanNodesTab.tsx:337-345 — Docker, OVA, AMI or Helm; host agent mode
  "cbsrc.nodes.col.runs_as": {
    label: "Runs as",
    what: "How the node runs: Docker container, OVA appliance, AWS AMI or Helm chart. Host agent means it collects only its own host from read-only mounts and is never given a credential.",
    why: "It tells you where to look when a node needs restarting or upgrading.",
    example: "Helm chart in the prod-payments cluster.",
  },
  // src: frontend/components/cbom/sources/ScanNodesTab.tsx:342 — node_version reported by the node
  "cbsrc.nodes.col.version": {
    label: "Version",
    what: "The software version the node reported.",
    why: "Old versions may miss newer collectors; upgrade them with the install command.",
    example: "1.8.2.",
  },
  // src: frontend/components/cbom/sources/ScanNodesTab.tsx:343, frontend/components/cbom/sources/ScanNodesTab.tsx:789-791 — signed or legacy unsigned
  "cbsrc.nodes.col.requests": {
    label: "Requests",
    what: "Whether the node signs every request with a key made at enrollment (Signed), or is a legacy node that does not.",
    why: "With signing, a copied node token alone cannot act as the node.",
    example: "Legacy: unsigned. Reset the node and register it again to sign.",
  },
  // src: frontend/components/cbom/sources/ScanNodesTab.tsx:344 — last heartbeat
  "cbsrc.nodes.col.last_seen": {
    label: "Last seen",
    what: "How long ago the node's last heartbeat arrived.",
    why: "More than 2 minutes means it is offline.",
    example: "12 seconds ago.",
  },
  // src: frontend/components/cbom/sources/ScanNodesTab.tsx:345 — targets routed through the node
  "cbsrc.nodes.col.targets": {
    label: "Targets",
    what: "How many servers and addresses are routed through this node.",
    why: "A heavily loaded node may need the parallel limits lowered or a second node.",
    example: "2,304.",
  },
  // src: frontend/components/cbom/sources/ScanNodesTab.tsx:405-409 — run on any VM or cluster inside the segment
  "cbsrc.nodes.add": {
    label: "Add a scan node",
    what: "Register a new scan node: name it, choose how to run it, allow its outbound traffic, then run the install command on a VM or cluster inside the segment you want to scan.",
    why: "Without a node, servers, clusters, databases and network ranges cannot be collected.",
    example: "node-dc1 as a Docker container on a Linux VM in DC1-core.",
  },
  // src: frontend/components/cbom/sources/ScanNodesTab.tsx:426-427 — up to 64 characters
  "cbsrc.nodes.name": {
    label: "Node name",
    what: "A name for the node, up to 64 characters, shown wherever a source picks its node.",
    why: "Name it after its location so the right node is picked for each source.",
    example: "node-dc1.",
  },
  // src: frontend/components/cbom/sources/ScanNodesTab.tsx:430-433 — pick one or type your own
  "cbsrc.nodes.segment": {
    label: "Network segment",
    what: "The network segment the node sits in; pick an existing one or type your own, up to 64 characters.",
    why: "Segments group nodes and appear in run results, so findings can be traced to a network.",
    example: "DC1-core.",
  },
  // src: frontend/components/cbom/sources/ScanNodesTab.tsx:435-437 — the node's time zone
  "cbsrc.nodes.tz": {
    label: "Time zone",
    what: "The time zone of the node's location, used in its install settings.",
    why: "Makes the node's own logs line up with your local time.",
    example: "Asia/Kolkata.",
  },
  // src: frontend/components/cbom/sources/ScanNodesTab.tsx:64-70 — Docker, OVA, AMI, Helm
  "cbsrc.nodes.deploy": {
    label: "Deployment",
    what: "How to run the node: a Docker container on any Linux VM, an OVA appliance for VMware, an AWS AMI in your VPC, or a Helm chart in your Kubernetes cluster. Docker and Helm are the proven ways; the others you build from the published template.",
    why: "It decides the install command you get.",
    example: "Docker container on an existing RHEL 9 VM.",
  },
  // src: frontend/components/cbom/sources/ScanNodesTab.tsx:503-508 — ZeroShield API and your targets
  "cbsrc.nodes.col.destination": {
    label: "Destination",
    what: "Where the node connects to: ZeroShield's API host, and the targets it reads.",
    why: "Firewalls must allow these connections from the node, and nothing inbound.",
    example: "api.zeroshield.ai.",
  },
  // src: frontend/components/cbom/sources/ScanNodesTab.tsx:503-508 — HTTPS to ZeroShield; 22, 5986, 6443, database and TLS ports to targets
  "cbsrc.nodes.col.port": {
    label: "Port",
    what: "The destination port: HTTPS to ZeroShield, and 22, 5986, 6443 and your database and TLS ports to targets.",
    why: "A blocked port shows up as unreachable targets in the connection test.",
    example: "443 to api.zeroshield.ai.",
  },
  // src: frontend/components/cbom/sources/ScanNodesTab.tsx:503-508 — jobs in, results out; read-only collection
  "cbsrc.nodes.col.used_for": {
    label: "Used for",
    what: "What the connection is for: jobs in and results out (HTTPS to ZeroShield), or read-only collection from your targets.",
    why: "Lets your firewall team approve each rule for a stated purpose.",
    example: "Jobs in, results out (HTTPS).",
  },
  // src: frontend/components/cbom/sources/ScanNodesTab.tsx:512-513, frontend/components/cbom/sources/ScanNodesTab.tsx:726-727 — an http proxy URL
  "cbsrc.nodes.proxy": {
    label: "Proxy",
    what: "Optional: the HTTP proxy the node uses to reach ZeroShield.",
    why: "Nodes in locked-down segments often reach the internet only through a proxy.",
    example: "http://proxy.bank.local:8080.",
  },
  // src: frontend/components/cbom/sources/ScanNodesTab.tsx:516-525 — PEM up to 64 KB
  "cbsrc.nodes.proxy_ca": {
    label: "Proxy CA certificate",
    what: "Only if your proxy inspects TLS: the PEM certificate of the proxy's CA, up to 64 KB.",
    why: "Without it the node refuses the proxy's re-signed certificate and cannot connect.",
    example: "bank-proxy-ca.pem.",
  },
  // src: frontend/components/cbom/sources/ScanNodesTab.tsx:532-534 — trust the proxy CA only for ZeroShield hostnames
  "cbsrc.nodes.tls_inspect": {
    label: "Proxy inspects TLS",
    what: "Tick if your proxy decrypts TLS. The node then trusts the proxy's CA, and only for ZeroShield's hostnames.",
    why: "Limiting the extra trust to ZeroShield's hostnames keeps the node's other TLS checks strict.",
    example: "Tick for a Zscaler or Blue Coat proxy with SSL inspection on.",
  },
  // src: frontend/components/cbom/sources/ScanNodesTab.tsx:572-583 — outbound only, read-only, metadata only
  "cbsrc.nodes.does": {
    label: "What the node does, and never does",
    what: "The node opens no inbound ports, uses each credential only on its targets, reads with read-only accounts, and sends metadata only: algorithms, key sizes, versions and locations, never private keys.",
    why: "These are the guarantees your security team reviews before approving a node.",
    example: "For a private key file, only its public half and type are sent.",
  },
  // src: frontend/components/cbom/sources/ScanNodesTab.tsx:702-708 — the node's own SSH key
  "cbsrc.nodes.ssh_key": {
    label: "Node SSH public key",
    what: "The public half of the SSH key this node generated. Install it for the login user on servers that use the node-generated key.",
    why: "The private key never leaves the node, so nothing secret is stored by ZeroShield.",
    example: "ssh-ed25519 AAAAC3Nza... zs-node-7.",
  },
  // src: frontend/components/cbom/sources/ScanNodesTab.tsx:789-800 — require signed scan nodes
  "cbsrc.nodes.signing": {
    label: "Request signing",
    what: "Scan nodes sign every request with a key made at enrollment. A team admin can require it, so nodes that do not sign are refused.",
    why: "A copied node token alone is then not enough to act as the node.",
    example: "Turn on once every node shows Signed.",
  },
  // src: frontend/components/cbom/sources/ScanNodesTab.tsx:795-797 — refuse unsigned nodes
  "cbsrc.nodes.require_signed": {
    label: "Require signed scan nodes",
    what: "Refuse requests from nodes that do not sign them. Legacy unsigned nodes stop working until reset and registered again.",
    why: "Closes the gap of a stolen node token being replayed from another machine.",
    example: "On, after resetting the one legacy node.",
  },
  // ────────────────────────────────────────────────────────────── CBOM Sources: agent pools, schedules, run comparison, scan sidebar, remediation waves
  // src: frontend/components/cbom/sources/AgentPoolsCard.tsx:1-2, frontend/components/cbom/sources/AgentPoolsCard.tsx:92-95 — one token for a Helm DaemonSet
  "cbsrc.pool.card": {
    label: "Host agents on Kubernetes",
    what: "One token for a Helm DaemonSet: every pod enrolls as its own agent-mode scan node named after its Kubernetes node, reads only that node's files through a read-only mount, and is never given a credential.",
    why: "Covers every worker node's crypto (keys, certificates, libraries) without SSH access to each one.",
    example: "A pool token for prod-cluster enrolls 24 host agents, one per worker node.",
  },
  // src: frontend/components/cbom/sources/AgentPoolsCard.tsx:112-113 — up to 64 characters
  "cbsrc.pool.name": {
    label: "Name",
    what: "A name for the pool, up to 64 characters; its agents are named after their Kubernetes nodes.",
    why: "Identifies which cluster the agents belong to.",
    example: "prod-cluster.",
  },
  // src: frontend/components/cbom/sources/AgentPoolsCard.tsx:116-117 — up to 64 characters
  "cbsrc.pool.segment": {
    label: "Network segment",
    what: "The network segment recorded for every agent of the pool, up to 64 characters.",
    why: "Findings from the agents are grouped by segment in run results.",
    example: "DC1-k8s.",
  },
  // src: frontend/components/cbom/sources/AgentPoolsCard.tsx:119-126 — enrolled nodes keep working
  "cbsrc.pool.expiry": {
    label: "Token expires in",
    what: "How long the pool token can enroll new agents. Agents that already enrolled keep working after it expires.",
    why: "A short expiry limits the damage if the token leaks from the Helm values.",
    example: "24 hours: long enough to roll out the DaemonSet.",
  },
  // src: frontend/components/cbom/sources/AgentPoolsCard.tsx:127-128 — 1 to 1,000; at least the number of Kubernetes nodes
  "cbsrc.pool.max": {
    label: "Nodes that may enroll",
    what: "The most agents the token may enroll, 1 to 1,000. Set at least the number of Kubernetes nodes.",
    why: "A cap stops a leaked token from enrolling unlimited fake nodes.",
    example: "30 for a 24-node cluster that may grow.",
  },
  // src: frontend/components/cbom/sources/AgentPoolsCard.tsx:162 — the pool token's name
  "cbsrc.pool.col.token": {
    label: "Token",
    what: "The pool token, by name. The token value itself is shown once, when it is created.",
    why: "Revoke a token here if it may have leaked.",
    example: "prod-cluster.",
  },
  // src: frontend/components/cbom/sources/AgentPoolsCard.tsx:163 — active, expired or revoked
  "cbsrc.pool.col.status": {
    label: "Status",
    what: "Whether the token can still enroll agents: Active, All enrollments used, Expired or Revoked.",
    why: "Only active tokens accept new agents; enrolled agents keep working either way.",
    example: "Expired.",
  },
  // src: frontend/components/cbom/sources/AgentPoolsCard.tsx:164 — agents enrolled out of the maximum
  "cbsrc.pool.col.enrolled": {
    label: "Enrolled",
    what: "How many agents enrolled with this token, out of the maximum allowed.",
    why: "Fewer than your node count means some pods did not start or could not reach ZeroShield.",
    example: "22 of 30.",
  },
  // src: frontend/components/cbom/sources/AgentPoolsCard.tsx:165 — when the token stops enrolling
  "cbsrc.pool.col.expires": {
    label: "Expires",
    what: "When the token stops enrolling new agents.",
    why: "Create a new token before scaling the cluster after this time.",
    example: "15 Nov 2026, 11:00 am IST.",
  },
  // src: frontend/components/cbom/sources/AgentPoolsCard.tsx:166 — agent nodes of the pool
  "cbsrc.pool.col.nodes": {
    label: "Nodes",
    what: "The agent scan nodes this token enrolled, as listed under Registered scan nodes.",
    why: "Each agent appears as its own node with its own status.",
    example: "prod-cluster-ip-10-30-1-12, prod-cluster-ip-10-30-1-13, ...",
  },
  // src: frontend/components/cbom/sources/SchedulesCard.tsx:1-3, frontend/components/cbom/sources/SchedulesCard.tsx:166 — daily, weekly or monthly; charged like Start scan
  "cbsrc.sched.card": {
    label: "Scheduled runs",
    what: "Collection runs that start on their own, daily, weekly or monthly, at a time in the team's time zone. Each run charges credits like Start a scan and is skipped, with the reason, when the team has too few.",
    why: "Regular runs show what changed and prove fixes landed.",
    example: "Weekly, Sunday 02:00 Asia/Kolkata: servers, databases and cloud.",
  },
  // src: frontend/components/cbom/sources/SchedulesCard.tsx:68-69 — up to 64 characters
  "cbsrc.sched.name": {
    label: "Name",
    what: "A name for the schedule, up to 64 characters.",
    why: "Runs started by a schedule are labelled with it.",
    example: "Weekly full collection.",
  },
  // src: frontend/components/cbom/sources/SchedulesCard.tsx:71-80 — daily, weekly, monthly
  "cbsrc.sched.repeat": {
    label: "Repeat",
    what: "How often the schedule starts a run: daily, weekly or monthly.",
    why: "More frequent runs catch drift sooner but cost more credits.",
    example: "Weekly.",
  },
  // src: frontend/components/cbom/sources/SchedulesCard.tsx:82-90 — day of the week
  "cbsrc.sched.day": {
    label: "Day",
    what: "The day of the week a weekly schedule runs.",
    why: "Pick a day inside your scan window.",
    example: "Sunday.",
  },
  // src: frontend/components/cbom/sources/SchedulesCard.tsx:92-95 — 1 to 28
  "cbsrc.sched.monthday": {
    label: "Day of month",
    what: "The day of the month a monthly schedule runs, 1 to 28 so it exists in every month.",
    why: "Align it with your monthly patch cycle to prove fixes.",
    example: "5: the run after the monthly patch weekend.",
  },
  // src: frontend/components/cbom/sources/SchedulesCard.tsx:98-101 — team time zone; the scan window still applies
  "cbsrc.sched.time": {
    label: "Time",
    what: "The time the run starts, in the team's time zone (set with the scan window on Network TLS). The scan window still applies: work outside it waits.",
    why: "A start time outside the window only queues jobs that wait.",
    example: "02:00.",
  },
  // src: frontend/components/cbom/sources/scheduleForm.ts:9, frontend/components/cbom/sources/scheduleForm.ts:27 — servers, Kubernetes, databases, cloud, network
  "cbsrc.sched.groups": {
    label: "Groups",
    what: "Which groups of sources each scheduled run collects. Network is off by default and needs the SOC agreement.",
    why: "Leave out groups that should only run on demand.",
    example: "Servers, Kubernetes, databases and cloud.",
  },
  // src: frontend/components/cbom/sources/scheduleForm.ts:19 — any, or at least low, medium, high, critical
  "cbsrc.sched.min_crit": {
    label: "Only sources with criticality",
    what: "Limit the schedule to sources whose business criticality is at least this level, or Any.",
    why: "Scan critical systems more often without paying for every source each time.",
    example: "High: a daily run of only high and critical sources.",
  },
  // src: frontend/components/cbom/sources/SchedulesCard.tsx:1-3, frontend/components/cbom/sources/SchedulesCard.tsx:125-127 — kept with the schedule
  "cbsrc.sched.soc": {
    label: "SOC agreement for schedules",
    what: "Confirm that your SOC has agreed the network ranges and scan windows for every scheduled run. It is kept with the schedule.",
    why: "Unattended network scans need standing SOC approval.",
    example: "Tick after the SOC approved weekly scans of 10.20.0.0/16.",
  },
  // src: frontend/components/cbom/sources/ChangesPanel.tsx:1-3, frontend/components/cbom/sources/ChangesPanel.tsx:228-232 — the previous complete run or a chosen one
  "cbsrc.compare.with": {
    label: "Compare with",
    what: "The run to compare this one with: by default each source's previous complete collection, or a run you choose. Partial or failed jobs show as not compared, never as everything removed.",
    why: "Comparing shows exactly what changed between two points in time.",
    example: "Run #38, before the TLS hardening change.",
  },
  // src: frontend/components/cbom/sources/SidebarSources.tsx:1-3 — off by default; adds the group's run and credits to the estimate
  "cbsrc.sidebar.include": {
    label: "Include CBOM Sources",
    what: "Also run a collection of this group of CBOM Sources with this scan. Off by default; turning it on adds that group's collection run and its credits to the estimate. Sources are managed on the CBOM Sources page.",
    why: "One action then covers the code and the infrastructure that runs it.",
    example: "Include servers: adds 6.12 credits for 3 server sources.",
  },
  // src: frontend/components/cbom/sources/SidebarSources.tsx:160-165 — required with network TLS
  "cbsrc.sidebar.soc": {
    label: "SOC agreement",
    what: "Confirm that your SOC has agreed the network ranges and scan windows. Required when network TLS is included.",
    why: "Active network probing without SOC agreement is often treated as an incident.",
    example: "Tick after the SOC acknowledged the ranges.",
  },
  // src: frontend/components/cbom/sources/WavesControls.tsx:1-3 — suggested wave per asset and the team's assignment
  "cbsrc.waves.card": {
    label: "Remediation waves",
    what: "Each asset's suggested wave: 1 exposed or harvest-now-decrypt-later critical/high, 2 other critical/high, 3 medium/low, 4 post-quantum migration. Assign a wave, owner, target date and status; plans follow the asset to later runs and scans.",
    why: "Waves turn a long findings list into an ordered plan with owners and dates.",
    example: "Wave 1: RSA-2048 key exchange on api.bank.in:443, owner Payments, due 31 Dec.",
  },
  // src: frontend/components/cbom/sources/WavesControls.tsx:142-145 — hides assets without a wave
  "cbsrc.waves.only_planned": {
    label: "Only assets that need action",
    what: "Show only assets that have a wave, hiding those that need no action.",
    why: "Keeps the list to what someone has to fix.",
    example: "On: 1,284 assets narrow to 96.",
  },
  // src: frontend/components/cbom/sources/WavesControls.tsx:160-164 — selection for the bulk bar
  "cbsrc.waves.select": {
    label: "Select asset",
    what: "Select assets to assign together with the bar above.",
    why: "Assign a whole group to one owner and date in one step.",
    example: "Tick the 12 wave-1 certificates of api.bank.in.",
  },
  // src: frontend/components/cbom/sources/WavesControls.tsx:93-99 — set or keep the wave
  "cbsrc.waves.bulk_wave": {
    label: "Wave",
    what: "The wave to give the selected assets: 1 to 4, Use suggested (the wave worked out from impact and exposure), or Keep wave.",
    why: "Override the suggestion when you know better, for example a system due to be retired.",
    example: "Wave 2.",
  },
  // src: frontend/components/cbom/sources/WavesControls.tsx:100-101 — up to 128 characters
  "cbsrc.waves.bulk_owner": {
    label: "Owner",
    what: "Who fixes the selected assets, up to 128 characters. Blank keeps each one's owner.",
    why: "Each fix needs a named owner to happen.",
    example: "Payments platform team.",
  },
  // src: frontend/components/cbom/sources/WavesControls.tsx:102-103 — date
  "cbsrc.waves.bulk_date": {
    label: "Target date",
    what: "When the selected assets should be fixed by. Blank keeps each one's date.",
    why: "Dates let you track the plan against regulator deadlines.",
    example: "31 Mar 2027.",
  },
  // src: frontend/components/cbom/sources/WavesControls.tsx:27, frontend/components/cbom/sources/WavesControls.tsx:105-112 — open, in progress, done, risk accepted
  "cbsrc.waves.bulk_status": {
    label: "Status",
    what: "The status to set: Open, In progress, Done or Risk accepted; or Keep status.",
    why: "Done items should disappear from the next run; Risk accepted records a decision.",
    example: "In progress.",
  },
  // ────────────────────────────────────────────────────────────── CBOM Sources: network appliances, container images, CMDB import
  // src: frontend/components/cbom/sources/AppliancesSection.tsx:1-3, frontend/components/cbom/sources/AppliancesSection.tsx:59-61, backend/utilities/cbom_sources/kinds.py:673-674 — Cisco IOS/ASA, FortiOS over SSH; PAN-OS, F5 over API
  "cbsrc.app.card": {
    label: "Network appliances",
    what: "Read-only configuration pulls from routers, firewalls and load balancers through a scan node: Cisco IOS and ASA and FortiOS over SSH show commands, PAN-OS and F5 BIG-IP over API reads. TLS, SSH and IKE/IPsec settings and key sizes are inventoried.",
    why: "VPN tunnels and load balancers carry most traffic; weak IKE groups there are harvest-now-decrypt-later targets.",
    example: "fw-dc1 (FortiGate): IKE phase 1 uses DH group 14 (2048-bit MODP), quantum-vulnerable.",
  },
  // src: frontend/components/cbom/sources/AppliancesSection.tsx:28-35 — the appliance platform
  "cbsrc.app.col.vendor": {
    label: "Vendor",
    what: "The appliance platform and how it is read (SSH show commands or API).",
    why: "Each platform has its own read commands and credential type.",
    example: "Cisco ASA.",
  },
  // src: frontend/components/cbom/sources/AppliancesSection.tsx:216 — devices of the source
  "cbsrc.app.col.targets": {
    label: "Targets",
    what: "The devices this source reads, all with the same account.",
    why: "Group devices that share an account and platform into one source.",
    example: "3 devices.",
  },
  // src: frontend/components/cbom/sources/shared.tsx:76-84 — last connection test
  "cbsrc.col.test": {
    label: "Test",
    what: "The result of the last connection test: Not tested, Testing, Passed, Partly ready, Failed or Could not test.",
    why: "A source that has not passed a test is likely to fail its collection jobs.",
    example: "Passed.",
  },
  // src: frontend/components/cbom/sources/AppliancesSection.tsx:28-35, frontend/components/cbom/sources/AppliancesSection.tsx:199-210 — what is read on each platform
  "cbsrc.app.vendor": {
    label: "Vendor",
    what: "The platform of the devices. The hint lists exactly what is read: show commands for Cisco IOS, ASA and FortiOS; read-only API calls for PAN-OS and F5 BIG-IP.",
    why: "Only the listed reads are sent, so your change board can approve them up front.",
    example: "F5 BIG-IP: GET client-ssl profiles and key type and size only.",
  },
  // src: frontend/components/cbom/sources/AppliancesSection.tsx:213-214 — up to 64 characters
  "cbsrc.app.name": {
    label: "Name",
    what: "A name for this appliance source, up to 64 characters, shown in lists, run results and reports.",
    why: "Each finding records it as its source.",
    example: "dc1-firewalls.",
  },
  // src: frontend/components/cbom/sources/AppliancesSection.tsx:216-218 — one address or host name per line
  "cbsrc.app.devices": {
    label: "Devices",
    what: "The devices to read, one address or host name per line; all use the same account.",
    why: "Devices not listed keep their weak VPN settings unseen.",
    example: "10.20.0.1 and fw-dc1.bank.local.",
  },
  // src: frontend/components/cbom/sources/AppliancesSection.tsx:221-222 — default 22 for SSH, 443 for API
  "cbsrc.app.port": {
    label: "Port",
    what: "The management port: 22 by default for SSH platforms, 443 for API platforms.",
    why: "A management interface on a custom port fails the test until it is set here.",
    example: "8443 for a BIG-IP management port.",
  },
  // src: frontend/components/cbom/sources/AppliancesSection.tsx:225-226 — a read-only account, up to 64 characters
  "cbsrc.app.login": {
    label: "Login",
    what: "A read-only account on the devices, up to 64 characters. On Cisco ASA it must land in privileged EXEC.",
    why: "A read-only role limits what a leaked password could change.",
    example: "zs-cbom with privilege 15 view-only.",
  },
  // src: frontend/components/cbom/sources/AppliancesSection.tsx:230, backend/utilities/cbom_sources/kinds.py:258-260 — encrypted at rest; SSH passwords need a pinned host key
  "cbsrc.app.secret": {
    label: "Password or API key",
    what: "The account's password, or the API key for PAN-OS. Encrypted at rest and sent only to the scan node. SSH platforms require the pinned host key below, so the password only goes to the real device.",
    why: "Pinning stops a spoofed device from capturing the password.",
    example: "The PAN-OS API key generated for zs-cbom.",
  },
  // src: frontend/components/cbom/sources/AppliancesSection.tsx:231-232 — the node that reaches the management interface
  "cbsrc.app.node": {
    label: "Scan node",
    what: "The scan node that reaches the devices' management interfaces.",
    why: "Management networks are usually isolated; the node must sit where it can reach them.",
    example: "node-mgmt in the out-of-band network.",
  },
  // src: frontend/components/cbom/sources/AppliancesSection.tsx:235-238 — known_hosts lines, required for SSH
  "cbsrc.app.known_hosts": {
    label: "Pinned host key",
    what: "The devices' SSH host keys in known_hosts format. Required for SSH platforms.",
    why: "A device whose key does not match is refused before the password is sent.",
    example: "fw-dc1.bank.local ssh-rsa AAAAB3Nza...",
  },
  // src: frontend/components/cbom/sources/AppliancesSection.tsx:241-242 — PEM, for a privately issued management certificate
  "cbsrc.app.ca": {
    label: "CA certificate",
    what: "Optional PEM certificate of the CA that issued the management certificate of API platforms. The certificate is always verified.",
    why: "Needed when the management interface uses an internal CA.",
    example: "bank-root-ca.pem.",
  },
  // src: frontend/components/cbom/sources/ContainerImagesSection.tsx:1-5, frontend/components/cbom/sources/ContainerImagesSection.tsx:54-56 — pulled over HTTPS, 1 credit per image per run
  "cbsrc.img.card": {
    label: "Container images",
    what: "The scan node pulls images from your registry over HTTPS (verified by digest, never written to disk) and lists the crypto packages inside with package URLs. 1 credit per image per run.",
    why: "Images ship their own OpenSSL and crypto libraries, often older than the host's.",
    example: "registry.bank.in/payments/api:2.4.1 contains openssl 1.1.1k.",
  },
  // src: backend/utilities/cbom_sources/kinds.py:735, backend/utilities/cbom_sources/kinds.py:741 — up to 50 per source
  "cbsrc.img.col.images": {
    label: "Images",
    what: "How many images this source pulls, up to 50.",
    why: "Each image costs 1 credit per run.",
    example: "12 images: 12 credits per run.",
  },
  // src: frontend/components/cbom/sources/ContainerImagesSection.tsx:1-5 — anonymous or a vault reference
  "cbsrc.img.col.credentials": {
    label: "Credentials",
    what: "How the registry is accessed: anonymous, or a credential read from your vault on the node. ZeroShield never stores a registry password.",
    why: "Private registries need a credential; keeping it in your vault keeps it off ZeroShield.",
    example: "Vault: secret/zs-cbom/registry.",
  },
  // src: frontend/components/cbom/sources/ContainerImagesSection.tsx:179-180 — up to 64 characters
  "cbsrc.img.name": {
    label: "Name",
    what: "A name for this image source, up to 64 characters, shown in lists, run results and reports.",
    why: "Each package found records it as its source.",
    example: "payments-images.",
  },
  // src: frontend/components/cbom/sources/ContainerImagesSection.tsx:182-183 — an agentless node that reaches the registry
  "cbsrc.img.node": {
    label: "Scan node",
    what: "An agentless scan node that reaches the registry over HTTPS.",
    why: "Host-agent nodes never pull images.",
    example: "node-dc1.",
  },
  // src: frontend/components/cbom/sources/ContainerImagesSection.tsx:185-187, backend/utilities/cbom_sources/kinds.py:735 — up to 50; registry/repository:tag or @sha256
  "cbsrc.img.refs": {
    label: "Images",
    what: "Up to 50 images, one per line: registry/repository:tag or @sha256:digest. Docker Hub is used when no registry is named.",
    why: "A digest pins exactly what was scanned; a tag may move.",
    example: "registry.bank.in/payments/api@sha256:4f1c...",
  },
  // src: frontend/components/cbom/sources/ContainerImagesSection.tsx:190-200 — anonymous or from a vault (admins)
  "cbsrc.img.cred": {
    label: "Registry credentials",
    what: "Anonymous for public pulls, or From a vault (team admins): the node reads the credential from your vault and sends it only to the registry's own host or its token service.",
    why: "The credential never passes through ZeroShield.",
    example: "From a vault for the private registry.bank.in.",
  },
  // src: frontend/components/cbom/sources/ContainerImagesSection.tsx:213-214 — up to 512 characters; under ZS_VAULT_PATH_PREFIX on the node
  "cbsrc.img.vault_path": {
    label: "Secret path",
    what: "Where the registry credential lives in your vault, up to 512 characters, under the prefix the node's operator allows (ZS_VAULT_PATH_PREFIX).",
    why: "The prefix keeps a source from reading arbitrary secrets through the node.",
    example: "secret/zs-cbom/registry/bank.",
  },
  // src: backend/utilities/cbom_sources/kinds.py:745 — 1 to 8,192 MB, default 2,048
  "cbsrc.img.max": {
    label: "Largest image",
    what: "The largest image to pull, compressed, 1 to 8,192 MB (default 2,048). Bigger images are reported as not read.",
    why: "Caps the node's bandwidth and time on one huge image.",
    example: "4096 for ML images with large CUDA layers.",
  },
  // src: frontend/components/cbom/sources/ContainerImagesSection.tsx:222-223 — only for a private CA
  "cbsrc.img.ca": {
    label: "Registry CA certificate",
    what: "Optional PEM certificate of the CA that issued the registry's certificate. The registry's certificate is always verified.",
    why: "Needed for an internal registry with a private CA.",
    example: "bank-root-ca.pem.",
  },
  // src: frontend/components/cbom/sources/CmdbImportDialog.tsx:1-4, frontend/components/cbom/sources/CmdbImportDialog.tsx:44-55 — existing sources keep how they connect
  "cbsrc.cmdb.updates": {
    label: "Metadata updates",
    what: "Existing sources whose owner, application, criticality, exposure, data classification or environment would change. How they connect is untouched, so running and queued jobs are kept.",
    why: "Keeps CBOM ownership in line with your CMDB without re-testing sources.",
    example: "dc-mumbai-linux: owner none → Payments platform team.",
  },
  // src: frontend/components/cbom/sources/CmdbImportDialog.tsx:1-4, frontend/components/cbom/sources/CmdbImportDialog.tsx:57-68 — new Linux server sources or network ranges
  "cbsrc.cmdb.creates": {
    label: "New sources",
    what: "Sources the import would create: hosts not yet in any server source become Linux server sources on the chosen node; CIDRs become network ranges.",
    why: "New sources still need a credential and a passing test before they are collected.",
    example: "cmdb-import-1 (14 Linux hosts) · owner: Cards ops.",
  },
  // src: frontend/components/cbom/sources/CmdbImportDialog.tsx:70-80 — left unchanged
  "cbsrc.cmdb.conflicts": {
    label: "Conflicts",
    what: "Rows that disagree with what is already set, for example a host in two sources with different owners. They are left unchanged.",
    why: "Resolve them in the CMDB or by hand so the right owner gets the findings.",
    example: "10.20.5.17: owner Payments in one source, Cards in another.",
  },
  // src: frontend/components/cbom/sources/CmdbImportDialog.tsx:82-92 — rows that could not be used
  "cbsrc.cmdb.skipped": {
    label: "Skipped or partly read rows",
    what: "CSV or CMDB rows that could not be used, or were only partly read, with the reason.",
    why: "Fix them at the source so the next import covers them.",
    example: "Row 37: criticality \"P1\" is not low, medium, high or critical.",
  },
  // src: frontend/components/cbom/sources/CmdbImportDialog.tsx:142-151 — CSV or ServiceNow CMDB
  "cbsrc.cmdb.source": {
    label: "Import from",
    what: "CSV file: columns host / fqdn / ip / cidr, owner, application, criticality, exposure, data_classification, environment, os. ServiceNow CMDB: reads the CMDB table set in Settings > Integrations (default cmdb_ci_server).",
    why: "Importing keeps owners and criticality in one place instead of typing them per source.",
    example: "ServiceNow CMDB, table cmdb_ci_server.",
  },
  // src: frontend/components/cbom/sources/CmdbImportDialog.tsx:153-168 — up to 5,000 rows and 2 MB, header row required
  "cbsrc.cmdb.csv": {
    label: "CSV",
    what: "The CSV to import, pasted or uploaded: up to 5,000 rows and 2 MB, with a header row.",
    why: "The header names the columns, so their order does not matter.",
    example: "host,owner,criticality\\napp-01.bank.local,Payments,high.",
  },
  // src: frontend/components/cbom/sources/CmdbImportDialog.tsx:1-4, frontend/components/cbom/sources/CmdbImportDialog.tsx:171-173 — new hosts become Linux server sources
  "cbsrc.cmdb.create": {
    label: "Create sources for new hosts",
    what: "Also create sources for hosts and CIDRs that are not in any source yet. Off: only existing sources are updated.",
    why: "Bringing every CMDB host into scope closes blind spots.",
    example: "On: 14 new hosts become a Linux server source on node-dc1.",
  },
  // src: frontend/components/cbom/sources/CmdbImportDialog.tsx:175-176 — the node that can reach the new hosts
  "cbsrc.cmdb.node": {
    label: "Scan node for new sources",
    what: "The scan node new sources use: it must reach the new hosts.",
    why: "A node that cannot reach them makes every new source fail its test.",
    example: "node-dc1.",
  },
  // src: frontend/components/cbom/sources/CmdbImportDialog.tsx:1-4, frontend/components/cbom/sources/CmdbImportDialog.tsx:134 — admins only; preview, then confirm
  "cbsrc.cmdb.dialog": {
    label: "Import sources and metadata from a CMDB",
    what: "Upload a CSV or pull the ServiceNow CMDB, preview what changes, then confirm. Team admins only.",
    why: "Nothing changes until you confirm the preview.",
    example: "Preview: 12 metadata updates, 1 new source, 2 conflicts.",
  },
  // ────────────────────────────────────────────────────────────── CBOM Sources: Fleet > SSH CA (components/cbom/sources/fleet/SshCaSection.tsx)
  // src: frontend/components/cbom/sources/fleet/SshCaSection.tsx:1-5, frontend/components/cbom/sources/fleet/SshCaSection.tsx:178-181 — short-lived per-job certificates for the node's own key
  "cbsrc.sshca.card": {
    label: "SSH certificate authority",
    what: "ZeroShield signs each scan node's own key into a short-lived certificate for every job (5 minutes by default), with principals zs-<team>-<group>, bound to the node's address and with no forwarding or terminal. Servers trust this CA for the zs-cbom login only; every certificate issued is listed below.",
    why: "Servers trust one CA instead of every node key, and a stolen certificate is useless within minutes.",
    example: "prod-servers-ca, Ed25519, 300-second certificates.",
  },
  // src: frontend/components/cbom/sources/fleet/SshCaSection.tsx:191-192 — up to 64 characters
  "cbsrc.sshca.name": {
    label: "Name",
    what: "A name for the CA, up to 64 characters.",
    why: "Linux sources pick their SSH CA by this name.",
    example: "prod-servers-ca.",
  },
  // src: frontend/components/cbom/sources/fleet/SshCaSection.tsx:194-201 — built in or HashiCorp Vault SSH engine
  "cbsrc.sshca.provider": {
    label: "Where the CA key lives",
    what: "Built in: ZeroShield holds the CA key, encrypted (with AWS KMS when this deployment has a key). Vault: your HashiCorp Vault SSH secrets engine signs and the key never leaves Vault.",
    why: "With Vault, the signing key stays under your own controls and audit.",
    example: "Vault, using the ssh-client-signer mount.",
  },
  // src: frontend/components/cbom/sources/fleet/SshCaSection.tsx:203-205 — 60 to 3,600 seconds; renewed during a job
  "cbsrc.sshca.ttl": {
    label: "Certificate lifetime",
    what: "How long each job certificate is valid, 60 to 3,600 seconds. A job renews its certificate before it runs out.",
    why: "Shorter lifetimes shrink the window in which a copied certificate works.",
    example: "300 seconds.",
  },
  // src: frontend/components/cbom/sources/fleet/SshCaSection.tsx:208-214 — Ed25519 or ECDSA P-256
  "cbsrc.sshca.alg": {
    label: "Key type",
    what: "The CA key's algorithm: Ed25519 (recommended) or ECDSA P-256.",
    why: "Both are widely supported by OpenSSH; neither is quantum-safe, so plan a rotation when post-quantum SSH keys are supported.",
    example: "Ed25519.",
  },
  // src: frontend/components/cbom/sources/fleet/SshCaSection.tsx:217-225 — AWS KMS or the deployment key
  "cbsrc.sshca.wrap": {
    label: "Key encryption",
    what: "How the built-in CA key is encrypted at rest: with AWS KMS when this deployment has a KMS key, otherwise with the deployment key (ENCRYPTION_KEY).",
    why: "KMS keeps the CA key unusable without access to your KMS key.",
    example: "AWS KMS.",
  },
  // src: frontend/components/cbom/sources/fleet/SshCaSection.tsx:228-233 — labels of the allowed KMS keys
  "cbsrc.sshca.kms": {
    label: "KMS key",
    what: "Which of this deployment's allowed AWS KMS keys wraps the CA key.",
    why: "Separate keys per environment limit the reach of one KMS policy.",
    example: "cbom-sshca-prod (default).",
  },
  // src: frontend/components/cbom/sources/fleet/SshCaSection.tsx:238-239 — https, the active node
  "cbsrc.sshca.vault_addr": {
    label: "Vault address",
    what: "The HTTPS address of your Vault's active node.",
    why: "Signing requests go only to this address.",
    example: "https://vault.bank.in:8200.",
  },
  // src: frontend/components/cbom/sources/fleet/SshCaSection.tsx:241-242 — the SSH secrets engine path
  "cbsrc.sshca.vault_mount": {
    label: "SSH engine mount",
    what: "The path where the SSH secrets engine is mounted in Vault.",
    why: "The token below is limited to signing under this mount.",
    example: "ssh-client-signer.",
  },
  // src: frontend/components/cbom/sources/fleet/SshCaSection.tsx:244-245 — allowed_critical_options must include source-address
  "cbsrc.sshca.vault_role": {
    label: "Signing role",
    what: "The Vault SSH role that signs. Its allowed_critical_options must include source-address and its default_extensions must be empty.",
    why: "Without source-address the certificates would work from any machine.",
    example: "zs-cbom-signer.",
  },
  // src: frontend/components/cbom/sources/fleet/SshCaSection.tsx:247-248 — write-only; may only call <mount>/sign/<role>
  "cbsrc.sshca.vault_token": {
    label: "Vault token",
    what: "A Vault token that may only call <mount>/sign/<role>. Write-only: it is never shown again.",
    why: "A token limited to signing cannot read secrets or change the CA.",
    example: "A periodic token with a policy allowing update on ssh-client-signer/sign/zs-cbom-signer.",
  },
  // src: frontend/components/cbom/sources/fleet/SshCaSection.tsx:47-52 — active, rotation, retired, revoked
  "cbsrc.sshca.col.state": {
    label: "State",
    what: "Active (signs), Rotation (trusted, not signing yet), Retired (still trusted during the overlap) or Revoked.",
    why: "Promote a rotation only once every server trusts the new key, or scan logins fail.",
    example: "Rotation: trusted, not signing yet.",
  },
  // src: frontend/components/cbom/sources/fleet/SshCaSection.tsx:285 — algorithm and fingerprint
  "cbsrc.sshca.col.key": {
    label: "Key",
    what: "The CA key's algorithm and SHA-256 fingerprint.",
    why: "Compare the fingerprint with TrustedUserCAKeys on a server to confirm it trusts this CA.",
    example: "ssh-ed25519 SHA256:3f9c...",
  },
  // src: frontend/components/cbom/sources/fleet/SshCaSection.tsx:286 — default certificate lifetime in seconds
  "cbsrc.sshca.col.lifetime": {
    label: "Lifetime",
    what: "The default lifetime of the certificates this CA issues, in seconds.",
    why: "Shorter is safer; jobs renew as needed.",
    example: "300 s.",
  },
  // src: frontend/components/cbom/sources/fleet/SshCaSection.tsx:287-290 — certificates issued by this CA
  "cbsrc.sshca.col.certs": {
    label: "Certificates",
    what: "How many certificates this CA has issued.",
    why: "Each one is listed in the certificate audit below.",
    example: "1,284.",
  },
  // src: frontend/components/cbom/sources/fleet/SshCaSection.tsx:326-327 — lowercase letters, digits, . _ -
  "cbsrc.sshca.group": {
    label: "Server group",
    what: "The server group for the principals file: certificates carry zs-<team>-<group>, and a server accepts only the groups in its file. Lowercase letters, digits, dots, underscores and dashes.",
    why: "Groups let production servers refuse certificates meant for test servers.",
    example: "prod.",
  },
  // src: frontend/components/cbom/sources/fleet/SshCaSection.tsx:340-345 — read trusted keys, KRL and principals only
  "cbsrc.sshca.trust_tokens": {
    label: "Trust tokens",
    what: "A trust token lets your servers or configuration management fetch this team's trusted keys, revocation list and principals, and nothing else. It is shown once.",
    why: "Servers keep their trust files current on their own, so rotations need no manual roll-out.",
    example: "prod-servers, used by 212 servers in the last 24 hours.",
  },
  // src: frontend/components/cbom/sources/fleet/SshCaSection.tsx:351-352 — up to 64 characters
  "cbsrc.sshca.token_name": {
    label: "Token name",
    what: "A name for the trust token, up to 64 characters.",
    why: "Name it after the servers that will use it, so you know what breaks if it is revoked.",
    example: "prod-servers.",
  },
  // src: frontend/components/cbom/sources/fleet/SshCaSection.tsx:361-364 — shown once; keep it root-only
  "cbsrc.sshca.new_token": {
    label: "Copy it now",
    what: "The new trust token is shown only once. Store it in a file only root can read and point ZS_TRUST_TOKEN at it.",
    why: "Anyone with the token can read your trusted keys and revocation list.",
    example: "/etc/zs-cbom/trust-token, mode 0600.",
  },
  // src: frontend/components/cbom/sources/fleet/SshCaSection.tsx:375 — the token's prefix
  "cbsrc.sshca.col.token": {
    label: "Token",
    what: "The first characters of the token, to match it with the file on your servers.",
    why: "The full value is never shown again.",
    example: "zst_4f1c...",
  },
  // src: frontend/components/cbom/sources/fleet/SshCaSection.tsx:376 — servers that fetched in the last 24 hours
  "cbsrc.sshca.col.servers": {
    label: "Servers (24 h)",
    what: "How many servers fetched their trust files with this token in the last 24 hours.",
    why: "During a rotation it shows how many servers already have the new key.",
    example: "212 of your 230 production servers.",
  },
  // src: frontend/components/cbom/sources/fleet/SshCaSection.tsx:377 — last fetch
  "cbsrc.sshca.col.last_used": {
    label: "Last used",
    what: "When a server last fetched with this token.",
    why: "A token unused for weeks may belong to retired servers; revoke it.",
    example: "14 Nov 2026, 02:05 am IST.",
  },
  // src: frontend/components/cbom/sources/fleet/SshCaSection.tsx:378 — active or revoked
  "cbsrc.sshca.col.token_status": {
    label: "Status",
    what: "Whether the token still works: active, or revoked (servers using it get 401 and keep their current files).",
    why: "Revoke a token as soon as it may have leaked.",
    example: "Active.",
  },
  // src: frontend/components/cbom/sources/fleet/SshCaSection.tsx:409 — when the certificate was issued
  "cbsrc.sshca.col.issued": {
    label: "Issued",
    what: "When the certificate was issued.",
    why: "Match it with sshd's log on a server to trace a scan login.",
    example: "14 Nov 2026, 02:00:07 am IST.",
  },
  // src: frontend/components/cbom/sources/fleet/SshCaSection.tsx:410 — serial and CA
  "cbsrc.sshca.col.serial": {
    label: "Serial",
    what: "The certificate's serial number and the CA that issued it.",
    why: "sshd logs the serial, so you can tie each login to a job.",
    example: "88213 · CA #3.",
  },
  // src: frontend/components/cbom/sources/fleet/SshCaSection.tsx:411 — principals in the certificate
  "cbsrc.sshca.col.principals": {
    label: "Principals",
    what: "The principals written into the certificate.",
    why: "A server accepts it only if its principals file lists one of them.",
    example: "zs-12-prod.",
  },
  // src: frontend/components/cbom/sources/fleet/SshCaSection.tsx:412 — source-address restriction
  "cbsrc.sshca.col.from": {
    label: "From",
    what: "The source-address restriction: the only addresses the certificate works from.",
    why: "A certificate copied elsewhere is refused.",
    example: "10.20.1.15/32.",
  },
  // src: frontend/components/cbom/sources/fleet/SshCaSection.tsx:413 — node, job, at claim or renewal
  "cbsrc.sshca.col.node_job": {
    label: "Node / job",
    what: "The scan node and job the certificate was issued for, and whether at the job's claim or as a renewal.",
    why: "Lets you trace every login back to a specific collection job.",
    example: "node #7 · job #4410 · at claim.",
  },
  // src: frontend/components/cbom/sources/fleet/SshCaSection.tsx:414 — valid_before
  "cbsrc.sshca.col.valid_until": {
    label: "Valid until",
    what: "When the certificate stops working.",
    why: "After this time it cannot be used even if copied.",
    example: "14 Nov 2026, 02:05:07 am IST.",
  },
  // src: frontend/components/cbom/sources/fleet/SshCaSection.tsx:53, frontend/components/cbom/sources/fleet/SshCaSection.tsx:415 — valid, expired, revoked
  "cbsrc.sshca.col.cert_status": {
    label: "Status",
    what: "valid, expired or revoked (in the revocation list; servers refuse it once they have the new list).",
    why: "Revoke a certificate if its node may be compromised before it expires.",
    example: "expired.",
  },
  // src: frontend/components/cbom/sources/fleet/SshCaSection.tsx:444-449 — promote before the readiness check passes
  "cbsrc.sshca.promote_now": {
    label: "Promote now",
    what: "Promote the new key now, before the readiness check shows every server has it. Servers that do not trust it yet refuse every scan login.",
    why: "Use only when you know every server already has the new trusted keys.",
    example: "Tick after your Ansible run pushed the new trusted keys everywhere.",
  },
  // src: frontend/components/cbom/sources/fleet/SshCaSection.tsx:456-458 — recorded in the audit, up to 512 characters
  "cbsrc.sshca.reason": {
    label: "Reason",
    what: "Why you are revoking, up to 512 characters. It is recorded in the audit.",
    why: "Auditors and teammates see why a CA, certificate or token was revoked.",
    example: "Node VM snapshot copied to an untrusted host.",
  },
  // ────────────────────────────────────────────────────────────── CBOM Sources: Review & Run, business criticality
  // src: backend/utilities/cbom_sources/posture.py:12-14, backend/utilities/cbom_sources/posture.py:35-39 — impact weight x criticality x exposure
  "cbsrc.rr.criticality": {
    label: "Business criticality and exposure",
    what: "Per source: business criticality (Low x0.5, Medium x1 by default, High x1.5, Critical x2) and internet exposure (from the collected facts, or set; internet-facing x1.5). A finding's risk score is its impact weight times both. Runs snapshot them when they start.",
    why: "Ranks the same weak cipher higher on a critical, internet-facing system than on an internal test box.",
    example: "High finding (7) on a Critical, internet-facing source: 7 x 2 x 1.5 = 21.",
  },
  // ────────────────────────────────────────────────────────────── Settings > Integrations (components/integrations/IntegrationsPage.tsx)
  // src: frontend/components/integrations/IntegrationsPage.tsx:126-127 — one record per finding; resolved when a later complete run no longer finds it
  "int.card.servicenow": {
    label: "ServiceNow",
    what: "Opens one ServiceNow record per new finding (de-duplicated by a correlation id) and resolves it when a later complete run no longer finds it. Also the source for the CMDB import on CBOM Sources.",
    why: "Findings land in the queue your teams already work from, and close themselves when fixed.",
    example: "INC0012345: RSA-1024 certificate on api.bank.in:443, assigned to Payments.",
  },
  // src: frontend/components/integrations/IntegrationsPage.tsx:128 — RFC 5424 with CEF or JSON
  "int.card.syslog": {
    label: "Syslog (SIEM)",
    what: "Sends every event as an RFC 5424 syslog message with a CEF or JSON payload to your SIEM or SOAR.",
    why: "Your SOC sees crypto findings next to other security alerts.",
    example: "A CEF event Finding opened, severity High, to ArcSight on 6514.",
  },
  // src: frontend/components/integrations/IntegrationsPage.tsx:129 — batched JSON events
  "int.card.splunk_hec": {
    label: "Splunk HEC",
    what: "Sends every event to a Splunk HTTP Event Collector, batched as JSON events.",
    why: "Lets you build Splunk dashboards and alerts on crypto findings.",
    example: "sourcetype zeroshield:cbom in index security.",
  },
  // src: frontend/components/integrations/IntegrationsPage.tsx:130 — HMAC-SHA256 over timestamp and body
  "int.card.webhook": {
    label: "Signed webhook",
    what: "POSTs every event as JSON to your receiver, signed with HMAC-SHA256 over the timestamp and the body.",
    why: "Any SOAR or in-house tool can act on events and prove they came from ZeroShield.",
    example: "A Certificate expiring event POSTed to https://soar.bank.in/hooks/zeroshield.",
  },
  // src: frontend/components/integrations/IntegrationsPage.tsx:131 — OSCAL 1.2.3 assessment results, schema-validated, signed
  "int.card.oscal": {
    label: "OSCAL push",
    what: "When a Sources run or a CBOM code scan finishes, pushes its OSCAL 1.2.3 assessment results (schema-validated) to your GRC tool, signed like the webhook.",
    why: "Auditors get machine-readable evidence without exports by hand.",
    example: "Run #42's assessment results pushed to https://grc.bank.in/api/oscal.",
  },
  // src: frontend/components/integrations/IntegrationsPage.tsx:271-273 — on or off per integration
  "int.enabled": {
    label: "Forward events",
    what: "On: events are queued and delivered to this destination. Off: nothing is sent; the settings are kept.",
    why: "Turn it off during a destination's maintenance instead of deleting the integration.",
    example: "Off while the SIEM is being migrated.",
  },
  // src: frontend/components/integrations/IntegrationsPage.tsx:51-54 — PEM; certificates are always verified
  "int.common.ca_pem": {
    label: "CA certificate",
    what: "Optional PEM certificate of the CA that signed the destination's certificate, when it is not publicly trusted. The destination's certificate is always verified.",
    why: "Without it, a destination with an internal CA fails every delivery on the TLS check.",
    example: "bank-root-ca.pem for siem.bank.local.",
  },
  // src: frontend/components/integrations/IntegrationsPage.tsx:57 — https://<instance>.service-now.com
  "int.sn.instance_url": {
    label: "Instance URL",
    what: "Your ServiceNow instance's address.",
    why: "Records are created only on this instance.",
    example: "https://bank.service-now.com.",
  },
  // src: frontend/components/integrations/IntegrationsPage.tsx:58 — incident or sn_vul_vulnerable_item
  "int.sn.table": {
    label: "Table",
    what: "The table records are created in: incident, or sn_vul_vulnerable_item with Vulnerability Response.",
    why: "Use the table your remediation teams work from.",
    example: "sn_vul_vulnerable_item.",
  },
  // src: frontend/components/integrations/IntegrationsPage.tsx:59 — user and password or OAuth client credentials
  "int.sn.auth": {
    label: "Authentication",
    what: "How ZeroShield signs in to ServiceNow: a user and password, or OAuth client credentials.",
    why: "OAuth credentials can be scoped and rotated without a user account.",
    example: "OAuth client credentials for the zeroshield-integration app.",
  },
  // src: frontend/components/integrations/IntegrationsPage.tsx:60 — basic authentication user
  "int.sn.username": {
    label: "User",
    what: "The ServiceNow user for basic authentication, with rights to create and update records in the table.",
    why: "A dedicated integration user makes the records' origin clear in audit history.",
    example: "svc_zeroshield.",
  },
  // src: frontend/components/integrations/IntegrationsPage.tsx:61 — OAuth client credentials
  "int.sn.client_id": {
    label: "OAuth client ID",
    what: "The client ID of the OAuth application registered in ServiceNow.",
    why: "Pairs with the client secret below.",
    example: "3f9c1e2a7b...",
  },
  // src: frontend/components/integrations/IntegrationsPage.tsx:62 — optional
  "int.sn.assignment_group": {
    label: "Assignment group",
    what: "Optional: the group new records are assigned to.",
    why: "Records without a group may sit unassigned.",
    example: "PKI Operations.",
  },
  // src: frontend/components/integrations/IntegrationsPage.tsx:63 — optional
  "int.sn.category": {
    label: "Category",
    what: "Optional: the category set on new records.",
    why: "Lets you filter and report crypto findings in ServiceNow.",
    example: "Security.",
  },
  // src: frontend/components/integrations/IntegrationsPage.tsx:64 — incident: 6 (Resolved)
  "int.sn.resolve_state": {
    label: "Resolved state value",
    what: "The state value set when a finding is no longer found by a later complete run.",
    why: "A wrong value leaves fixed findings open in ServiceNow.",
    example: "6 (Resolved) for incident.",
  },
  // src: frontend/components/integrations/IntegrationsPage.tsx:65 — close code on resolve
  "int.sn.close_code": {
    label: "Resolution code",
    what: "The resolution (close) code set when a record is resolved.",
    why: "Some instances refuse to resolve a record without a close code.",
    example: "Solution provided.",
  },
  // src: frontend/components/integrations/IntegrationsPage.tsx:66-68 — resolving always goes through
  "int.sn.min_severity": {
    label: "Open records from severity",
    what: "The lowest severity that opens a new record. Resolving a record always goes through.",
    why: "Keeps low findings out of the ticket queue while still closing records that exist.",
    example: "High and above.",
  },
  // src: frontend/components/integrations/IntegrationsPage.tsx:69-70 — one record per finding
  "int.sn.correlation_field": {
    label: "Correlation field",
    what: "The field that stores ZeroShield's finding id. Before creating a record, ZeroShield looks it up by this field, so each finding has one record.",
    why: "Prevents duplicates when a finding is seen in every run.",
    example: "correlation_id.",
  },
  // src: frontend/components/integrations/IntegrationsPage.tsx:71 — the table the CMDB import reads
  "int.sn.cmdb_table": {
    label: "CMDB table",
    what: "The CMDB table the CMDB import on CBOM Sources reads.",
    why: "Point it at the class that holds your servers.",
    example: "cmdb_ci_server.",
  },
  // src: frontend/components/integrations/IntegrationsPage.tsx:72 — encoded query, optional
  "int.sn.cmdb_query": {
    label: "CMDB filter",
    what: "Optional: a ServiceNow encoded query that limits which CMDB records are imported.",
    why: "Leaves decommissioned or non-production CIs out.",
    example: "operational_status=1.",
  },
  // src: frontend/components/integrations/IntegrationsPage.tsx:73 — fields tried in order
  "int.sn.cmdb_host": {
    label: "CMDB host fields",
    what: "The CMDB fields that hold the host, tried in order.",
    why: "The first non-empty field becomes the target the import matches or adds.",
    example: "fqdn, ip_address, host_name, name.",
  },
  // src: frontend/components/integrations/IntegrationsPage.tsx:74 — maps to the source owner
  "int.sn.cmdb_owner": {
    label: "CMDB owner field",
    what: "The CMDB field mapped to the source owner.",
    why: "Owners from the CMDB become the remediation owners.",
    example: "owned_by.",
  },
  // src: frontend/components/integrations/IntegrationsPage.tsx:75 — maps to the source application
  "int.sn.cmdb_application": {
    label: "CMDB application field",
    what: "The CMDB field mapped to the source application.",
    why: "Groups findings by the application they affect.",
    example: "u_application.",
  },
  // src: frontend/components/integrations/IntegrationsPage.tsx:76 — maps to the source environment
  "int.sn.cmdb_environment": {
    label: "CMDB environment field",
    what: "The CMDB field mapped to the source environment.",
    why: "Separates production from test in plans and reports.",
    example: "used_for.",
  },
  // src: frontend/components/integrations/IntegrationsPage.tsx:77 — optional; maps to business criticality
  "int.sn.cmdb_criticality": {
    label: "CMDB criticality field",
    what: "Optional: the CMDB field mapped to business criticality (low, medium, high or critical).",
    why: "Criticality scales the risk score of every finding of the source.",
    example: "busines_criticality.",
  },
  // src: frontend/components/integrations/IntegrationsPage.tsx:78 — optional; maps to internet exposure
  "int.sn.cmdb_exposure": {
    label: "CMDB exposure field",
    what: "Optional: the CMDB field mapped to internet exposure.",
    why: "Internet-facing multiplies the risk score by 1.5.",
    example: "u_internet_facing.",
  },
  // src: frontend/components/integrations/IntegrationsPage.tsx:79 — optional
  "int.sn.cmdb_classification": {
    label: "CMDB data classification field",
    what: "Optional: the CMDB field mapped to the data classification (public, internal, confidential, restricted).",
    why: "Sensitive data under weak crypto is migrated first.",
    example: "u_data_classification.",
  },
  // src: frontend/components/integrations/IntegrationsPage.tsx:83 — syslog collector
  "int.sys.host": {
    label: "Collector host",
    what: "The hostname or address of your syslog collector.",
    why: "Every event is sent here.",
    example: "siem.bank.local.",
  },
  // src: frontend/components/integrations/IntegrationsPage.tsx:84-85 — TLS, TCP, UDP
  "int.sys.transport": {
    label: "Transport",
    what: "TLS (RFC 5425, port 6514), TCP with octet counting, or UDP (RFC 5426, no delivery confirmation).",
    why: "Only TLS protects the events in transit; UDP may lose them silently.",
    example: "TLS to siem.bank.local on 6514.",
  },
  // src: frontend/components/integrations/IntegrationsPage.tsx:86 — default 6514 for TLS, 514 for TCP and UDP
  "int.sys.port": {
    label: "Port",
    what: "Optional: the collector's port. Default 6514 for TLS, 514 for TCP and UDP.",
    why: "A wrong port fails the test event.",
    example: "6514.",
  },
  // src: frontend/components/integrations/IntegrationsPage.tsx:87 — CEF or JSON
  "int.sys.format": {
    label: "Message format",
    what: "The payload format: CEF (ArcSight) or JSON.",
    why: "Pick the one your SIEM parses without a custom parser.",
    example: "CEF for ArcSight; JSON for Elastic.",
  },
  // src: frontend/components/integrations/IntegrationsPage.tsx:88 — syslog facility number
  "int.sys.facility": {
    label: "Facility",
    what: "The syslog facility number set on each message; 16 is local0.",
    why: "Lets the collector route ZeroShield events to their own file or index.",
    example: "16 (local0).",
  },
  // src: frontend/components/integrations/IntegrationsPage.tsx:89 — the HOSTNAME field
  "int.sys.sender": {
    label: "Sender name",
    what: "The name put in the HOSTNAME field of each message.",
    why: "Identifies the events as ZeroShield's in the SIEM.",
    example: "zeroshield.",
  },
  // src: frontend/components/integrations/IntegrationsPage.tsx:93 — https
  "int.hec.url": {
    label: "HEC URL",
    what: "The address of your Splunk HTTP Event Collector.",
    why: "Events are posted only here.",
    example: "https://splunk.bank.local:8088.",
  },
  // src: frontend/components/integrations/IntegrationsPage.tsx:94 — optional
  "int.hec.index": {
    label: "Index",
    what: "Optional: the Splunk index to write to. Blank uses the token's default index.",
    why: "Keeps crypto events in the index your SOC searches.",
    example: "security.",
  },
  // src: frontend/components/integrations/IntegrationsPage.tsx:95 — sourcetype of each event
  "int.hec.sourcetype": {
    label: "Sourcetype",
    what: "The sourcetype set on each event.",
    why: "Splunk searches and field extraction key off the sourcetype.",
    example: "zeroshield:cbom.",
  },
  // src: frontend/components/integrations/IntegrationsPage.tsx:96 — source of each event
  "int.hec.source": {
    label: "Source",
    what: "The source set on each event.",
    why: "Tells events from different ZeroShield teams or deployments apart.",
    example: "zeroshield-prod.",
  },
  // src: frontend/components/integrations/IntegrationsPage.tsx:100 — https
  "int.webhook.url": {
    label: "Receiver URL",
    what: "The HTTPS address that receives the signed JSON events.",
    why: "Events are posted only here.",
    example: "https://soar.bank.local/hooks/zeroshield.",
  },
  // src: frontend/components/integrations/IntegrationsPage.tsx:121 — https
  "int.oscal.url": {
    label: "GRC endpoint URL",
    what: "The HTTPS address of your GRC tool's OSCAL endpoint.",
    why: "Assessment results are pushed only here.",
    example: "https://grc.bank.local/api/oscal.",
  },
  // src: frontend/components/integrations/IntegrationsPage.tsx:135, frontend/components/integrations/IntegrationsPage.tsx:307-310 — write-only
  "int.secret.password": {
    label: "Password",
    what: "The ServiceNow user's password. Encrypted at rest and never shown again; changing the URL or user clears it unless you enter it again.",
    why: "Clearing it on change keeps it from going to a host it was not meant for.",
    example: "The svc_zeroshield password.",
  },
  // src: frontend/components/integrations/IntegrationsPage.tsx:135, frontend/components/integrations/IntegrationsPage.tsx:307-310 — write-only
  "int.secret.client_secret": {
    label: "OAuth client secret",
    what: "The OAuth application's client secret. Encrypted at rest and never shown again.",
    why: "With the client ID it obtains tokens to create records.",
    example: "The secret shown when the OAuth app was created.",
  },
  // src: frontend/components/integrations/IntegrationsPage.tsx:136, frontend/components/integrations/IntegrationsPage.tsx:307-310 — write-only
  "int.secret.hec_token": {
    label: "HEC token",
    what: "The Splunk HEC token. Encrypted at rest and never shown again.",
    why: "Anyone with it can write events to your Splunk; scope it to one index.",
    example: "A token created under Data inputs > HTTP Event Collector.",
  },
  // src: frontend/components/integrations/IntegrationsPage.tsx:137, frontend/components/integrations/IntegrationsPage.tsx:307-310 — 16 or more characters; write-only
  "int.secret.signing": {
    label: "Signing secret",
    what: "The shared secret, 16 characters or more, used to sign each request (HMAC-SHA256). Generate creates one; copy it to your receiver before saving, as it is never shown again.",
    why: "Your receiver uses it to reject requests not sent by ZeroShield.",
    example: "A 43-character random value from Generate.",
  },
  // src: frontend/components/integrations/IntegrationsPage.tsx:31-40, frontend/components/integrations/IntegrationsPage.tsx:333-343 — which events are sent
  "int.events": {
    label: "Events",
    what: "Which events this destination receives: finding opened or resolved, asset added or removed, certificate renewed or expiring in 30 days, scheduled run skipped, run or code scan finished.",
    why: "Send only what the destination acts on, to keep noise down.",
    example: "Finding opened and Certificate expiring for the SOC.",
  },
  // src: backend/utilities/integrations/dispatch.py:1-11 — at least once, in order, back-off, dead-letter
  "int.log": {
    label: "Delivery log",
    what: "Every event is delivered at least once, in order per destination, with the same event id on each retry. A failing destination is retried with back-off (30 s doubling to 30 min); events it refuses for good go to the dead-letter list, from where you can retry them.",
    why: "Shows whether your SIEM or ServiceNow actually received each event.",
    example: "Dead-lettered: HTTP 400 from ServiceNow, field u_category not found.",
  },
  // src: frontend/components/integrations/IntegrationsPage.tsx:410-416 — one integration or all
  "int.log.filter_kind": {
    label: "Integration filter",
    what: "Show deliveries of one integration, or of all.",
    why: "Retry all needs one integration chosen.",
    example: "ServiceNow.",
  },
  // src: frontend/components/integrations/IntegrationsPage.tsx:417-423 — pending, delivered, dead-lettered
  "int.log.filter_status": {
    label: "Status filter",
    what: "Show deliveries by status: pending, delivered or dead-lettered.",
    why: "Dead-lettered events were not received and may need a retry.",
    example: "Dead-lettered.",
  },
  // src: frontend/components/integrations/IntegrationsPage.tsx:440 — when the event was queued
  "int.log.col.queued": {
    label: "Queued",
    what: "When the event was queued for this destination.",
    why: "Events are delivered oldest first.",
    example: "14 Nov 2026, 02:31 am IST.",
  },
  // src: frontend/components/integrations/IntegrationsPage.tsx:441 — destination
  "int.log.col.integration": {
    label: "Integration",
    what: "The destination the event is for.",
    why: "Each destination has its own queue.",
    example: "Splunk HEC.",
  },
  // src: frontend/components/integrations/IntegrationsPage.tsx:31-40, frontend/components/integrations/IntegrationsPage.tsx:442 — event type
  "int.log.col.event": {
    label: "Event",
    what: "What happened: finding opened or resolved, asset added or removed, certificate renewed or expiring, scheduled run skipped, run or scan finished.",
    why: "Lets you check a specific finding reached the destination.",
    example: "Finding resolved.",
  },
  // src: frontend/components/integrations/IntegrationsPage.tsx:443 — pending, delivered, dead
  "int.log.col.status": {
    label: "Status",
    what: "Pending (queued or backing off), delivered, or dead-lettered (refused for good, or still undelivered after the maximum age).",
    why: "Dead-lettered events need fixing at the destination, then a retry.",
    example: "Pending: next attempt in 4 minutes.",
  },
  // src: backend/utilities/integrations/dispatch.py:46, frontend/components/integrations/IntegrationsPage.tsx:444 — delivery attempts
  "int.log.col.attempts": {
    label: "Attempts",
    what: "How many times delivery was tried.",
    why: "Many attempts point at a destination that is down or refusing the credentials.",
    example: "3: two timeouts, then delivered.",
  },
  // src: frontend/components/integrations/IntegrationsPage.tsx:445 — last response or error
  "int.log.col.result": {
    label: "Result",
    what: "The destination's last answer or the error.",
    why: "Names the exact cause to fix at the destination.",
    example: "HTTP 401: the HEC token is disabled.",
  },
} as const satisfies Record<string, InfoTipEntry>;

export type InfoTipId = keyof typeof INFO_TIPS;
