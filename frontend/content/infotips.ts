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
 *  - "why": why it matters (the risk or consequence); shown between the text and the example. Required.
 *
 * Components: <InfoTip id="…" /> and <FieldLabel infoId="…"> in components/ui/info-tip.tsx.
 */
export interface InfoTipEntry {
  /** What the (i) button is about; the button is named "About <label>". */
  label: string;
  /** What it is, in plain words, with the real limits, units and behaviour. */
  what: string;
  /** Why it matters: the risk or consequence, one or two sentences. */
  why: string;
  /** One concrete example. */
  example: string;
}

export const INFO_TIPS = {
  // ────────────────────────────────────────────────────────────── shared by the scan list pages (routers/scans.py)
  // src: backend/utilities/db/schemas.py:8-9, backend/routers/scans.py:156-161 — title 1-256 characters; creating stores a NOT_STARTED scan, no credits
  "scan.new.title": {
    label: "Scan title",
    what: "A name for the new scan, 1 to 256 characters, shown in the scan list. Creating the scan uses no credits: you choose what to scan, see the credit estimate and start it on the next page.",
    why: "A clear title is how your team finds this scan again among dozens in the list and in reports.",
    example: "payments-api main, November release.",
  },
  // src: backend/utilities/db/schemas.py:46-47, backend/routers/scans.py:815-845 — rename sets only the title (max 256)
  "scan.rename.title": {
    label: "Scan name",
    what: "The new name of this scan, up to 256 characters. Only the label changes: results, findings and credits stay as they are.",
    why: "Renaming keeps lists and reports readable without rerunning or losing anything.",
    example: "payments-api before the PCI audit.",
  },
  // src: frontend/app/[team_id]/sast/page.tsx:1259 — case-insensitive match on the title, in the loaded list
  "scan.filter.search": {
    label: "Search by title",
    what: "Shows only the scans whose title contains this text (upper or lower case does not matter). It filters the list already loaded in this page.",
    why: "Finds one scan quickly in a long list without scrolling.",
    example: "Typing \"api\" keeps \"payments-API main\" and \"api-gateway\".",
  },
  // src: backend/new_models.py:131, backend/routers/scans.py:599-610, backend/utilities/celery/celery_connection.py:186-192, backend/utilities/scan/cancel_scan.py:1-8 — the scan states and the refunds
  "scan.status": {
    label: "Scan status",
    what: "Not started: created, never run. Pending: queued for a scan worker. Started: running (the bar shows progress). Retry: the worker is retrying it. Success: finished, findings stored. Failure: stopped with an error; its credits were refunded. Cancelled: stopped by a user; its credits were refunded.",
    why: "The status tells you whether results exist yet and whether the credits were kept or refunded.",
    example: "A scan stuck in Pending is waiting for a free worker; it moves to Started when one picks it up.",
  },
  // src: backend/new_models.py:132, frontend/utils/datetime.ts:6-7 — stored in UTC; the text names no time zone because an IST browser reads the API's offset-less UTC time as local time until #48 is fixed
  "scan.table.created": {
    label: "Created at",
    what: "When the scan was created: the date and time it was added to this list, before it was started.",
    why: "Results reflect the code as it was when the scan ran, so the date tells you how current they are.",
    example: "9 Aug 2026, 07:30 pm.",
  },
  // src: backend/utilities/celery/celery_connection.py:182, backend/utilities/celery/celery_connection.py:200-215, frontend/utils/datetime.ts:6-7 — today's behaviour: set on every status poll of a pending or started scan (also without a change) and on every chat message; #47 narrows it to real changes
  "scan.table.updated": {
    label: "Last updated",
    what: "The last time the platform touched this scan: a status or progress change, a status check while it is queued or running (the list checks those each time it loads), or a chat message about its results.",
    why: "Shows which scans are still moving and which have been quiet for a while.",
    example: "A scan queued since yesterday shows today's time once anyone opens the list today.",
  },
  // src: backend/routers/scans.py:475-486, backend/new_models.py:123, backend/utilities/db/scan_list_item.py:72, backend/utilities/celery/celery_connection.py:186-192, backend/utilities/scan/cancel_scan.py:1-8 — credit_consumed is the estimate (set by /estimate before any charge; credit_charged is separate), charged at start, refunded on failure or cancel
  "scan.table.credits": {
    label: "Credits",
    what: "The scan's credit estimate. It is charged when the scan starts and refunded if the scan fails or is cancelled. A scan that was only estimated, and never started, has not been charged.",
    why: "Lets you see what each scan cost against the team balance.",
    example: "12.4 on a finished scan: 12.4 credits left the balance when it started.",
  },
  // src: backend/routers/scans.py:156-159, backend/utilities/db/scan_list_item.py:73-74 — owner_user_id is the user who created the scan
  "scan.table.owner": {
    label: "Owner",
    what: "The team member who created the scan.",
    why: "Tells you whom to ask about a scan's setup or results.",
    example: "Priya Shah, priya@acme.com.",
  },
  // src: backend/routers/scans.py:634-651, backend/routers/scans.py:488-493, backend/utilities/celery/celery_connection.py:186-192, backend/utilities/scan/cancel_scan.py:1-8 — start re-estimates; a changed price answers 409 estimate_changed and charges nothing; failure and cancel refund
  "scan.cfg.run": {
    label: "Run scan",
    what: "Starts the scan and charges the estimated credits. The start prices the scan again first: if the price changed (another file, repository, branch or option), nothing is charged and you see the new price; press Start scan again to accept it. Failed and cancelled scans are refunded.",
    why: "Credits leave the balance at this point, so the price is checked again first.",
    example: "Estimate 3.2 credits, press Start scan: 3.2 credits leave the team balance.",
  },

  // ────────────────────────────────────────────────────────────── repository source (components/repository-card.tsx)
  // src: RabbitMQ/worker/helpers/context/scan_context.py:162-173, RabbitMQ/worker/helpers/context/git_hosts.py:8-14 — a zip or a clone of GitHub/GitLab/Bitbucket
  "repo.source": {
    label: "Repository",
    what: "Where the code comes from: a .zip you upload, or a repository on GitHub, GitLab or Bitbucket that the scan worker clones. Use one of them.",
    why: "The scanner can only analyse code it can reach, so choose where it should fetch it from.",
    example: "Upload payments-api.zip, or connect https://github.com/acme/payments-api.",
  },
  // src: backend/utilities/scan/format_input.py:44-52, RabbitMQ/worker/helpers/context/scan_context.py:175-216, backend/utilities/scan/credit_estimate.py:8-10 — upload capped at 50 MB (413); unpacked at most 2 GB and 50,000 zip entries (folders count); the estimate is bound to the file's size and SHA-256
  "repo.zip": {
    label: "Zip file",
    what: "A .zip of your source code, scanned instead of a repository: at most 50 MB to upload, and it may unpack to at most 2 GB and 50,000 entries (files and folders). The credit estimate is for this exact file: a different file is priced again when the scan starts.",
    why: "Lets you scan code that is not in a hosted repository, within the upload limits.",
    example: "payments-api.zip made with \"git archive --format=zip -o payments-api.zip HEAD\".",
  },
  // src: RabbitMQ/worker/helpers/context/git_hosts.py:8-14, RabbitMQ/worker/helpers/context/scan_context.py:92-139 — https on github.com / gitlab.com / bitbucket.org (or sub-domains), or a host listed in GIT_ALLOWED_HOSTS
  "repo.url": {
    label: "Repository URL",
    what: "The https address of the repository. GitHub, GitLab and Bitbucket (and their sub-domains) are accepted; a self-hosted Git server works only if your administrator listed it in GIT_ALLOWED_HOSTS.",
    why: "The worker clones exactly this address; a typo or unsupported host fails the scan.",
    example: "https://github.com/acme/payments-api.",
  },
  // src: RabbitMQ/worker/helpers/context/scan_context.py:31-49, RabbitMQ/worker/helpers/context/scan_context.py:89 — clone of that branch; default main
  "repo.branch": {
    label: "Branch",
    what: "The branch the scan worker clones and scans. Leave it empty to scan main.",
    why: "Findings describe only the branch scanned, so pick the one that ships.",
    example: "release/2026.11.",
  },
  // src: RabbitMQ/worker/helpers/context/scan_context.py:91-108 — GitHub token optional; a value that looks like a URL is ignored
  "repo.pat.github": {
    label: "GitHub token",
    what: "A personal access token that can read the repository. Optional for public repositories, required for private ones. It is used to clone; paste the token itself, not a URL.",
    why: "Without a token that can read it, a private repository cannot be cloned.",
    example: "A fine-grained token with read-only Contents access to acme/payments-api.",
  },
  // src: RabbitMQ/worker/helpers/context/scan_context.py:110-139 — GitLab (user oauth2) and Bitbucket (user x-token-auth) require a token
  "repo.pat.required": {
    label: "Access token",
    what: "A token that can read the repository; required for GitLab and Bitbucket. The scan worker uses it to clone the repository.",
    why: "GitLab and Bitbucket refuse to clone without it, so the scan would fail.",
    example: "A GitLab project access token with the read_repository scope.",
  },

  // ────────────────────────────────────────────────────────────── SAST: scan configuration (components/sast-options-sidebar.tsx)
  // src: RabbitMQ/worker/helpers/tools/sast_agent/main.py:51-92, RabbitMQ/worker/helpers/context/codebase_context.py:114-141 — today's behaviour: built-in exclusions and your patterns go through the same matcher on the file's full path (#37, #45)
  "sast.cfg.scope": {
    label: "Scan scope",
    what: "Which files are analysed: the files of the chosen language, minus the language's built-in exclusions (such as node_modules, dist and build for JavaScript) and minus the patterns you add below. Exclusions are matched against each file's full path.",
    why: "Files outside the scope are neither analysed nor charged, so it decides both coverage and cost.",
    example: "Add \"tests\" to leave the tests folders out of a Python scan.",
  },
  // src: RabbitMQ/worker/helpers/context/codebase_context.py:114-141, RabbitMQ/worker/helpers/tools/sast_agent/main.py:91-92 — today's behaviour of file_path_matches_pattern: one name matches a path segment starting with it; two names one after the other; a third and later name is dropped; names are regular expressions (#37)
  "sast.cfg.exclude": {
    label: "Exclude path patterns",
    what: "Each pattern is one or two folder or file names, one per box. One name skips every file whose path has a folder or file name starting with it; two names skip paths where they appear one after the other (a third name is ignored). Names are read as regular expressions, so a dot matches any character. Skipped files are not analysed and not charged.",
    why: "Leaving out vendored or generated code cuts noise and credits; leaving out real code hides findings.",
    example: "\"vendor\" skips vendor/ and vendors/; \"src\" / \"legacy\" skips src/legacy.",
  },
  // src: RabbitMQ/worker/helpers/tools/sast_agent/main.py:51-83 — one file extension per language; Ruby's built-in "tmp" exclusion matches the /tmp clone path, so Ruby scans analyse no file until #45 is fixed
  "sast.cfg.language": {
    label: "Primary app language",
    what: "Only files with this language's extension are analysed: Python .py, JavaScript .js, Java .java, PHP .php, C .c, Ruby .rb, Rust .rs, Swift .swift, C# .cs, Kotlin .kt. Other files are ignored. Ruby scans currently analyse no files: Ruby's built-in tmp exclusion matches the folder the repository is cloned into.",
    why: "Only files of the chosen language are read, so the wrong choice analyses nothing useful.",
    example: "For a Node service choose JavaScript; note that .ts and .jsx files are not analysed.",
  },
  // src: RabbitMQ/worker/helpers/tools/sast_agent/main.py:493-494, backend/utilities/scan/estimate_scan.py:210 — 1 credit per 0.5 MB of analysed files + 0.04/0.836, rounded to 0.01
  "sast.cfg.estimate": {
    label: "Estimate scan credits",
    what: "Measures the files in scope and prices the scan: 2 credits per MB of analysed source code, plus about 0.05 credits, rounded to 0.01. Nothing is charged until you start the scan.",
    why: "Shows the price before any credits are charged.",
    example: "3 MB of Python after exclusions: about 6.05 credits.",
  },

  // ────────────────────────────────────────────────────────────── SAST: list page (app/[team_id]/sast/page.tsx)
  // src: backend/utilities/dashboard/scan_list.py:672-673 — status NOT_STARTED
  "sast.kpi.not_started": {
    label: "Not Started",
    what: "SAST scans that were created but never started. They have used no credits.",
    why: "These scans were set up but never run, so they hold no results yet.",
    example: "You created \"payments-api\" but closed the page before estimating: it counts here.",
  },
  // src: backend/utilities/dashboard/scan_list.py:664-665, backend/routers/scans.py:599-610 — status pending: claimed by start, waiting for a worker
  "sast.kpi.pending": {
    label: "Pending",
    what: "SAST scans that were started and are queued, waiting for a scan worker to pick them up.",
    why: "A growing number here means scans are waiting for a free worker.",
    example: "Three scans started together: one runs, two wait here.",
  },
  // src: backend/utilities/dashboard/scan_list.py:666-667, backend/utilities/celery/celery_connection.py:204-208 — status started: a worker is running it
  "sast.kpi.started": {
    label: "Started",
    what: "SAST scans a worker is running now. The table shows each one's progress.",
    why: "Results for these scans are not complete yet.",
    example: "A scan at 40% in the table counts here until it finishes.",
  },
  // src: backend/utilities/dashboard/scan_list.py:668-669, backend/utilities/celery/celery_connection.py:125-133, backend/utilities/dashboard/scan_list.py:690-779 — status success: results stored; findings charts use success only (Scans Per Day, Status and Remediation use every scan)
  "sast.kpi.success": {
    label: "Success",
    what: "SAST scans that finished and stored their findings. Only these feed the findings charts (severity, risk, category, language and top repositories).",
    why: "Only successful scans contribute findings to the charts on this page.",
    example: "A scan that found 0 issues still counts as a success.",
  },
  // src: backend/utilities/dashboard/scan_list.py:670-671, backend/utilities/celery/celery_connection.py:186-192 — status failure; credits refunded once
  "sast.kpi.failure": {
    label: "Failure",
    what: "SAST scans that stopped with an error. Their credits were refunded automatically. Open one to read the reason and run it again.",
    why: "Failed scans have no results; rerun them after fixing the cause.",
    example: "A clone that failed because the token had expired.",
  },
  // src: backend/utilities/dashboard/scan_list.py:674-675 — created_at date equals today's UTC date
  "sast.kpi.created_today": {
    label: "Created today",
    what: "SAST scans created since 00:00 UTC today, in any status.",
    why: "Shows how much scanning activity there has been today.",
    example: "A scan created at 04:00 IST on 11 Nov is 22:30 UTC on 10 Nov, so it counted for 10 Nov.",
  },
  // src: backend/utilities/dashboard/scan_list.py:676-677, backend/utilities/celery/celery_connection.py:200-215 — last_updated date equals today's UTC date; today it also moves on status polls without a change and on chat messages (#47)
  "sast.kpi.updated_today": {
    label: "Updated today",
    what: "SAST scans whose Last updated time is today (since 00:00 UTC). A status change counts, and so do a status check of a queued or running scan and a chat message about its results.",
    why: "Shows which scans had activity today, including ones that are still waiting.",
    example: "A scan queued since yesterday counts here once anyone opens the scan list today.",
  },
  // src: backend/utilities/dashboard/scan_list.py:781-809 — weights 4/3/2/1 over every finding of successful scans, average /4 *10
  "sast.avg_risk": {
    label: "Average Risk Score",
    what: "Severity-weighted average of all findings from successful SAST scans, from 0 to 10. Each finding weighs Critical 4, High 3, Medium 2, Low 1; the average weight is divided by 4 and multiplied by 10. All-Critical gives 10, all-Low 2.5.",
    why: "One number to compare the overall severity of your code over time.",
    example: "1 Critical and 3 Low findings: (4+1+1+1)/4 = 1.75, so 1.75/4 x 10 = 4.4.",
  },
  // src: backend/utilities/dashboard/scan_list.py:690-709, backend/utilities/dashboard/scan_list.py:796-806 — totals per severity over successful scans
  "sast.chart.severity": {
    label: "Risk Severity Distribution",
    what: "How many findings of each severity (Critical, High, Medium, Low) all successful SAST scans found together. The severity is the one the analysis gave each finding.",
    why: "Critical and High findings are the ones to fix first.",
    example: "Critical 4, High 12, Medium 30, Low 9.",
  },
  // src: backend/utilities/dashboard/scan_list.py:735-747, backend/utilities/dashboard/scan_list.py:818-829 — "compliance" is each standard's share of the control references; overall = mean of the top 8 shares
  "sast.chart.policy": {
    label: "Policy Compliance",
    what: "Findings are mapped to controls of standards such as PCI DSS or ISO 27001. Each row counts those references (violations) for one standard and shows its share of all references, top 8. It is not a pass rate. The overall score is the average of the shares shown.",
    why: "Shows which compliance requirements your code findings put at risk.",
    example: "60 references to PCI DSS and 40 to ISO 27001: PCI DSS 60%, ISO 27001 40%, overall 50%.",
  },
  // src: backend/utilities/dashboard/scan_list.py:756-779, backend/utilities/dashboard/scan_list.py:839 — one entry per successful scan, top 5 by its 0-10 score
  "sast.chart.top_repos": {
    label: "Top Repositories by Risk",
    what: "The 5 successful scans with the highest risk score (0 to 10, weighted the same way as the Average Risk Score), with their finding count and language. A repository scanned twice can appear twice.",
    why: "Points you to the repositories that need attention first.",
    example: "payments-api 8.1 with 14 issues, then auth-service 7.5 with 6.",
  },
  // src: backend/utilities/dashboard/scan_list.py:792-793 — every scan, keyed by the UTC date it was created
  "sast.chart.scans_per_day": {
    label: "Scans Per Day",
    what: "How many SAST scans were created on each day (UTC), whatever their status.",
    why: "Shows how regularly your team scans.",
    example: "Five scans created on 10 Nov show a bar of 5.",
  },
  // src: backend/utilities/dashboard/scan_list.py:663-673 — five buckets: pending, started, success, failure, not_started; cancelled and retry scans are in none
  "sast.chart.status": {
    label: "Scan Status Breakdown",
    what: "SAST scans of this team by their current status: Success, Started, Pending, Failure and Not started. Cancelled scans and scans being retried are not shown.",
    why: "A pile of failures or pending scans signals a setup or capacity problem.",
    example: "20 scans: 15 Success, 1 Started, 4 Failure.",
  },
  // src: backend/utilities/dashboard/scan_list.py:690-709 — successful scans' findings by severity, on the scan's creation date
  "sast.chart.risks_over_time": {
    label: "Risks Over Time",
    what: "Findings of successful SAST scans by severity, plotted on the day (UTC) each scan was created.",
    why: "Shows whether the severity of findings is going up or down.",
    example: "A scan created on 3 Nov that found 2 High issues adds 2 to High on 3 Nov.",
  },
  // src: backend/utilities/dashboard/scan_list.py:714-729, backend/utilities/dashboard/scan_list.py:812-815, backend/utilities/dashboard/scan_list.py:31-37 — OWASP Top 10 2021 labels, top 8
  "sast.chart.by_category": {
    label: "Vulnerabilities by Category",
    what: "Findings grouped by OWASP Top 10 (2021) category, the 8 largest. A finding mapped to two categories counts in both.",
    why: "Recurring categories point to a coding pattern worth training on.",
    example: "Injection 12, Broken Access Control 7, Cryptographic Failures 3.",
  },
  // src: backend/utilities/dashboard/scan_list.py:749-753, backend/utilities/dashboard/scan_list.py:832-836 — finding count per configured app language, top 8
  "sast.chart.by_language": {
    label: "Vulnerabilities by Language",
    what: "Findings per application language (the language chosen when each scan was configured), the 8 largest.",
    why: "Shows which code bases carry most of the findings.",
    example: "Python 30, Java 12.",
  },
  // src: backend/utilities/dashboard/scan_list.py:683-688 — distinct repo URLs and zip count of successful scans with results
  "sast.chart.sources": {
    label: "Scan Sources",
    what: "The distinct repository URLs, and the number of zip uploads, among successful SAST scans that returned results.",
    why: "Shows how much of your code estate is being scanned.",
    example: "2 zip uploads and https://github.com/acme/payments-api.",
  },
  // src: backend/utilities/dashboard/remediation_metrics.py:17-90, backend/utilities/db/schemas.py:15-17 — from each finding's status: not_started, in_progress, fixed, ignored
  "sast.remed.section": {
    label: "Remediation Metrics",
    what: "Measured from the status your team sets on each finding (Not started, In progress, Fixed, Ignored) across all SAST scans. The targets are fixed goals shown for comparison.",
    why: "Finding issues matters only if they get fixed; these show whether they do.",
    example: "Mark a finding Fixed in the results page and these numbers update.",
  },
  // src: backend/utilities/dashboard/remediation_metrics.py:43-80, frontend/app/[team_id]/sast/page.tsx:936 — mean of (fixed_at or ignored_at - created_at); target 3 days
  "sast.remed.mttr": {
    label: "Mean Time to Remediate",
    what: "Average time from when a finding was recorded to when it was marked Fixed or Ignored. The target is 3 days.",
    why: "A long time to fix keeps known weaknesses exploitable.",
    example: "One finding fixed after 2 days and one ignored after 4 days: 3.0 days.",
  },
  // src: backend/utilities/dashboard/remediation_metrics.py:47-49, backend/utilities/dashboard/scan_list.py:796-809, frontend/app/[team_id]/sast/page.tsx:960-962 — fixed critical / all critical findings; target 95%
  "sast.remed.critical_fixed": {
    label: "Critical Issues Fixed",
    what: "Critical findings marked Fixed, as a percentage of all Critical findings from successful SAST scans. Ignored findings do not count as fixed. The target is 95%.",
    why: "Critical findings are the most likely to be exploited.",
    example: "8 Critical findings, 6 marked Fixed: 75%.",
  },
  // src: backend/utilities/dashboard/remediation_metrics.py:38-40, frontend/app/[team_id]/sast/page.tsx:984 — critical or high and not fixed/ignored; target 10
  "sast.remed.backlog": {
    label: "High Priority Backlog",
    what: "Critical and High findings that are not yet marked Fixed or Ignored. The target is 10 or fewer.",
    why: "Open Critical and High findings are your current exposure.",
    example: "14 open Critical/High findings: 4 above target.",
  },
  // src: backend/utilities/dashboard/remediation_metrics.py:30, backend/utilities/dashboard/remediation_metrics.py:55-69, frontend/app/[team_id]/sast/page.tsx:1006 — fixed_at/ignored_at date >= today - 7 days (UTC): 8 dates; target 20
  "sast.remed.velocity": {
    label: "Remediation Velocity",
    what: "Findings marked Fixed or Ignored today or on the 7 dates before it (UTC), so over up to 8 calendar days. The target is 20 a week.",
    why: "Shows whether fixes keep up with new findings.",
    example: "On Wednesday 12 Nov: 12 fixed and 3 ignored since Wednesday 5 Nov gives 15/week.",
  },
  // src: frontend/app/[team_id]/sast/page.tsx:1169-1173,1346, backend/utilities/db/scan_list_item.py:38-41 — github/gitlab/bitbucket from repo_type, zip_file when a zip was used
  "sast.filter.type": {
    label: "Scan type",
    what: "Shows only scans of one source: GitHub, GitLab or Bitbucket repositories, or zip uploads.",
    why: "Narrows the list to one code source.",
    example: "Choose Zip file to list only scans of uploaded archives.",
  },
  // src: frontend/app/[team_id]/sast/page.tsx:107-115,1297, frontend/app/[team_id]/sast/page.tsx:98-105,1297 — tiers on the 0-10 per-scan risk score; scans without findings drop out
  "sast.filter.risk": {
    label: "Risk score filter",
    what: "Shows only scans whose risk score (0 to 10) is in a tier: Critical 9 or more, High 7 to 9, Medium 5 to 7, Low under 5. Scans without findings have no score and are hidden by any tier.",
    why: "Focuses the list on the riskiest scans.",
    example: "High keeps a scan scored 7.5 and hides one scored 9.2.",
  },
  // src: frontend/app/[team_id]/sast/page.tsx:1175-1190 — sorts the loaded rows
  "sast.filter.sort": {
    label: "Sort",
    what: "Orders the table by creation date, risk score, coverage or credits, ascending or descending. Scans with no value for the chosen column go last when sorting high to low.",
    why: "Brings the scans you care about to the top.",
    example: "Risk descending puts the riskiest scan first.",
  },
  // src: backend/utilities/db/scan_list_item.py:77 — app_lang from the scan's settings
  "sast.table.language": {
    label: "Language",
    what: "The application language chosen for the scan. It decides which file extension was analysed.",
    why: "Only this language's files were analysed, so other code in the repository was not checked.",
    example: "python: only .py files were analysed.",
  },
  // src: backend/utilities/db/scan_list_item.py:9-26 — counts per impact of a successful scan
  "sast.table.vulns": {
    label: "Vulnerabilities",
    what: "Findings of this scan by severity: Critical (red), High (orange), Medium (amber), Low (blue). Counted only once the scan succeeded.",
    why: "Shows at a glance how serious this scan's findings are.",
    example: "2 red, 5 orange, 1 amber, 0 blue.",
  },
  // src: backend/utilities/db/scan_list_item.py:82, frontend/app/[team_id]/sast/page.tsx:99-105,1465 — per-scan weighted sum / count / 4 * 10
  "sast.table.risk": {
    label: "Risk score",
    what: "This scan's severity-weighted average, 0 to 10: Critical 4, High 3, Medium 2, Low 1, averaged over its findings, divided by 4 and multiplied by 10. Empty when it found nothing.",
    why: "Lets you compare scans by overall severity.",
    example: "2 High and 2 Low findings: (3+3+1+1)/4 = 2, so 5.0.",
  },
  // src: backend/utilities/db/scan_list_item.py:38-41 — repo_type or zip_file
  "sast.table.type": {
    label: "Scan type",
    what: "Where the code came from: GitHub, GitLab, Bitbucket or a zip upload.",
    why: "Tells you where the scanned code came from.",
    example: "GitLab.",
  },
  // src: backend/utilities/db/scan_list_item.py:76, frontend/app/[team_id]/sast/page.tsx:1609-1613,1467 — repo_url from the scan's settings; the SAST list item does not return zip_file_used, so a zip upload shows a dash until #49 is fixed
  "sast.table.source": {
    label: "Repository",
    what: "The repository that was scanned (its last path segment; hover for the full URL). A scan of an uploaded zip file shows a dash.",
    why: "Tells you which code the findings belong to.",
    example: "payments-api for https://github.com/acme/payments-api.",
  },
  // src: backend/utilities/db/scan_list_item.py:39, RabbitMQ/worker/helpers/context/scan_context.py:89 — the branch from the scan's settings (main by default)
  "scan.table.branch": {
    label: "Branch",
    what: "The branch that was cloned and scanned. Empty for zip uploads.",
    why: "Findings apply to this branch only.",
    example: "main.",
  },
  // src: backend/utilities/db/scan_list_item.py:24-31, RabbitMQ/worker/helpers/context/codebase_context.py:210-213 — included / (included + excluded) files with the language's extension
  "sast.table.coverage": {
    label: "Coverage",
    what: "Share of the language's source files that were analysed: analysed files divided by analysed plus excluded files. Exclusions are the language defaults and your patterns.",
    why: "Low coverage means much of the code was not analysed, so a clean result proves less.",
    example: "180 files analysed and 20 excluded: 90.0%.",
  },
  // src: RabbitMQ/worker/scan_worker.py:138-164, backend/utilities/db/scan_list_item.py:43 — start_time is taken before the context check and the clone, end after the analysis
  "sast.detail.duration": {
    label: "Duration",
    what: "How long the scan worker spent on the scan, from start to results, including the clone.",
    why: "Unusually long scans may hit limits; watch for them on large repositories.",
    example: "4m 12s.",
  },
  // src: backend/utilities/db/scan_list_item.py:46-60 — sum of compliance_controls of the critical and high findings listed
  "sast.detail.policy": {
    label: "Policy Violations",
    what: "How many compliance controls (for example PCI DSS or ISO 27001 clauses) the Critical and High findings listed below map to, added up.",
    why: "Shows how many audit requirements this scan's serious findings touch.",
    example: "Two findings mapped to 3 and 2 controls: 5 violations.",
  },
  // src: backend/utilities/db/scan_list_item.py:46-60 — critical and high findings of the scan
  "sast.detail.top": {
    label: "Top vulnerabilities",
    what: "The Critical and High findings of this scan, each with the number of compliance controls it maps to.",
    why: "These are the findings to fix first in this scan.",
    example: "SQL injection in orders.py, 3 policy violations.",
  },

  // ────────────────────────────────────────────────────────────── IaC: scan configuration (components/iac-options-sidebar.tsx)
  // src: RabbitMQ/worker/helpers/tools/iac_agent/main.py:56-88, RabbitMQ/worker/helpers/context/codebase_context.py:56-82, RabbitMQ/worker/helpers/context/codebase_context.py:114-141, RabbitMQ/worker/helpers/context/codebase_context.py:228-233 — no pattern: every file of the formats; patterns and extensions of all formats are merged; one name matches a path segment starting with it, a third and later name is dropped (#37)
  "iac.cfg.include": {
    label: "Include path patterns",
    what: "Only files of this format whose full path matches a pattern are analysed. A pattern is one or two folder or file names, one per box; one name matches any folder or file name starting with it. No pattern means every file of the format, but the patterns of all formats in the scan are combined: next to Terraform, give each other format a pattern.",
    why: "Files that match no pattern are not analysed, so a wrong pattern hides misconfigurations.",
    example: "\"charts\" includes every charts folder; \"deploy\" / \"k8s\" includes deploy/k8s.",
  },

  // ────────────────────────────────────────────────────────────── SCA + SBOM: scan configuration (components/sca-sbom-options-sidebar.tsx)
  // src: RabbitMQ/worker/helpers/tools/sca_sbom_agent/main.py:71-125, RabbitMQ/worker/helpers/tools/sca_sbom_agent/main.py:283-288 — repository or zip: Syft + cdxgen inventory, Grype vulnerabilities
  "sbom.cfg.repository": {
    label: "Analyze Repository",
    what: "Builds the software bill of materials from your code (Syft and cdxgen, merged into CycloneDX) and matches every package against known vulnerabilities with Grype.",
    why: "Builds the list of every dependency you ship, the basis for finding known vulnerabilities.",
    example: "A Node repository: packages come from package-lock.json, CVEs from Grype.",
  },
  // src: RabbitMQ/worker/helpers/tools/sca_sbom_agent/main.py:185-226, RabbitMQ/worker/helpers/tools/sca_sbom_agent/main.py:289-290 — an uploaded JSON SBOM is analysed by the AI summariser instead of building an inventory
  "sbom.cfg.sbom_file": {
    label: "SBOM file",
    what: "An SBOM you already have, as a JSON file. No code is cloned: the file's contents are analysed by the scan's AI model to list vulnerable dependencies. Choosing a file clears the repository or zip.",
    why: "Reuses an SBOM you already produce, so no code has to be cloned.",
    example: "bom.json exported by your build in CycloneDX JSON.",
  },
  // src: RabbitMQ/worker/helpers/tools/sca_sbom_agent/main.py:313-323, backend/utilities/scan/estimate_scan.py:210 — constant 0.01/0.836 credits, rounded to 0.01
  "sbom.cfg.estimate": {
    label: "Estimate scan credits",
    what: "An SCA + SBOM scan has a flat price of about 0.01 credits, whatever the size of the repository or file. Nothing is charged until you start the scan.",
    why: "Shows the price before any credits are charged.",
    example: "Any repository: 0.01 credits.",
  },

  // ────────────────────────────────────────────────────────────── SCA + SBOM: list page (app/[team_id]/sbom_sca/page.tsx)
  // src: backend/utilities/dashboard/scan_list.py:958-960, backend/utilities/dashboard/scan_list.py:1079, RabbitMQ/worker/helpers/tools/sca_sbom_agent/merge_inventory.py:109-122 — len of all result rows of successful scans; each package with no known vulnerability is stored as a Low row (inventory_only) until #46 is fixed
  "sbom.kpi.total": {
    label: "Total Vulnerabilities",
    what: "All result rows of this team's successful SCA + SBOM scans, added up: each known vulnerability, plus each package found with no known vulnerability (stored as a Low row).",
    why: "Dependencies are a common way in for attackers; this sizes the problem.",
    example: "1 vulnerable package and 3 packages with no known vulnerability: 4.",
  },
  // src: backend/utilities/dashboard/scan_list.py:989-998, backend/utilities/dashboard/scan_list.py:1080 — impact critical
  "sbom.kpi.critical": {
    label: "Critical Vulnerabilities",
    what: "Of those, the findings rated Critical.",
    why: "Critical vulnerabilities in dependencies are often exploited soon after disclosure.",
    example: "A remote-code-execution CVE in a direct dependency.",
  },
  // src: backend/utilities/dashboard/scan_list.py:1005-1018, backend/utilities/dashboard/scan_list.py:1081 — number of compliance control references of all findings
  "sbom.kpi.policy": {
    label: "Policy Violations",
    what: "How many compliance-control references (PCI DSS, ISO 27001 and others) the findings map to, added up over all findings.",
    why: "Shows how many audit requirements the dependency findings touch.",
    example: "One finding mapped to 2 controls and one to 3: 5.",
  },
  // src: backend/utilities/dashboard/scan_list.py:975-976, backend/utilities/dashboard/scan_list.py:1074-1082 — medium + high risk license categories over all result rows, packages with no known vulnerability included (#46)
  "sbom.kpi.license_risks": {
    label: "License Risks",
    what: "Result rows of successful scans, vulnerable packages or not, whose license is medium-risk (weak copyleft such as LGPL or MPL, Creative Commons, commercial) or high-risk (strong copyleft such as GPL, network copyleft such as AGPL, source-available such as SSPL or BUSL).",
    why: "Some licenses impose obligations on how you distribute your software.",
    example: "A package under LGPL-3.0 counts here even with no known vulnerability.",
  },
  // src: backend/utilities/dashboard/scan_list.py:975, backend/utilities/dashboard/scan_list.py:1074, backend/utilities/dashboard/sbom_license.py:233-258 — strong copyleft, network copyleft, source-available
  "sbom.kpi.high_risk_licenses": {
    label: "High Risk Licenses",
    what: "Findings whose package is under a strong copyleft (GPL), network copyleft (AGPL) or source-available (SSPL, BUSL) license.",
    why: "Strong copyleft or source-available licenses can force you to publish code or change your product.",
    example: "A package licensed AGPL-3.0.",
  },
  // src: backend/utilities/dashboard/scan_list.py:1019-1021, backend/utilities/dashboard/scan_list.py:1077 — each row scores weight/4*10, averaged, Python round(x, 1); packages with no known vulnerability are Low rows (#46)
  "sbom.kpi.avg_risk": {
    label: "Avg Risk Score",
    what: "Average over all result rows of successful scans, 0 to 10: Critical counts 10, High 7.5, Medium 5, Low 2.5. Packages with no known vulnerability are Low rows, so many of them pull the average towards 2.5. Rounded to one decimal.",
    why: "One number to compare dependency risk over time.",
    example: "1 Critical and 3 packages with no known vulnerability: (10 + 3 × 2.5) / 4 = 4.4.",
  },
  // src: backend/utilities/dashboard/scan_list.py:999-1002, backend/utilities/dashboard/sbom_license.py:382-392, RabbitMQ/worker/helpers/context/schema.py:34, RabbitMQ/worker/helpers/tools/sca_sbom_agent/main.py:137-158, RabbitMQ/worker/helpers/tools/sca_sbom_agent/parser.py:128-155 — reachability is a label the AI model sets from the Grype match text (id, severity, description, package, fix, locations); no source file is in its context
  "sbom.kpi.reachable": {
    label: "Reachable Issues",
    what: "Vulnerabilities the AI model labelled Reachable. It judges from the vulnerability and package data (description, severity, where the package was found); it does not read your code, so treat the label as a hint.",
    why: "A vulnerability your code actually reaches is far more urgent than one it never calls.",
    example: "A CVE in a web framework's request parser may be labelled Reachable although your code never uses that parser.",
  },
  // src: backend/utilities/dashboard/scan_list.py:1030-1037, backend/utilities/dashboard/finding_metrics.py:18-40 — stored findings by status
  "sbom.chart.remediation": {
    label: "Remediation Actions Required",
    what: "All stored findings of SCA + SBOM scans by the status your team set: Fixed, In progress, Not started, Ignored.",
    why: "Shows how far the team has got with fixing dependency findings.",
    example: "40 findings: 10 Fixed, 5 In progress, 22 Not started, 3 Ignored.",
  },
  // src: backend/utilities/dashboard/scan_list.py:988-998, backend/utilities/dashboard/scan_list.py:1038-1043 — totals per impact over all result rows; Low includes packages with no known vulnerability (#46)
  "sbom.chart.severity": {
    label: "Severity Distribution",
    what: "Result rows of successful scans by severity: Critical, High, Medium and Low. Low also counts every package found with no known vulnerability.",
    why: "Critical and High rows are the ones to look at first.",
    example: "Critical 2, High 9, Medium 15, Low 310 in a repository with about 300 packages.",
  },
  // src: backend/utilities/dashboard/scan_list.py:1044-1056, backend/utilities/dashboard/sbom_license.py:382-392, RabbitMQ/worker/helpers/context/schema.py:34 — the AI model's label (no code in its context); missing counts as Not assessed; packages with no known vulnerability are stored Not reachable (#46)
  "sbom.chart.reachability": {
    label: "Reachability Distribution",
    what: "Result rows by the reachability label the AI model gave each one from the vulnerability and package data (it does not read your code): Reachable, Potentially reachable, Not reachable, or Not assessed. Not reachable also counts packages with no known vulnerability.",
    why: "Helps you prioritise reachable vulnerabilities over unreachable ones.",
    example: "A CVE in a package found only in a test lock file is often labelled Not reachable.",
  },
  // src: backend/utilities/dashboard/scan_list.py:986, backend/utilities/dashboard/scan_list.py:1024-1028 — per creation date (UTC) of each successful scan; Low includes packages with no known vulnerability (#46)
  "sbom.chart.trends": {
    label: "Vulnerability Trends Over Time",
    what: "Result rows of successful scans by severity, on the day (UTC) each scan was created. Low also counts packages with no known vulnerability.",
    why: "Shows whether dependency risk is growing or shrinking.",
    example: "Scans created on 5 Nov found 3 High in total: High shows 3 on 5 Nov.",
  },
  // src: backend/utilities/dashboard/scan_list.py:1003-1004, backend/utilities/dashboard/scan_list.py:1058, backend/utilities/dashboard/sbom_license.py:20-30 — license family of each finding's package
  "sbom.chart.licenses": {
    label: "Licenses Distribution",
    what: "Findings grouped by the license family of their package: permissive, public domain, weak copyleft, Creative Commons, commercial, strong copyleft, network copyleft, source-available, or not declared.",
    why: "Shows whether license obligations are concentrated in a few families.",
    example: "MIT and Apache-2.0 are permissive; GPL-3.0 is strong copyleft.",
  },
  // src: backend/utilities/dashboard/scan_list.py:1060-1072, frontend/app/[team_id]/sbom_sca/page.tsx:448 — sorted by impact, first 20 shown
  "sbom.chart.top": {
    label: "Top Vulnerabilities by Risk Score",
    what: "The 20 most severe findings (Critical first), each with its reachability, direct or transitive dependency type, and license family.",
    why: "These are the dependency issues to fix first.",
    example: "lodash 4.17.15, reachable, direct, permissive, Critical.",
  },
  // src: backend/utilities/dashboard/scan_list.py:1022-1023, backend/utilities/dashboard/scan_list.py:1087-1097 — per level: average of weight/4*10
  "sbom.chart.risk_by_reach": {
    label: "Average Risk Score per Reachability",
    what: "The average risk score (0 to 10: Critical 10, High 7.5, Medium 5, Low 2.5) of the findings at each reachability level.",
    why: "Shows whether your riskiest vulnerabilities are also reachable.",
    example: "Reachable 8.8 means the reachable findings are mostly Critical or High.",
  },
  // src: backend/utilities/dashboard/scan_list.py:1005-1018, backend/utilities/dashboard/scan_list.py:1099-1105 — references per standard: PCI DSS, ISO 27001-27004
  "sbom.chart.policy": {
    label: "Policy Compliance Data",
    what: "How many compliance-control references the findings have per standard (PCI DSS, ISO 27001, 27002, 27003, 27004), and each standard's share of them.",
    why: "Shows which standards your dependency findings affect most.",
    example: "PCI DSS 12 of 20 references: 60%.",
  },
  // src: backend/utilities/db/scan_list_item.py:157-166 — counts per impact of a successful scan's result rows; packages with no known vulnerability are Low rows (#46)
  "sbom.table.vulns": {
    label: "Vulnerabilities",
    what: "This scan's result rows by severity once it succeeded: Critical (red), High (orange), Medium (amber), Low (blue). Blue also counts every package found with no known vulnerability.",
    why: "Shows at a glance how serious this scan's results are.",
    example: "0 red, 3 orange, 6 amber, 280 blue for a repository with about 280 packages.",
  },
  // src: backend/utilities/db/scan_list_item.py:176-178, frontend/app/[team_id]/sbom_sca/page.tsx:113-116,927 — today's scale: weights 4/3/2/1 averaged over result rows, 0 without rows (#35, #46)
  "sbom.table.risk": {
    label: "Risk score",
    what: "This scan's severity-weighted average on a 1 to 4 scale: Critical 4, High 3, Medium 2, Low 1, averaged over its result rows (packages with no known vulnerability count as Low). 0 when the scan has no rows or did not succeed.",
    why: "Lets you compare scans by overall severity.",
    example: "1 High and 1 Low: (3 + 1) / 2 = 2.",
  },
  // src: backend/utilities/db/scan_list_item.py:95-117, backend/utilities/db/scan_list_item.py:384-417, frontend/app/[team_id]/iac/page.tsx:123-126,959, frontend/app/[team_id]/dast/page.tsx:115-118,870 — today's scale for IaC and DAST: weights 4/3/2/1 averaged over findings, 0 without findings (#35)
  "scan.table.risk": {
    label: "Risk score",
    what: "This scan's severity-weighted average on a 1 to 4 scale: Critical 4, High 3, Medium 2, Low 1, averaged over its findings. 0 when it found nothing or did not succeed.",
    why: "Lets you compare scans by overall severity.",
    example: "1 High and 1 Low finding: (3 + 1) / 2 = 2.",
  },
  // src: frontend/app/[team_id]/sbom_sca/page.tsx:118-125,818, frontend/app/[team_id]/iac/page.tsx:128-135,838, frontend/app/[team_id]/dast/page.tsx:120-127,766, frontend/app/[team_id]/ai_bom/page.tsx:114-121,719, frontend/app/[team_id]/llm/page.tsx:123-130,760, frontend/app/[team_id]/cbom/page.tsx:120-127,928 — tiers on the Risk score column; the column is 1-4 for SCA + SBOM, IaC and DAST today (#35), 0-10 for AI BOM, LLM and CBOM; a null score matches no tier
  "scan.filter.risk": {
    label: "Risk score filter",
    what: "Shows only scans whose Risk score is in a tier: Critical 9 or more, High 7 to 9, Medium 5 to 7, Low under 5. Where this table's score runs from 1 to 4 (SCA + SBOM, IaC, DAST), every scored scan is in Low. A scan without a score (shown as a dash) is hidden by any tier.",
    why: "Focuses the list on the riskiest scans.",
    example: "On the LLM list, High keeps a scan scored 7.5 and hides one scored 9.2.",
  },
  // src: frontend/app/[team_id]/sbom_sca/page.tsx:699-712, frontend/app/[team_id]/iac/page.tsx:719-732, frontend/app/[team_id]/dast/page.tsx:637-650, frontend/app/[team_id]/ai_bom/page.tsx:601-614, frontend/app/[team_id]/llm/page.tsx:568-581, frontend/app/[team_id]/cbom/page.tsx:668-681,971 — sorts the loaded rows; missing values count as -1
  "scan.filter.sort": {
    label: "Sort",
    what: "Orders the table by creation date, risk score or credits, high or low first. Scans with no value for the chosen column go last when sorting high first.",
    why: "Brings the scans you care about to the top.",
    example: "Credits (high first) puts the most expensive scan on top.",
  },
  // src: backend/utilities/db/scan_list_item.py:184-186 — repo_url, or zip upload, or SBOM file
  "sbom.table.source": {
    label: "Repository",
    what: "The repository that was scanned (hover for the full URL), or Zip file for an uploaded archive. Empty for an uploaded SBOM file.",
    why: "Tells you which code or file the results belong to.",
    example: "payments-api.",
  },

  // ────────────────────────────────────────────────────────────── IaC: scan configuration (components/iac-options-sidebar.tsx)
  // src: backend/utilities/dashboard/scan_list.py:541-557, backend/utilities/db/scan_list_item.py:148 — stored as a label; the worker does not read it
  "iac.cfg.environment": {
    label: "Environment",
    what: "Which environment this infrastructure code is for: Development, Staging or Production. It is a label for your dashboards (the environment filter and heatmap); it does not change what the scan checks.",
    why: "Lets you tell production findings from test ones in lists and charts.",
    example: "Production for the Terraform that deploys your live VPC.",
  },
  // src: RabbitMQ/worker/helpers/tools/iac_agent/main.py:56-82 — one mode per context; each mode reads its file types
  "iac.cfg.contexts": {
    label: "IaC contexts",
    what: "The kinds of infrastructure code in the repository, one context each. Each kind reads its own files: Terraform .tf/.tfvars/.tfstate/.tf.json, Kubernetes and Helm .yaml/.yml, Ansible .yml/.yaml/.ini, CloudFormation .yaml/.yml/.json, Pulumi and CDK their program files.",
    why: "Each format is read only if it has a context, so a missing one is a blind spot.",
    example: "A repository with Terraform and Helm charts: add both contexts.",
  },
  // src: RabbitMQ/worker/helpers/tools/iac_agent/main.py:56-88, RabbitMQ/worker/helpers/context/codebase_context.py:228-233 — the format decides the extensions; Terraform adds its own .tf patterns; the other formats' include patterns narrow their files (merged across formats: see iac.cfg.include)
  "iac.cfg.context_type": {
    label: "Context type",
    what: "The infrastructure format of this context; it decides which file extensions are read. Terraform needs no pattern: its files are found by extension anywhere. For the other formats, the include patterns below narrow which files are read.",
    why: "The format decides which files are read.",
    example: "Kubernetes, with the include pattern \"k8s\".",
  },
  // src: RabbitMQ/worker/helpers/tools/iac_agent/main.py:207-227, backend/utilities/scan/estimate_scan.py:210 — 1 credit per 0.5 MB of matched files, rounded to 0.01
  "iac.cfg.estimate": {
    label: "Estimate scan credits",
    what: "Measures the infrastructure files the contexts match and prices the scan at 2 credits per MB, rounded to 0.01. Nothing is charged until you start the scan.",
    why: "Shows the price before any credits are charged.",
    example: "400 KB of Terraform: about 0.78 credits.",
  },

  // ────────────────────────────────────────────────────────────── IaC: list page (app/[team_id]/iac/page.tsx)
  // src: backend/utilities/dashboard/scan_list.py:575 — successful IaC scans
  "iac.kpi.total_scans": {
    label: "Total scans",
    what: "IaC scans of this team that finished successfully.",
    why: "Shows how much of your infrastructure code has been checked.",
    example: "12 scans run, 2 failed: 10.",
  },
  // src: backend/utilities/dashboard/scan_list.py:456-480, backend/utilities/dashboard/scan_list.py:576 — findings of successful scans
  "iac.kpi.total_issues": {
    label: "Total issues",
    what: "Misconfigurations found by all successful IaC scans, added up.",
    why: "Sizes the misconfiguration backlog.",
    example: "An S3 bucket without encryption is one issue.",
  },
  // src: backend/utilities/dashboard/scan_list.py:466-478, backend/utilities/dashboard/scan_list.py:577 — impact critical
  "iac.kpi.critical": {
    label: "Total critical",
    what: "Of those, the issues rated Critical.",
    why: "Critical misconfigurations, such as public storage, are the first to fix.",
    example: "A security group open to 0.0.0.0/0 on SSH.",
  },
  // src: backend/utilities/dashboard/scan_list.py:564-569, backend/utilities/dashboard/remediation_metrics.py:43-80 — mean of fixed/ignored time minus creation, in days
  "iac.kpi.mttr": {
    label: "Avg MTTR (days)",
    what: "Mean time to remediate: the average time, in days, from when an issue was recorded to when it was marked Fixed or Ignored.",
    why: "A long time to fix leaves misconfigurations deployed.",
    example: "One issue fixed after 1 day and one after 3 days: 2.0.",
  },
  // src: backend/utilities/dashboard/scan_list.py:509-518, backend/utilities/dashboard/scan_list.py:570 — per scan included / (included + excluded) files, averaged
  "iac.kpi.coverage": {
    label: "Coverage %",
    what: "For each successful scan, the share of candidate files that were analysed (analysed divided by analysed plus excluded), averaged over the scans.",
    why: "Low coverage means some infrastructure files were not checked.",
    example: "Two scans with 100% and 80%: 90.0%.",
  },
  // src: backend/utilities/dashboard/scan_list.py:493-507, backend/utilities/dashboard/scan_list.py:580 — compliance-control references with a standard
  "iac.kpi.policy": {
    label: "Policy violations",
    what: "How many compliance-control references (PCI DSS, ISO 27001 and others) the issues map to, added up.",
    why: "Shows how many audit requirements the misconfigurations touch.",
    example: "One issue mapped to 2 controls: 2.",
  },
  // src: backend/utilities/dashboard/scan_list.py:520-526, backend/utilities/dashboard/scan_list.py:571 — 0-10, weights 4/3/2/1, averaged over issues
  "iac.kpi.avg_risk": {
    label: "Avg risk score",
    what: "Severity-weighted average of all issues of successful scans, from 0 to 10: Critical 4, High 3, Medium 2, Low 1, the average weight divided by 4 and multiplied by 10.",
    why: "One number to compare infrastructure risk over time.",
    example: "Half Critical, half Low: (4+1)/2 = 2.5, so 6.3.",
  },
  // src: backend/utilities/dashboard/scan_list.py:466-478, backend/utilities/dashboard/scan_list.py:584-589 — totals per impact
  "iac.chart.severity": {
    label: "Severity Distribution",
    what: "Issues of successful IaC scans by severity: Critical, High, Medium and Low.",
    why: "Critical and High issues are the ones to fix first.",
    example: "Critical 1, High 6, Medium 10, Low 3.",
  },
  // src: backend/utilities/dashboard/scan_list.py:464, backend/utilities/dashboard/scan_list.py:482-486 — per creation date (UTC)
  "iac.chart.over_time": {
    label: "Issues Over Time",
    what: "Issues of successful scans by severity, on the day (UTC) each scan was created.",
    why: "Shows whether misconfigurations are growing or shrinking.",
    example: "A scan created on 4 Nov with 3 High issues adds 3 to High on 4 Nov.",
  },
  // src: backend/utilities/dashboard/scan_list.py:488-491, backend/utilities/dashboard/scan_list.py:593-606 — issues per category; the six categories always shown
  "iac.chart.posture": {
    label: "Security Posture Overview",
    what: "Issues per security category: Network Security, Data Protection, Access Control, Logging and Monitoring, Secret Management, Audit and Compliance (and any other category found).",
    why: "Shows which security areas have the most problems.",
    example: "Network Security 7 means seven issues about firewalls, ports or routing.",
  },
  // src: backend/utilities/dashboard/scan_list.py:615-622, backend/utilities/dashboard/finding_metrics.py:18-40 — stored findings by status
  "iac.chart.pipeline": {
    label: "Remediation Pipeline",
    what: "Issues by the status your team set on them: Fixed, In progress, Not started, Ignored, each as a share of all issues found.",
    why: "Shows how far the team has got with fixing issues.",
    example: "20 issues, 5 marked Fixed: Fixed 25%.",
  },
  // src: backend/utilities/dashboard/scan_list.py:493-507, backend/utilities/dashboard/scan_list.py:609, frontend/app/[team_id]/iac/page.tsx:469 — references per standard, share of all references
  "iac.chart.compliance": {
    label: "Compliance Framework Violations",
    what: "How many compliance-control references the issues have per standard, and that standard's share of all references. It is not a pass rate.",
    why: "Shows which standards your infrastructure issues affect most.",
    example: "PCI DSS 6 of 10 references: 60.0%.",
  },
  // src: backend/utilities/dashboard/scan_list.py:541-562 — successful scans with results counted per (environment, IaC type)
  "iac.chart.heatmap": {
    label: "Environment × Cloud Resource Heatmap",
    what: "How many successful scans covered each IaC type (rows) in each environment (columns). The environment is the one chosen when the scan was configured.",
    why: "Shows which environments and formats are scanned, and which are not.",
    example: "Kubernetes × production = 3: three production scans had a Kubernetes context.",
  },
  // src: backend/utilities/dashboard/finding_metrics.py:89-125, backend/utilities/dashboard/scan_list.py:624-625 — per resolution date, average time to fix or ignore
  "iac.chart.mttr_per_day": {
    label: "MTTR Per Day",
    what: "For each day (UTC), the average time to remediate of the issues marked Fixed or Ignored that day, in days.",
    why: "Shows whether fixes are getting faster or slower.",
    example: "Two issues fixed on 6 Nov after 1 and 2 days: 1.5 on 6 Nov.",
  },
  // src: backend/utilities/dashboard/scan_list.py:528-539 — one count per scan and IaC type, not per resource
  "iac.chart.providers": {
    label: "Resources by Provider",
    what: "How many successful scans included each IaC type (Terraform, Kubernetes, Helm, …). It counts scans per type, not individual cloud resources.",
    why: "Shows which infrastructure formats your scans cover.",
    example: "Terraform 8, Kubernetes 3.",
  },
  // src: frontend/app/[team_id]/iac/page.tsx:715-718,874, backend/utilities/db/scan_list_item.py:148 — matches the scan's environment label
  "iac.filter.environment": {
    label: "Environment filter",
    what: "Shows only scans configured for one environment: Development, Staging or Production.",
    why: "Separates production results from development and staging.",
    example: "Production lists only scans labelled Production.",
  },
  // src: backend/utilities/db/scan_list_item.py:142-143 — repo_url, or zip upload (IaC; the same fields for CBOM and AI BOM)
  "scan.table.source": {
    label: "Repository",
    what: "The repository that was scanned (its last path segment; hover for the full URL), or Zip file for an uploaded archive.",
    why: "Tells you which code the results belong to.",
    example: "infra-live for https://github.com/acme/infra-live.",
  },
  // src: backend/utilities/db/scan_list_item.py:145 — the IaC context types of the scan
  "iac.table.provider": {
    label: "Cloud provider",
    what: "The IaC types this scan read (its contexts), such as Terraform or Kubernetes.",
    why: "Tells you which infrastructure formats this scan covered.",
    example: "terraform, helm.",
  },
  // src: backend/utilities/db/scan_list_item.py:148 — environment label from the scan's settings
  "iac.table.environment": {
    label: "Environment",
    what: "The environment chosen when the scan was configured. It is a label only.",
    why: "Tells you which environment the results apply to.",
    example: "staging.",
  },
  // src: backend/utilities/db/scan_list_item.py:94-109 — counts per impact of a successful scan
  "iac.table.vulns": {
    label: "Vulnerabilities",
    what: "This scan's issues by severity: Critical (red), High (orange), Medium (amber), Low (blue). Counted once the scan succeeded.",
    why: "Shows at a glance how serious this scan's issues are.",
    example: "1 red, 2 orange, 4 amber, 0 blue.",
  },

  // ────────────────────────────────────────────────────────────── DAST: scan configuration (components/dast-options-sidebar.tsx)
  // src: backend/utilities/dast/ssrf.py:1-12, backend/utilities/dast/ssrf.py:79-82 — http/https; scope = the target's host; private/metadata addresses refused unless the operator allows them
  "dast.cfg.target_url": {
    label: "Target URL",
    what: "The web application to test, starting with http:// or https://. Its host is the scan's scope: the login URL and additional URLs must be on the same host. Hosts that resolve to private, loopback or cloud-metadata addresses are refused unless your administrator allowed them.",
    why: "The scan only tests this host, so the URL sets both what is tested and what is left alone.",
    example: "https://staging.shop.example.com.",
  },
  // src: RabbitMQ/dast_worker/helpers/agent/scan_config.py:17-75 — URL workers 10 / 5 / 2 and longer timeouts when slower
  "dast.cfg.speed": {
    label: "Scan speed",
    what: "How hard the scan pushes the target. Fast tests 10 URLs at a time with short timeouts, Medium 5, Slow 2 with the longest timeouts (gentlest on a fragile server). Your administrator can change the worker counts.",
    why: "Faster scans finish sooner but load your application more.",
    example: "Slow for a small staging server that falls over under load.",
  },
  // src: RabbitMQ/dast_worker/helpers/crawler/crawler.py:48-50, RabbitMQ/dast_worker/helpers/agent/main.py:373 — the crawler stops at max_urls; credits 0.08 per URL
  "dast.cfg.max_urls": {
    label: "Max URLs",
    what: "The most pages the crawler collects from the target before testing. Each URL tested costs 0.08 credits, so this also caps the price (additional URLs come on top).",
    why: "It caps both what is tested and the most the scan can cost.",
    example: "100 URLs: at most 8 credits.",
  },
  // src: RabbitMQ/dast_worker/helpers/agent/main.py:72-73, RabbitMQ/dast_worker/helpers/checks/nuclei/basic_templates.py:11-37 — all five fields required; a headless browser signs in with them
  "dast.cfg.auth": {
    label: "Authentication",
    what: "How the scanner signs in: a headless browser opens the login URL, types the username and password into the fields found by their XPaths and clicks the submit button. All fields are required, so the pages behind the login are tested too.",
    why: "Most vulnerabilities hide behind the login; without it only public pages are tested.",
    example: "Login URL https://shop.example.com/login with a test account.",
  },
  // src: backend/utilities/dast/ssrf.py:79-82, RabbitMQ/dast_worker/helpers/checks/nuclei/basic_templates.py:11-21 — opened first; must be on the target's host
  "dast.cfg.login_url": {
    label: "Login URL",
    what: "The page with the sign-in form. It must be on the same host as the target URL.",
    why: "The scanner signs in here; a wrong page means it tests only public pages.",
    example: "https://shop.example.com/login.",
  },
  // src: RabbitMQ/dast_worker/helpers/checks/nuclei/construct_temp.py:10-27, RabbitMQ/dast_worker/helpers/checks/nuclei/basic_templates.py:21-31 — XPath of the input clicked and typed into
  "dast.cfg.xpath_user": {
    label: "Username field XPath",
    what: "An XPath that finds the username (or email) input on the login page. In the browser: right-click the field, Inspect, then Copy > Copy XPath.",
    why: "Without the right field the sign-in fails and logged-in pages go untested.",
    example: "//input[@name='email'].",
  },
  // src: RabbitMQ/dast_worker/helpers/checks/nuclei/construct_temp.py:10-27, RabbitMQ/dast_worker/helpers/checks/nuclei/basic_templates.py:31-37 — XPath of the password input
  "dast.cfg.xpath_pass": {
    label: "Password field XPath",
    what: "An XPath that finds the password input on the login page.",
    why: "Without the right field the sign-in fails and logged-in pages go untested.",
    example: "//input[@type='password'].",
  },
  // src: RabbitMQ/dast_worker/helpers/checks/nuclei/construct_temp.py:10-27 — XPath of the button clicked to submit
  "dast.cfg.xpath_submit": {
    label: "Submit button XPath",
    what: "An XPath that finds the button the scanner clicks to sign in.",
    why: "Without the right button the sign-in never completes.",
    example: "//button[@type='submit'].",
  },
  // src: RabbitMQ/dast_worker/helpers/agent/context.py:4-10, backend/utilities/scan/format_input.py:165-181 — sent to the worker for the sign-in; redacted from the scan's stored settings
  "dast.cfg.username": {
    label: "Username",
    what: "The account the scanner signs in with. Use a test account: the scan submits forms and tries attacks while signed in.",
    why: "The scan acts as this user, so a test account keeps real data safe.",
    example: "dast-test@shop.example.com.",
  },
  // src: RabbitMQ/dast_worker/helpers/agent/context.py:4-10, backend/utilities/scan/credit_estimate.py:29-30 — sent to the worker; never part of the stored estimate digest
  "dast.cfg.password": {
    label: "Password",
    what: "The password of that test account. It is sent to the scan worker for the sign-in and is not shown again.",
    why: "Needed to sign in; use a test account's password, never a real user's.",
    example: "The password of dast-test@shop.example.com.",
  },
  // src: RabbitMQ/dast_worker/helpers/crawler/crawler.py:60-63, backend/utilities/dast/ssrf.py:79-82 — always added to the crawl; must be on the target's host
  "dast.cfg.additional_urls": {
    label: "Additional URLs to scan",
    what: "Pages to test even if the crawler does not find them (they are added to the crawl). They must be on the target's host. Each one costs 0.08 credits like any other URL.",
    why: "Pages no link leads to are otherwise never tested.",
    example: "https://shop.example.com/admin/reports (linked from nowhere).",
  },
  // src: RabbitMQ/dast_worker/helpers/crawler/crawler.py:51-56, RabbitMQ/dast_worker/helpers/crawler/crawler.py:108-123 — include or exclude, not both; * matches anything, searched anywhere in the URL
  "dast.cfg.url_patterns": {
    label: "URL patterns",
    what: "Either Include (test only crawled URLs that match) or Exclude (skip URLs that match), not both. In a pattern * matches anything, and the pattern may match any part of the URL. Additional URLs are always tested.",
    why: "Keeps the scan away from pages such as logout or delete, or focuses it on one area.",
    example: "Exclude https://shop.example.com/logout* so the scan does not sign itself out.",
  },
  // src: RabbitMQ/dast_worker/helpers/agent/main.py:350-375, backend/utilities/scan/estimate_scan.py:193 — the estimate crawls the target now; 0.08 credits per URL found
  "dast.cfg.estimate": {
    label: "Estimate scan credits",
    what: "Crawls the target now (real requests to your site) to count the URLs the scan would test, and prices them at 0.08 credits each. Nothing is charged until you start the scan.",
    why: "Shows the price before any credits are charged; the crawl sends real requests to your site.",
    example: "The crawl finds 60 URLs: 4.8 credits.",
  },

  // ────────────────────────────────────────────────────────────── DAST: automatic profiles (components/dast/DastProfilesTab.tsx, DastScheduleFields.tsx)
  // src: backend/utilities/dast/schemas.py:40-56, backend/utilities/dast/dispatch.py:115-121 — profile title; each run is titled "<title> (<trigger>)"
  "dast.profile.title": {
    label: "Profile title",
    what: "A name for this saved DAST setup. Each run it starts appears in the scan list as \"<title> (<how it started>)\".",
    why: "Lets you tell runs of different profiles apart in the scan list.",
    example: "Shop staging nightly.",
  },
  // src: backend/routers/dast_profiles.py:112-155, backend/routers/dast_profiles.py:253-274, backend/utilities/dast/beat.py:71, backend/routers/cicd.py:99, backend/utilities/dast/dispatch.py:84-121 — saved settings run by schedule, Run now or CI; each run is a new scan charged up front
  "dast.profile.form": {
    label: "DAST profile",
    what: "Saved DAST settings (target, sign-in, limits, schedule) that can run without you: on its schedule, with Run now, or from your CI pipeline. Each run becomes a new scan in the list and is charged Max URLs x 0.08 credits when it starts.",
    why: "Saved settings let scans repeat without you, for regular coverage.",
    example: "A profile for staging that runs every night at 02:00 IST.",
  },
  // src: backend/routers/dast_profiles.py:253-274, backend/utilities/dast/dispatch.py:89-90, backend/utilities/dast/schedule.py:1 — Run now; skipped while a run is in flight; next run in IST
  "dast.profile.list": {
    label: "Saved profiles",
    what: "Your team's DAST profiles with their schedule, next run (IST) and last scan. Run now starts a new scan at once; a run is skipped while the profile's previous run is still in progress.",
    why: "Shows what runs automatically, and when.",
    example: "\"Shop staging · daily 02:00 IST · next 12 Nov 2026, 02:00 am IST\".",
  },
  // src: frontend/components/dast/DastScheduleFields.tsx:190-216, backend/utilities/dast/schemas.py:37 — the five selects write the cron expression
  "dast.profile.cron_builder": {
    label: "Visual cron builder",
    what: "Pick minute, hour, day, month and weekday from lists; the builder writes the matching cron expression below. Every means any value.",
    why: "Builds a valid schedule without writing cron syntax by hand.",
    example: "Minute 0, Hour 9, Weekday Monday gives 0 9 * * 1.",
  },
  // src: backend/utilities/dast/schemas.py:46, backend/utilities/dast/credits.py:4-6, backend/utilities/dast/dispatch.py:103 — 1-10,000; every run is charged max_urls x 0.08 up front
  "dast.profile.max_urls": {
    label: "Max URLs",
    what: "The most pages a run crawls and tests, from 1 to 10,000. An automatic run is charged Max URLs x 0.08 credits when it starts (no estimate crawl), whatever it then finds.",
    why: "It caps both how much each run tests and what each run costs.",
    example: "200 URLs: each run costs 16 credits.",
  },
  // src: backend/utilities/dast/dispatch.py:84-88, backend/utilities/dast/schemas.py:55 — runs refused without consent
  "dast.profile.consent": {
    label: "Authorization",
    what: "Confirms you are allowed to attack-test this target. A DAST scan sends real attack payloads; without this confirmation the profile cannot be saved or run.",
    why: "Attack-testing a site you are not allowed to test can be illegal and disrupt its owner.",
    example: "Tick it for your own staging site, never for a third-party site.",
  },
  // src: backend/utilities/dast/schedule.py:1-24, backend/utilities/dast/dispatch.py:89-90 — next_run_at computed in Asia/Kolkata; a run in flight makes the next one skip
  "dast.profile.schedule": {
    label: "Schedule",
    what: "When the profile runs by itself: off, hourly, every N hours, daily, weekdays, weekly, monthly, once, or a cron expression. Times are India Standard Time. A run is skipped if the previous one is still in progress.",
    why: "Regular runs catch new vulnerabilities soon after each release.",
    example: "Weekdays at 02:00 IST.",
  },
  // src: backend/utilities/dast/schemas.py:33, backend/utilities/dast/schedule.py:1 — 1 to 24 hours
  "dast.profile.interval": {
    label: "Every N hours",
    what: "Hours between runs, from 1 to 24 (IST clock).",
    why: "Shorter intervals catch changes sooner but cost more credits.",
    example: "6 runs four times a day.",
  },
  // src: backend/utilities/dast/schemas.py:34, backend/utilities/dast/schedule.py:1 — 0-6 weekday
  "dast.profile.weekday": {
    label: "Weekday",
    what: "The day of the week a weekly schedule runs on (IST).",
    why: "Pick a quiet day so the scan does not load the site at peak hours.",
    example: "Sunday.",
  },
  // src: backend/utilities/dast/schemas.py:35 — 1 to 28, so every month has the day
  "dast.profile.monthday": {
    label: "Day of month",
    what: "The day a monthly schedule runs on, from 1 to 28 so that every month has it (IST).",
    why: "Align it with your release or patch cycle.",
    example: "1 runs on the first of each month.",
  },
  // src: backend/utilities/dast/schemas.py:36, backend/utilities/dast/schedule.py:1 — a single run at that IST time
  "dast.profile.once_at": {
    label: "Run at",
    what: "The date and time (IST) of a single run.",
    why: "Lets you schedule one test, for example after a release, without staying online.",
    example: "15 Nov 2026, 23:00.",
  },
  // src: backend/utilities/dast/schemas.py:32, backend/utilities/dast/schedule.py:26-34 — HH:MM, clamped to 00:00-23:59
  "dast.profile.times": {
    label: "Fire times",
    what: "The times of day (24-hour HH:MM, IST) the schedule runs. You can add several.",
    why: "Choose hours when test traffic will not disturb users.",
    example: "02:00 and 14:00.",
  },
  // src: backend/utilities/dast/schemas.py:37, backend/utilities/dast/schedule.py:1 — 5-field cron evaluated in IST, 0 = Sunday
  "dast.profile.cron": {
    label: "Cron expression",
    what: "A 5-field cron expression (minute, hour, day of month, month, day of week) evaluated in IST, with 0 = Sunday. The builder above fills it for you.",
    why: "Gives full control over complex schedules.",
    example: "0 9 * * 1-5 runs at 09:00 IST Monday to Friday.",
  },

  // ────────────────────────────────────────────────────────────── DAST: list page (app/[team_id]/dast/page.tsx)
  // src: backend/utilities/dashboard/scan_list.py:216, backend/utilities/dashboard/scan_list.py:291 — successful DAST scans
  "dast.kpi.total_scans": {
    label: "Total scans",
    what: "DAST scans of this team that finished successfully, manual and automatic.",
    why: "Shows how often your web applications are tested.",
    example: "A nightly profile that ran 7 times adds 7.",
  },
  // src: backend/utilities/dashboard/scan_list.py:251-256, backend/utilities/dashboard/scan_list.py:284-295 — stored findings of DAST scans by impact
  "dast.kpi.severity": {
    label: "Findings by severity",
    what: "Findings of all DAST scans with this severity (Critical, High, Medium or Low), counted from the stored findings. A finding without a severity counts as Low.",
    why: "Critical and High findings in a live application are the most urgent.",
    example: "Total high 4: four High findings across all runs.",
  },
  // src: backend/utilities/dashboard/scan_list.py:104, backend/utilities/dashboard/scan_list.py:257-259, backend/utilities/dashboard/scan_list.py:288 — 10 / 7.5 / 5 / 2.5 per finding, averaged
  "dast.kpi.avg_risk": {
    label: "Avg risk score",
    what: "Average over all DAST findings, 0 to 10: each Critical counts 10, High 7.5, Medium 5, Low 2.5.",
    why: "One number to compare web-application risk over time.",
    example: "One High and one Low: (7.5 + 2.5) / 2 = 5.0.",
  },
  // src: backend/utilities/dashboard/scan_list.py:251-256, backend/utilities/dashboard/scan_list.py:299 — totals per impact
  "dast.chart.severity": {
    label: "Severity Distribution",
    what: "All DAST findings by severity: Critical, High, Medium, Low.",
    why: "Critical and High findings are the ones to fix first.",
    example: "Critical 0, High 4, Medium 9, Low 12.",
  },
  // src: backend/utilities/dashboard/scan_list.py:234-248 — successful scans' findings on the scan's creation date (UTC)
  "dast.chart.over_time": {
    label: "Issues Over Time",
    what: "Findings of successful DAST scans by severity, on the day (UTC) each scan was created.",
    why: "Shows whether your applications are getting safer.",
    example: "A nightly run on 7 Nov with 2 Medium findings adds 2 to Medium on 7 Nov.",
  },
  // src: backend/utilities/dashboard/scan_list.py:88-101, backend/utilities/dashboard/scan_list.py:271-273, backend/utilities/dashboard/scan_list.py:301 — 12 categories
  "dast.chart.posture": {
    label: "Security Posture Overview",
    what: "Findings in 12 web-security categories: injection, XSS and client side, authentication, authorization, session and state, file and resource, server-side execution, information disclosure, crypto and transport, security headers, API security, denial of service.",
    why: "Shows which web-security areas have the most problems.",
    example: "Security headers 8: eight findings about missing or weak headers.",
  },
  // src: backend/utilities/dashboard/scan_list.py:69-80, backend/utilities/dashboard/scan_list.py:266-269, backend/utilities/dashboard/scan_list.py:302 — the ten OWASP 2021 keys
  "dast.chart.owasp": {
    label: "OWASP Top 10",
    what: "Findings per OWASP Top 10 (2021) category, A01 to A10. A finding mapped to two categories counts in both.",
    why: "Lets you report findings in the framework most teams and auditors use.",
    example: "A03 Injection 3, A05 Security Misconfiguration 6.",
  },
  // src: backend/utilities/dashboard/scan_list.py:81-87, backend/utilities/dashboard/scan_list.py:274-276, backend/utilities/dashboard/scan_list.py:303-306 — five categories, mean of 10/7.5/5/2.5
  "dast.chart.risk_by_category": {
    label: "Average Risk Score per Category",
    what: "The average risk score (Critical 10, High 7.5, Medium 5, Low 2.5) of the findings in five categories: injection, XSS and client side, authentication, authorization, session and state.",
    why: "Shows which kind of weakness carries the most risk.",
    example: "Injection 8.8: the injection findings are mostly Critical or High.",
  },
  // src: backend/utilities/dashboard/scan_list.py:103, backend/utilities/dashboard/scan_list.py:278-282, backend/utilities/dashboard/scan_list.py:307-310 — by the scanner's confidence; missing counts as low
  "dast.chart.risk_by_confidence": {
    label: "Average Risk Score per Confidence",
    what: "The average risk score of findings grouped by how sure the scanner is that each one is real: high, medium or low confidence (unknown counts as low).",
    why: "High-confidence findings are the least likely to be false positives.",
    example: "High confidence 7.5: the certain findings are mostly High.",
  },
  // src: backend/utilities/dashboard/scan_list.py:102, backend/utilities/dashboard/scan_list.py:261-264, backend/utilities/dashboard/scan_list.py:311 — references to PCI DSS, ISO 27001-27004
  "dast.chart.compliance": {
    label: "Compliance Violations",
    what: "How many compliance-control references the findings have for PCI DSS and ISO 27001, 27002, 27003 and 27004.",
    why: "Shows which audit requirements your web findings touch.",
    example: "PCI DSS 5: findings map to five PCI DSS controls in total.",
  },
  // src: backend/utilities/db/scan_list_item.py:386-395 — counts per impact of a successful scan
  "dast.table.vulns": {
    label: "Vulnerabilities",
    what: "This scan's findings by severity: Critical (red), High (orange), Medium (amber), Low (blue). Counted once the scan succeeded.",
    why: "Shows at a glance how serious this scan's findings are.",
    example: "0 red, 1 orange, 3 amber, 5 blue.",
  },
  // src: backend/utilities/db/scan_list_item.py:440 — target_url from the settings of the scan
  "dast.table.target": {
    label: "Target URL",
    what: "The site this scan tested.",
    why: "Tells you which site the findings belong to.",
    example: "https://staging.shop.example.com.",
  },
  // src: backend/utilities/db/scan_list_item.py:392-402, RabbitMQ/dast_worker/helpers/crawler/crawler.py:40-71 — URLs the crawler kept for testing
  "dast.table.urls": {
    label: "URLs scanned",
    what: "How many URLs the scan tested: the pages the crawler kept after your patterns, plus the additional URLs.",
    why: "Few URLs tested means much of the site was not covered.",
    example: "48 URLs tested.",
  },
  // src: backend/utilities/db/scan_list_item.py:432, RabbitMQ/dast_worker/helpers/crawler/crawler.py:79-106 — tested / (tested + dropped by the patterns)
  "dast.table.coverage": {
    label: "Coverage %",
    what: "Tested URLs as a share of all crawled URLs, after your include or exclude patterns dropped some. 100% when no pattern removed anything.",
    why: "Low coverage means your patterns or limits left crawled pages untested.",
    example: "45 tested, 5 excluded by a pattern: 90.0%.",
  },

  // ────────────────────────────────────────────────────────────── AI BOM: scan configuration (components/ai-bom-options-sidebar.tsx)
  // src: RabbitMQ/worker/helpers/tools/ai_bom_agent/main.py:391-394, RabbitMQ/worker/helpers/tools/ai_bom_agent/main.py:426-447 — repository: model and source files; AI BOM file: AI summariser
  "aibom.cfg.repository": {
    label: "Analyze Repository",
    what: "Finds the AI in your code: model files, embedding models, Hugging Face models, AI SDKs and external AI providers, datasets, and their licenses, and builds a CycloneDX AI bill of materials.",
    why: "You cannot govern AI you do not know you use; this finds it in the code.",
    example: "A service that imports the OpenAI SDK and loads a local .onnx model.",
  },
  // src: RabbitMQ/worker/helpers/tools/ai_bom_agent/main.py:122-150 — an existing AI-BOM JSON analysed by the AI model (map-reduce)
  "aibom.cfg.file": {
    label: "AI BOM file",
    what: "An AI bill of materials you already have, as a JSON file. No code is cloned: the file's contents are analysed by the scan's AI model to list risks. Choosing a file clears the repository or zip.",
    why: "Reuses an AI BOM you already produce, so no code has to be cloned.",
    example: "aibom.cdx.json exported from another tool.",
  },
  // src: RabbitMQ/worker/helpers/tools/ai_bom_agent/main.py:426-447, backend/utilities/scan/estimate_scan.py:210 — 2 credits per MB of model/source files + ~0.05; a file is ~0.01
  "aibom.cfg.estimate": {
    label: "Estimate scan credits",
    what: "A repository or zip costs 2 credits per MB of model and source files plus about 0.05; an uploaded AI BOM file about 0.01. Rounded to 0.01. Nothing is charged until you start the scan.",
    why: "Shows the price before any credits are charged.",
    example: "4 MB of Python and model files: about 8.05 credits.",
  },

  // ────────────────────────────────────────────────────────────── AI BOM: list page (app/[team_id]/ai_bom/page.tsx)
  // src: backend/utilities/dashboard/scan_list.py:1853-1860 — detections of successful scans
  "aibom.kpi.assets": {
    label: "AI Assets",
    what: "Every AI component detection in successful AI BOM scans: models, datasets, AI libraries and external AI providers, added up across scans.",
    why: "Sizes your AI footprint, the starting point for AI governance.",
    example: "The OpenAI SDK found in 4 files counts 4 here.",
  },
  // src: backend/utilities/dashboard/scan_list.py:1821, backend/utilities/dashboard/scan_list.py:1884-1886, backend/utilities/dashboard/scan_list.py:1956 — distinct (provider, name) of model components
  "aibom.kpi.models": {
    label: "Models",
    what: "Distinct models (local model files, Hugging Face models, embedding models), counted once per provider and name across all scans.",
    why: "Each model is something to license, document and monitor.",
    example: "bert-base-uncased found in two repositories counts 1.",
  },
  // src: backend/utilities/dashboard/scan_list.py:1890-1892, backend/utilities/dashboard/scan_list.py:1957 — distinct dataset names
  "aibom.kpi.datasets": {
    label: "Datasets",
    what: "Distinct datasets the code loads, counted once per name.",
    why: "Datasets carry privacy and licensing obligations.",
    example: "squad loaded by two notebooks counts 1.",
  },
  // src: backend/utilities/dashboard/scan_list.py:1887-1889, backend/utilities/dashboard/scan_list.py:1958 — distinct providers of external_provider detections
  "aibom.kpi.providers": {
    label: "External Providers",
    what: "Distinct external AI services your code calls, such as OpenAI or Anthropic, counted once each.",
    why: "Each external AI provider receives your data and is a third-party risk.",
    example: "OpenAI used in 4 files and Anthropic in 1: 2.",
  },
  // src: backend/utilities/dashboard/scan_list.py:1894-1896 — impact critical or high
  "aibom.kpi.high_risk": {
    label: "High Risk",
    what: "AI asset detections rated Critical or High.",
    why: "These AI components need review first.",
    example: "A model downloaded without a pinned revision, rated High.",
  },
  // src: backend/utilities/dashboard/scan_list.py:1898-1904, backend/utilities/dashboard/aibom_license.py:83-92 — libraries without a usable license
  "aibom.kpi.unlicensed": {
    label: "Unlicensed",
    what: "AI libraries with no usable open-source license declared. Models and external providers are not counted here.",
    why: "Using code without a clear license is a legal risk.",
    example: "An internal AI package with no license field.",
  },
  // src: backend/utilities/dashboard/scan_list.py:1906-1910, backend/utilities/dashboard/scan_list.py:1960-1963 — assets with a declared license and a model card / total
  "aibom.kpi.governance": {
    label: "Governance Readiness",
    what: "Share of AI asset detections that have both a declared license and a model card: the documentation an AI governance review asks for.",
    why: "Regulations such as the EU AI Act expect licenses and model documentation.",
    example: "10 assets, 4 with license and model card: 40%.",
  },
  // src: backend/utilities/dashboard/scan_list.py:1965-1971 — 0-10, weights 4/3/2/1
  "aibom.kpi.avg_risk": {
    label: "Avg Risk Score",
    what: "Severity-weighted average of all AI asset findings, 0 to 10: Critical 4, High 3, Medium 2, Low 1, the average weight divided by 4 and multiplied by 10.",
    why: "One number to compare AI risk over time.",
    example: "2 High and 2 Low: (3+3+1+1)/4 = 2, so 5.0.",
  },
  // src: backend/utilities/dashboard/scan_list.py:1979-2018, backend/utilities/dashboard/finding_metrics.py:18-40 — stored findings of successful scans by status
  "aibom.chart.remediation": {
    label: "Remediation Actions Required",
    what: "Stored findings of successful AI BOM scans by the status your team set: Fixed, In progress, Not started, Ignored.",
    why: "Shows how far the team has got with AI findings.",
    example: "12 findings: 3 Fixed, 9 Not started.",
  },
  // src: backend/utilities/dashboard/scan_list.py:1862-1866 — impact per detection
  "aibom.chart.severity": {
    label: "Severity Distribution",
    what: "AI asset detections by severity: Critical, High, Medium, Low.",
    why: "Critical and High detections are the ones to review first.",
    example: "High 3, Medium 7, Low 20.",
  },
  // src: backend/utilities/dashboard/scan_list.py:1868-1869 — component_type per detection
  "aibom.chart.asset_type": {
    label: "Asset Type Distribution",
    what: "Detections by kind of AI component: local model file, Hugging Face model, embedding model, dataset, AI library, external provider and others.",
    why: "Shows what kind of AI your code depends on most.",
    example: "external_provider 5, huggingface_model 2.",
  },
  // src: backend/utilities/dashboard/scan_list.py:1871-1872 — resolved provider per detection
  "aibom.chart.provider": {
    label: "Provider Distribution",
    what: "Detections by the AI vendor or source behind them, such as openai, anthropic or huggingface.",
    why: "Shows which vendors your AI use depends on.",
    example: "openai 6, huggingface 3.",
  },
  // src: backend/utilities/dashboard/scan_list.py:1874-1875 — resolved license per detection
  "aibom.chart.license": {
    label: "License Distribution",
    what: "Detections by license, as declared or resolved for each component (for example MIT, Apache-2.0, a proprietary API's terms, or not declared).",
    why: "Shows the license obligations attached to your AI components.",
    example: "Apache-2.0 8, NOASSERTION 3.",
  },
  // src: backend/utilities/dashboard/scan_list.py:1930-1936, backend/utilities/dashboard/scan_list.py:1973-1977 — the 10 most severe detections
  "aibom.chart.top_risks": {
    label: "Top AI Risks",
    what: "The 10 most severe AI asset detections (Critical first), with their type, provider, license and impact.",
    why: "These are the AI components to review first.",
    example: "gpt-4o · external_provider · openai · proprietary · High.",
  },
  // src: backend/utilities/db/scan_list_item.py:489-510 — counts per impact of a successful scan
  "aibom.table.risks": {
    label: "Risks",
    what: "This scan's AI asset findings by severity: Critical (red), High (orange), Medium (amber), Low (blue). Counted once the scan succeeded.",
    why: "Shows at a glance how serious this scan's findings are.",
    example: "0 red, 2 orange, 5 amber, 11 blue.",
  },
  // src: backend/utilities/db/scan_list_item.py:526-529 — weighted 4/3/2/1 average, /4 *10
  "aibom.table.risk": {
    label: "Risk score",
    what: "This scan's severity-weighted average, 0 to 10: Critical 4, High 3, Medium 2, Low 1, averaged over its findings, divided by 4 and multiplied by 10.",
    why: "Lets you compare scans by overall severity.",
    example: "1 High and 1 Low: (3+1)/2 = 2, so 5.0.",
  },

  // ────────────────────────────────────────────────────────────── MCP: scan configuration (components/mcp-options-sidebar.tsx)
  // src: backend/utilities/db/schemas.py:159-169, RabbitMQ/worker/helpers/tools/mcp_agent/context.py:5-9 — the MCP server endpoint the worker connects to
  "mcp.cfg.server_url": {
    label: "MCP server URL",
    what: "The address of the MCP (Model Context Protocol) server to test. The scan connects to it, lists its tools, prompts and resources, and checks each one for risks such as prompt injection or dangerous capabilities.",
    why: "The scan tests only this server, so the address sets what is checked.",
    example: "https://mcp.example.com/mcp.",
  },
  // src: backend/utilities/db/schemas.py:161, RabbitMQ/worker/helpers/tools/mcp_agent/context.py:7 — httpstreamable or sse
  "mcp.cfg.server_mode": {
    label: "Server mode",
    what: "The transport the server speaks: Streamable HTTP (the current MCP standard) or SSE (Server-Sent Events, the older one). Pick what the server documents.",
    why: "The wrong transport means the scan cannot talk to the server.",
    example: "Streamable HTTP for a server whose endpoint ends in /mcp.",
  },
  // src: backend/utilities/db/schemas.py:163, backend/utilities/dashboard/scan_list.py:1326-1329 — a label used by the Environment Risk Analysis chart
  "mcp.cfg.environment": {
    label: "Environment",
    what: "Which environment the server belongs to: Development, Staging or Production. A label for the dashboard's Environment Risk Analysis; it does not change the tests.",
    why: "Lets you tell production servers from test ones in charts.",
    example: "Production for the server your agents use live.",
  },
  // src: backend/utilities/db/schemas.py:162, RabbitMQ/worker/helpers/tools/mcp_agent/context.py:8-9 — JSON object of HTTP headers sent with every request
  "mcp.cfg.headers": {
    label: "Headers (JSON)",
    what: "Extra HTTP headers sent with every request to the server, as a JSON object, typically for authentication.",
    why: "Servers that require authentication refuse the scan without them.",
    example: "{\"Authorization\": \"Bearer <token>\"}.",
  },
  // src: RabbitMQ/worker/helpers/tools/mcp_agent/main.py:253-285, backend/utilities/scan/estimate_scan.py:210 — connects now; 0.005 credits per tool, prompt and resource
  "mcp.cfg.estimate": {
    label: "Estimate scan credits",
    what: "Connects to the server now, lists its tools, prompts and resources, and prices each at 0.005 credits, rounded to 0.01. Nothing is charged until you start the scan.",
    why: "Shows the price before any credits are charged; it connects to the server now.",
    example: "40 tools, 4 prompts, 6 resources: 0.25 credits.",
  },

  // ────────────────────────────────────────────────────────────── MCP: list page (app/[team_id]/mcp/page.tsx)
  // src: backend/utilities/dashboard/scan_list.py:1371 — every MCP scan in any status
  "mcp.kpi.total_scans": {
    label: "Total Scans",
    what: "All MCP scans of this team, in any status.",
    why: "Shows how much MCP testing your team has done.",
    example: "8 scans: 6 succeeded, 1 running, 1 failed.",
  },
  // src: backend/utilities/dashboard/scan_list.py:1320-1325, backend/utilities/dashboard/scan_list.py:1372 — critical findings of all scans
  "mcp.kpi.critical": {
    label: "Critical Issues",
    what: "Findings rated Critical across the tools, prompts and resources of all MCP scans.",
    why: "Critical MCP issues can let an AI agent act beyond its intended reach.",
    example: "A tool that runs shell commands from model input.",
  },
  // src: backend/utilities/dashboard/scan_list.py:1346-1349, backend/utilities/dashboard/scan_list.py:1368 — each finding weight/4*10, averaged
  "mcp.kpi.avg_risk": {
    label: "Avg Risk Score",
    what: "Average over all MCP findings, 0 to 10: Critical counts 10, High 7.5, Medium 5, Low 2.5.",
    why: "One number to compare MCP risk over time.",
    example: "One Critical and one Medium: 7.5.",
  },
  // src: backend/utilities/dashboard/scan_list.py:1293-1294, backend/utilities/dashboard/scan_list.py:1369 — status started
  "mcp.kpi.active": {
    label: "Active Scans",
    what: "MCP scans a worker is running now.",
    why: "Results for these scans are not complete yet.",
    example: "2 while two servers are being tested.",
  },
  // src: backend/utilities/dashboard/scan_list.py:1243-1248, backend/utilities/dashboard/scan_list.py:1375 — findings marked fixed in the last 7 x 24 h
  "mcp.kpi.resolved": {
    label: "Resolved (7d)",
    what: "MCP findings marked Fixed in the last 7 days (the last 168 hours). Ignored findings are not counted.",
    why: "Shows whether the team is fixing what scans find.",
    example: "5 findings fixed this week.",
  },
  // src: backend/utilities/dashboard/scan_list.py:1291-1300 — started / success / failure; everything else (incl. pending) counts as not started
  "mcp.chart.status": {
    label: "Scan Status Distribution",
    what: "MCP scans by status: Started, Success, Failure, and Not started (which also counts queued and cancelled scans).",
    why: "Failures or stuck scans point to connection or setup problems.",
    example: "6 Success, 1 Started, 1 Failure.",
  },
  // src: backend/utilities/dashboard/scan_list.py:1348-1351, backend/routers/scans.py:88 — per server: average of weight/4*10; scans come newest first, so the earliest scan's value is kept
  "mcp.chart.risk_trend": {
    label: "Risk Score Trend",
    what: "For each MCP server, the average risk score (0 to 10: Critical 10, High 7.5, Medium 5, Low 2.5) of its scan's findings. A server scanned several times shows one value, from its earliest scan (the list is read newest first and later rows overwrite).",
    why: "Shows which servers are getting riskier.",
    example: "mcp.example.com 6.3.",
  },
  // src: backend/utilities/dashboard/scan_list.py:1352-1356 — findings by severity on the scan's creation date (UTC)
  "mcp.chart.risks_over_time": {
    label: "Risks Over Time",
    what: "MCP findings by severity, on the day (UTC) each scan was created.",
    why: "Shows whether MCP risk is growing or shrinking.",
    example: "A scan created on 9 Nov with 3 High findings adds 3 to High on 9 Nov.",
  },
  // src: backend/utilities/dashboard/scan_list.py:1307-1325 — totals per impact
  "mcp.chart.severity": {
    label: "Severity Distribution",
    what: "All MCP findings by severity: Critical, High, Medium, Low.",
    why: "Critical and High findings are the ones to fix first.",
    example: "Critical 1, High 5, Medium 9, Low 2.",
  },
  // src: backend/utilities/dashboard/scan_list.py:1326-1329 — findings counted by the scan's environment label
  "mcp.chart.environment": {
    label: "Environment Risk Analysis",
    what: "How many findings come from servers labelled Development, Staging or Production (the environment chosen when each scan was configured).",
    why: "Production findings matter most because real users and data are involved.",
    example: "Production 7 means seven findings on production servers.",
  },
  // src: backend/utilities/dashboard/scan_list.py:1330-1345 — compliance-control references per standard
  "mcp.chart.compliance": {
    label: "Compliance Framework Distribution",
    what: "How many compliance-control references the MCP findings have per standard.",
    why: "Shows which standards your MCP findings touch.",
    example: "ISO 27001 9, PCI DSS 3.",
  },
  // src: backend/utilities/dashboard/scan_list.py:1378, backend/utilities/dashboard/finding_metrics.py:18-40 — stored findings by status
  "mcp.chart.remediation": {
    label: "Remediation Status",
    what: "MCP findings by the status your team set: Not started, In progress, Fixed, Ignored.",
    why: "Shows how far the team has got with fixing.",
    example: "Fixed 5, Not started 12.",
  },
  // src: backend/utilities/dashboard/scan_list.py:1256-1259, backend/utilities/dashboard/scan_list.py:1286-1289, backend/utilities/dashboard/scan_list.py:1346-1347 — by the resource category of each finding
  "mcp.chart.asset_category": {
    label: "Asset Category Vulnerabilities",
    what: "Findings by what the affected tool, prompt or resource gives access to: web, file system, code execution, database, search, vector store, document store.",
    why: "Tools that reach files, code or the network are the most dangerous to misuse.",
    example: "Code execution 3: three findings on tools that can run code.",
  },
  // src: backend/utilities/dashboard/scan_list.py:1357-1359, RabbitMQ/worker/scan_worker.py:157-164 — duration_of_scan per server
  "mcp.chart.duration": {
    label: "Scan Duration Trends",
    what: "How long each server's MCP scan took, in seconds, from the worker starting to results. A server scanned several times shows its earliest scan.",
    why: "A sudden change can signal a server that grew or misbehaves.",
    example: "mcp.example.com 95.",
  },
  // src: backend/utilities/dashboard/scan_list.py:1261-1264, backend/utilities/dashboard/scan_list.py:1348-1349, backend/utilities/dashboard/scan_list.py:1363-1366 — average weight/4*10 per category
  "mcp.chart.posture": {
    label: "Security Posture Overview",
    what: "The average risk score (0 to 10: Critical 10, High 7.5, Medium 5, Low 2.5) of the findings in each asset category; 0 where there are none.",
    why: "Shows which areas carry the most risk.",
    example: "File system 8.8: its findings are mostly Critical or High.",
  },
  // src: backend/utilities/dashboard/finding_metrics.py:89-125, backend/utilities/dashboard/scan_list.py:1379-1380 — per resolution date
  "mcp.chart.mttr": {
    label: "Mean Time to Remediate per Day",
    what: "For each day (UTC), the average time between a finding being recorded and being marked Fixed or Ignored, for the findings resolved that day.",
    why: "Shows whether fixes are getting faster.",
    example: "Two findings fixed on 8 Nov after 1 and 3 days: 2 days on 8 Nov.",
  },
  // src: backend/utilities/dashboard/scan_list.py:1389-1400 — per scan date: findings and those marked ignored
  "mcp.chart.effectiveness": {
    label: "Scan Effectiveness Trend",
    what: "Per scan date, the findings the scans produced and how many of them your team marked Ignored (treated as false positives).",
    why: "Many ignored findings can mean noisy results that need tuning.",
    example: "10 findings on 5 Nov, 2 ignored.",
  },
  // src: backend/utilities/dashboard/scan_list.py:1382-1388 — 100 minus the framework's share of that day's references
  "mcp.chart.compliance_trend": {
    label: "Compliance Framework Score Trend",
    what: "Per scan date and standard: 100 minus that standard's share of the day's compliance-control references. A relative measure, not an audit score.",
    why: "Shows whether compliance is improving over time.",
    example: "PCI DSS has 3 of 10 references on 5 Nov: 70.",
  },
  // src: backend/utilities/dashboard/scan_list.py:1401-1420 — resolved findings by days from creation to fixed/ignored, 30-day buckets
  "mcp.chart.age": {
    label: "Vulnerability Age Distribution",
    what: "Resolved findings (Fixed or Ignored) grouped by how many days they stayed open, in 30-day buckets up to 210 days. Open findings are not shown.",
    why: "Findings that stayed open long show where fixing is slow.",
    example: "A finding fixed after 45 days counts in 30-60 days.",
  },
  // src: frontend/app/[team_id]/mcp/page.tsx:712-716 — sorts the loaded rows by created_at
  "scan.filter.sort_created": {
    label: "Sort",
    what: "Orders the table by creation date, newest or oldest first.",
    why: "Brings the newest or oldest scans to the top.",
    example: "Newest puts the scan you created last on top.",
  },
  // src: backend/utilities/db/scan_list_item.py:282 — host part of the server URL
  "mcp.table.server": {
    label: "Server",
    what: "A short name for the MCP server, taken from its URL's host.",
    why: "Tells you which server the findings belong to.",
    example: "example for https://mcp.example.com.",
  },
  // src: backend/utilities/db/scan_list_item.py:205-266, frontend/app/[team_id]/mcp/page.tsx:1007-1011,949 — today's scale: weights 4/3/2/1 averaged over findings, 0 without findings (#35)
  "mcp.table.risk": {
    label: "Risk Score",
    what: "This scan's severity-weighted average on a 1 to 4 scale: Critical 4, High 3, Medium 2, Low 1, averaged over its findings. 0 when it found nothing or did not succeed.",
    why: "Lets you compare scans by overall severity.",
    example: "1 High and 1 Low finding: (3 + 1) / 2 = 2.",
  },
  // src: backend/utilities/db/scan_list_item.py:204-215, backend/utilities/db/scan_list_item.py:284-289 — tools, prompts and resources the server exposed
  "mcp.table.discovery": {
    label: "Discovery",
    what: "What the scan found on the server: T tools, P prompts, R resources.",
    why: "Shows how much the server exposes to an AI agent.",
    example: "T: 40 P: 4 R: 6.",
  },
  // src: backend/utilities/db/scan_list_item.py:249-261 — tools/prompts/resources rated high or critical
  "mcp.table.risky": {
    label: "Risky assets",
    what: "Tools, prompts and resources the scan rated High or Critical risk.",
    why: "These are the tools, prompts or resources to review first.",
    example: "3: two tools and one resource.",
  },
  // src: backend/utilities/db/scan_list_item.py:217-245 — counts per impact of a successful scan
  "mcp.table.vulns": {
    label: "Vulnerabilities",
    what: "This scan's findings by severity: Critical (red), High (orange), Medium (amber), Low (blue). Counted once the scan succeeded.",
    why: "Shows at a glance how serious this scan's findings are.",
    example: "1 red, 2 orange, 0 amber, 4 blue.",
  },

  // ────────────────────────────────────────────────────────────── LLM red teaming: scan configuration (components/llm-options-sidebar.tsx)
  // src: backend/utilities/db/schemas.py:176-186 — openai, anthropic, gemini or custom
  "llm.cfg.model_type": {
    label: "Model Type",
    what: "Where the model under test is hosted: OpenAI, Anthropic, Google Gemini, or Custom (any HTTP endpoint you describe below).",
    why: "The scan must speak the provider's API to send its attack prompts.",
    example: "Custom for your own chatbot API.",
  },
  // src: backend/utilities/db/schemas.py:178, backend/utilities/db/scan_list_item.py:355 — the provider's model id
  "llm.cfg.model_name": {
    label: "Model Name",
    what: "The model id the provider expects, exactly as in its API, or a name for your custom model. It also labels the scan in the Model Risk Comparison chart.",
    why: "Each model behaves differently; results apply only to the model tested.",
    example: "gpt-4o-mini.",
  },
  // src: backend/utilities/db/schemas.py:181 — secret field, never printed
  "llm.cfg.api_key": {
    label: "API Key",
    what: "The provider API key the red-team prompts are sent with. Every test prompt is billed by your provider on this key. It is never printed in logs.",
    why: "Prompts are sent with this key, so your provider bills them; use a key with limits.",
    example: "An OpenAI key from a project with a spending limit.",
  },
  // src: backend/utilities/db/schemas.py:179, RabbitMQ/worker/helpers/tools/llm_agent/main.py:142-155 — answers per prompt; not part of the credit price
  "llm.cfg.generations": {
    label: "Generations per benchmark",
    what: "How many answers the model is asked to give for each attack prompt. More generations catch inconsistent behaviour but send more requests to your provider; the credit price does not change.",
    why: "More answers per prompt catch inconsistent behaviour at the cost of more provider calls.",
    example: "3 sends each prompt three times.",
  },
  // src: backend/utilities/db/schemas.py:185 — the endpoint of a custom model
  "llm.cfg.model_uri": {
    label: "Model URI",
    what: "The URL the scan calls to talk to your custom model (POST by default).",
    why: "The scan sends every attack prompt to this address.",
    example: "https://chat.example.com/api/v1/complete.",
  },
  // src: backend/utilities/db/schemas.py:182 — HTTP headers of the custom request
  "llm.cfg.headers": {
    label: "Headers (JSON)",
    what: "HTTP headers sent with every request to the custom model, as a JSON object, usually for authentication.",
    why: "Endpoints that require authentication refuse the scan without them.",
    example: "{\"Authorization\": \"Bearer <token>\"}.",
  },
  // src: backend/utilities/db/schemas.py:183 — the JSON body with the prompt placeholder
  "llm.cfg.request_template": {
    label: "Request Template",
    what: "The JSON body sent to your model, with a placeholder where each attack prompt goes.",
    why: "A wrong template means the model never receives the attack prompts.",
    example: "{\"message\": \"$INPUT\"}.",
  },
  // src: backend/utilities/db/schemas.py:184 — where the answer is in the response
  "llm.cfg.response_field": {
    label: "Response JSON Field",
    what: "The field of your model's JSON response that holds the answer text, which the detectors then judge.",
    why: "Without the right field the detectors judge an empty answer.",
    example: "reply for a response {\"reply\": \"…\"}.",
  },
  // src: backend/utilities/db/schemas.py:180, RabbitMQ/worker/helpers/tools/llm_agent/main.py:142-155 — garak probes; 0.002 credits each
  "llm.cfg.probes": {
    label: "Security Benchmarks",
    what: "The attack families (garak probes) to run against the model, such as jailbreaks, prompt injection, data leakage or toxicity. Each selected benchmark costs 0.002 credits.",
    why: "Each benchmark tests a different way a model can be misused.",
    example: "promptinject and dan for a customer-facing chatbot.",
  },
  // src: RabbitMQ/worker/helpers/tools/llm_agent/main.py:142-155, backend/utilities/scan/estimate_scan.py:210 — number of probes x 0.002
  "llm.cfg.estimate": {
    label: "Estimate scan credits",
    what: "Prices the scan at 0.002 credits per selected benchmark, rounded to 0.01. Your model provider bills its own usage separately. Nothing is charged until you start the scan.",
    why: "Shows the price before any credits are charged.",
    example: "10 benchmarks: 0.02 credits.",
  },

  // ────────────────────────────────────────────────────────────── LLM red teaming: list page (app/[team_id]/llm/page.tsx)
  // src: backend/utilities/dashboard/scan_list.py:1500-1518 — the same status counters as SAST (UTC day for today); last_updated also moves on status polls and chat messages (#47)
  "llm.kpi.status": {
    label: "Scan counts by status",
    what: "LLM scans of this team per status (Not started, Pending, Started, Success, Failure), and how many were created or updated since 00:00 UTC today. A status check of a running scan or a chat message also counts as an update.",
    why: "Shows how many tests ran and how many are stuck or failed.",
    example: "Updated today 2: two scans started or finished today (UTC).",
  },
  // src: backend/utilities/dashboard/scan_list.py:1553-1555, backend/utilities/dashboard/scan_list.py:1638 — successful scans
  "llm.kpi.success": {
    label: "Scans (success)",
    what: "LLM scans that finished successfully. Only these feed the risk cards and charts.",
    why: "Only these scans contribute to the risk numbers on this page.",
    example: "5 scans succeeded.",
  },
  // src: backend/utilities/dashboard/scan_list.py:1619-1626 — weight/4*10 per finding, averaged
  "llm.kpi.avg_risk": {
    label: "Avg Risk Score",
    what: "Average over all findings of successful LLM scans, 0 to 10: Critical counts 10, High 7.5, Medium 5, Low 2.5.",
    why: "One number to compare model risk over time.",
    example: "One Critical and one Low: 6.3.",
  },
  // src: backend/utilities/dashboard/scan_list.py:1564-1567, backend/utilities/dashboard/scan_list.py:1617-1618 — findings of successful scans
  "llm.kpi.vulns": {
    label: "Vulnerabilities",
    what: "Findings of successful LLM scans: all of them (Total Vulns), and those rated Critical (Critical Vulns).",
    why: "Sizes how often your models can be misused.",
    example: "Total 12, Critical 2.",
  },
  // src: backend/utilities/dashboard/scan_list.py:1532-1543, backend/utilities/dashboard/scan_list.py:1628-1631 — 10 minus the number of OWASP LLM categories with a finding
  "llm.kpi.owasp": {
    label: "OWASP Score",
    what: "10 minus the number of OWASP Top 10 for LLM categories that have at least one finding. 10 means no category was hit; it does not weigh how many findings each has.",
    why: "A quick read of how many OWASP LLM risk areas are affected.",
    example: "Findings in LLM01 and LLM06 only: 8.",
  },
  // src: backend/utilities/dashboard/scan_list.py:1602-1606, backend/utilities/dashboard/scan_list.py:1633-1635 — (tests - hits) / tests over successful scans
  "llm.kpi.passed_rate": {
    label: "Passed Rate",
    what: "Share of attack attempts the models resisted, over all successful scans: attempts that did not trigger a detector divided by all attempts.",
    why: "Shows how well your models resist attacks overall.",
    example: "1,000 attempts, 80 hits: 92.0%.",
  },
  // src: backend/utilities/dashboard/scan_list.py:1564-1567 — findings by impact
  "llm.chart.risk_level": {
    label: "Risk Level Distribution",
    what: "Findings of successful LLM scans by severity: Critical, High, Medium, Low.",
    why: "Critical and High findings are the ones to address first.",
    example: "High 4, Medium 6, Low 2.",
  },
  // src: backend/utilities/dashboard/scan_list.py:1592-1601 — per probe: passed and failed attempts
  "llm.chart.attack_vectors": {
    label: "Attack Vector Test Results",
    what: "For each benchmark (garak probe), how many attack attempts the models resisted (passed) and how many succeeded (failed), over all successful scans.",
    why: "Shows which kinds of attack your models fail most.",
    example: "dan: 45 passed, 5 failed.",
  },
  // src: backend/utilities/dashboard/scan_list.py:1581-1590, backend/utilities/dashboard/scan_list.py:1653-1656 — per model name: findings-weighted 0-10 score
  "llm.chart.model_risk": {
    label: "Model Risk Comparison",
    what: "The average risk score (0 to 10, weights Critical 4, High 3, Medium 2, Low 1) of each model's findings, across its successful scans.",
    why: "Helps you choose the safer model for a use case.",
    example: "gpt-4o-mini 5.0, my-chatbot 7.5.",
  },
  // src: backend/utilities/dashboard/scan_list.py:1544-1551, backend/utilities/dashboard/scan_list.py:1607-1613, backend/utilities/dashboard/scan_list.py:1659-1665 — average of each scan's resistance scores
  "llm.chart.posture": {
    label: "AI Security Posture Overview",
    what: "Average of the scans' resistance scores in six areas: jailbreak resistance, injection resistance, hallucination resistance, bias resistance, content safety and data privacy. 0 where no scan reported one.",
    why: "Shows the weakest areas of your models' defences.",
    example: "Jailbreak resistance 7.2.",
  },
  // src: backend/utilities/dashboard/scan_list.py:1532-1543, backend/utilities/dashboard/scan_list.py:1568-1580, backend/utilities/dashboard/scan_list.py:1666-1669 — findings per OWASP LLM category
  "llm.chart.owasp": {
    label: "OWASP Top 10 LLM Metrics",
    what: "Findings per OWASP Top 10 for LLM Applications category (LLM01 Prompt Injection to LLM10). A finding mapped to two categories counts in both.",
    why: "Lets you report findings in the OWASP LLM framework.",
    example: "LLM01 6, LLM06 2.",
  },
  // src: backend/utilities/dashboard/scan_list.py:1502-1519 — every LLM scan by its UTC creation date
  "llm.chart.scans_per_day": {
    label: "Scans Per Day",
    what: "How many LLM scans were created on each day (UTC), whatever their status.",
    why: "Shows how regularly models are tested.",
    example: "3 scans created on 10 Nov.",
  },
  // src: backend/utilities/dashboard/scan_list.py:1500-1512 — counts by status
  "llm.chart.status": {
    label: "Scan Status Breakdown",
    what: "All LLM scans of this team by their current status.",
    why: "Failures point to configuration or provider problems.",
    example: "5 Success, 1 Failure.",
  },
  // src: backend/utilities/db/scan_list_item.py:371 — model type from the scan's settings
  "llm.table.model_type": {
    label: "Model type",
    what: "Where the tested model is hosted: openai, anthropic, gemini or custom.",
    why: "Tells you where the tested model runs.",
    example: "openai.",
  },
  // src: backend/utilities/db/scan_list_item.py:355, backend/utilities/db/scan_list_item.py:372 — model name from the settings or the results
  "llm.table.model_name": {
    label: "Model name",
    what: "The model id that was tested.",
    why: "Results apply only to this model.",
    example: "gpt-4o-mini.",
  },
  // src: backend/utilities/db/scan_list_item.py:374 — number of selected probes
  "llm.table.probes": {
    label: "Probes",
    what: "How many security benchmarks (garak probes) the scan was configured with.",
    why: "More benchmarks mean a broader test.",
    example: "10 probes selected.",
  },
  // src: backend/utilities/db/scan_list_item.py:343-351, backend/utilities/db/scan_list_item.py:377 — distinct MITRE ATLAS tactics of the findings
  "llm.table.mitre": {
    label: "MITRE",
    what: "How many different MITRE ATLAS tactics (the adversarial-AI attack stages) the scan's findings map to.",
    why: "Shows how many adversarial-AI attack stages the findings cover.",
    example: "3: initial access, ML model access and exfiltration.",
  },
  // src: backend/utilities/db/scan_list_item.py:298-315 — counts per impact of a successful scan
  "llm.table.vulns": {
    label: "Vulnerabilities",
    what: "This scan's findings by severity: Critical (red), High (orange), Medium (amber), Low (blue). Counted once the scan succeeded.",
    why: "Shows at a glance how serious this scan's findings are.",
    example: "1 red, 0 orange, 3 amber, 2 blue.",
  },
  // src: backend/utilities/db/scan_list_item.py:335-341 — 0-10 weighted per scan
  "llm.table.risk": {
    label: "Risk score",
    what: "This scan's severity-weighted average, 0 to 10: Critical 4, High 3, Medium 2, Low 1, averaged over its findings, divided by 4 and multiplied by 10.",
    why: "Lets you compare scans by overall severity.",
    example: "1 Critical and 1 Medium: (4+2)/2 = 3, so 7.5.",
  },

  // ────────────────────────────────────────────────────────────── CBOM: scan configuration (components/cbom-options-sidebar.tsx, cbom-ci-scan-settings-form.tsx)
  // src: RabbitMQ/worker/helpers/tools/cbom_agent/main.py:186-196 — deterministic engine, no language model
  "cbom.cfg.repository": {
    label: "Analyze Repository",
    what: "Inventories the cryptography in your code: algorithms, key sizes, certificates, keys, protocols and crypto libraries, graded for strength and quantum safety, into a CycloneDX CBOM. The engine is rule-based; no AI model reads your code.",
    why: "You cannot plan a post-quantum migration without knowing where your cryptography is.",
    example: "Finds RSA-1024 in a Java KeyPairGenerator call and flags it weak and quantum-vulnerable.",
  },
  // src: RabbitMQ/worker/helpers/tools/cbom_agent/main.py:186-196, backend/utilities/scan/credit_estimate.py:14-24 — an uploaded CBOM is analysed for a flat 0.01
  "cbom.cfg.file": {
    label: "CBOM file",
    what: "A CycloneDX CBOM you already have, as a JSON file, graded by the same rules. Analysing a file costs a flat 0.01 credits. Choosing a file clears the repository or zip.",
    why: "Grades a CBOM you already have without cloning code.",
    example: "cbom.json produced by another scanner.",
  },
  // src: RabbitMQ/worker/helpers/tools/cbom_agent/main.py:155-162, aibom/src/aibom/cbom/posture/safeio.py:22 — vendored and build directories are skipped unless asked
  "cbom.cfg.vendored": {
    label: "Scan vendored and build directories",
    what: "Also reads vendor/, dist/, build/ and node_modules/: third-party code and build output, skipped by default. Turn it on to see crypto your dependencies ship; it makes the scan larger and dearer.",
    why: "Third-party and build code ships with your product, so its crypto is your exposure too.",
    example: "A Go service with a vendor/ folder of crypto libraries.",
  },
  // src: RabbitMQ/worker/helpers/context/scan_context.py:22-28, RabbitMQ/worker/helpers/context/scan_context.py:44-47 — up to 1,000 commits, blobs over 2 MB not downloaded
  "cbom.cfg.history": {
    label: "Scan git history for keys",
    what: "Clones up to 1,000 commits of the branch (files over 2 MB are skipped) and reports key and certificate files that were committed and later deleted: they stay readable in the history.",
    why: "A key removed from the code is still exposed if it remains in git history.",
    example: "A server.key added in 2023 and removed a week later is still reported.",
  },
  // src: backend/utilities/scan/credit_estimate.py:25-27, RabbitMQ/worker/helpers/tools/cbom_agent/main.py:186-196 — 1 credit per 5 MB of binaries/images/firmware
  "cbom.cfg.binaries": {
    label: "Scan binaries, container images and firmware",
    what: "Also reads compiled binaries, docker save / OCI image archives and firmware: linked crypto libraries, crypto constants, embedded keys and the packages inside images. Adds 1 credit per 5 MB of such content.",
    why: "Compiled code and images ship crypto libraries that source scans do not see.",
    example: "A 50 MB image archive in the zip adds 10 credits.",
  },
  // src: RabbitMQ/worker/helpers/tools/cbom_agent/main.py:186-196, backend/utilities/scan/credit_estimate.py:14-24, backend/utilities/scan/estimate_scan.py:210 — 1 credit per 0.5 MB source + binaries/5 MB, minimum 1; file 0.01
  "cbom.cfg.estimate": {
    label: "Estimate scan credits",
    what: "A repository or zip costs 2 credits per MB of source files (plus 1 per 5 MB of binaries when that option is on), at least 1 credit; an uploaded CBOM file 0.01. Nothing is charged until you start the scan.",
    why: "Shows the price before any credits are charged.",
    example: "300 KB of source: 1 credit (the minimum).",
  },

  // ────────────────────────────────────────────────────────────── CBOM: list page (app/[team_id]/cbom/page.tsx)
  // src: backend/utilities/dashboard/scan_list.py:1701-1755, backend/utilities/cbom_sources/cbom_metrics.py:164-171 — inventory rows of code scans + latest Sources collections, each asset once
  "cbom.kpi.assets": {
    label: "Crypto Assets",
    what: "Cryptographic assets found: algorithms, keys, certificates, protocols and libraries, from successful code scans and the latest CBOM Sources collections. An asset seen by both is counted once, from its latest observation.",
    why: "This is your cryptographic bill of materials; everything else is a view of it.",
    example: "A TLS certificate found in the repository and on the live server counts 1.",
  },
  // src: backend/utilities/cbom_sources/cbom_metrics.py:122-128, aibom/src/aibom/cbom/weakness.py:93-108 — rows graded weak (broken digests, asymmetric keys under 2048 bits, ...)
  "cbom.kpi.weak": {
    label: "Weak Algorithms",
    what: "Assets graded weak: cryptography that is broken or too short today, for example MD5 or SHA-1 in signatures, or RSA, DSA and DH keys under 2048 bits.",
    why: "Weak cryptography can be attacked now, without a quantum computer.",
    example: "A password hash using MD5.",
  },
  // src: backend/utilities/cbom_sources/cbom_metrics.py:129-135, backend/utilities/cbom_sources/cbom_metrics.py:28-40 — verdict quantum-vulnerable
  "cbom.kpi.quantum_vulnerable": {
    label: "Quantum Vulnerable",
    what: "Assets a large quantum computer would break: public-key cryptography such as RSA, ECDSA, ECDH and DH, which need moving to post-quantum algorithms.",
    why: "Data protected by these can be recorded now and decrypted later (harvest now, decrypt later).",
    example: "An ECDHE key exchange without a post-quantum hybrid.",
  },
  // src: backend/utilities/cbom_sources/cbom_metrics.py:136-137 — algorithm_type certificate
  "cbom.kpi.certificates": {
    label: "Certificates",
    what: "X.509 certificates found in code, files or on live endpoints.",
    why: "Certificates expire and carry keys and signature algorithms that need migrating.",
    example: "The certificate served on api.example.com:443.",
  },
  // src: backend/utilities/cbom_sources/cbom_metrics.py:138-139 — algorithm_type key or secret
  "cbom.kpi.keys": {
    label: "Keys",
    what: "Keys and secrets found: private keys, symmetric keys and other key material.",
    why: "Exposed keys must be rotated; long-lived keys need a migration plan.",
    example: "A PEM private key committed in config/.",
  },
  // src: backend/utilities/cbom_sources/cbom_metrics.py:28-46, backend/utilities/cbom_sources/cbom_metrics.py:174-178 — judged assets not vulnerable / judged; none judged shows no value
  "cbom.kpi.readiness": {
    label: "Quantum Readiness",
    what: "Share of assets with a quantum verdict that are safe: post-quantum, hybrid, or symmetric with enough margin (AES-128 counts as ready). Assets broken today count as not ready. Assets without a verdict (hashes, settings) are left out.",
    why: "Tracks your post-quantum migration in one number.",
    example: "10 judged assets, 3 quantum-vulnerable: 70%.",
  },
  // src: backend/utilities/cbom_sources/cbom_metrics.py:20-21, backend/utilities/cbom_sources/cbom_metrics.py:82-89 — 0-10 over findings: critical 9, high 7, medium 5, low 2
  "cbom.kpi.avg_risk": {
    label: "Avg Risk Score",
    what: "Average risk of the crypto findings, 0 to 10: Critical counts 9, High 7, Medium 5, Low 2. Clean inventory rows are not findings and are left out.",
    why: "One number to compare crypto risk over time.",
    example: "One High and one Low finding: (7 + 2) / 2 = 4.5.",
  },
  // src: backend/utilities/dashboard/scan_list.py:1757-1783 — code-scan findings by your status; Sources findings by their remediation plan status
  "cbom.chart.remediation": {
    label: "Remediation Actions Required",
    what: "Crypto findings by status: code-scan findings by the status your team set, CBOM Sources findings by their remediation plan status (open counts as Not started).",
    why: "Shows how far the team has got with fixing crypto findings.",
    example: "30 findings: 5 Fixed, 3 In progress, 22 Not started.",
  },
  // src: backend/utilities/cbom_sources/cbom_metrics.py:1-15, backend/utilities/dashboard/scan_list.py:1803 — findings by severity, inventory separately
  "cbom.chart.severity": {
    label: "Severity Distribution",
    what: "Crypto findings by severity (Critical, High, Medium, Low) and the clean inventory rows as Informational.",
    why: "Critical and High findings are the ones to fix first.",
    example: "High 4, Medium 9, Informational 120.",
  },
  // src: backend/utilities/cbom_sources/cbom_metrics.py:116-121, backend/utilities/dashboard/scan_list.py:1804 — algorithm_type of every row
  "cbom.chart.algorithm_type": {
    label: "Algorithm Type Distribution",
    what: "All crypto assets by the type the engine gave them (for example certificate, key or secret); assets without a type count as other.",
    why: "Shows which kinds of cryptography dominate your migration work.",
    example: "certificate 6, key 3, other 12.",
  },
  // src: backend/utilities/cbom_sources/cbom_metrics.py:99, backend/utilities/cbom_sources/cbom_metrics.py:122-128 — weak / moderate / strong / quantum-safe
  "cbom.chart.strength": {
    label: "Crypto Strength Distribution",
    what: "All crypto assets by strength grade: weak (replace now), moderate, strong, quantum-safe. Assets without a grade are not shown.",
    why: "Weak and moderate assets are the near-term fixes.",
    example: "weak 5, moderate 12, strong 60, quantum_safe 2.",
  },
  // src: backend/utilities/cbom_sources/cbom_metrics.py:101, backend/utilities/cbom_sources/cbom_metrics.py:129-135 — quantum_safe / quantum_vulnerable / broken_today
  "cbom.chart.quantum": {
    label: "Quantum Readiness",
    what: "Assets with a quantum verdict: quantum-safe, quantum-vulnerable (breakable by a future quantum computer), and broken today (already insecure without one).",
    why: "Quantum-vulnerable assets are your post-quantum migration list.",
    example: "Safe 30, Vulnerable 12, Broken today 2.",
  },
  // src: backend/utilities/cbom_sources/cbom_metrics.py:1-15, backend/utilities/dashboard/scan_list.py:1808 — the 10 riskiest findings
  "cbom.chart.top_risks": {
    label: "Top Cryptographic Risks",
    what: "The 10 riskiest crypto findings, with algorithm, type, strength, quantum safety, impact and where each was found (a code scan or a CBOM Sources collection).",
    why: "Start here when you have time for only a few fixes.",
    example: "RSA-1024 · asymmetric · weak · not quantum safe · High · payments-api.",
  },
  // src: backend/routers/cbom_deliverables.py:1-20 — PDFs built in memory from every completed CBOM scan; no language model; no credits charged by the route
  "cbom.deliverables": {
    label: "Deliverables",
    what: "Team-wide regulatory PDFs (for example a certificate register or a post-quantum roadmap) built from every completed CBOM scan of the team. They are generated in-house, with no AI model, and download straight away.",
    why: "Auditors and regulators ask for these documents; they are built from the same data as the screens.",
    example: "Download the PQC roadmap for the board pack.",
  },
  // src: backend/utilities/db/scan_list_item.py:445-453, backend/utilities/cbom_sources/run_list.py:1-12 — code scan: findings by severity plus inventory; Sources run: counts as collected, QV = quantum-vulnerable assets
  "cbom.table.risks": {
    label: "Risks",
    what: "This row's crypto findings by severity: Critical (red), High (orange), Medium (amber), Low (blue). A Sources run's counts are as collected: the impact each asset was judged with when it was read, before your remediation statuses. QV is the number of quantum-vulnerable assets.",
    why: "Shows at a glance how serious each scan's or run's crypto findings are.",
    example: "0 red, 2 orange, 5 amber, 1 blue, QV:3.",
  },
  // src: backend/utilities/cbom_sources/cbom_metrics.py:26, backend/utilities/cbom_sources/run_list.py:228 — 0-10: critical 9, high 7, medium 5, low 2; a Sources run uses the same average over its counts as collected
  "cbom.table.risk": {
    label: "Risk score",
    what: "This row's average finding risk, 0 to 10: Critical 9, High 7, Medium 5, Low 2; inventory rows are left out. A Sources run's score is the same average over its counts as collected.",
    why: "Lets you compare scans and runs by overall severity.",
    example: "Two Medium findings: 5.0.",
  },

  // ────────────────────────────────────────────────────────────── Team dashboard (app/[team_id]/page.tsx, backend/utilities/dashboard/team.py)
  // src: backend/utilities/dashboard/team.py:86-97, backend/utilities/dashboard/team.py:113-134 — every scan of the team plus its CBOM Sources runs
  "team.section.activity": {
    label: "Your Team's Recent Activity",
    what: "Scans of every product in this team, plus CBOM Sources collection runs, counted together.",
    why: "Shows how actively the team is testing across products.",
    example: "A SAST scan and a CBOM Sources run both count as one scan each.",
  },
  // src: backend/utilities/dashboard/team.py:173-190 — stored findings of all scans + Sources findings not already found by a code scan
  "team.kpi.findings": {
    label: "Total findings",
    what: "Findings stored for all scans of this team, in any product, plus CBOM Sources findings that no code scan already reported.",
    why: "Sizes the team's total security backlog.",
    example: "40 SAST + 12 SCA + 8 CBOM findings: 60.",
  },
  // src: backend/utilities/dashboard/team.py:13, backend/utilities/dashboard/team.py:114-134, backend/utilities/dashboard/team.py:196 — STARTED/RETRY scans + running Sources runs
  "team.kpi.started": {
    label: "Started scans",
    what: "Scans running now (started or retrying), plus CBOM Sources runs in progress.",
    why: "Results for these are not complete yet.",
    example: "2 while a DAST scan and a Sources run are working.",
  },
  // src: backend/utilities/dashboard/team.py:13, backend/utilities/dashboard/team.py:114-134, backend/utilities/dashboard/team.py:197 — SUCCESS scans + done/partial Sources runs
  "team.kpi.completed": {
    label: "Completed scans",
    what: "Scans that finished successfully, plus CBOM Sources runs that finished (fully or partly).",
    why: "Shows how many scans and runs produced results.",
    example: "30 completed scans across all products.",
  },
  // src: backend/utilities/dashboard/team.py:13, backend/utilities/dashboard/team.py:114-134, backend/utilities/dashboard/team.py:198 — NOT_STARTED/PENDING scans + queued Sources runs
  "team.kpi.not_started": {
    label: "Not started",
    what: "Scans created but not running yet (never started, or queued for a worker), plus queued CBOM Sources runs.",
    why: "Scans that never ran give no coverage.",
    example: "A scan you created and never estimated counts here.",
  },
  // src: backend/utilities/dashboard/team.py:174-177, backend/utilities/dashboard/team.py:190 — status fixed (or a fixed date) + Sources findings whose remediation is done
  "team.kpi.fixed": {
    label: "Fixed findings",
    what: "Findings your team marked Fixed, plus CBOM Sources findings whose remediation is done.",
    why: "Shows how much of the backlog the team has closed.",
    example: "15 of 60 findings fixed.",
  },
  // src: backend/utilities/dashboard/team.py:191-193 — fixed / total * 100
  "team.kpi.remediation": {
    label: "Remediation",
    what: "Fixed findings as a percentage of all findings of the team.",
    why: "One number for how much of what was found has been fixed.",
    example: "15 fixed of 60: 25.0%.",
  },
  // src: backend/utilities/dashboard/team.py:226-236 — scans created in the last 30 days by type; Sources runs count as CBOM
  "team.chart.activity": {
    label: "Scan activity by type",
    what: "Scans created in the last 30 days, per product (SAST, SCA + SBOM, IaC, DAST, CBOM, AI BOM, MCP, LLM). CBOM Sources runs count as CBOM.",
    why: "Shows which products the team uses, and which it neglects.",
    example: "SAST 12, DAST 4, CBOM 3.",
  },
  // src: backend/utilities/dashboard/team.py:237-290 — high and critical findings of scans created in the last 30 days
  "team.chart.severity30": {
    label: "Vulnerabilities by severity (last 30 days)",
    what: "High and Critical findings of the scans created in the last 30 days (Medium and Low are not counted here). A CBOM asset seen twice counts once.",
    why: "Shows the serious findings of the last month at a glance.",
    example: "Critical 3, High 17.",
  },
  // src: backend/utilities/dashboard/team.py:199-205, frontend/app/[team_id]/page.tsx:463 — scans by creation date
  "team.chart.daily": {
    label: "Daily scan volume",
    what: "How many scans the team created each day, all products together, in any status.",
    why: "Shows how regularly the team scans.",
    example: "7 scans on 10 Nov.",
  },
  // src: backend/utilities/dashboard/team.py:13, backend/utilities/dashboard/team.py:114-134 — four buckets over scans and Sources runs
  "team.chart.status": {
    label: "Scan status distribution",
    what: "All scans and CBOM Sources runs by state: Not started (including queued), Running (including retrying), Completed, Failed.",
    why: "Failures or stuck scans point to setup or capacity problems.",
    example: "Completed 30, Failed 2, Running 1.",
  },
  // src: backend/utilities/dashboard/team.py:135-170 — findings of all products and their status changes over time
  "team.section.findings": {
    label: "Findings & Remediation",
    what: "Findings of all products and what your team did with them, day by day (dates in UTC).",
    why: "Finding issues matters only if they get fixed; this shows the trend.",
    example: "A spike of fixes after a remediation sprint.",
  },
  // src: backend/utilities/dashboard/team.py:141-163 — per day: findings created (by current status), plus fixes and ignores on their own dates
  "team.chart.remediations_per_day": {
    label: "Remediations status per day",
    what: "For each day: the findings recorded that day by their current status, plus the findings marked Fixed and Ignored that day.",
    why: "Shows whether fixing keeps pace with finding.",
    example: "10 Nov: 8 new (5 Not started, 3 In progress), 4 fixed.",
  },
  // src: backend/utilities/dashboard/team.py:150-153 — by creation date
  "team.chart.findings_per_day": {
    label: "Findings per day",
    what: "How many findings were recorded each day, across all products.",
    why: "Spikes usually follow new scans or new code.",
    example: "25 findings on the day a large SAST scan finished.",
  },
  // src: backend/utilities/dashboard/team.py:157-159 — by fixed date
  "team.chart.fixes_per_day": {
    label: "Fixes per day",
    what: "How many findings were marked Fixed each day.",
    why: "Shows the team's fixing rhythm.",
    example: "6 fixes on 9 Nov.",
  },
  // src: backend/utilities/dashboard/team.py:160-162 — by ignored date
  "team.chart.false_positives": {
    label: "False positive trends",
    what: "How many findings were marked Ignored each day: the findings your team judged false positives or accepted risks.",
    why: "Many ignored findings may point to noisy scan settings.",
    example: "3 ignored on 8 Nov.",
  },
  // src: backend/utilities/dashboard/team.py:89, frontend/app/[team_id]/page.tsx:821-834 — CI/CD integrations by creation date
  "team.section.integrations": {
    label: "Your Team's Integrations",
    what: "CI/CD integrations your team created, by creation date.",
    why: "Shows which pipelines scan automatically.",
    example: "2 integrations created on 1 Nov.",
  },

  // ────────────────────────────────────────────────────────────── Team settings (app/[team_id]/settings/page.tsx)
  // src: backend/routers/team.py:86, backend/utilities/team/invitations.py:219, backend/routers/team.py:173 — creator is admin, invitees join as member
  "settings.members": {
    label: "Team members",
    what: "Everyone in this team and their role. Admin: the team's creator (and other admins) can edit the team, invite, remove members and delete it. Member: runs scans and works on findings. Tick members to remove them.",
    why: "Roles decide who can change settings, credentials and team data.",
    example: "you@acme.com admin, dev@acme.com member.",
  },
  // src: backend/utilities/team/invitations.py:1-9, backend/utilities/team/invitations.py:33 — single-use link, 7 days, no password mailed
  "settings.invite": {
    label: "Invite by email",
    what: "Mails the address a single-use invitation link, valid for 7 days. No password is sent: a new person chooses one on the invitation page, an existing user signs in and accepts. Nobody joins until they accept.",
    why: "Only invited people can see the team's scans and findings.",
    example: "dev@acme.com joins as a member after clicking the link.",
  },
  // src: backend/utilities/team/invitations.py:1-9, backend/utilities/team/invitations.py:33, backend/routers/team.py:466-490 — open invitations; resend replaces the link; revoke cancels it
  "settings.invitations": {
    label: "Pending invitations",
    what: "Invitations not yet accepted, with their status and expiry (7 days after sending). Resend mails a new link (the old one stops working); Revoke cancels it.",
    why: "Expired or unaccepted invitations may need resending or revoking.",
    example: "dev@acme.com · pending · expires 18 Nov.",
  },
  // src: backend/utilities/db/schemas.py:24-37, backend/utilities/integrations/jira.py:111-208 — Jira Cloud REST v3 with email + API token
  "settings.jira": {
    label: "Jira",
    what: "Connects the team to Jira (REST API v3, as used by Jira Cloud) so scans can create Jira issues from findings. Each scan chooses its project and whether tickets are created automatically.",
    why: "Findings reach your team's normal work queue instead of staying in a dashboard.",
    example: "https://acme.atlassian.net with a bot account's API token.",
  },
  // src: backend/utilities/integrations/jira.py:111-121 — basic auth email + token
  "settings.jira.email": {
    label: "Jira email",
    what: "The email of the Jira account the tickets are created as. It needs access to the projects you will pick.",
    why: "Tickets are created as this account, so it needs access to the projects.",
    example: "security-bot@acme.com.",
  },
  // src: backend/utilities/db/schemas.py:27, backend/utilities/integrations/jira.py:118 — the site URL; REST paths are added to it
  "settings.jira.url": {
    label: "Jira URL",
    what: "The address of your Jira site, without a path.",
    why: "Tickets are created on this site only.",
    example: "https://acme.atlassian.net.",
  },
  // src: backend/utilities/db/schemas.py:26, backend/utilities/integrations/jira.py:111-121 — secret field, never printed; basic auth with the email
  "settings.jira.token": {
    label: "Jira API token",
    what: "An API token of that Jira account (Atlassian account settings > Security > API tokens). It is stored for the team and never printed in logs.",
    why: "Without a valid token no ticket can be created.",
    example: "A token created for the security-bot account.",
  },
  // src: backend/utilities/db/schemas.py:20-22, backend/routers/team.py:193-215 — admin only
  "settings.team.name": {
    label: "Team name",
    what: "The team's name, shown in the team switcher. Only admins can change it.",
    why: "Helps members find the right team in the switcher.",
    example: "Payments platform.",
  },
  // src: backend/utilities/db/schemas.py:20-22, backend/routers/team.py:193-215 — optional text
  "settings.team.description": {
    label: "Description",
    what: "An optional note about what this team covers.",
    why: "Tells members what the team covers.",
    example: "Scans for the payments services and their infrastructure.",
  },
  // src: backend/routers/team.py:297-330 — admin only; the default team cannot be deleted; scans and CBOM Sources data are deleted
  "settings.danger": {
    label: "Danger zone",
    what: "Deleting the team removes its scans, findings and CBOM Sources data for everyone. Only admins can do it, and your default team cannot be deleted.",
    why: "Deletion cannot be undone and affects every member.",
    example: "Delete a team created for a finished project.",
  },

  // ────────────────────────────────────────────────────────────── Per-scan ticketing (components/ticketing-integrations-settings.tsx)
  // src: backend/utilities/db/schemas.py:39-45, backend/utilities/integrations/jira.py:196 — project used for issues created from this scan
  "ticketing.jira_project": {
    label: "Jira project ID",
    what: "The Jira project where tickets for this scan's findings are created, using the Jira connection in team Settings.",
    why: "Tickets land in this project, so pick the one the owners work in.",
    example: "10001 (the numeric id of project SEC).",
  },
  // src: backend/utilities/db/schemas.py:39-41, backend/utilities/celery/celery_connection.py:236-239, backend/utilities/integrations/jira_ticketing.py:20, backend/utilities/integrations/jira_ticketing.py:199-242 — one task per finding when the scan succeeds, cap 50
  "ticketing.auto_create": {
    label: "Create tickets automatically",
    what: "When on, one Jira task is created per finding as soon as this scan succeeds (at most 50 per scan). Marking a finding Fixed closes its ticket.",
    why: "Every finding becomes a tracked task without manual work.",
    example: "Turn it on for a nightly scan your team triages in Jira.",
  },

  // ────────────────────────────────────────────────────────────── Account (app/[team_id]/account/page.tsx)
  // src: backend/routers/auth.py:351-363 — the current password is checked before the change
  "account.current_password": {
    label: "Current password",
    what: "Your present password, to prove it is you before the change.",
    why: "Stops someone at an unlocked screen from changing your password.",
    example: "The password you signed in with today.",
  },
  // src: backend/utilities/auth/auth_utils.py:203-243, frontend/utils/password_rules.ts:1-8 — 8 to 128 characters, at most 512 bytes
  "account.new_password": {
    label: "New password",
    what: "8 to 128 characters (an emoji counts as one), at most 512 bytes. After the change every other browser and device is signed out; this one stays signed in.",
    why: "A strong, unique password protects access to your team's findings.",
    example: "A passphrase such as \"correct-horse-battery-staple\".",
  },
  // src: frontend/app/[team_id]/account/page.tsx:56-68,123 — must equal the new password
  "account.confirm_password": {
    label: "New password again",
    what: "Type the new password once more, so a typo does not lock you out.",
    why: "Prevents a typo from locking you out.",
    example: "The same passphrase as above.",
  },
  // src: backend/routers/auth.py:1-8 — logout revokes every token issued before it
  "account.sessions": {
    label: "Sessions",
    what: "Sign out everywhere ends every session of your account, on every browser and device, this one included.",
    why: "Ends access from a lost or shared device.",
    example: "Use it after signing in on a shared computer.",
  },

  // ────────────────────────────────────────────────────────────── Admin (app/admin/page.tsx, superusers only)
  // src: backend/routers/admin.py:200-262 — superuser account; temporary password; a single-use choose-your-password link is mailed
  "admin.create_user": {
    label: "Create admin user",
    what: "Creates a superuser account. The password you set is temporary: the user must choose their own at first sign-in, and is mailed a single-use link to do it (the password itself is never mailed).",
    why: "Admins can see and change every team, so create them sparingly.",
    example: "ops@zeroshield.example with a temporary password.",
  },
  // src: backend/routers/admin.py:220-235 — one account per email
  "admin.email": {
    label: "Email",
    what: "The new admin's sign-in email. It must not belong to an existing account.",
    why: "The new admin signs in with it.",
    example: "ops@zeroshield.example.",
  },
  // src: backend/routers/admin.py:219-222, backend/utilities/auth/auth_utils.py:203-243 — temporary; 8-128 characters
  "admin.password": {
    label: "Password",
    what: "A temporary password, 8 to 128 characters; the user replaces it at first sign-in.",
    why: "A temporary password limits the damage if it is shared insecurely.",
    example: "A random 16-character string.",
  },
  // src: backend/routers/admin.py:236-246 — stored on the account
  "admin.name": {
    label: "Name",
    what: "The new admin's first and last name, shown in team member lists and scan owners.",
    why: "Shows who the admin is in member lists and scan owners.",
    example: "Asha Rao.",
  },
  // src: backend/routers/admin.py:153-199, backend/routers/admin.py:355-424 — every user, teams, superuser switch
  "admin.users": {
    label: "Users",
    what: "Every account on this installation, its teams and whether it has admin (superuser) access. The switch grants or removes that access.",
    why: "Lets you review who has access, and who has admin rights.",
    example: "Turn off Admin Access for someone who changed role.",
  },
  // src: backend/routers/admin.py:97-152, backend/routers/admin.py:291-354 — every team; the credit balance is set (not added), never negative
  "admin.teams": {
    label: "Teams",
    what: "Every team with its members, credit balance and scan count. Editing the balance sets it to the number you enter (it does not add to it); it cannot be negative.",
    why: "Lets you check usage and set credit balances.",
    example: "Set 5000 to give a team 5,000 credits in total.",
  },

  // ────────────────────────────────────────────────────────────── results views, shared (components/SASTResults.tsx, SbomResults.tsx, finding-selection-menu.tsx)
  // src: backend/utilities/dashboard/scan_metadata.py:73-101, backend/utilities/dashboard/scan_metadata.py:120-124 — repo_url from the scan's settings
  "results.meta.repository": {
    label: "Repository",
    what: "The address of the repository this scan cloned. Hover for the full address when it is cut short.",
    why: "Tells you which code the findings belong to.",
    example: "https://github.com/acme/payments-api.",
  },
  // src: backend/utilities/dashboard/scan_metadata.py:76-77, backend/utilities/dashboard/scan_metadata.py:122-123, RabbitMQ/worker/helpers/context/scan_context.py:89 — the branch from the scan's settings (SAST shows main when none was given)
  "results.meta.branch": {
    label: "Branch",
    what: "The branch that was cloned and scanned. A zip upload or an uploaded SBOM file has no branch, so the card is not shown for them.",
    why: "Findings apply to this branch only.",
    example: "release/2026.11.",
  },
  // src: backend/utilities/dashboard/scan_metadata.py:75, backend/utilities/dashboard/scan_metadata.py:13, frontend/components/SbomResults.tsx:1104 — zip_file_used, sbom_file_used (SCA + SBOM), else a repository
  "results.meta.source": {
    label: "Source",
    what: "Where the scanned input came from: a repository that was cloned, a ZIP upload, or (SCA + SBOM only) an SBOM file you uploaded.",
    why: "Tells you where the scanned input came from.",
    example: "ZIP upload for a scan started from payments-api.zip.",
  },
  // src: backend/utilities/db/findings.py:29-42, backend/utilities/celery/create_findings.py:10-48, backend/routers/scans.py:1203-1254 — the scan's stored findings, one per row, each with a status the team sets
  "results.findings": {
    label: "Findings",
    what: "This scan's findings, one per row, each with a status your team sets. Click a title for the details; select rows to file Jira tickets; use Action to set a finding's status.",
    why: "Each row is something to fix, accept or track.",
    example: "\"SQL injection in orders.py\", High, Not started.",
  },
  // src: frontend/components/SASTResults.tsx:1083, frontend/components/SbomResults.tsx:1189 — exact match on the finding's impact
  "results.filter.impact": {
    label: "Impact filter",
    what: "Shows only the findings of one impact (severity): Critical, High, Medium or Low. It filters the findings already loaded in this page.",
    why: "Focuses the table on the most serious findings.",
    example: "Choose Critical to see only the Critical findings.",
  },
  // src: frontend/components/SASTResults.tsx:793-798,1164, frontend/components/SbomResults.tsx:844-850,1272, backend/routers/scans.py:1151-1174 — selects the rows shown (after search and filters); the selection menu files them in Jira
  "results.select_all": {
    label: "Select all",
    what: "Selects every finding the table shows (after search and filters). The selected findings can then be filed in Jira from the Actions menu above the table.",
    why: "Lets you act on a whole group of findings at once.",
    example: "Filter Impact to Critical, select all, then Actions > Create Jira ticket.",
  },
  // src: backend/routers/scans.py:1203-1254, backend/utilities/db/finding_state.py:20-35, backend/utilities/dashboard/remediation_metrics.py:17-90 — fixed sets fixed_at and closes the Jira issue; ignored sets ignored_at; the remediation metrics read these
  "results.finding.action": {
    label: "Action",
    what: "Sets a finding's status. Fixed records when it was fixed and closes its Jira issue, if it has one. Ignored records when it was dismissed. In progress and Not started only change the status. The remediation metrics are computed from these statuses.",
    why: "Statuses drive the remediation metrics and close linked Jira issues.",
    example: "Mark a false positive Ignored: it leaves the high-priority backlog.",
  },
  // src: backend/new_models.py:131, backend/utilities/db/schemas.py:15-17, backend/routers/scans.py:1230-1249 — finding_status not_started (new), in_progress, fixed, ignored
  "results.table.status": {
    label: "Status",
    what: "The status your team set on this finding: Not started (every finding starts here), In progress, Fixed or Ignored. Change it with Action.",
    why: "Shows what the team decided about each finding.",
    example: "In progress while a fix is in review.",
  },
  // src: RabbitMQ/worker/helpers/context/schema.py:18, backend/utilities/db/findings.py:87-105, backend/utilities/db/findings.py:129-153 — impact as stored with the finding
  "results.table.impact": {
    label: "Impact",
    what: "The severity the scan's analysis gave this finding: Critical, High, Medium or Low.",
    why: "Fix Critical and High first.",
    example: "High for a vulnerable dependency with a known remote exploit.",
  },
  // src: frontend/components/SASTResults.tsx:650-655,1172, frontend/components/SbomResults.tsx:150-155,1282 — number of entries in the finding's owasp_top_10
  "results.table.owasp": {
    label: "OWASP Top 10",
    what: "How many OWASP Top 10 categories this finding maps to. Click the title to see which.",
    why: "Lets you report findings in the OWASP framework.",
    example: "1: A03:2021 Injection.",
  },
  // src: frontend/components/SASTResults.tsx:650-655,1173, frontend/components/SbomResults.tsx:150-155,1283 — number of entries in the finding's compliance_controls
  "results.table.compliance": {
    label: "Compliance controls",
    what: "How many compliance controls (for example PCI DSS requirements or ISO 27001 clauses) this finding maps to. Click the title to see which.",
    why: "Shows which audit requirements a finding touches.",
    example: "3: PCI DSS 6.2.4, ISO 27001 A.8.28 and ISO 27002 8.28.",
  },
  // src: frontend/components/finding-selection-menu.tsx:44-119, backend/routers/scans.py:1122-1174 — one Jira issue per selected stored finding (a finding with an issue keeps it); needs a successful scan, the scan's Jira project and the team's Jira connection
  "results.selection.actions": {
    label: "Actions for the selection",
    what: "Acts on the selected findings. Create Jira ticket files one Jira issue per finding in the project set on this scan's Ticketing integrations tab; a finding that already has an issue is not filed again. Some results pages also set the status of all selected findings here.",
    why: "Turns selected findings into tracked work in one step.",
    example: "Select 3 Critical findings, Create Jira ticket: 3 issues in project SEC.",
  },

  // ────────────────────────────────────────────────────────────── SAST: results view (components/SASTResults.tsx)
  // src: backend/utilities/dashboard/scan.py:181-192, frontend/components/SASTResults.tsx:220-233,279 — findings per OWASP category; each bar relative to the largest
  "sast.res.owasp": {
    label: "OWASP Top 10 metrics",
    what: "This scan's findings per OWASP Top 10 category. Each ring's length is relative to the largest category; hover a ring for its count. A finding mapped to two categories counts in both.",
    why: "Recurring categories point to a coding pattern to fix at the source.",
    example: "Injection 5 is the full ring; Cryptographic Failures 2 is 40% of it.",
  },
  // src: backend/utilities/dashboard/scan.py:170-176, backend/utilities/dashboard/scan.py:203-205 — count per impact
  "sast.res.risk": {
    label: "Risk metrics",
    what: "How many findings of this scan have each impact: Critical, High, Medium and Low.",
    why: "Critical and High findings are the ones to fix first.",
    example: "Critical 1, High 4, Medium 7, Low 2.",
  },
  // src: backend/utilities/dashboard/scan.py:207-215, frontend/components/SASTResults.tsx:240-243,364 — findings per CVE id, top 20
  "sast.res.cves": {
    label: "CVEs per vulnerability",
    what: "For each CVE the analysis linked to a finding, how many of this scan's findings reference it; the 20 most referenced.",
    why: "A CVE shared by many findings is one fix with a large effect.",
    example: "CVE-2021-44228 referenced by 3 findings.",
  },
  // src: backend/utilities/dashboard/scan.py:194-201, frontend/components/SASTResults.tsx:409 — findings per compliance control, all, largest first
  "sast.res.compliance": {
    label: "Compliance Controls Failed count",
    what: "How many of this scan's findings map to each compliance control (for example a PCI DSS requirement), every control, largest first. A finding mapped to three controls counts once for each.",
    why: "Shows which audit requirements this scan's findings put at risk.",
    example: "PCI DSS 6.2.4: 4 findings.",
  },
  // src: backend/utilities/dashboard/scan.py:220-228, frontend/components/SASTResults.tsx:251-258,447, frontend/components/SASTResults.tsx:463-468,447 — control references grouped by standard (text before " - "), share of the total, top 12; icons mark the share
  "sast.res.policy": {
    label: "Policy Violations",
    what: "This scan's compliance-control references grouped by standard, with each standard's share of all references (top 12). It is a share, not a pass rate: the tick or cross only marks how large the share is.",
    why: "Shows which standards this scan affects most.",
    example: "6 PCI DSS and 4 ISO 27001 references: PCI DSS 60%, ISO 27001 40%.",
  },
  // src: backend/utilities/dashboard/scan.py:28-33, backend/utilities/dashboard/scan.py:216-218, frontend/components/SASTResults.tsx:262-266,487 — score by impact (10/7.5/5/2.5), keyed by title, top 24
  "sast.res.risk_scores": {
    label: "Risk scores per finding",
    what: "Each finding's risk score from its impact, on a 0 to 10 scale: Critical 10, High 7.5, Medium 5, Low 2.5. The 24 highest are shown as F1, F2…; hover for the title. Findings with the same title appear once.",
    why: "Shows whether risk is concentrated in a few findings.",
    example: "F1 \"SQL injection in orders.py\" 10.",
  },
  // src: backend/utilities/dashboard/scan.py:231-232, backend/utilities/dashboard/remediation_metrics.py:17-90 — from the status of this scan's findings
  "sast.res.remed.section": {
    label: "Remediation Metrics",
    what: "Measured from the status your team sets on this scan's findings (Not started, In progress, Fixed, Ignored). The targets are fixed goals shown for comparison.",
    why: "Shows whether this scan's findings are being fixed.",
    example: "Mark a finding Fixed in the table below and these numbers update.",
  },
  // src: backend/utilities/dashboard/remediation_metrics.py:43-80, frontend/components/SASTResults.tsx:552-554 — mean of (fixed_at or ignored_at - created_at); target 3 days
  "sast.res.remed.mttr": {
    label: "Mean Time to Remediate",
    what: "Average time from when this scan's findings were recorded to when they were marked Fixed or Ignored. The target is 3 days.",
    why: "A long time to fix keeps known weaknesses exploitable.",
    example: "One finding fixed after 2 days and one ignored after 4 days: 3.0 days.",
  },
  // src: backend/utilities/dashboard/remediation_metrics.py:47-49, backend/utilities/dashboard/scan.py:203-205, frontend/components/SASTResults.tsx:576-581 — fixed critical / all critical findings of the scan; target 95%
  "sast.res.remed.critical_fixed": {
    label: "Critical Issues Fixed",
    what: "This scan's Critical findings marked Fixed, as a percentage of all its Critical findings. Ignored findings do not count as fixed. The target is 95%.",
    why: "Critical findings are the most likely to be exploited.",
    example: "4 Critical findings, 3 marked Fixed: 75%.",
  },
  // src: backend/utilities/dashboard/remediation_metrics.py:38-40, frontend/components/SASTResults.tsx:601-602 — critical or high and not fixed/ignored; target 10
  "sast.res.remed.backlog": {
    label: "High Priority Backlog",
    what: "This scan's Critical and High findings that are not yet marked Fixed or Ignored. The target is 10 or fewer.",
    why: "Open Critical and High findings are this scan's current exposure.",
    example: "12 open Critical/High findings: 2 above target.",
  },
  // src: backend/utilities/dashboard/remediation_metrics.py:30, backend/utilities/dashboard/remediation_metrics.py:55-69, frontend/components/SASTResults.tsx:622-623 — fixed_at/ignored_at date >= today - 7 days (UTC): 8 dates; target 20
  "sast.res.remed.velocity": {
    label: "Remediation Velocity",
    what: "This scan's findings marked Fixed or Ignored today or on the 7 dates before it (UTC), so over up to 8 calendar days. The target is 20 a week.",
    why: "Shows whether fixes keep up.",
    example: "5 fixed and 1 ignored since last Wednesday: 6/week.",
  },
  // src: backend/utilities/dashboard/scan_metadata.py:79-99, RabbitMQ/worker/helpers/context/codebase_context.py:210-213 — included / (included + excluded) documents of the language
  "sast.res.coverage": {
    label: "Code coverage",
    what: "Share of the chosen language's source files that were analysed: analysed files divided by analysed plus excluded files. Exclusions are the language's built-in ones and your patterns.",
    why: "Low coverage means much of the code was not analysed, so a clean result proves less.",
    example: "180 files analysed and 20 excluded: 90.0%.",
  },
  // src: backend/utilities/dashboard/scan_metadata.py:79-99 — len(included) / len(included) + len(excluded)
  "sast.res.files": {
    label: "Files scanned",
    what: "Files analysed / files of the chosen language in the repository (analysed plus excluded). Files of other languages are not counted.",
    why: "Shows how much of the repository was analysed.",
    example: "180 / 200: 20 files were excluded by patterns.",
  },
  // src: frontend/components/SASTResults.tsx:717-728,1070 — case-insensitive match on title, description, impact, status, suggested fix and location of the loaded findings
  "sast.res.search": {
    label: "Search findings",
    what: "Shows only the findings whose title, description, impact, status, suggested fix or location contains this text (upper or lower case does not matter).",
    why: "Finds the findings for one file or topic quickly.",
    example: "\"orders.py\" keeps the findings located in orders.py.",
  },
  // src: backend/utilities/db/findings.py:44-49, backend/utilities/db/findings.py:96, frontend/components/SASTResults.tsx:699-705,1106 — the per-finding score is 1-4 (impact), the tiers are 0-10, so only Low matches; bug reported to the coordinator, issue not yet filed
  "sast.res.filter.risk": {
    label: "Risk score filter",
    what: "Shows only findings whose risk score is in a tier: Critical 9 or more, High 7 to 9, Medium 5 to 7, Low under 5. Today a SAST finding's score is 1 to 4, so Low keeps every finding and the other tiers none (a known bug); filter by Impact instead.",
    why: "Focuses the table on the riskiest findings.",
    example: "To list the Critical findings, choose Critical in the Impact filter.",
  },
  // src: frontend/components/SASTResults.tsx:1181-1182, frontend/components/SASTResults.tsx:1341-1363 — description cut to 80 characters; the dialog shows description, location, suggested fix and snippet
  "sast.res.description": {
    label: "Description",
    what: "The analysis's explanation of the issue, cut to 80 characters; hover for the whole text, or click the title for the description, location, code snippet and suggested fix.",
    why: "Explains what is wrong before you open the details.",
    example: "\"User input from the order form reaches a SQL query in orders.py without parame…\" (hover for the rest).",
  },
  // src: backend/utilities/db/findings.py:44-49, backend/utilities/db/findings.py:96, frontend/components/SASTResults.tsx:1222-1229 — risk_score_map: low 1 … critical 4
  "sast.res.table.risk": {
    label: "Risk score",
    what: "This finding's risk score, set by its impact: Critical 4, High 3, Medium 2, Low 1. The Risk scores per finding chart shows the same findings on a 0 to 10 scale.",
    why: "Lets you sort and compare findings by severity.",
    example: "4 for a Critical finding.",
  },
  // src: frontend/components/SASTResults.tsx:1174, frontend/components/SASTResults.tsx:650-655,1174 — number of CVE ids on the finding
  "sast.res.table.cves": {
    label: "CVE count",
    what: "How many CVE identifiers the analysis linked to this finding. Click the title to see them.",
    why: "Linked CVEs show the issue is known and documented.",
    example: "1 for a finding about a vulnerable Log4j call.",
  },

  // ────────────────────────────────────────────────────────────── SCA + SBOM: results view (components/SbomResults.tsx)
  // src: backend/utilities/dashboard/scan.py:857-858, RabbitMQ/worker/helpers/tools/sca_sbom_agent/merge_inventory.py:109-122 — len(results) of this scan; packages with no known vulnerability are Low rows (#46)
  "sbom.res.kpi.total": {
    label: "Total vulnerabilities",
    what: "This scan's result rows: each known vulnerability in your dependencies, plus each package found with no known vulnerability (stored as a Low row).",
    why: "Sizes this scan's dependency risk.",
    example: "1 vulnerable package and 3 packages with no known vulnerability: 4.",
  },
  // src: backend/utilities/dashboard/scan.py:840-842, backend/utilities/dashboard/scan.py:858 — impact critical
  "sbom.res.kpi.critical": {
    label: "Critical",
    what: "Of those, the vulnerabilities rated Critical.",
    why: "Critical dependency vulnerabilities are often exploited soon after disclosure.",
    example: "A remote-code-execution CVE in a direct dependency.",
  },
  // src: backend/utilities/dashboard/scan.py:849-853 — number of compliance-control entries over all results
  "sbom.res.kpi.policy": {
    label: "Policy violations",
    what: "How many compliance-control references (PCI DSS, ISO 27001 and others) this scan's vulnerabilities map to, added up.",
    why: "Shows how many audit requirements this scan's findings touch.",
    example: "One vulnerability mapped to 2 controls and one to 3: 5.",
  },
  // src: backend/utilities/dashboard/scan.py:860-864, backend/utilities/dashboard/scan.py:95-97 — medium + high risk license categories over all result rows (#46)
  "sbom.res.kpi.license_risks": {
    label: "License risks",
    what: "This scan's result rows, vulnerable packages or not, whose license is medium-risk (weak copyleft such as LGPL or MPL, Creative Commons, commercial) or high-risk (strong copyleft such as GPL, network copyleft such as AGPL, source-available such as SSPL or BUSL).",
    why: "Some licenses impose obligations on how you distribute your software.",
    example: "A package under LGPL-3.0 counts here even with no known vulnerability.",
  },
  // src: backend/utilities/dashboard/scan.py:865-869, backend/utilities/dashboard/scan.py:96 — strong copyleft, network copyleft, source-available
  "sbom.res.kpi.high_risk_licenses": {
    label: "High-risk licenses",
    what: "Vulnerabilities whose package is under a strong copyleft (GPL), network copyleft (AGPL) or source-available (SSPL, BUSL) license.",
    why: "Strong copyleft or source-available licenses can force code publication or product changes.",
    example: "A vulnerable package licensed AGPL-3.0.",
  },
  // src: backend/utilities/dashboard/scan.py:28-33, backend/utilities/dashboard/scan.py:853-859 — mean of 10/7.5/5/2.5 per result row, Python round(x, 1); packages with no known vulnerability are Low rows (#46)
  "sbom.res.kpi.avg_risk": {
    label: "Avg risk score",
    what: "Average over this scan's result rows, 0 to 10: Critical counts 10, High 7.5, Medium 5, Low 2.5. Packages with no known vulnerability are Low rows. Rounded to one decimal.",
    why: "One number to compare this scan with others.",
    example: "1 Critical and 3 packages with no known vulnerability: (10 + 3 × 2.5) / 4 = 4.4.",
  },
  // src: backend/utilities/dashboard/scan.py:843-846, RabbitMQ/worker/helpers/context/schema.py:34, RabbitMQ/worker/helpers/tools/sca_sbom_agent/main.py:137-158 — the AI model's label; no source file in its context
  "sbom.res.kpi.reachable": {
    label: "Reachable issues",
    what: "Vulnerabilities the AI model labelled Reachable. It judges from the vulnerability and package data (description, severity, where the package was found); it does not read your code, so treat the label as a hint.",
    why: "A vulnerability your code reaches is far more urgent than one it never calls.",
    example: "A CVE in a web framework's request parser may be labelled Reachable although your code never uses that parser.",
  },
  // src: backend/utilities/dashboard/scan.py:871-879, backend/utilities/dashboard/finding_metrics.py:18-40, frontend/components/SbomResults.tsx:246-250,338 — stored result rows of the scan by status, share of all; packages with no known vulnerability included (#46)
  "sbom.res.remediation": {
    label: "Remediation actions",
    what: "This scan's result rows by the status your team set (Fixed, In progress, Not started, Ignored), each as a count and a share of all its rows.",
    why: "Shows how far fixing has got for this scan.",
    example: "10 rows: 2 Fixed (20%), 1 In progress, 7 Not started.",
  },
  // src: backend/utilities/dashboard/scan.py:837-839, backend/utilities/dashboard/scan.py:953 — count per impact; Low includes packages with no known vulnerability (#46)
  "sbom.res.severity": {
    label: "Severity distribution",
    what: "How many of this scan's result rows have each impact: Critical, High, Medium and Low. Low also counts packages with no known vulnerability.",
    why: "Critical and High rows are the ones to look at first.",
    example: "Critical 1, High 3, Medium 6, Low 2.",
  },
  // src: backend/utilities/dashboard/scan.py:843-844, backend/utilities/dashboard/scan.py:881-896, RabbitMQ/worker/helpers/context/schema.py:34 — the AI model's label; missing counts as Not assessed; packages with no known vulnerability are stored Not reachable (#46)
  "sbom.res.reachability": {
    label: "Reachability distribution",
    what: "This scan's result rows by the reachability label the AI model gave each one from the vulnerability and package data (it does not read your code): Reachable, Potentially reachable, Not reachable, or Not assessed. Not reachable also counts packages with no known vulnerability.",
    why: "Helps you prioritise reachable vulnerabilities.",
    example: "A CVE in a package found only in a test lock file is often labelled Not reachable.",
  },
  // src: backend/utilities/dashboard/scan.py:898-912, backend/utilities/celery/create_findings.py:68-84 — findings by impact on their created_at date (UTC); a scan's findings are all recorded when it finishes
  "sbom.res.trends": {
    label: "Vulnerability trends over time",
    what: "This scan's findings by severity, on the date (UTC) each was recorded. A scan records all its findings when it finishes, so this usually shows a single day.",
    why: "Shows when the findings were recorded.",
    example: "12 findings recorded on 11 Nov: one point with Critical 1, High 3, Medium 6, Low 2.",
  },
  // src: backend/utilities/dashboard/scan.py:847-848, backend/utilities/dashboard/scan.py:914, backend/utilities/dashboard/sbom_license.py:330-375 — license family per result (SPDX from the inventory, else the model's category, else a curated package map, else not declared)
  "sbom.res.licenses": {
    label: "Licenses Distribution",
    what: "This scan's vulnerabilities by the license family of their package. The license comes from the SBOM when it records one, else from the AI model's category, else from a built-in list of well-known packages; otherwise Not declared.",
    why: "Shows which license obligations come with the vulnerable packages.",
    example: "MIT and Apache-2.0 are permissive; GPL-3.0 is strong copyleft.",
  },
  // src: backend/utilities/dashboard/scan.py:853-856, backend/utilities/dashboard/scan.py:931-939 — per reachability label: mean of 10/7.5/5/2.5, 0 when none
  "sbom.res.risk_by_reach": {
    label: "Average risk score per reachability",
    what: "For each reachability label, the average risk (0 to 10: Critical 10, High 7.5, Medium 5, Low 2.5) of this scan's vulnerabilities with that label; 0 when there are none.",
    why: "Shows whether the riskiest vulnerabilities are also reachable.",
    example: "Reachable 8.8: the vulnerabilities labelled Reachable are mostly Critical or High.",
  },
  // src: backend/utilities/dashboard/scan.py:916-929, frontend/components/SbomResults.tsx:529-534,516 — sorted by impact, first 20
  "sbom.res.top": {
    label: "Top vulnerabilities by risk score",
    what: "This scan's vulnerabilities, Critical first, the first 20, each with its reachability label, direct or transitive dependency, and license family.",
    why: "These are the dependency issues to fix first.",
    example: "lodash 4.17.15, reachable, direct, permissive, Critical.",
  },
  // src: frontend/components/SbomResults.tsx:611-627,1176 — case-insensitive match on title, description, impact, dependency and finding id of the loaded findings
  "sbom.res.search": {
    label: "Search findings",
    what: "Shows only the findings whose title, description, impact, dependency or finding id contains this text (upper or lower case does not matter).",
    why: "Finds the findings for one package quickly.",
    example: "\"lodash\" keeps every finding in a lodash version.",
  },
  // src: backend/utilities/db/findings.py:142, backend/utilities/dashboard/bom_risk_score.py:152-173, frontend/components/SbomResults.tsx:594-600,1212 — tiers on the 0-10 per-finding score
  "sbom.res.filter.risk": {
    label: "Risk score filter",
    what: "Shows only findings whose risk score (0 to 10) is in a tier: Critical 9 or more, High 7 to 9, Medium 5 to 7, Low under 5.",
    why: "Focuses the table on the riskiest findings.",
    example: "High keeps a finding scored 8.5 and hides one scored 9.4.",
  },
  // src: RabbitMQ/worker/helpers/context/schema.py:32-33, backend/utilities/db/findings.py:133-152 — the package (with version) as the analysis named it
  "sbom.res.table.dependency": {
    label: "Dependency",
    what: "The package, with its version, that the vulnerability is in. Hover for the full name when it is cut short.",
    why: "Names the package to upgrade or replace.",
    example: "lodash@4.17.15.",
  },
  // src: backend/utilities/dashboard/bom_risk_score.py:20-26, backend/utilities/dashboard/bom_risk_score.py:93-99, backend/utilities/dashboard/bom_risk_score.py:152-173 — impact base + 0.7 per CVE (max 3) + reachability + 0.5 high-risk license, 0-10, one decimal
  "sbom.res.table.risk": {
    label: "Risk score",
    what: "This finding's risk, 0 to 10: a base for its impact (Critical 7.5, High 5.5, Medium 3.5, Low 1.2), plus 0.7 per CVE (at most 3), plus its reachability label (Reachable 1.6, Potentially reachable 0.9, Not assessed 0.3), plus 0.5 for a high-risk license.",
    why: "Lets you compare findings by severity and context.",
    example: "High, 2 CVEs, labelled Reachable: 5.5 + 1.4 + 1.6 = 8.5.",
  },
  // src: backend/utilities/dashboard/sbom_license.py:382-392, RabbitMQ/worker/helpers/context/schema.py:34 — the AI model's label
  "sbom.res.table.reachability": {
    label: "Reachability",
    what: "The reachability label the AI model gave this vulnerability from the vulnerability and package data: Reachable, Potentially reachable, Not reachable or Not assessed. It does not read your code.",
    why: "Reachable vulnerabilities are the most urgent.",
    example: "Not reachable for a CVE in a test-only package.",
  },
  // src: backend/utilities/dashboard/sbom_license.py:330-375, RabbitMQ/worker/helpers/context/schema.py:35 — SPDX from the inventory, else the model's category (it may guess), else a curated package map, else not declared
  "sbom.res.table.license": {
    label: "License",
    what: "The license family of the package. It comes from the SBOM when it records a license, else from the AI model's category (which may be its own judgement), else from a built-in list of well-known packages; otherwise Not declared.",
    why: "Tells you the obligations that come with the package.",
    example: "Permissive for a package licensed MIT.",
  },
  // src: frontend/components/SbomResults.tsx:1414, frontend/components/SbomResults.tsx:1429-1435, RabbitMQ/worker/helpers/context/schema.py:30-35 — shown when the scan has no stored findings: the analysis's own list
  "sbom.res.vuln.title": {
    label: "Vulnerability",
    what: "The vulnerabilities the analysis reported, shown when this scan has no stored findings. Click a title for the description and the suggested fix.",
    why: "Lists what the analysis found even when no findings were stored.",
    example: "Prototype pollution in lodash.",
  },
  // src: frontend/components/SbomResults.tsx:1434-1435 — one dependency, or the number of them
  "sbom.res.vuln.deps": {
    label: "Dependencies",
    what: "The package the vulnerability is in, or the number of packages when it affects several.",
    why: "Names the package to upgrade or replace.",
    example: "\"3 dependencies\" for a CVE found in three lodash copies.",
  },
  // src: frontend/components/SbomResults.tsx:867-904,1411, backend/routers/scans.py:1179-1189 — rows without a stored finding id: one combined Jira issue from the summary
  "sbom.res.vuln.select": {
    label: "Select rows",
    what: "Selects rows of this list for a Jira ticket. These rows are not stored findings, so all the selected rows go into one combined Jira issue.",
    why: "Lets you file these vulnerabilities as Jira work.",
    example: "Select 4 rows, Create Jira ticket: one issue listing the 4 vulnerabilities.",
  },
  // ────────────────────────────────────────────────────────────── CBOM Sources: shared by the tabs, and Servers (components/cbom/sources/ServersTab.tsx)
  // src: frontend/components/cbom/sources/ServersTab.tsx:967, backend/utilities/cbom_sources/kinds.py:26 — 1-64 letters, digits, spaces, dots, dashes, underscores
  "cbsrc.common.name": {
    label: "Source name",
    what: "A name for this source, 1 to 64 letters, digits, spaces, dots, dashes or underscores. It labels the source in lists, run results, the CBOM and reports.",
    why: "Every asset a run finds records the source it came from, so a clear name tells an auditor where a weak key or certificate lives.",
    example: "dc-mumbai-linux for the Linux servers of the Mumbai data centre.",
  },
  // src: frontend/components/cbom/sources/ServersTab.tsx:977-987, backend/utilities/cbom_sources/jobs.py:323 — jobs of the source run on this node
  "cbsrc.common.node": {
    label: "Scan node",
    what: "The scan node, inside your network, that connects to these targets and collects their crypto. Every job of this source (connection tests and collection) runs on it.",
    why: "Only a node that can reach the targets on the right port can read them; a node in the wrong network segment makes every target unreachable.",
    example: "node-dc1 in the 10.20.0.0/16 segment for servers in 10.20.5.0/24.",
  },
  // src: frontend/components/cbom/sources/ServersTab.tsx:991-999, frontend/components/cbom/sources/ServersTab.tsx:993 — 1,000 lines; ranges up to /16; 262,144 addresses per source
  "cbsrc.servers.targets": {
    label: "Targets",
    what: "The servers to read: IP addresses, CIDR ranges or hostnames, one per line, up to 1,000 lines. A range may be at most a /16 and a source at most 262,144 addresses. Import CSV adds the first column of a file.",
    why: "Only listed targets are scanned, so a server left out is a blind spot in the CBOM.",
    example: "10.20.0.0/24, 10.20.5.17 and app-01.bank.local: 256 + 1 + 1 targets.",
  },
  // src: frontend/components/cbom/sources/teamNeverScan.ts:93-94 — per-source exclusions; never-scan always wins
  "cbsrc.common.never_scan": {
    label: "Never scan",
    what: "Addresses, ranges or hostnames this source must never touch, one per line or comma-separated. A hostname also covers every address it resolves to from the scan node. The team never-scan list on the Network tab applies as well. Never-scan always wins over targets.",
    why: "Keeps fragile or out-of-scope systems (a core banking host, a partner's range) out of every job.",
    example: "10.20.0.1, 10.20.0.254 keeps the two gateways out of 10.20.0.0/24.",
  },
  // src: frontend/components/cbom/sources/ServersTab.tsx:121-124 — SSH 22, WinRM over HTTPS 5986, LDAPS 636 by default
  "cbsrc.servers.port": {
    label: "Port",
    what: "The port the scan node connects to: SSH for Linux (default 22), WinRM over HTTPS for Windows (5986), LDAPS for Active Directory (636).",
    why: "A port that is closed or filtered from the node fails the connection test for every server.",
    example: "2222 when your Linux servers run sshd on a non-standard port.",
  },
  // src: frontend/components/cbom/sources/ServersTab.tsx:1092-1099, backend/utilities/cbom_sources/kinds.py:27 — up to 64 characters; DOMAIN\\user accepted for Windows and AD
  "cbsrc.servers.login": {
    label: "Login user",
    what: "The account the scan node logs in as, up to 64 characters. For Linux a read-only account on each server (zs-cbom by default); for Windows and Active Directory a local or domain account, DOMAIN\\user accepted.",
    why: "A dedicated read-only account limits what a leaked credential could do and makes the scan easy to spot in audit logs.",
    example: "zs-cbom on Linux; BANK\\svc-zscbom for Active Directory.",
  },
  // src: frontend/components/cbom/sources/ServersTab.tsx:1115-1132 — trust on first use or pinned known_hosts; a password forces pinning
  "cbsrc.servers.host_key_policy": {
    label: "Host key policy",
    what: "How the node checks each server's SSH host key before logging in. Trust on first use remembers the key on first contact and refuses and alerts if it changes. Pin fingerprints accepts only the keys you paste. A password credential requires pinned keys.",
    why: "The host key check stops a machine impersonating the server from capturing the credential.",
    example: "Pin fingerprints with the output of ssh-keyscan for servers you already trust.",
  },
  // src: frontend/components/cbom/sources/ServersTab.tsx:1136-1143 — public keys only
  "cbsrc.servers.known_hosts": {
    label: "known_hosts lines",
    what: "The SSH host keys to accept, in known_hosts format: the output of ssh-keyscan or your existing known_hosts file. Public keys only; upload a file or paste the lines.",
    why: "A server whose key is not listed is refused, so a spoofed server never receives the login.",
    example: "10.20.0.11 ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAA...",
  },
  // src: frontend/components/cbom/sources/ServersTab.tsx:1177-1185, backend/utilities/cbom_sources/kinds.py:21 — PEM up to 64 KB, checked before the login is sent
  "cbsrc.servers.ca_pem": {
    label: "CA certificate",
    what: "Optional PEM certificate of the CA that issued the WinRM (HTTPS) or LDAPS certificate of the servers. The server's certificate is checked against it before the login is sent. Needed when an internal CA issued it.",
    why: "Without the right CA the TLS check fails and the node never sends the password.",
    example: "The root certificate of BANK-ISSUING-CA, as -----BEGIN CERTIFICATE-----...",
  },
  // src: frontend/components/cbom/sources/ServersTab.tsx:128-134,1226, frontend/components/cbom/sources/ServersTab.tsx:1226-1238 — node key, SSH CA, SSH certificate, vault reference or password; vault and SSH CA for admins only
  "cbsrc.servers.credential": {
    label: "Credential",
    what: "How the node proves who it is. Node-generated SSH key (recommended, the private key never leaves the node), SSH CA certificate (signed per job for minutes), your own SSH certificate, a vault reference, or a password. Only team admins choose vault or SSH CA.",
    why: "The credential is the most sensitive thing a source holds; options that keep secrets off ZeroShield reduce what a breach could expose.",
    example: "Linux: Node-generated SSH key, then install the shown public key for zs-cbom.",
  },
  // src: frontend/components/cbom/sources/ServersTab.tsx:1293-1305, backend/utilities/cbom_sources/kinds.py:20 — secrets up to 256 KB, encrypted at rest
  "cbsrc.servers.ssh_certificate": {
    label: "SSH certificate",
    what: "An OpenSSH user certificate signed by your own SSH CA, used together with the private key below. Encrypted at rest and sent only to the scan node that runs the job.",
    why: "A short-lived certificate expires on its own, so a copied credential stops working.",
    example: "ssh-ed25519-cert-v01@openssh.com AAAA... zs-cbom valid for 8 hours.",
  },
  // src: frontend/components/cbom/sources/ServersTab.tsx:1306-1318, backend/utilities/cbom_sources/kinds.py:20 — secrets up to 256 KB, encrypted at rest
  "cbsrc.servers.private_key": {
    label: "Private key",
    what: "The private key that goes with the SSH certificate, in OpenSSH or PEM format. Encrypted at rest, never shown again, sent only to the scan node that runs the job.",
    why: "Without the matching private key the certificate cannot be used to log in.",
    example: "-----BEGIN OPENSSH PRIVATE KEY----- ....",
  },
  // src: frontend/components/cbom/sources/ServersTab.tsx:1325-1335 — the CA's active key signs the node's key for each job
  "cbsrc.servers.ssh_ca": {
    label: "SSH CA",
    what: "The ZeroShield SSH CA (created on Fleet > SSH CA) whose active key signs the scan node's own key for each job; the certificate lives for minutes. Rotating the CA needs no change here.",
    why: "Servers trust one CA instead of a key per node, and no long-lived credential exists to steal.",
    example: "prod-ssh-ca, trusted on the servers through TrustedUserCAKeys.",
  },
  // src: frontend/components/cbom/sources/ServersTab.tsx:1338, frontend/components/cbom/sources/ServersTab.tsx:1338-1341 — zs-<team>-<name>, one per line
  "cbsrc.servers.principals": {
    label: "Principals",
    what: "The principals written into each job's certificate, one per line, in the form zs-<team id>-<name>. A server accepts the certificate only for a login whose principals file lists one of them.",
    why: "Principals decide which servers accept the certificate, so prod and test servers can trust different ones.",
    example: "zs-12-prod, listed in /etc/ssh/zs-cbom/principals/zs-cbom on the production servers.",
  },
  // src: frontend/components/cbom/sources/ServersTab.tsx:1343-1347 — source-address of the certificate; /16 or narrower (IPv6 /48)
  "cbsrc.servers.source_addresses": {
    label: "Addresses the servers see the node as",
    what: "The source-address restriction written into each certificate: the addresses or networks (/16 or narrower, IPv6 /48) the servers see the node connect from. Blank uses the node's own addresses.",
    why: "A certificate copied off the node cannot be used from anywhere else.",
    example: "10.20.1.15, or 10.20.1.0/28 when the node sits behind a NAT pool.",
  },
  // src: frontend/components/cbom/sources/ServersTab.tsx:136-141 — HashiCorp Vault, CyberArk, AWS Secrets Manager, Azure Key Vault
  "cbsrc.common.vault_provider": {
    label: "Vault",
    what: "The secrets manager the scan node reads the credential from when a job runs: HashiCorp Vault, CyberArk, AWS Secrets Manager or Azure Key Vault.",
    why: "The password stays in your vault and is never stored by ZeroShield.",
    example: "CyberArk, where the svc-zscbom password is already rotated daily.",
  },
  // src: frontend/components/cbom/sources/ServersTab.tsx:1373-1381 — only the reference is stored
  "cbsrc.common.vault_path": {
    label: "Secret path",
    what: "Where the secret lives in your vault. The scan node reads it when the job runs; ZeroShield stores only this reference. Only a team admin can add or change it.",
    why: "A wrong path fails every job of the source at the login step.",
    example: "secret/data/cbom/linux-prod for HashiCorp Vault KV v2.",
  },
  // src: frontend/components/cbom/sources/ServersTab.tsx:1397-1407, backend/utilities/cbom_sources/kinds.py:20 — encrypted at rest; blank on edit keeps the saved one
  "cbsrc.common.password": {
    label: "Password",
    what: "The account's password. Encrypted at rest by ZeroShield, sent only to the scan node that runs the job and never shown again. When editing, leave it blank to keep the saved one.",
    why: "Changing the targets, port, login or node clears a stored password, so it is never sent to a host it was not meant for.",
    example: "The password of svc-zscbom, rotated every 90 days.",
  },
  // src: frontend/components/cbom/sources/ServersTab.tsx:142-171,1415, frontend/components/cbom/sources/ServersTab.tsx:1415-1429 — Tier 1 read-only commands; Tier 2 adds an exact sudo allowlist
  "cbsrc.servers.tier": {
    label: "Privilege tier",
    what: "Tier 1 runs read-only commands as the login user: packages, crypto configs, readable keys, certificates and keystores. Tier 2 adds an exact sudo allowlist (no wildcards) to see which process loads which crypto library, socket owners, the effective SSH config and disk encryption.",
    why: "Tier 2 finds crypto in use at runtime that config files alone do not show, at the cost of a sudoers entry.",
    example: "Tier 2 shows that java on port 8443 loads libssl 1.1.1 with TLS 1.0 enabled.",
  },
  // src: frontend/components/cbom/sources/ServersTab.tsx:1257-1267 — the public key for the login user
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
  // src: frontend/components/cbom/sources/ServersTab.tsx:1546-1578 — team network window, any time, or a custom copy
  "cbsrc.common.window": {
    label: "Scan window",
    what: "When collection may run: the team scan window set on the Network tab, any time, or a custom copy of the weekly hours for this source. Connection tests always run straight away.",
    why: "Keeps scans out of business hours or change freezes on production systems.",
    example: "Network window (team): weekdays 22:00 to 06:00 IST.",
  },
  // src: frontend/components/cbom/sources/ServersTab.tsx:932-937, frontend/components/cbom/sources/ServersTab.tsx:118-125,476 — Linux, Windows or Active Directory sources
  "cbsrc.servers.form": {
    label: "Add servers",
    what: "A server source is one list of Linux servers, Windows servers or an Active Directory, read through one scan node with a read-only account. Pick the type, then where the servers are and how to log in.",
    why: "Servers hold most of the keys, certificates and crypto libraries an inventory has to cover.",
    example: "Linux: 10.20.0.0/24 through node-dc1, login zs-cbom with the node's SSH key.",
  },
  // src: frontend/components/cbom/sources/ServersTab.tsx:514-549 — each source with its target count after exclusions
  "cbsrc.servers.list": {
    label: "Configured server sources",
    what: "The server sources of this team with their type, target count after exclusions, scan node, privilege tier and last connection test.",
    why: "Sources here are what a run on the Review & Run tab collects from.",
    example: "dc-mumbai-linux · Linux · 256 targets · node-dc1 · Tier 1 · Passed.",
  },
  // src: frontend/components/cbom/sources/ServersTab.tsx:142-171,1629, frontend/components/cbom/sources/ServersTab.tsx:1627-1633 — the command lists; nothing is installed
  "cbsrc.servers.what_runs": {
    label: "Exactly what runs on each server",
    what: "The exact commands the node runs on each server for the chosen type and tier. Nothing is installed; output is parsed on the node.",
    why: "Your change board can review every command before approving the scan.",
    example: "Tier 1 runs openssl version -a and cat /etc/ssh/sshd_config, among others.",
  },
  // src: backend/utilities/cbom_sources/jobs.py:323, backend/utilities/cbom_sources/jobs.py:716-726 — up to 5 sampled targets
  "cbsrc.servers.test": {
    label: "Connection test",
    what: "The result of the last connection test: up to 5 sampled targets, each checked for reachability, login and privilege. Passed when every sample is ready, Partly ready when some are.",
    why: "It proves the node, network path and credential work before a full run spends credits.",
    example: "4 of 5 samples ready: 10.20.0.9 refused the login.",
  },
  // src: frontend/components/cbom/sources/ServersTab.tsx:118-125 — the source kind
  "cbsrc.col.type": {
    label: "Type",
    what: "The kind of source: what it reads and how.",
    why: "Each type uses a different protocol, port and credential.",
    example: "Linux servers over SSH; Active Directory over LDAPS.",
  },
  // src: backend/utilities/cbom_sources/jobs.py:323 — targets after exclusions
  "cbsrc.col.targets": {
    label: "Targets",
    what: "How many addresses or names this source covers after its never-scan list and the team never-scan list are removed.",
    why: "Collection credits and run time grow with the number of targets.",
    example: "254 for 10.20.0.0/24 minus the two gateways.",
  },
  // src: frontend/components/cbom/sources/ServersTab.tsx:977-987 — the scan node that runs the source's jobs
  "cbsrc.col.node": {
    label: "Node",
    what: "The scan node that runs this source's jobs.",
    why: "An offline node means the source cannot be tested or collected.",
    example: "node-dc1 · Online.",
  },
  // src: frontend/components/cbom/sources/ServersTab.tsx:1415-1429 — Tier 1 or Tier 2
  "cbsrc.col.tier": {
    label: "Tier",
    what: "The privilege tier of a Linux source: Tier 1 without sudo, Tier 2 with the exact sudo allowlist.",
    why: "Tier 2 sees runtime crypto use that Tier 1 cannot.",
    example: "Tier 2 on the application servers, Tier 1 elsewhere.",
  },
  // src: backend/utilities/cbom_sources/jobs.py:716-736 — passed, partial, failed, could not test
  "cbsrc.col.last_test": {
    label: "Last test",
    what: "The result of the latest connection test: Not tested, Testing, Passed (every sample ready), Partly ready, Failed or Could not test, with its summary below.",
    why: "A source that has not passed a test is likely to fail its collection jobs.",
    example: "Partly ready · 3 of 5 samples ready.",
  },
  // src: backend/utilities/cbom_sources/jobs.py:323 — sampled target
  "cbsrc.test.server": {
    label: "Server",
    what: "One of the targets sampled for the connection test.",
    why: "Samples stand in for the whole range, so fix their failures before running.",
    example: "10.20.0.17.",
  },
  // src: frontend/components/cbom/sources/ServersTab.tsx:1800-1802 — yes, no, or waiting
  "cbsrc.test.reachable": {
    label: "Reachable",
    what: "Whether the scan node could open a connection to the server on the configured port.",
    why: "No here points at routing, a firewall or the wrong port, not the credential.",
    example: "No: port 22 is filtered between node-dc1 and 10.20.0.17.",
  },
  // src: frontend/components/cbom/sources/ServersTab.tsx:1800-1803 — yes, no, or waiting
  "cbsrc.test.login": {
    label: "Login",
    what: "Whether the login user could authenticate with the configured credential.",
    why: "No here means the key, certificate or password is not accepted on that server.",
    example: "No: the node's key is not in authorized_keys of zs-cbom.",
  },
  // src: frontend/components/cbom/sources/ServersTab.tsx:1791, frontend/components/cbom/sources/ServersTab.tsx:1804 — sudo allowlist (Linux Tier 2) or Windows group
  "cbsrc.test.privilege": {
    label: "Privilege",
    what: "Linux Tier 2: whether the sudo allowlist works. Windows: whether the account may open a WinRM shell (Remote Management Users with WinRM access). Not needed for Linux Tier 1.",
    why: "Without it, runtime crypto use is not collected even though the login works.",
    example: "No: the sudoers file was not installed on 10.20.0.17.",
  },
  // src: frontend/components/cbom/sources/ServersTab.tsx:1779-1784 — the sample's status and note
  "cbsrc.test.result": {
    label: "Result",
    what: "The sample's overall status with the node's note, for example Ready, Unreachable or Login failed.",
    why: "The note names the exact cause to fix.",
    example: "Login failed · Permission denied (publickey).",
  },
  // ────────────────────────────────────────────────────────────── CBOM Sources: source metadata (components/cbom/sources/SourceMetadata.tsx)
  // src: backend/utilities/cbom_sources/kinds.py:55-56, backend/utilities/cbom_sources/kinds.py:67, backend/utilities/cbom_sources/waves.py:121 — up to 128 characters; the default remediation owner
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
  // src: backend/utilities/cbom_sources/kinds.py:54, backend/utilities/cbom_sources/posture.py:47, backend/utilities/cbom_sources/posture.py:398 — overrides the derived exposure; internet x1.5
  "cbsrc.meta.exposure": {
    label: "Internet exposure",
    what: "Overrides the internet exposure worked out from the collected facts: From collected facts (no override), Internet-facing, Internal or Unknown. Internet-facing multiplies the risk score of this source's findings by 1.5.",
    why: "Systems reachable from the internet are attacked first, so their weak crypto ranks higher.",
    example: "Internet-facing for the API gateway servers behind the public load balancer.",
  },
  // src: backend/utilities/cbom_sources/kinds.py:53, backend/utilities/cbom_sources/posture.py:44, backend/utilities/cbom_sources/posture.py:496-497 — low 0.5, medium 1, high 1.5, critical 2
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
  // src: frontend/components/cbom/sources/SourceMetadata.tsx:240-250 — which sources the bulk edit changes
  "cbsrc.meta.select": {
    label: "Select sources",
    what: "Choose the sources the values below are written to; the first box selects every source.",
    why: "Only selected sources change; the others keep their values.",
    example: "Tick dc-mumbai-linux and dc-mumbai-windows, then Apply.",
  },
  // ────────────────────────────────────────────────────────────── CBOM Sources: Kubernetes, databases, HSMs and key managers (components/cbom/sources/ClustersDatabasesTab.tsx)
  // src: frontend/components/cbom/sources/ClustersDatabasesTab.tsx:374 — read through a scan node
  "cbsrc.k8sdb.intro": {
    label: "Kubernetes clusters and databases",
    what: "Kubernetes clusters, databases, HSMs and key managers, each read through a scan node inside your network.",
    why: "Clusters and databases terminate much of your TLS and store keys and certificates that servers alone do not show.",
    example: "prod-payments cluster and pg-core-01 database, both through node-dc1.",
  },
  // src: frontend/components/cbom/sources/ClustersDatabasesTab.tsx:426-472 — clusters, databases, HSMs and key managers of the team
  "cbsrc.k8sdb.list": {
    label: "Configured clusters and databases",
    what: "The cluster, database, HSM and key manager sources of this team with their endpoint, access level or login, scan node and last connection test.",
    why: "These sources are what a run collects from on the Review & Run tab.",
    example: "pg-core-01 · PostgreSQL · pg-core-01.bank.local:5432 · zs_cbom · Passed.",
  },
  // src: frontend/components/cbom/sources/ClustersDatabasesTab.tsx:468 — API server URL, host and port, module or KMIP host
  "cbsrc.col.endpoint": {
    label: "Endpoint",
    what: "Where the source is reached: the cluster's API server URL, the database host and port, the PKCS#11 module, or the KMIP server.",
    why: "The scan node must reach this endpoint for the source's jobs to succeed.",
    example: "https://10.30.0.5:6443 for a cluster.",
  },
  // src: frontend/components/cbom/sources/ClustersDatabasesTab.tsx:469 — tier for clusters, login for databases
  "cbsrc.col.access": {
    label: "Access / login",
    what: "How the source is read: the access tier of a cluster (Tier 1 without Secrets, Tier 2 with) or the login of a database.",
    why: "It shows how much each source's credential can see.",
    example: "Tier 1 for prod-payments; zs_cbom for pg-core-01.",
  },
  // src: frontend/components/cbom/sources/ClustersDatabasesTab.tsx:909-915 — read through the Kubernetes API with a read-only ClusterRole
  "cbsrc.k8s.form": {
    label: "Kubernetes cluster",
    what: "A Kubernetes cluster read through its API with a read-only ClusterRole: versions, API server and ingress TLS, cert-manager certificates, keys in ConfigMaps and service mesh mTLS policy.",
    why: "Clusters hold many certificates that rotate on their own and are easy to lose track of.",
    example: "prod-payments, https://10.30.0.5:6443, Tier 1, through node-dc1.",
  },
  // src: frontend/components/cbom/sources/ClustersDatabasesTab.tsx:918-919 — 1-64 characters
  "cbsrc.k8s.name": {
    label: "Cluster name",
    what: "A name for this cluster, 1 to 64 letters, digits, spaces, dots, dashes or underscores, shown in lists, run results and reports.",
    why: "Each asset found records it as its source.",
    example: "prod-payments.",
  },
  // src: frontend/components/cbom/sources/ClustersDatabasesTab.tsx:921-932 — the Kubernetes API endpoint
  "cbsrc.k8s.api_url": {
    label: "API server URL",
    what: "The HTTPS address of the cluster's Kubernetes API server, as in the server field of your kubeconfig.",
    why: "The scan node talks only to this URL; it must be reachable from the node.",
    example: "https://10.30.0.5:6443.",
  },
  // src: frontend/components/cbom/sources/ClustersDatabasesTab.tsx:934-941, backend/utilities/cbom_sources/kinds.py:21 — PEM up to 64 KB; optional with certificate-authority-data
  "cbsrc.k8s.ca": {
    label: "Cluster CA certificate",
    what: "The PEM certificate of the cluster's CA, used to verify the API server before the token is sent. Optional when the kubeconfig embeds certificate-authority-data.",
    why: "Without verification a spoofed API server could capture the service account token.",
    example: "The ca.crt from /etc/kubernetes/pki on a control plane node.",
  },
  // src: frontend/components/cbom/sources/ClustersDatabasesTab.tsx:988-997 — kubeconfig or token from vault
  "cbsrc.k8s.credential": {
    label: "Cluster credential",
    what: "Upload kubeconfig: encrypted at rest and sent only to the scan node. Token from vault: the node fetches it when the job runs (team admins only).",
    why: "A token kept in your vault never rests on ZeroShield.",
    example: "A kubeconfig for the service account zs-cbom bound to the ClusterRole below.",
  },
  // src: frontend/components/cbom/sources/ClustersDatabasesTab.tsx:890-894,1006, frontend/components/cbom/sources/ClustersDatabasesTab.tsx:1005-1017 — exec and auth-provider plugins refused
  "cbsrc.k8s.kubeconfig": {
    label: "Kubeconfig file",
    what: "The kubeconfig of the zs-cbom service account. It is sent once, encrypted at rest and sent only to the scan node that runs the job. Configs that use exec or auth-provider plugins are refused.",
    why: "Plugins would run commands on the scan node; a static token keeps the node's footprint read-only.",
    example: "zs-cbom.kubeconfig with a token for the zs-cbom service account.",
  },
  // src: frontend/components/cbom/sources/ClustersDatabasesTab.tsx:1052-1053 — up to 128 characters; blank uses current-context
  "cbsrc.k8s.context": {
    label: "Context",
    what: "Which context of the kubeconfig to use, up to 128 characters. Blank uses its current-context.",
    why: "A kubeconfig with several clusters would otherwise read whichever was last selected.",
    example: "prod-payments-admin.",
  },
  // src: frontend/components/cbom/sources/ClustersDatabasesTab.tsx:1072-1093 — Tier 1 without Secrets; Tier 2 reads TLS Secrets, private keys dropped unparsed
  "cbsrc.k8s.tier": {
    label: "Access tier",
    what: "Tier 1 reads versions, API server and ingress TLS, Secret names, cert-manager Certificates, certificates in ConfigMaps and mesh mTLS policy. Tier 2 also reads the certificates of TLS Secrets; their private keys are dropped unparsed and never stored or sent.",
    why: "Tier 2 covers certificates kept only in Secrets, but its token can read Secret values.",
    example: "Tier 2 finds the expiring ingress certificate stored in secret payments-tls.",
  },
  // src: frontend/components/cbom/sources/ClustersDatabasesTab.tsx:1095-1103 — Kubernetes cannot grant Secret names without values
  "cbsrc.k8s.tier2_warning": {
    label: "Tier 2 can read Secret values",
    what: "Kubernetes cannot grant access to Secret names without their values, so a Tier 2 token can read them. Only metadata such as fingerprints is sent to ZeroShield.",
    why: "The token is as sensitive as the Secrets it can read; protect it accordingly.",
    example: "Try Tier 2 on a staging cluster before production.",
  },
  // src: frontend/components/cbom/sources/ClustersDatabasesTab.tsx:1136-1138 — link the cloud account that runs it
  "cbsrc.k8s.managed": {
    label: "Managed cluster",
    what: "Tick for EKS, AKS or GKE clusters to link the cloud account source that runs the cluster.",
    why: "The cloud account holds the encryption-at-rest settings of the cluster's Secrets.",
    example: "EKS cluster prod-payments, linked to the AWS account aws-prod.",
  },
  // src: frontend/components/cbom/sources/ClustersDatabasesTab.tsx:1141-1147 — stored as a link until cloud collection reads it
  "cbsrc.k8s.cloud": {
    label: "Cloud account",
    what: "The cloud account source that runs this managed cluster. Secret encryption at rest is read from this account once cloud collection is available; until then it is stored as a link.",
    why: "Ties the cluster's findings to the account where the fix is made.",
    example: "aws-prod · AWS account.",
  },
  // src: frontend/components/cbom/sources/ClustersDatabasesTab.tsx:1387-1392, backend/utilities/cbom_sources/kinds.py:382-391 — read-only login
  "cbsrc.db.form": {
    label: "Database",
    what: "A database server read with a read-only login: its TLS setup, certificates and encryption settings. Run the grant shown below once as an admin.",
    why: "Databases hold the most sensitive data; weak TLS or unencrypted storage there is a top finding.",
    example: "pg-core-01.bank.local:5432, login zs_cbom, Require TLS with the bank CA.",
  },
  // src: frontend/components/cbom/sources/ClustersDatabasesTab.tsx:1396-1397 — 1-64 characters
  "cbsrc.db.name": {
    label: "Name",
    what: "A name for this database source, 1 to 64 characters, shown in lists, run results and reports.",
    why: "Each asset found records it as its source.",
    example: "pg-core-01.",
  },
  // src: frontend/components/cbom/sources/ClustersDatabasesTab.tsx:62-69, backend/utilities/cbom_sources/kinds.py:379 — PostgreSQL, MySQL/MariaDB, SQL Server, Oracle, MongoDB, Redis
  "cbsrc.db.engine": {
    label: "Engine",
    what: "The database engine: PostgreSQL, MySQL / MariaDB, SQL Server, Oracle, MongoDB or Redis. It sets the default port, the grant to run and how the login is protected.",
    why: "Each engine exposes its crypto settings differently, so the wrong engine reads nothing.",
    example: "SQL Server, default port 1433.",
  },
  // src: backend/utilities/cbom_sources/kinds.py:384 — up to 253 characters
  "cbsrc.db.host": {
    label: "Host",
    what: "The database server's hostname or IP address, up to 253 characters, as the scan node reaches it.",
    why: "Use the name in the server's certificate so the TLS check passes.",
    example: "pg-core-01.bank.local.",
  },
  // src: backend/utilities/cbom_sources/kinds.py:379, backend/utilities/cbom_sources/kinds.py:385 — 1-65535; engine default when blank
  "cbsrc.db.port": {
    label: "Port",
    what: "The database port, 1 to 65535. Blank uses the engine's default: PostgreSQL 5432, MySQL 3306, SQL Server 1433, Oracle 1521, MongoDB 27017, Redis 6379.",
    why: "A wrong port fails the connection test before the login is tried.",
    example: "6432 when PostgreSQL sits behind PgBouncer.",
  },
  // src: backend/utilities/cbom_sources/kinds.py:386, backend/utilities/cbom_sources/kinds.py:27 — up to 64 characters; optional for engines that run without authentication
  "cbsrc.db.login": {
    label: "Login",
    what: "The read-only login the node connects with, up to 64 characters. Optional for MongoDB and Redis servers that run without authentication.",
    why: "A dedicated login with only the grants below limits what a leaked password can do.",
    example: "zs_cbom.",
  },
  // src: backend/utilities/cbom_sources/kinds.py:391 — up to 128 characters; required for Oracle
  "cbsrc.db.database": {
    label: "Database or service name",
    what: "For Oracle, the service (PDB) the login and grants belong to (required). For other engines, the database to connect to first (optional); server-wide settings are read from there.",
    why: "Oracle logins exist per service, so a wrong name fails the login.",
    example: "ORCLPDB1 for Oracle; postgres for PostgreSQL.",
  },
  // src: frontend/components/cbom/sources/ClustersDatabasesTab.tsx:1455-1463 — password or password from vault
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
  // src: backend/utilities/cbom_sources/kinds.py:389 — on by default
  "cbsrc.db.require_tls": {
    label: "Require TLS to the database",
    what: "On (the default): the node connects only over TLS. Off: it may connect without TLS and records that the server allows plaintext.",
    why: "TLS keeps the login and the data in transit away from anyone on the network path.",
    example: "Leave on; turn off only for a legacy server you are documenting as plaintext.",
  },
  // src: frontend/components/cbom/sources/ClustersDatabasesTab.tsx:1501-1518, backend/utilities/cbom_sources/kinds.py:390 — PEM up to 64 KB; required with a password for MySQL, Redis, SQL Server
  "cbsrc.db.ca": {
    label: "Database CA certificate",
    what: "The PEM certificate of the CA that signed the database server's certificate. The node checks the server against it before sending a password. Required with a password for MySQL, Redis and SQL Server; optional otherwise.",
    why: "It proves the node is talking to the real database, not an impostor collecting credentials.",
    example: "bank-root-ca.pem.",
  },
  // src: frontend/components/cbom/sources/ClustersDatabasesTab.tsx:1788-1793, frontend/components/cbom/sources/ClustersDatabasesTab.tsx:1628-1639,1789 — attributes only, never key values
  "cbsrc.km.form": {
    label: "HSM or key manager",
    what: "An HSM or token read through PKCS#11, or a KMIP key manager. Keys are inventoried by their attributes only: type, size, flags, state and dates. No key value ever leaves the device.",
    why: "Keys in HSMs sign payments and certificates; their algorithms and sizes decide the post-quantum migration work.",
    example: "hsm-payments-01, a Luna HSM read through module luna.",
  },
  // src: frontend/components/cbom/sources/ClustersDatabasesTab.tsx:1796-1797 — 1-64 characters
  "cbsrc.km.name": {
    label: "Name",
    what: "A name for this HSM or key manager source, 1 to 64 characters, shown in lists, run results and reports.",
    why: "Each key found records it as its source.",
    example: "hsm-payments-01.",
  },
  // src: frontend/components/cbom/sources/ClustersDatabasesTab.tsx:1800-1809 — PKCS#11 or KMIP
  "cbsrc.km.provider": {
    label: "Kind of key manager",
    what: "HSM or token (PKCS#11): read through the vendor library on the scan node. KMIP server: read over TLS with a client certificate.",
    why: "It decides how the node connects and which credential it needs.",
    example: "KMIP for a Thales CipherTrust Manager.",
  },
  // src: frontend/components/cbom/sources/ClustersDatabasesTab.tsx:1815-1823 — mapped in ZS_PKCS11_MODULES on the node
  "cbsrc.km.module": {
    label: "Module name",
    what: "The name the scan node's operator maps to a PKCS#11 library in ZS_PKCS11_MODULES on the node. ZeroShield never sends a library path.",
    why: "Only libraries the node's operator approved can be loaded.",
    example: "luna, mapped to /usr/safenet/lunaclient/lib/libCryptoki2_64.so.",
  },
  // src: frontend/components/cbom/sources/ClustersDatabasesTab.tsx:1825-1826 — up to 32 characters; blank reads every initialised token
  "cbsrc.km.token": {
    label: "Token label",
    what: "The label of the token or partition to read, up to 32 characters. Blank reads every initialised token the module shows.",
    why: "Limits the read to the partition you mean when an HSM is shared.",
    example: "payments-partition.",
  },
  // src: frontend/components/cbom/sources/ClustersDatabasesTab.tsx:1831-1837 — PIN, PIN from vault; optional
  "cbsrc.km.pin_source": {
    label: "PIN source",
    what: "The crypto user PIN, typed here (encrypted at rest) or fetched from your vault when the job runs. Optional: without it only public objects are read.",
    why: "Private and secret keys are only listed after a login with the PIN.",
    example: "PIN from vault for the crypto user of payments-partition.",
  },
  // src: frontend/components/cbom/sources/ClustersDatabasesTab.tsx:1842, backend/utilities/cbom_sources/kinds.py:20 — encrypted at rest
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
  // src: frontend/components/cbom/sources/ClustersDatabasesTab.tsx:1862 — default 5696
  "cbsrc.km.port": {
    label: "KMIP port",
    what: "The KMIP port, default 5696.",
    why: "A wrong port fails the connection test before TLS starts.",
    example: "5696.",
  },
  // src: frontend/components/cbom/sources/ClustersDatabasesTab.tsx:1866-1873 — optional PEM; verifies the KMIP server
  "cbsrc.km.ca": {
    label: "Server CA certificate",
    what: "Optional PEM certificate of the CA that issued the KMIP server's certificate. With it the node verifies the server; TLS client authentication never reveals the client key either way.",
    why: "Verifying the server proves the inventory comes from your real key manager.",
    example: "The CipherTrust root CA certificate.",
  },
  // src: frontend/components/cbom/sources/ClustersDatabasesTab.tsx:1876, backend/utilities/cbom_sources/kinds.py:20 — PEM, encrypted at rest
  "cbsrc.km.client_cert": {
    label: "Client certificate",
    what: "The PEM client certificate the node presents to the KMIP server. Encrypted at rest and sent only to the scan node.",
    why: "KMIP servers admit only clients with a certificate they trust.",
    example: "zs-cbom-client.crt issued by the KMIP server's CA.",
  },
  // src: frontend/components/cbom/sources/ClustersDatabasesTab.tsx:1877, backend/utilities/cbom_sources/kinds.py:20 — PEM, unencrypted; encrypted at rest
  "cbsrc.km.client_key": {
    label: "Client private key",
    what: "The unencrypted PEM private key of the client certificate. Encrypted at rest by ZeroShield, never shown again, sent only to the scan node.",
    why: "Give the KMIP client read-only rights so this key can list objects but not export them.",
    example: "-----BEGIN PRIVATE KEY----- ....",
  },
  // ────────────────────────────────────────────────────────────── CBOM Sources: Cloud & Identity (components/cbom/sources/CloudIdentityTab.tsx)
  // src: frontend/components/cbom/sources/CloudIdentityTab.tsx:75-89,520 — AWS by role, Azure by app registration, Google Cloud by service account
  "cbsrc.cloud.connect": {
    label: "Connect a cloud account",
    what: "Connect an AWS account (ZeroShield assumes a read-only role with your external ID, no keys exchanged), an Azure subscription (Key Vault metadata through an app registration) or Google Cloud (KMS, CA Service and Secret Manager metadata through a service account).",
    why: "Cloud KMS keys, certificates and secrets are a large part of the crypto estate and are invisible to network scans.",
    example: "AWS account 111122223333 with the ZeroShieldCBOMReader role in eu-west-1 and ap-south-1.",
  },
  // src: frontend/components/cbom/sources/CloudIdentityTab.tsx:579-592 — the checks of the last validation
  "cbsrc.cloud.validation": {
    label: "Validation",
    what: "The checks of the last validation of the selected account: each read-only call ZeroShield tried and whether it passed, failed, was skipped or hit an error.",
    why: "An account that fails a check is collected only partly, so fix the role or permission it names.",
    example: "kms:ListKeys in ap-south-1 · Fail: the role is missing kms:ListKeys.",
  },
  // src: frontend/components/cbom/sources/CloudIdentityTab.tsx:596-600 — 4 credits per account per run
  "cbsrc.cloud.list": {
    label: "Connected cloud accounts",
    what: "The cloud accounts of this team. Accounts that pass validation are scanned read-only from ZeroShield's cloud, 4 credits per account per run.",
    why: "Only accounts listed here are part of a run's cloud inventory.",
    example: "payments-prod · AWS · One account · 2 regions · Valid.",
  },
  // src: frontend/components/cbom/sources/CloudIdentityTab.tsx:624 — the provider's account or tenant
  "cbsrc.cloud.col.account": {
    label: "Account",
    what: "The cloud provider and the account, subscription or project identifier.",
    why: "Tells you where to make a fix in the provider's console.",
    example: "AWS 111122223333.",
  },
  // src: frontend/components/cbom/sources/CloudIdentityTab.tsx:1115-1125 — one account or a whole AWS Organization
  "cbsrc.cloud.col.scope": {
    label: "Scope",
    what: "What the connection covers: one account, or every member account of an AWS Organization through a StackSet.",
    why: "An Organization connection picks up new member accounts without another setup.",
    example: "Whole AWS Organization · 37 accounts.",
  },
  // src: frontend/components/cbom/sources/CloudIdentityTab.tsx:1259-1266 — regions read in each run
  "cbsrc.cloud.col.regions": {
    label: "Regions",
    what: "For an AWS account, how many regions are read in each run; resources in other regions are not inventoried. A dash for Azure and Google Cloud.",
    why: "Keys and certificates in a forgotten region are a common blind spot.",
    example: "2: eu-west-1 and ap-south-1.",
  },
  // src: frontend/components/cbom/sources/CloudIdentityTab.tsx:628 — time of the last validation
  "cbsrc.cloud.col.validated": {
    label: "Last validated",
    what: "When the account was last validated (ZeroShield tried each read-only call), or Never.",
    why: "A role changed since then may make the next run fail.",
    example: "12 Nov 2026, 10:42 am IST.",
  },
  // src: frontend/components/cbom/sources/CloudIdentityTab.tsx:143-149, frontend/components/cbom/sources/CloudIdentityTab.tsx:629 — result of the last validation
  "cbsrc.cloud.col.status": {
    label: "Status",
    what: "The result of the last validation: Not tested, Testing, Passed (every check passed), Partly ready (some checks failed), Failed or Could not test. Hover the badge for its summary.",
    why: "Only valid accounts are scanned fully in a run.",
    example: "Partly ready: KMS passed, ACM was denied.",
  },
  // src: frontend/components/cbom/sources/CloudIdentityTab.tsx:705 — CAs, CLM tools and your domains
  "cbsrc.cloud.certificates": {
    label: "Certificates",
    what: "Where your certificates come from: certificate authorities and CLM tools you connect, and the domains you own (searched in Certificate Transparency logs where available).",
    why: "Certificates issued outside your managed CAs are the ones that expire unnoticed.",
    example: "AD CS through node-dc1, and bank.in searched in CT logs.",
  },
  // src: frontend/components/cbom/sources/CloudIdentityTab.tsx:100-111,714, frontend/components/cbom/sources/CloudIdentityTab.tsx:714, backend/utilities/cbom_sources/kinds.py:605-618 — AD CS, Vault and EJBCA by a scan node; AWS Private CA by its AWS account; CLM tools not collected
  "cbsrc.cloud.cas": {
    label: "Certificate authorities and CLM",
    what: "Microsoft AD CS, HashiCorp Vault PKI and EJBCA are read by a scan node inside your network. AWS Private CA is read by the connected AWS account it names. Venafi, Keyfactor, DigiCert, Sectigo and other CLM tools are not collected: only their name and API address are saved, no key is asked for and nothing is charged.",
    why: "Your CA knows every certificate it issued, including ones on hosts no scan reaches.",
    example: "AD CS on ca01.bank.local, read by node-dc1 over WinRM.",
  },
  // src: frontend/components/cbom/sources/CloudIdentityTab.tsx:761, frontend/components/cbom/sources/CloudIdentityTab.tsx:761 — public OIDC and SAML metadata, free
  "cbsrc.cloud.idps": {
    label: "Identity providers",
    what: "Signing keys and certificates of your identity providers, read by ZeroShield's cloud from each provider's public OIDC and SAML metadata. Free.",
    why: "An IdP signing with RSA-2048 or SHA-1 signs every login; it is a key migration target.",
    example: "Okta at https://bank.okta.com: 2 signing keys, RS256, one expiring in 30 days.",
  },
  // src: frontend/components/cbom/sources/CloudIdentityTab.tsx:1115-1125 — CloudFormation stack or StackSet
  "cbsrc.aws.scope": {
    label: "Scope",
    what: "One account: create a CloudFormation stack in that account. Whole AWS Organization: deploy a StackSet from the management account to every member account.",
    why: "It decides which template you deploy and which accounts are inventoried.",
    example: "Whole AWS Organization for 37 accounts managed by Control Tower.",
  },
  // src: frontend/components/cbom/sources/CloudIdentityTab.tsx:1152-1185 — off by default; template parameters follow the switches
  "cbsrc.aws.optional_reads": {
    label: "Optional reads",
    what: "Extra permissions you may grant the read-only role, off by default. The template's parameters follow these switches; changing one later means updating the stack and validating again.",
    why: "Each adds coverage but also a permission that could, in a misconfigured account, return a secret.",
    example: "Turn on Read Glue connections to see which connections skip TLS.",
  },
  // src: frontend/components/cbom/sources/CloudIdentityTab.tsx:1153-1168 — kms:Decrypt for Lambda environments; only their shape is kept
  "cbsrc.aws.lambda_cmk": {
    label: "Decrypt Lambda environment variables",
    what: "Lets the role decrypt Lambda environment variables so ZeroShield can check them for keys and passwords; only their shape is kept, never the values. Off: each function's environment is listed as not inspected.",
    why: "Hard-coded keys in Lambda environments are a frequent finding.",
    example: "On: a function with DB_PASSWORD set in plain text is flagged.",
  },
  // src: frontend/components/cbom/sources/CloudIdentityTab.tsx:1170-1183 — TLS enforcement and password storage of each connection
  "cbsrc.aws.glue": {
    label: "Read Glue connections",
    what: "Reports whether each Glue connection enforces TLS and where its password is stored. ZeroShield asks with HidePassword and keeps only those settings.",
    why: "If Data Catalog password encryption is off, this permission could return a password in plain text.",
    example: "jdbc-core-banking: TLS not enforced, password in the connection.",
  },
  // src: backend/utilities/cbom_sources/kinds.py:29, frontend/components/cbom/sources/CloudIdentityTab.tsx:1239-1254 — arn:aws:iam::<12 digits>:role/<name>
  "cbsrc.aws.role_arn": {
    label: "Role ARN",
    what: "The ARN of the read-only role the stack created (the RoleArn output). For an Organization, the role in the management account.",
    why: "ZeroShield assumes this role with your external ID; nothing else gives it access.",
    example: "arn:aws:iam::111122223333:role/ZeroShieldCBOMReader.",
  },
  // src: frontend/components/cbom/sources/CloudIdentityTab.tsx:1259, frontend/components/cbom/sources/CloudIdentityTab.tsx:1259-1276 — AWS region codes; the first one is used for the test read
  "cbsrc.aws.regions": {
    label: "Regions",
    what: "The AWS regions to read, as region codes; press Enter or Add region after each. The first region is used for the validation read.",
    why: "Resources in regions not listed are not inventoried.",
    example: "ap-south-1 and ap-south-2 for the Mumbai and Hyderabad regions.",
  },
  // src: frontend/components/cbom/sources/CloudIdentityTab.tsx:1293-1300 — up to 64 characters; blank uses aws-<account id>
  "cbsrc.aws.name": {
    label: "Name",
    what: "A name for this account, up to 64 characters. Blank uses aws-<account id>.",
    why: "Each asset found records it as its source.",
    example: "payments-prod.",
  },
  // src: frontend/components/cbom/sources/CloudIdentityTab.tsx:1468-1469 — up to 64 characters
  "cbsrc.azure.name": {
    label: "Name",
    what: "A name for this Azure connection, 1 to 64 characters, shown in lists, run results and reports.",
    why: "Each asset found records it as its source.",
    example: "azure-prod.",
  },
  // src: backend/utilities/cbom_sources/kinds.py:28, frontend/components/cbom/sources/CloudIdentityTab.tsx:1471-1481 — a GUID
  "cbsrc.azure.tenant": {
    label: "Directory (tenant) ID",
    what: "The GUID of your Microsoft Entra directory (tenant), from the app registration's Overview page.",
    why: "The app registration signs in to this tenant only.",
    example: "72f988bf-86f1-41af-91ab-2d7cd011db47.",
  },
  // src: backend/utilities/cbom_sources/kinds.py:28, frontend/components/cbom/sources/CloudIdentityTab.tsx:1483-1493 — a GUID
  "cbsrc.azure.client": {
    label: "Application (client) ID",
    what: "The GUID of the app registration that the reader script gave Key Vault Reader access.",
    why: "ZeroShield signs in as this app; its roles decide what can be read.",
    example: "0f3c6a2e-1b5d-4c8e-9a7f-2d4e6b8c0a1f.",
  },
  // src: frontend/components/cbom/sources/CloudIdentityTab.tsx:1496-1508 — client secret or certificate
  "cbsrc.azure.credential": {
    label: "Credential",
    what: "Client secret: from Certificates & secrets in the app registration. Certificate: a PEM certificate with its private key; ZeroShield signs a client assertion with it.",
    why: "A certificate credential never sends a reusable secret over the network.",
    example: "Certificate, with the same certificate uploaded to the app registration.",
  },
  // src: frontend/components/cbom/sources/CloudIdentityTab.tsx:1512, frontend/components/cbom/sources/CloudIdentityTab.tsx:1511-1520 — encrypted at rest; changing tenant, client ID or credential clears it
  "cbsrc.azure.secret": {
    label: "Client secret or certificate",
    what: "The client secret, or the PEM certificate with its private key. Encrypted at rest by ZeroShield and never shown again; changing the tenant, client ID or credential type clears it.",
    why: "It is the only credential of the connection; rotate it in Azure and paste the new one here.",
    example: "A client secret value created today, valid for 6 months.",
  },
  // src: frontend/components/cbom/sources/CloudIdentityTab.tsx:1523-1534 — one GUID per line, optional
  "cbsrc.azure.subs": {
    label: "Subscription IDs",
    what: "Optional: the subscriptions to read, one GUID per line. Blank reads every subscription the app can see.",
    why: "Narrowing it keeps a shared app registration from inventorying another unit's subscriptions.",
    example: "11111111-2222-3333-4444-555555555555.",
  },
  // src: frontend/components/cbom/sources/CloudIdentityTab.tsx:1637-1638 — up to 64 characters
  "cbsrc.gcp.name": {
    label: "Name",
    what: "A name for this Google Cloud connection, 1 to 64 characters, shown in lists, run results and reports.",
    why: "Each asset found records it as its source.",
    example: "gcp-payments.",
  },
  // src: frontend/components/cbom/sources/CloudIdentityTab.tsx:1640-1650 — numeric; blank lists projects instead
  "cbsrc.gcp.org": {
    label: "Organization ID",
    what: "The numeric ID of your Google Cloud organization. Leave blank to list the projects below instead.",
    why: "With an organization ID every project under it is read, including new ones.",
    example: "123456789012.",
  },
  // src: frontend/components/cbom/sources/CloudIdentityTab.tsx:1652-1661 — one per line; needed without an organization ID
  "cbsrc.gcp.projects": {
    label: "Project IDs",
    what: "The project IDs to read, one per line. Needed when there is no organization ID.",
    why: "Projects not listed are not inventoried.",
    example: "payments-prod and core-banking-dr.",
  },
  // src: frontend/components/cbom/sources/CloudIdentityTab.tsx:1663-1673 — up to 254 characters
  "cbsrc.gcp.email": {
    label: "Service account",
    what: "The email of the service account that the gcloud script granted the viewer roles to.",
    why: "ZeroShield reads as this account; its roles decide what is visible.",
    example: "zs-cbom@payments-prod.iam.gserviceaccount.com.",
  },
  // src: frontend/components/cbom/sources/CloudIdentityTab.tsx:1676, frontend/components/cbom/sources/CloudIdentityTab.tsx:1675-1688 — encrypted at rest; changing the service account clears it
  "cbsrc.gcp.key": {
    label: "Service account key (JSON)",
    what: "The JSON key of the service account, pasted or uploaded. Encrypted at rest by ZeroShield and never shown again; changing the service account clears it.",
    why: "Anyone with this key can act as the service account, so it should hold viewer roles only.",
    example: "The .json file from IAM > Service accounts > Keys.",
  },
  // src: frontend/components/cbom/sources/CloudIdentityTab.tsx:1690-1701 — .json up to 64 KB
  "cbsrc.gcp.key_file": {
    label: "Upload the key file",
    what: "Pick the .json key file instead of pasting it; it fills the key field above. Up to 64 KB.",
    why: "Uploading avoids copy-paste errors in the long key.",
    example: "zs-cbom-payments-prod-3f2a.json.",
  },
  // src: frontend/components/cbom/sources/CloudIdentityTab.tsx:1831, frontend/components/cbom/sources/CloudIdentityTab.tsx:1830-1836 — up to 200 domains; saved, not yet searched
  "cbsrc.cert.domains": {
    label: "Domains to search in Certificate Transparency logs",
    what: "Domains you own, up to 200. They are saved for the certificate collector; ZeroShield does not query Certificate Transparency logs on this deployment yet.",
    why: "CT logs list every public certificate issued for your domains, including ones nobody registered with IT.",
    example: "bank.in and bankonline.co.in.",
  },
  // src: frontend/components/cbom/sources/CloudIdentityTab.tsx:1945-1954 — searched every run from ZeroShield's cloud; credits per domain
  "cbsrc.ct.discovery": {
    label: "Certificate Transparency",
    what: "Every run, ZeroShield's cloud searches public Certificate Transparency logs for certificates issued for these domains, including hosts no scan node reaches. Expiring, expired, revoked and weak certificates, and certificates from CAs you have not listed, are flagged. 0.2 credits per domain searched, per run.",
    why: "A certificate issued by a CA you do not use can mean a mis-issuance or a shadow IT service.",
    example: "bank.in: 412 certificates found, 3 from an unexpected CA.",
  },
  // src: frontend/components/cbom/sources/CloudIdentityTab.tsx:1880, frontend/components/cbom/sources/CloudIdentityTab.tsx:1956-1989 — up to 1,000 domains; a leading *. is dropped
  "cbsrc.ct.domains": {
    label: "Domains",
    what: "The domains to search, up to 1,000. A leading *. is dropped; add each registered domain once.",
    why: "Each domain is one search per run, so list the ones you own.",
    example: "bank.in.",
  },
  // src: frontend/components/cbom/sources/CloudIdentityTab.tsx:2008-2011 — search subdomains too
  "cbsrc.ct.subdomains": {
    label: "Include subdomains",
    what: "Also search certificates for every subdomain of the listed domains.",
    why: "Most forgotten certificates sit on subdomains such as uat-api.bank.in.",
    example: "On: certificates for netbanking.bank.in are found too.",
  },
  // src: frontend/components/cbom/sources/CloudIdentityTab.tsx:2013, frontend/components/cbom/sources/CloudIdentityTab.tsx:2013-2015 — up to 50; matched on name, organisation or CN
  "cbsrc.ct.issuers": {
    label: "Certificate authorities you use",
    what: "Optional, up to 50: the CAs you expect. A certificate from any other CA is flagged as unexpected. Matched against the CA's name, organisation or CN: the whole value or its first words (at least 3 characters).",
    why: "Unexpected issuers point at mis-issuance or teams buying certificates outside policy.",
    example: "DigiCert and Let's Encrypt.",
  },
  // src: frontend/components/cbom/sources/CloudIdentityTab.tsx:2342-2359 — Sectigo or other
  "cbsrc.ca.product": {
    label: "Product",
    what: "Which certificate product this connection is for, when the row covers several.",
    why: "It names the source in reports.",
    example: "Sectigo Certificate Manager.",
  },
  // src: frontend/components/cbom/sources/CloudIdentityTab.tsx:2364-2365 — up to 64 characters
  "cbsrc.ca.name": {
    label: "Name",
    what: "A name for this CA connection, 1 to 64 characters, shown in lists, run results and reports.",
    why: "Each certificate found records it as its source.",
    example: "AD CS Mumbai.",
  },
  // src: frontend/components/cbom/sources/CloudIdentityTab.tsx:2370-2372, backend/utilities/cbom_sources/kinds.py:513 — AD CS, Vault, EJBCA are read through a node
  "cbsrc.ca.node": {
    label: "Scan node",
    what: "The scan node, in a segment that reaches the certificate authority, that reads it.",
    why: "Internal CAs are rarely reachable from the internet, so a node inside the network reads them.",
    example: "node-dc1, which reaches ca01.bank.local on 5986.",
  },
  // src: frontend/components/cbom/sources/CloudIdentityTab.tsx:2391-2392 — reached over WinRM HTTPS (5986)
  "cbsrc.ca.host": {
    label: "CA server",
    what: "The AD CS server's hostname, reached over WinRM HTTPS (5986). Run the Windows setup script from the Servers tab on it first.",
    why: "The CA database lists every certificate it issued, including ones on hosts no scan reaches.",
    example: "ca01.bank.local.",
  },
  // src: frontend/components/cbom/sources/CloudIdentityTab.tsx:2394-2395, backend/utilities/cbom_sources/kinds.py:27 — up to 64 characters
  "cbsrc.ca.login": {
    label: "Read-only Windows account",
    what: "A read-only Windows account on the CA server, in Remote Management Users; DOMAIN\\user is accepted.",
    why: "A non-admin account limits what a leaked password can do on your CA.",
    example: "BANK\\svc-zscbom.",
  },
  // src: frontend/components/cbom/sources/CloudIdentityTab.tsx:2397-2406 — encrypted at rest; changing server, account, CA or node clears it
  "cbsrc.ca.password": {
    label: "Password",
    what: "The password of the read-only account. Encrypted at rest and sent only to the scan node; changing the server, account, CA or node clears it.",
    why: "Clearing it on change keeps the password from going to a host it was not meant for.",
    example: "The password of svc-zscbom.",
  },
  // src: frontend/components/cbom/sources/CloudIdentityTab.tsx:2412-2428 — read through a connected AWS account's role
  "cbsrc.ca.aws": {
    label: "AWS account",
    what: "The connected AWS account whose read-only role reads AWS Private CA. No new credential is needed.",
    why: "Private CAs in AWS issue internal certificates that never appear in CT logs.",
    example: "payments-prod · 111122223333.",
  },
  // src: frontend/components/cbom/sources/CloudIdentityTab.tsx:2433-2443 — HTTPS, up to 512 characters
  "cbsrc.ca.api_url": {
    label: "API address",
    what: "The HTTPS address of the CA or CLM API, up to 512 characters. For Venafi, Keyfactor, DigiCert, Sectigo and others only this address and the name are saved: nothing is read from them.",
    why: "The scan node or the certificate collector calls only this address.",
    example: "https://vault.corp.example.com:8200 for Vault PKI.",
  },
  // src: frontend/components/cbom/sources/CloudIdentityTab.tsx:2448-2457 — read-only policy; encrypted at rest
  "cbsrc.ca.vault_token": {
    label: "Vault token",
    what: "A Vault token bound to the read-only policy shown below. Encrypted at rest and sent only to the scan node; changing the address, CA or node clears it.",
    why: "The policy lets it list PKI mounts and transit keys without signing or decrypting.",
    example: "A periodic token created with vault token create -policy=zs-cbom-read.",
  },
  // src: frontend/components/cbom/sources/CloudIdentityTab.tsx:2458-2466 — the read-only HCL policy
  "cbsrc.ca.vault_policy": {
    label: "Policy for the token",
    what: "The Vault policy to bind to the token: read and list on PKI and transit metadata only.",
    why: "Review it before creating the token; it grants no sign, issue or decrypt rights.",
    example: "vault policy write zs-cbom-read zs-cbom-read.hcl.",
  },
  // src: frontend/components/cbom/sources/CloudIdentityTab.tsx:2474 — PEM, encrypted at rest
  "cbsrc.ca.client_cert": {
    label: "Client certificate",
    what: "The PEM client certificate the scan node presents to the EJBCA REST API. Encrypted at rest and sent only to the scan node.",
    why: "EJBCA admits only clients whose certificate maps to an administrator role.",
    example: "zs-cbom-reader.crt issued by the EJBCA ManagementCA.",
  },
  // src: frontend/components/cbom/sources/CloudIdentityTab.tsx:2475-2484 — PEM, unencrypted; encrypted at rest
  "cbsrc.ca.client_key": {
    label: "Client private key",
    what: "The unencrypted PEM private key of the client certificate. Encrypted at rest and sent only to the scan node; changing the address, CA or node clears it.",
    why: "Give the matching EJBCA role read-only rights so the key cannot issue certificates.",
    example: "-----BEGIN PRIVATE KEY----- ....",
  },
  // src: frontend/components/cbom/sources/CloudIdentityTab.tsx:2491-2499 — optional PEM; verified before signing in
  "cbsrc.ca.ca_pem": {
    label: "CA of the server certificate",
    what: "Optional PEM certificate of the CA that issued the server's TLS (or WinRM) certificate. The node verifies the server with it before signing in.",
    why: "Needed when the server uses a private CA; without it the TLS check fails.",
    example: "bank-root-ca.pem.",
  },
  // src: frontend/components/cbom/sources/CloudIdentityTab.tsx:2618-2619 — up to 64 characters
  "cbsrc.idp.name": {
    label: "Name",
    what: "A name for this identity provider, 1 to 64 characters, shown in lists, run results and reports.",
    why: "Each signing key found records it as its source.",
    example: "Okta workforce.",
  },
  // src: frontend/components/cbom/sources/CloudIdentityTab.tsx:2622-2630 — a GUID
  "cbsrc.idp.tenant": {
    label: "Directory (tenant) ID",
    what: "The GUID of your Microsoft Entra directory (tenant).",
    why: "The app registration signs in to this tenant only.",
    example: "72f988bf-86f1-41af-91ab-2d7cd011db47.",
  },
  // src: frontend/components/cbom/sources/CloudIdentityTab.tsx:2641-2650,2636 — HTTPS, up to 512 characters
  "cbsrc.idp.base_url": {
    label: "Okta domain or base URL",
    what: "Okta: your Okta domain. Keycloak: the base URL of the server. ADFS: the server address; its public OpenID metadata and federation metadata are read from it. HTTPS, up to 512 characters.",
    why: "Signing keys are read from this address's public metadata.",
    example: "https://adfs.bank.in for ADFS.",
  },
  // src: frontend/components/cbom/sources/CloudIdentityTab.tsx:2653-2655 — up to 128 characters
  "cbsrc.idp.realm": {
    label: "Realm",
    what: "The Keycloak realm whose clients and keys are read, up to 128 characters.",
    why: "Each realm has its own signing keys.",
    example: "corp.",
  },
  // src: frontend/components/cbom/sources/CloudIdentityTab.tsx:2658-2660 — Entra application ID or Keycloak client ID
  "cbsrc.idp.client": {
    label: "Client ID",
    what: "Entra ID: the application (client) ID of the app registration with Application.Read.All. Keycloak: the confidential client with read-only access to clients and keys.",
    why: "With it ZeroShield also reads the app registrations' certificates and secrets metadata.",
    example: "zs-cbom-reader.",
  },
  // src: frontend/components/cbom/sources/CloudIdentityTab.tsx:2663, frontend/components/cbom/sources/CloudIdentityTab.tsx:2663, frontend/components/cbom/sources/CloudIdentityTab.tsx:2662-2670 — optional; encrypted at rest
  "cbsrc.idp.secret": {
    label: "Client secret or API token",
    what: "Optional, not asked for ADFS. The Okta API token or the client secret. Signing keys are read from public metadata without it; with it, more is read. Encrypted at rest and never shown again.",
    why: "Without it, only the provider's published signing keys are inventoried.",
    example: "A read-only Okta API token.",
  },
  // src: frontend/components/cbom/sources/CloudIdentityTab.tsx:2710-2732 — HTTPS, up to 1,000 characters
  "cbsrc.idp.saml_url": {
    label: "SAML metadata URL",
    what: "The HTTPS address of an identity provider's SAML metadata, up to 1,000 characters. Its signing and encryption certificates are read from it.",
    why: "Covers identity providers without a dedicated connector (ADFS has its own row).",
    example: "https://idp.bank.in/saml/metadata.xml.",
  },
  // src: frontend/components/cbom/sources/CloudIdentityTab.tsx:2710-2732 — HTTPS, up to 1,000 characters
  "cbsrc.idp.oidc_url": {
    label: "OIDC discovery URL",
    what: "The HTTPS address of an OpenID Connect discovery document, up to 1,000 characters. Its JWKS signing keys are read from it.",
    why: "Covers any OIDC provider, including in-house ones.",
    example: "https://sso.bank.in/.well-known/openid-configuration.",
  },
  // ────────────────────────────────────────────────────────────── CBOM Sources: Network TLS (components/cbom/sources/NetworkTab.tsx)
  // src: frontend/components/cbom/sources/NetworkTab.tsx:446-454 — the team emergency stop
  "cbsrc.net.stopped": {
    label: "All network scanning is stopped",
    what: "A team admin stopped all network scanning. Scan nodes skip network ranges and discovery sweeps until a team admin resumes it; other sources are not affected.",
    why: "The emergency stop exists so the SOC can halt probing at once if a device misbehaves.",
    example: "Stopped 12 minutes ago after a PLC on 10.50.0.0/24 raised an alarm.",
  },
  // src: frontend/components/cbom/sources/NetworkTab.tsx:465, frontend/components/cbom/sources/NetworkTab.tsx:467-497 — allowed ranges, never scan, SNI names, ports
  "cbsrc.net.scope": {
    label: "Scope",
    what: "What the network scan may touch and how: the allowed ranges and their scan nodes, the never-scan list, hostnames for SNI and the ports and protocols to probe.",
    why: "Nothing outside the allowed ranges is ever probed, and never-scan always wins.",
    example: "10.20.0.0/16 through node-dc1, except 10.20.99.0/24 (OT), on ports 443, 8443 and 22.",
  },
  // src: frontend/components/cbom/sources/NetworkTab.tsx:467-497, frontend/components/cbom/sources/NetworkTab.tsx:1180-1187,468 — nothing is scanned until a range is allowed
  "cbsrc.net.ranges": {
    label: "Allowed ranges",
    what: "The address ranges the network scan may probe, each with the scan node that reaches it. Nothing is scanned until you allow a range.",
    why: "An explicit allow list keeps scans inside the networks you approved.",
    example: "10.20.0.0/16 through node-dc1, Full mode.",
  },
  // src: frontend/components/cbom/sources/NetworkTab.tsx:1180 — a /16 or smaller, one IP, or a-b
  "cbsrc.net.col.range": {
    label: "Range",
    what: "The addresses: a CIDR range of /16 or smaller, one IP address, or a first-last range. A /24 or larger skips its network and broadcast addresses; a /25 or smaller is scanned whole.",
    why: "Each address in it may be probed on every listed port.",
    example: "10.20.5.0/24.",
  },
  // src: frontend/components/cbom/sources/NetworkTab.tsx:540, frontend/components/cbom/sources/NetworkTab.tsx:1203-1217 — Full or Fragile (version check only)
  "cbsrc.net.col.mode": {
    label: "Mode",
    what: "Full: complete TLS and SSH handshakes on every listed port. Fragile: a version check only, for OT or devices that may not cope with many handshakes.",
    why: "Old PLCs and medical devices can crash under repeated handshakes.",
    example: "Fragile for the SCADA network 10.50.0.0/24.",
  },
  // src: frontend/components/cbom/sources/NetworkTab.tsx:590, frontend/components/cbom/sources/NetworkTab.tsx:590-692 — up to 500 entries; always wins in every job of the team
  "cbsrc.net.never_scan": {
    label: "Never scan",
    what: "Addresses and ranges, up to 500, that no job of this team may touch. The node refuses them even if a job asks; a server, database, registry or Kubernetes API whose name resolves to a listed address is skipped as a whole. Add each with a reason.",
    why: "It protects OT networks, core routers and partner systems from any probe, whatever a source says.",
    example: "10.20.99.0/24 · OT plant network.",
  },
  // src: frontend/components/cbom/sources/NetworkTab.tsx:601, frontend/components/cbom/sources/NetworkTab.tsx:671-680 — up to 120 characters
  "cbsrc.net.col.reason": {
    label: "Reason",
    what: "Why the range is excluded, up to 120 characters, so others know not to remove it.",
    why: "An exclusion without a reason tends to be deleted during clean-ups.",
    example: "OT plant network, no active scanning per IT-OT policy.",
  },
  // src: frontend/components/cbom/sources/NetworkTab.tsx:701, frontend/components/cbom/sources/NetworkTab.tsx:701-710 — up to 10,000 names
  "cbsrc.net.sni": {
    label: "Hostnames for SNI",
    what: "Hostnames, up to 10,000, sent as SNI in TLS handshakes so servers that host several sites return each site's certificate.",
    why: "Without SNI a shared server shows only its default certificate and the others go uninventoried.",
    example: "www.bank.in and api.bank.in on the same load balancer address.",
  },
  // src: frontend/components/cbom/sources/NetworkTab.tsx:78-92,712, frontend/components/cbom/sources/NetworkTab.tsx:712, frontend/components/cbom/sources/NetworkTab.tsx:712-785 — up to 64 ports; TLS, StartTLS, SSH, RDP, IKE, OT
  "cbsrc.net.ports": {
    label: "Ports and protocols",
    what: "The ports probed on each address, up to 64, each with its protocol: TLS, StartTLS for LDAP, SMTP, IMAP, PostgreSQL or MySQL, SQL Server, SSH, RDP, IKE, and OT protocols (OPC UA, Modbus). Add a port, its protocol and an optional label.",
    why: "A service on a port that is not listed is never seen.",
    example: "7443 · TLS · admin console.",
  },
  // src: frontend/components/cbom/sources/NetworkTab.tsx:791 — window, rates, SOC contacts
  "cbsrc.net.safety": {
    label: "Safety",
    what: "When network scans may run, how fast they may go, and who your SOC should call.",
    why: "Probing at the wrong hour or speed can set off alarms or disturb fragile devices.",
    example: "Weekday nights only, 50 connections per second per node.",
  },
  // src: frontend/components/cbom/sources/NetworkTab.tsx:793-842 — weekly hours in a time zone; work pauses at the end
  "cbsrc.net.window": {
    label: "Scan window",
    what: "The weekly hours, in the chosen time zone, when network scans and sources set to the team window may run. Work pauses at the end of the window and resumes in the next one.",
    why: "Keeps probes out of business hours and change freezes.",
    example: "Weekday nights, 22:00 to 06:00 Asia/Kolkata: 40 hours a week.",
  },
  // src: frontend/components/cbom/sources/NetworkTab.tsx:111 — 1 to 500
  "cbsrc.net.rate_conn": {
    label: "Connections/s per node",
    what: "The most new connections per second each scan node opens, 1 to 500.",
    why: "Lower values avoid tripping IDS alerts and connection limits on firewalls.",
    example: "50 for a branch network behind a small firewall.",
  },
  // src: frontend/components/cbom/sources/NetworkTab.tsx:112 — 1 to 32
  "cbsrc.net.rate_parallel": {
    label: "Parallel per server",
    what: "The most connections a node keeps open to one server at a time, 1 to 32.",
    why: "Protects small servers from being overloaded by parallel handshakes.",
    example: "4 for older appliances that limit concurrent TLS sessions.",
  },
  // src: frontend/components/cbom/sources/NetworkTab.tsx:113 — 1 to 200
  "cbsrc.net.rate_handshakes": {
    label: "Handshakes per endpoint",
    what: "The most TLS or SSH handshakes made to one endpoint (address and port), 1 to 200. More handshakes test more protocol versions and cipher suites.",
    why: "A full cipher-suite enumeration needs many handshakes; fewer is gentler but less complete.",
    example: "60 enumerates TLS 1.0 to 1.3 suites on a typical web server.",
  },
  // src: frontend/components/cbom/sources/NetworkTab.tsx:876-930 — each node's source IPs and your contacts
  "cbsrc.net.soc": {
    label: "Tell your SOC",
    what: "The source IP addresses of each scan node, to give your SOC so the scans are recognised, and the contacts they can reach.",
    why: "An unannounced scan looks like an attack and may be blocked mid-run.",
    example: "node-dc1 scans from 10.20.1.15.",
  },
  // src: frontend/components/cbom/sources/NetworkTab.tsx:894 — the node
  "cbsrc.net.col.node": {
    label: "Scan node",
    what: "The scan node whose source addresses are listed.",
    why: "Each node scans from its own addresses.",
    example: "node-dc1.",
  },
  // src: frontend/components/cbom/sources/NetworkTab.tsx:895 — addresses the node reported
  "cbsrc.net.col.source_ips": {
    label: "Source IPs",
    what: "The addresses the node reported it connects from, to whitelist or recognise in your SOC tools.",
    why: "Behind NAT the address seen by targets may differ; check with your network team.",
    example: "10.20.1.15, fd00:20::15.",
  },
  // src: frontend/components/cbom/sources/NetworkTab.tsx:909, frontend/components/cbom/sources/NetworkTab.tsx:909-917 — up to 254 characters
  "cbsrc.net.soc_email": {
    label: "SOC email",
    what: "Your SOC's email address, up to 254 characters, recorded with the team's network settings as the contact for these scans.",
    why: "Gives operators one place to send questions about a scan they see.",
    example: "soc@bank.in.",
  },
  // src: frontend/components/cbom/sources/NetworkTab.tsx:920, frontend/components/cbom/sources/NetworkTab.tsx:920-928 — a phone number, up to 64 characters
  "cbsrc.net.emergency": {
    label: "Emergency stop contact",
    what: "A phone number, up to 64 characters, for whoever can stop the scans at once.",
    why: "If a device misbehaves during a scan, someone must be reachable to stop it.",
    example: "+91 22 5555 0100 (NOC, 24x7).",
  },
  // src: frontend/components/cbom/sources/NetworkTab.tsx:1198-1201 — the node that reaches the range
  "cbsrc.net.range_form_node": {
    label: "Scan node",
    what: "The scan node that probes this range. It must reach every address in it on the listed ports.",
    why: "A node in another segment sees every address as silent.",
    example: "node-dc1 for 10.20.0.0/16.",
  },
  // src: frontend/components/cbom/sources/NetworkTab.tsx:1419, frontend/components/cbom/sources/NetworkTab.tsx:1419-1420 — BIND export up to 8 MB; A, AAAA, CNAME names
  "cbsrc.net.sni_zone": {
    label: "Import a DNS zone file",
    what: "Add hostnames from a BIND zone export, up to 8 MB: the names of its A, AAAA and CNAME records.",
    why: "A zone file lists names nobody remembers to type in.",
    example: "bank.in.zone exported from the DNS server.",
  },
  // src: frontend/components/cbom/sources/NetworkTab.tsx:1422-1423 — text or CSV; first column
  "cbsrc.net.sni_list": {
    label: "Import a plain list",
    what: "Add hostnames from a text or CSV file; the first column of each row is used.",
    why: "Reuse an existing asset list instead of typing names.",
    example: "hosts.csv exported from the CMDB.",
  },
  // src: frontend/components/cbom/sources/NetworkTab.tsx:1426, frontend/components/cbom/sources/NetworkTab.tsx:1426-1433 — one per line, up to 10,000; duplicates dropped
  "cbsrc.net.sni_text": {
    label: "Hostnames",
    what: "One hostname per line, up to 10,000; duplicates are dropped.",
    why: "Each name is sent as SNI so the right certificate is returned.",
    example: "www.bank.in, api.bank.in, mail.bank.in.",
  },
  // ────────────────────────────────────────────────────────────── CBOM Sources: Evidence (components/cbom/sources/EvidenceTab.tsx)
  // src: backend/utilities/cbom_sources/evidence.py:16-17, frontend/components/cbom/sources/EvidenceTab.tsx:283-292,55 — areas at E0
  "cbsrc.ev.e0": {
    label: "E0 Unknown",
    what: "Areas with no usable answer: never answered, answered without evidence where evidence is needed, or with evidence older than 12 months.",
    why: "Each E0 area is a Q0 gap in the risk register, listed on Review & Run and never treated as safe.",
    example: "3 areas: the payment HSM vendor has not answered.",
  },
  // src: backend/utilities/cbom_sources/evidence.py:16-17, frontend/components/cbom/sources/EvidenceTab.tsx:283-292,55 — areas at E1
  "cbsrc.ev.e1": {
    label: "E1 Self-attested",
    what: "Areas answered by their owner or vendor without supporting evidence.",
    why: "A self-attested answer is better than nothing but would not satisfy an auditor.",
    example: "The card vendor says its terminals use AES-256, with no document.",
  },
  // src: backend/utilities/cbom_sources/evidence.py:16-17, frontend/components/cbom/sources/EvidenceTab.tsx:283-292,55 — areas at E2
  "cbsrc.ev.e2": {
    label: "E2 Documented",
    what: "Areas answered with a dated evidence document, such as a policy, certificate or report.",
    why: "Documented answers can be shown to an auditor and re-checked when the document is renewed.",
    example: "Key management policy v3 (PDF), dated March 2026.",
  },
  // src: backend/utilities/cbom_sources/evidence.py:16-17, frontend/components/cbom/sources/EvidenceTab.tsx:283-292,55 — areas at E3
  "cbsrc.ev.e3": {
    label: "E3 Verified",
    what: "Areas whose evidence your team has checked and confirmed.",
    why: "Verified evidence carries the same weight as a scan result.",
    example: "The HSM's FIPS 140-3 certificate checked against the NIST CMVP list.",
  },
  // src: frontend/components/cbom/sources/EvidenceTab.tsx:280-284,300, frontend/components/cbom/sources/EvidenceTab.tsx:299-325 — owner questionnaires with a confidence level
  "cbsrc.ev.areas": {
    label: "Areas that cannot be scanned",
    what: "Parts of your crypto estate no scan can read, such as vendor services and offline key ceremonies. Each has an owner questionnaire, a confidence level and an optional evidence link; a missing answer stays a visible gap.",
    why: "A CBOM that only lists what scans can see overstates your readiness.",
    example: "Card personalisation bureau: owner Cards ops, E1, due 30 Nov.",
  },
  // src: frontend/components/cbom/sources/EvidenceTab.tsx:320 — the evidence area
  "cbsrc.ev.col.area": {
    label: "Area",
    what: "The part of the estate the questionnaire covers.",
    why: "Each area is one gap until it is answered.",
    example: "Offline root CA key ceremony.",
  },
  // src: frontend/components/cbom/sources/EvidenceTab.tsx:321, frontend/components/cbom/sources/EvidenceTab.tsx:794 — who answers
  "cbsrc.ev.col.owner": {
    label: "Owner",
    what: "The person or team asked to answer for this area.",
    why: "An area without an owner is never answered.",
    example: "PKI team.",
  },
  // src: frontend/components/cbom/sources/shared.tsx:136-149 — E0 Unknown to E3 Verified
  "cbsrc.ev.col.confidence": {
    label: "Confidence",
    what: "How much the answer can be trusted: E0 Unknown, E1 Self-attested, E2 Documented (evidence document), E3 Verified (evidence checked by your team).",
    why: "Reports and the run's coverage weigh answers by this level.",
    example: "E2 Documented.",
  },
  // src: frontend/components/cbom/sources/EvidenceTab.tsx:323, frontend/components/cbom/sources/EvidenceTab.tsx:876-902 — the evidence document and its date
  "cbsrc.ev.col.evidence": {
    label: "Evidence",
    what: "The supporting document's title and link, and its date. Evidence older than 12 months drops back to E0 until renewed.",
    why: "Dated evidence shows the answer was true recently, not years ago.",
    example: "HSM FIPS certificate (PDF), 4 Feb 2026.",
  },
  // src: frontend/components/cbom/sources/EvidenceTab.tsx:324, frontend/components/cbom/sources/EvidenceTab.tsx:910 — when the owner should answer by
  "cbsrc.ev.col.due": {
    label: "Due",
    what: "When the owner should answer by.",
    why: "Overdue areas are the gaps to chase before an audit.",
    example: "30 Nov 2026.",
  },
  // src: frontend/components/cbom/sources/EvidenceTab.tsx:414-418 — single-use links, no login, 14 days
  "cbsrc.ev.vendors": {
    label: "Vendors",
    what: "Vendors asked to answer a questionnaire through a single-use link, with no login; the link expires in 14 days. A vendor who does not answer stays E0 Unknown, a Q0 gap.",
    why: "Third-party services use crypto you cannot scan but still answer for in an audit.",
    example: "Acme Payments, link sent 2 Nov, answered 6 Nov, E2.",
  },
  // src: frontend/components/cbom/sources/EvidenceTab.tsx:442 — vendor name
  "cbsrc.ev.col.vendor": {
    label: "Vendor",
    what: "The vendor asked to answer.",
    why: "Each vendor is one evidence area of its own.",
    example: "Acme Payments.",
  },
  // src: frontend/components/cbom/sources/EvidenceTab.tsx:443 — the single-use link
  "cbsrc.ev.col.link": {
    label: "Link status",
    what: "The state of the vendor's single-use link: not sent, sent and waiting, answered, or expired (after 14 days).",
    why: "An expired link needs a new one before the vendor can answer.",
    example: "Expired: press New link and send the vendor the fresh link.",
  },
  // src: frontend/components/cbom/sources/EvidenceTab.tsx:531, frontend/components/cbom/sources/EvidenceTab.tsx:663-696,531 — read-only preview
  "cbsrc.ev.preview": {
    label: "Questionnaire preview",
    what: "Read-only view of exactly what an owner or vendor is asked for the chosen area.",
    why: "Check the questions before sending a link to a vendor.",
    example: "Preview Card personalisation bureau: 5 questions and an evidence link.",
  },
  // src: frontend/components/cbom/sources/EvidenceTab.tsx:534-536 — which area to preview
  "cbsrc.ev.preview_area": {
    label: "Area",
    what: "The evidence area whose questionnaire is shown below.",
    why: "Each area asks different questions.",
    example: "Offline root CA key ceremony.",
  },
  // src: frontend/components/cbom/sources/EvidenceTab.tsx:809-843, frontend/components/cbom/sources/EvidenceTab.tsx:667-686 — yes/no/unknown or a free-text answer
  "cbsrc.ev.question": {
    label: "Question",
    what: "One question of the area's questionnaire, answered with a choice or in free text.",
    why: "Each answer feeds the area's confidence; an unanswered question keeps it a gap.",
    example: "Are keys generated inside a FIPS 140-3 Level 3 HSM? Yes.",
  },
  // src: frontend/components/cbom/sources/EvidenceTab.tsx:688 — E2 and E3 need one
  "cbsrc.ev.preview_link": {
    label: "Link to supporting evidence",
    what: "Where the person answering links a policy, certificate or report. Documented (E2) and Verified (E3) need one.",
    why: "Without evidence an answer stays Self-attested at best.",
    example: "https://intranet.bank.in/pki/ceremony-2026.pdf.",
  },
  // src: frontend/components/cbom/sources/EvidenceTab.tsx:794-796 — the person or team who answers
  "cbsrc.ev.owner": {
    label: "Owner",
    what: "Who answers for this area: a person or team. The area may suggest a usual owner.",
    why: "Named owners are who auditors ask, and who remediation is routed to.",
    example: "PKI team (usually: Information security).",
  },
  // src: frontend/components/cbom/sources/EvidenceTab.tsx:849-857 — Documented and Verified need a document and date
  "cbsrc.ev.confidence": {
    label: "Confidence",
    what: "The confidence of this area's answer: E0 Unknown, E1 Self-attested, E2 Documented or E3 Verified. Documented and Verified need an evidence document and its date.",
    why: "It decides how the area counts in coverage and reports.",
    example: "E3 after you checked the vendor's certificate yourself.",
  },
  // src: frontend/components/cbom/sources/EvidenceTab.tsx:876-877 — up to 200 characters
  "cbsrc.ev.title": {
    label: "Evidence title",
    what: "A short title for the evidence document, up to 200 characters.",
    why: "Auditors find the document by its title in the evidence pack.",
    example: "Key management policy v3 (PDF).",
  },
  // src: frontend/components/cbom/sources/EvidenceTab.tsx:879-886 — http or https, up to 1,000 characters
  "cbsrc.ev.url": {
    label: "Evidence link",
    what: "An http:// or https:// link to the document, up to 1,000 characters.",
    why: "The link lets a reviewer open the evidence in one click.",
    example: "https://intranet.bank.in/policies/kms-v3.pdf.",
  },
  // src: frontend/components/cbom/sources/EvidenceTab.tsx:876-888 — evidence older than 12 months drops to E0
  "cbsrc.ev.date": {
    label: "Evidence date",
    what: "The date of the document, not later than today. Evidence older than 12 months drops back to E0 until renewed.",
    why: "Crypto policies change; old evidence may describe a setup that no longer exists.",
    example: "14 Mar 2026.",
  },
  // src: frontend/components/cbom/sources/EvidenceTab.tsx:910-911 — when the owner should answer by
  "cbsrc.ev.due": {
    label: "Due date",
    what: "When the owner should answer by.",
    why: "A due date turns an open gap into a tracked task.",
    example: "30 Nov 2026.",
  },
  // src: frontend/components/cbom/sources/EvidenceTab.tsx:983-984 — required
  "cbsrc.ev.vendor_name": {
    label: "Vendor name",
    what: "The vendor's name, as shown in lists and reports.",
    why: "Each vendor becomes an evidence area of its own.",
    example: "Acme Payments Pvt Ltd.",
  },
  // src: frontend/components/cbom/sources/EvidenceTab.tsx:993-994 — for your records only
  "cbsrc.ev.vendor_email": {
    label: "Contact email",
    what: "Optional: the vendor contact's email, for your records only. ZeroShield does not email the vendor; you send the link yourself.",
    why: "Keeps who was asked next to the answer.",
    example: "security@acmepayments.in.",
  },
  // src: frontend/components/cbom/sources/EvidenceTab.tsx:1069-1075,1084 — E1 when answered, E2 with a link, E3 once verified
  "cbsrc.ev.vendor_confidence": {
    label: "Confidence",
    what: "The confidence of the vendor's answer. Set E1 when answered, E2 when the vendor gave an evidence link, E3 once you have verified the evidence.",
    why: "It decides how much the vendor's answer counts.",
    example: "E2: the vendor linked its PCI PIN attestation.",
  },
  // ────────────────────────────────────────────────────────────── CBOM Sources: Review & Run (components/cbom/sources/ReviewRunTab.tsx)
  // src: frontend/components/cbom/sources/ReviewRunTab.tsx:231-307,317, frontend/components/cbom/sources/ReviewRunTab.tsx:317 — one row per source group
  "cbsrc.rr.coverage": {
    label: "Coverage",
    what: "Every kind of source and what a run would collect from it: how much is in scope, what reaches it (scan nodes, ZeroShield's cloud or questionnaires), failed tests, the credits it costs per run and whether it is ready.",
    why: "Shows at a glance which parts of the estate the next run covers and which it leaves out.",
    example: "Servers · 3 sources, 612 targets · node-dc1 · No failed tests · 122.40 (0.2 per target) · Ready.",
  },
  // src: frontend/components/cbom/sources/ReviewRunTab.tsx:323 — the source group
  "cbsrc.rr.col.source": {
    label: "Source",
    what: "The group of sources: servers, Kubernetes, databases, cloud, network, identity, evidence or code scans.",
    why: "A run is started per group with the boxes under Start a scan.",
    example: "Databases.",
  },
  // src: frontend/components/cbom/sources/ReviewRunTab.tsx:324 — what the group covers
  "cbsrc.rr.col.in_scope": {
    label: "In scope",
    what: "How much of the group a run would cover: sources, targets, accounts or areas.",
    why: "Zero in scope means the group adds nothing to the CBOM yet.",
    example: "2 sources, 4 databases.",
  },
  // src: frontend/components/cbom/sources/ReviewRunTab.tsx:325 — scan nodes or ZeroShield's cloud
  "cbsrc.rr.col.through": {
    label: "Reached through",
    what: "What does the collecting: the scan nodes for in-network sources, or ZeroShield's cloud for cloud accounts, CT logs and identity providers.",
    why: "An offline node here means that group's jobs wait.",
    example: "node-dc1, node-dr1.",
  },
  // src: frontend/components/cbom/sources/ReviewRunTab.tsx:239, frontend/components/cbom/sources/ReviewRunTab.tsx:263, frontend/components/cbom/sources/ReviewRunTab.tsx:307 — estimated credits per run for the group
  "cbsrc.rr.col.credits": {
    label: "Credits",
    what: "The credits one run of this group is estimated to charge; code scans are charged per scan and evidence costs nothing.",
    why: "Credits come off the team balance when the run starts and are refunded for jobs that fail or expire.",
    example: "4.00 for one AWS account (4 credits per account per run).",
  },
  // src: frontend/components/cbom/sources/ReviewRunTab.tsx:326 — ready, needs attention or not set up
  "cbsrc.rr.col.status": {
    label: "Status",
    what: "Ready, a count of issues to fix (for example an offline node or a failed test), Not configured, or for evidence the number of gaps.",
    why: "Groups that are not ready are skipped and listed below with the fix.",
    example: "1 issue: a source has a failed connection test.",
  },
  // src: frontend/components/cbom/sources/ReviewRunTab.tsx:357 — sources the plan would skip
  "cbsrc.rr.skipped": {
    label: "Will be skipped unless you fix it",
    what: "Sources the next run would skip, each with the reason: an offline or missing node, a failed or missing test, a missing credential, or a closed scan window.",
    why: "A skipped source is a gap in the CBOM; fixing it before starting saves a second run.",
    example: "dc-mumbai-windows: the connection test failed (Login failed).",
  },
  // src: frontend/components/cbom/sources/ReviewRunTab.tsx:393-404 — jobs, run record, proof trail, evidence gaps
  "cbsrc.rr.after": {
    label: "What you get after the scan",
    what: "What a run produces: collection jobs per source for your scan nodes, a run record with the credits charged and refunded, a proof trail (audit log, node source IPs, the AWS role's CloudTrail calls) and evidence gaps listed as Q0, never assumed safe.",
    why: "The proof trail lets your SOC and auditors confirm exactly what was touched.",
    example: "Run #42: 2 databases, 1 AWS account and 32 server targets: 12.40 credits charged; 1.00 refunded for a database job that failed.",
  },
  // src: frontend/components/cbom/sources/ReviewRunTab.tsx:630, frontend/components/cbom/sources/ReviewRunTab.tsx:53-59,408 — choose groups, estimate the credits, start
  "cbsrc.rr.start": {
    label: "Start a scan",
    what: "Choose which groups to collect, estimate the credits, confirm the SOC agreement for network scans, then start the run.",
    why: "Credits are charged when the run starts; the estimate shows the cost and what will be skipped first.",
    example: "Servers (612 targets) and one AWS account: 122.40 + 4.00 = 126.40 credits.",
  },
  // src: frontend/components/cbom/sources/ReviewRunTab.tsx:53-59,636, frontend/components/cbom/sources/ReviewRunTab.tsx:633-639 — one box per group; how many sources are ready
  "cbsrc.rr.include": {
    label: "Include in the run",
    what: "Tick each group of sources to collect in this run; the count shows how many of its sources are ready.",
    why: "Leave out groups whose systems are in a change freeze.",
    example: "Servers · 3 ready.",
  },
  // src: frontend/components/cbom/sources/ReviewRunTab.tsx:698-709 — required when Network is included
  "cbsrc.rr.soc_ack": {
    label: "SOC agreement",
    what: "Confirm that your SOC has agreed the network ranges and scan windows. Required when the run includes Network.",
    why: "Active network probing without SOC agreement is often treated as an incident.",
    example: "Tick after the SOC acknowledged ranges 10.20.0.0/16 and the 22:00-06:00 window.",
  },
  // src: frontend/components/cbom/sources/ReviewRunTab.tsx:423 — the 50 most recent runs
  "cbsrc.rr.runs": {
    label: "Runs",
    what: "The 50 most recent collection runs of this team, newest first, with their status, jobs, assets and credits. Open Results for a run's findings, or Compare two finished runs.",
    why: "Comparing runs shows what changed: new weak keys, fixed ones, expired certificates.",
    example: "Run #42 · Done · 9 done · 1,284 assets · 12.40 charged / 1.00 refunded.",
  },
  // src: frontend/components/cbom/sources/ReviewRunTab.tsx:449 — run number
  "cbsrc.rr.col.run": {
    label: "Run",
    what: "The run's number, unique within ZeroShield.",
    why: "Reports and exports name the run by this number.",
    example: "#42, the run started on 13 Nov.",
  },
  // src: frontend/components/cbom/sources/ReviewRunTab.tsx:450 — when the run was created
  "cbsrc.rr.col.started": {
    label: "Started",
    what: "When the run was started.",
    why: "Findings reflect the estate at this time.",
    example: "13 Nov 2026, 11:05 pm IST.",
  },
  // src: frontend/components/cbom/sources/shared.tsx:118-125, backend/utilities/cbom_sources/jobs.py:121-133 — jobs.py run status: partial also when every job succeeded but one reported a partial or failed outcome
  "cbsrc.rr.col.run_status": {
    label: "Status",
    what: "Queued, Running, Done (every job succeeded completely), Partial (some jobs failed or expired, or a job finished but reported a partial or failed outcome), Failed or Cancelled.",
    why: "A Partial run's results miss the sources whose jobs failed.",
    example: "Partial: 8 of 9 jobs done, 1 expired.",
  },
  // src: frontend/components/cbom/sources/ReviewRunTab.tsx:156-160 — job counts by status
  "cbsrc.rr.col.jobs": {
    label: "Jobs",
    what: "The run's collection jobs (one per source) counted by status.",
    why: "Waiting jobs usually mean an offline scan node.",
    example: "8 done · 1 failed.",
  },
  // src: frontend/components/cbom/sources/ReviewRunTab.tsx:469-471 — assets collected
  "cbsrc.rr.col.assets": {
    label: "Assets",
    what: "How many crypto assets the run collected: certificates, keys, protocols, libraries and other items.",
    why: "A sudden drop between runs can mean a source stopped reporting.",
    example: "1,284.",
  },
  // src: frontend/components/cbom/sources/ReviewRunTab.tsx:472-474, backend/utilities/cbom_sources/jobs.py:86-108 — charged and refunded
  "cbsrc.rr.col.run_credits": {
    label: "Credits",
    what: "Credits charged when the run started, and credits refunded for jobs that failed, expired or were cancelled.",
    why: "You pay only for jobs that completed.",
    example: "12.40 charged / 1.00 refunded.",
  },
  // src: frontend/components/cbom/results/RunJobsTable.tsx:28 — scan node or ZeroShield cloud
  "cbsrc.rr.job.runs_on": {
    label: "Runs on",
    what: "Where the job ran: a scan node, or ZeroShield's cloud for cloud accounts, CT logs and identity providers.",
    why: "Points you at the node to check when a job fails.",
    example: "node-dc1.",
  },
  // src: frontend/components/cbom/sources/shared.tsx:101-108 — waiting, running, done, failed, cancelled, expired
  "cbsrc.rr.job.status": {
    label: "Status",
    what: "Waiting (for its node or window), Running, Done, Failed, Cancelled or Expired (never claimed in time; refunded). The note below says why it waits.",
    why: "Expired and failed jobs are refunded and their source has no new results in this run.",
    example: "Waiting · outside the scan window; starts at 22:00.",
  },
  // src: frontend/components/cbom/results/RunJobsTable.tsx:30 — assets the job collected
  "cbsrc.rr.job.assets": {
    label: "Assets",
    what: "How many assets this job collected from its source.",
    why: "Zero from a source that had assets before deserves a look.",
    example: "212 from dc-mumbai-linux.",
  },
  // src: frontend/components/cbom/results/RunJobsTable.tsx:31 — charged for the job; refunded marker
  "cbsrc.rr.job.credits": {
    label: "Credits",
    what: "The credits charged for this job, marked refunded when it failed, expired or was cancelled.",
    why: "Shows which part of the run's cost came back.",
    example: "25.60 refunded: a 128-target server job that expired.",
  },
  // src: frontend/components/cbom/results/RunJobsTable.tsx:32 — how many times the job was tried
  "cbsrc.rr.job.attempts": {
    label: "Attempts",
    what: "How many times a node tried this job. A job is retried after a transient failure.",
    why: "Many attempts point at a flaky network path or an overloaded node.",
    example: "2: the first try timed out, the second finished.",
  },
  // src: frontend/components/cbom/results/RunJobsTable.tsx:33 — the job's last error
  "cbsrc.rr.job.error": {
    label: "Error",
    what: "The last error the job reported, if any.",
    why: "It names the exact failure to fix before the next run.",
    example: "connect timeout to 10.20.0.17:22.",
  },
  // src: frontend/components/cbom/results/RunJobsTable.tsx:79 — sources skipped at start
  "cbsrc.rr.skipped_start": {
    label: "Skipped when the run started",
    what: "Sources that were not queued when the run started, each with the reason.",
    why: "They are not in this run's results and were not charged.",
    example: "dc-mumbai-windows: the scan node was offline.",
  },
  // ────────────────────────────────────────────────────────────── CBOM Sources: Review & Run, run details
  // src: frontend/components/cbom/results/RunJobsTable.tsx:27 — one job per source
  "cbsrc.rr.job.source": {
    label: "Source",
    what: "The source this job collected from; each source in the run has one job.",
    why: "Open the source's tab to fix a failed job.",
    example: "dc-mumbai-linux.",
  },
  // ────────────────────────────────────────────────────────────── CBOM Sources: Scan nodes (components/cbom/sources/ScanNodesTab.tsx)
  // src: frontend/components/cbom/sources/ScanNodesTab.tsx:297 — nodes of the team
  "cbsrc.nodes.count": {
    label: "Scan nodes",
    what: "How many scan nodes this team has registered or is registering.",
    why: "Each network segment you want to scan needs a node inside it.",
    example: "3: one per data centre and one in the DMZ.",
  },
  // src: backend/utilities/cbom_sources/planning.py:22, backend/utilities/cbom_sources/planning.py:69-78 — heartbeat within the last 120 s
  "cbsrc.nodes.online": {
    label: "Online",
    what: "Nodes that sent a heartbeat in the last 2 minutes and can take jobs now.",
    why: "Jobs for sources behind an offline node wait and expire.",
    example: "2 of 3 online.",
  },
  // src: backend/utilities/cbom_sources/planning.py:22, backend/utilities/cbom_sources/planning.py:69-78 — registered, no heartbeat for 120 s
  "cbsrc.nodes.offline": {
    label: "Offline",
    what: "Registered nodes with no heartbeat for more than 2 minutes: stopped, unable to reach ZeroShield, or their host is down.",
    why: "An offline node silently removes its whole segment from the next run.",
    example: "node-dr1 offline since the DR site's proxy changed.",
  },
  // src: frontend/components/cbom/sources/ScanNodesTab.tsx:300 — servers and addresses routed through these nodes
  "cbsrc.nodes.assigned": {
    label: "Targets assigned",
    what: "Servers and addresses routed through these nodes by your sources and network ranges.",
    why: "Shows how much depends on each node staying online.",
    example: "4,612 targets across 3 nodes.",
  },
  // src: frontend/components/cbom/sources/ScanNodesTab.tsx:303-306 — one per segment; outbound only
  "cbsrc.nodes.list": {
    label: "Registered scan nodes",
    what: "Your scan nodes: small read-only collectors inside your network, one per network segment. Each connects out to ZeroShield on one HTTPS port only and opens no inbound ports.",
    why: "Nodes are how ZeroShield reads systems that are not reachable from the internet.",
    example: "node-dc1 · DC1-core · Online · Docker container.",
  },
  // src: frontend/components/cbom/sources/ScanNodesTab.tsx:345 — node name
  "cbsrc.nodes.col.node": {
    label: "Node",
    what: "The node's name, as chosen when it was added.",
    why: "Sources and ranges pick their node by this name.",
    example: "node-dc1.",
  },
  // src: frontend/components/cbom/sources/ScanNodesTab.tsx:346, frontend/components/cbom/sources/ScanNodesTab.tsx:464-467 — the network segment it sits in
  "cbsrc.nodes.col.segment": {
    label: "Segment",
    what: "The network segment the node sits in.",
    why: "A source must use a node in a segment that reaches its targets.",
    example: "DC1-core.",
  },
  // src: frontend/components/cbom/sources/shared.tsx:64-69 — online, offline, waiting to register, token expired
  "cbsrc.nodes.col.status": {
    label: "Status",
    what: "Online (heartbeat in the last 2 minutes), Offline, Waiting to register (installed with a token that was not used yet) or Token expired (create a new registration token).",
    why: "Only online nodes take jobs.",
    example: "Token expired: the install command was not run within 24 hours.",
  },
  // src: frontend/components/cbom/sources/ScanNodesTab.tsx:73-79,348, frontend/components/cbom/sources/ScanNodesTab.tsx:370-378,348 — Docker, OVA, AMI or Helm; host agent mode
  "cbsrc.nodes.col.runs_as": {
    label: "Runs as",
    what: "How the node runs: Docker container, OVA appliance, AWS AMI or Helm chart. Host agent means it collects only its own host from read-only mounts and is never given a credential.",
    why: "It tells you where to look when a node needs restarting or upgrading.",
    example: "Helm chart in the prod-payments cluster.",
  },
  // src: frontend/components/cbom/sources/ScanNodesTab.tsx:349 — node_version reported by the node
  "cbsrc.nodes.col.version": {
    label: "Version",
    what: "The software version the node reported.",
    why: "Old versions may miss newer collectors; upgrade them with the install command.",
    example: "1.8.2.",
  },
  // src: frontend/components/cbom/sources/ScanNodesTab.tsx:350, frontend/components/cbom/sources/ScanNodesTab.tsx:852-855,350 — signed or legacy unsigned
  "cbsrc.nodes.col.requests": {
    label: "Requests",
    what: "Whether the node signs every request with a key made at enrollment (Signed), or is a legacy node that does not.",
    why: "With signing, a copied node token alone cannot act as the node.",
    example: "Legacy: unsigned. Reset the node and register it again to sign.",
  },
  // src: frontend/components/cbom/sources/ScanNodesTab.tsx:351 — last heartbeat
  "cbsrc.nodes.col.last_seen": {
    label: "Last seen",
    what: "How long ago the node's last heartbeat arrived.",
    why: "More than 2 minutes means it is offline.",
    example: "12 seconds ago.",
  },
  // src: frontend/components/cbom/sources/ScanNodesTab.tsx:352 — targets routed through the node
  "cbsrc.nodes.col.targets": {
    label: "Targets",
    what: "How many servers and addresses are routed through this node.",
    why: "A heavily loaded node may need the parallel limits lowered or a second node.",
    example: "2,304.",
  },
  // src: frontend/components/cbom/sources/ScanNodesTab.tsx:438-443 — run on any VM or cluster inside the segment
  "cbsrc.nodes.add": {
    label: "Add a scan node",
    what: "Register a new scan node: name it, choose how to run it, allow its outbound traffic, then run the install command on a VM or cluster inside the segment you want to scan.",
    why: "Without a node, servers, clusters, databases and network ranges cannot be collected.",
    example: "node-dc1 as a Docker container on a Linux VM in DC1-core.",
  },
  // src: frontend/components/cbom/sources/ScanNodesTab.tsx:460-461 — up to 64 characters
  "cbsrc.nodes.name": {
    label: "Node name",
    what: "A name for the node, up to 64 characters, shown wherever a source picks its node.",
    why: "Name it after its location so the right node is picked for each source.",
    example: "node-dc1.",
  },
  // src: frontend/components/cbom/sources/ScanNodesTab.tsx:464-467 — pick one or type your own
  "cbsrc.nodes.segment": {
    label: "Network segment",
    what: "The network segment the node sits in; pick an existing one or type your own, up to 64 characters.",
    why: "Segments group nodes and appear in run results, so findings can be traced to a network.",
    example: "DC1-core.",
  },
  // src: frontend/components/cbom/sources/ScanNodesTab.tsx:469-471 — the node's time zone
  "cbsrc.nodes.tz": {
    label: "Time zone",
    what: "The time zone of the node's location, used in its install settings.",
    why: "Makes the node's own logs line up with your local time.",
    example: "Asia/Kolkata.",
  },
  // src: frontend/components/cbom/sources/ScanNodesTab.tsx:73-79,482 — Docker, OVA, AMI, Helm
  "cbsrc.nodes.deploy": {
    label: "Deployment",
    what: "How to run the node: a Docker container on any Linux VM, an OVA appliance for VMware, an AWS AMI in your VPC, or a Helm chart in your Kubernetes cluster. Docker and Helm are the proven ways; the others you build from the published template.",
    why: "It decides the install command you get.",
    example: "Docker container on an existing RHEL 9 VM.",
  },
  // src: frontend/components/cbom/sources/ScanNodesTab.tsx:563-568 — ZeroShield API and your targets
  "cbsrc.nodes.col.destination": {
    label: "Destination",
    what: "Where the node connects to: ZeroShield's API host, and the targets it reads.",
    why: "Firewalls must allow these connections from the node, and nothing inbound.",
    example: "api.zeroshield.ai.",
  },
  // src: frontend/components/cbom/sources/ScanNodesTab.tsx:563-568 — HTTPS to ZeroShield; 22, 5986, 6443, database and TLS ports to targets
  "cbsrc.nodes.col.port": {
    label: "Port",
    what: "The destination port: HTTPS to ZeroShield, and 22, 5986, 6443 and your database and TLS ports to targets.",
    why: "A blocked port shows up as unreachable targets in the connection test.",
    example: "443 to api.zeroshield.ai.",
  },
  // src: frontend/components/cbom/sources/ScanNodesTab.tsx:563-568 — jobs in, results out; read-only collection
  "cbsrc.nodes.col.used_for": {
    label: "Used for",
    what: "What the connection is for: jobs in and results out (HTTPS to ZeroShield), or read-only collection from your targets.",
    why: "Lets your firewall team approve each rule for a stated purpose.",
    example: "Jobs in, results out (HTTPS).",
  },
  // src: frontend/components/cbom/sources/ScanNodesTab.tsx:572-573, frontend/components/cbom/sources/ScanNodesTab.tsx:789-790 — an http proxy URL
  "cbsrc.nodes.proxy": {
    label: "Proxy",
    what: "Optional: the HTTP proxy the node uses to reach ZeroShield.",
    why: "Nodes in locked-down segments often reach the internet only through a proxy.",
    example: "http://proxy.bank.local:8080.",
  },
  // src: frontend/components/cbom/sources/ScanNodesTab.tsx:576-585 — PEM up to 64 KB
  "cbsrc.nodes.proxy_ca": {
    label: "Proxy CA certificate",
    what: "Only if your proxy inspects TLS: the PEM certificate of the proxy's CA, up to 64 KB.",
    why: "Without it the node refuses the proxy's re-signed certificate and cannot connect.",
    example: "bank-proxy-ca.pem.",
  },
  // src: frontend/components/cbom/sources/ScanNodesTab.tsx:592-594 — trust the proxy CA only for ZeroShield hostnames
  "cbsrc.nodes.tls_inspect": {
    label: "Proxy inspects TLS",
    what: "Tick if your proxy decrypts TLS. The node then trusts the proxy's CA, and only for ZeroShield's hostnames.",
    why: "Limiting the extra trust to ZeroShield's hostnames keeps the node's other TLS checks strict.",
    example: "Tick for a Zscaler or Blue Coat proxy with SSL inspection on.",
  },
  // src: frontend/components/cbom/sources/ScanNodesTab.tsx:632-646 — outbound only, read-only, metadata only
  "cbsrc.nodes.does": {
    label: "What the node does, and never does",
    what: "The node opens no inbound ports, uses each credential only on its targets, reads with read-only accounts, and sends metadata only: algorithms, key sizes, versions and locations, never private keys.",
    why: "These are the guarantees your security team reviews before approving a node.",
    example: "For a private key file, only its public half and type are sent.",
  },
  // src: frontend/components/cbom/sources/ScanNodesTab.tsx:765-771 — the node's own SSH key
  "cbsrc.nodes.ssh_key": {
    label: "Node SSH public key",
    what: "The public half of the SSH key this node generated. Install it for the login user on servers that use the node-generated key.",
    why: "The private key never leaves the node, so nothing secret is stored by ZeroShield.",
    example: "ssh-ed25519 AAAAC3Nza... zs-node-7.",
  },
  // src: frontend/components/cbom/sources/ScanNodesTab.tsx:852-864 — require signed scan nodes
  "cbsrc.nodes.signing": {
    label: "Request signing",
    what: "Scan nodes sign every request with a key made at enrollment. A team admin can require it, so nodes that do not sign are refused.",
    why: "A copied node token alone is then not enough to act as the node.",
    example: "Turn on once every node shows Signed.",
  },
  // src: frontend/components/cbom/sources/ScanNodesTab.tsx:859-861 — refuse unsigned nodes
  "cbsrc.nodes.require_signed": {
    label: "Require signed scan nodes",
    what: "Refuse requests from nodes that do not sign them. Legacy unsigned nodes stop working until reset and registered again.",
    why: "Closes the gap of a stolen node token being replayed from another machine.",
    example: "On, after resetting the one legacy node.",
  },
  // ────────────────────────────────────────────────────────────── CBOM Sources: agent pools, schedules, run comparison, scan sidebar, remediation waves
  // src: frontend/components/cbom/sources/AgentPoolsCard.tsx:105, frontend/components/cbom/sources/AgentPoolsCard.tsx:104-108 — one token for a Helm DaemonSet
  "cbsrc.pool.card": {
    label: "Host agents on Kubernetes",
    what: "One token for a Helm DaemonSet: every pod enrolls as its own agent-mode scan node named after its Kubernetes node, reads only that node's files through a read-only mount, and is never given a credential.",
    why: "Covers every worker node's crypto (keys, certificates, libraries) without SSH access to each one.",
    example: "A pool token for prod-cluster enrolls 24 host agents, one per worker node.",
  },
  // src: frontend/components/cbom/sources/AgentPoolsCard.tsx:125-126 — up to 64 characters
  "cbsrc.pool.name": {
    label: "Name",
    what: "A name for the pool, up to 64 characters; its agents are named after their Kubernetes nodes.",
    why: "Identifies which cluster the agents belong to.",
    example: "prod-cluster.",
  },
  // src: frontend/components/cbom/sources/AgentPoolsCard.tsx:129-130 — up to 64 characters
  "cbsrc.pool.segment": {
    label: "Network segment",
    what: "The network segment recorded for every agent of the pool, up to 64 characters.",
    why: "Findings from the agents are grouped by segment in run results.",
    example: "DC1-k8s.",
  },
  // src: frontend/components/cbom/sources/AgentPoolsCard.tsx:132-139 — enrolled nodes keep working
  "cbsrc.pool.expiry": {
    label: "Token expires in",
    what: "How long the pool token can enroll new agents. Agents that already enrolled keep working after it expires.",
    why: "A short expiry limits the damage if the token leaks from the Helm values.",
    example: "24 hours: long enough to roll out the DaemonSet.",
  },
  // src: frontend/components/cbom/sources/AgentPoolsCard.tsx:140-141 — 1 to 1,000; at least the number of Kubernetes nodes
  "cbsrc.pool.max": {
    label: "Nodes that may enroll",
    what: "The most agents the token may enroll, 1 to 1,000. Set at least the number of Kubernetes nodes.",
    why: "A cap stops a leaked token from enrolling unlimited fake nodes.",
    example: "30 for a 24-node cluster that may grow.",
  },
  // src: frontend/components/cbom/sources/AgentPoolsCard.tsx:176 — the pool token's name
  "cbsrc.pool.col.token": {
    label: "Token",
    what: "The pool token, by name. The token value itself is shown once, when it is created.",
    why: "Revoke a token here if it may have leaked.",
    example: "prod-cluster.",
  },
  // src: frontend/components/cbom/sources/AgentPoolsCard.tsx:177 — active, expired or revoked
  "cbsrc.pool.col.status": {
    label: "Status",
    what: "Whether the token can still enroll agents: Active, All enrollments used, Expired or Revoked.",
    why: "Only active tokens accept new agents; enrolled agents keep working either way.",
    example: "Expired.",
  },
  // src: frontend/components/cbom/sources/AgentPoolsCard.tsx:178 — agents enrolled out of the maximum
  "cbsrc.pool.col.enrolled": {
    label: "Enrolled",
    what: "How many agents enrolled with this token, out of the maximum allowed.",
    why: "Fewer than your node count means some pods did not start or could not reach ZeroShield.",
    example: "22 of 30.",
  },
  // src: frontend/components/cbom/sources/AgentPoolsCard.tsx:179 — when the token stops enrolling
  "cbsrc.pool.col.expires": {
    label: "Expires",
    what: "When the token stops enrolling new agents.",
    why: "Create a new token before scaling the cluster after this time.",
    example: "15 Nov 2026, 11:00 am IST.",
  },
  // src: frontend/components/cbom/sources/AgentPoolsCard.tsx:180 — agent nodes of the pool
  "cbsrc.pool.col.nodes": {
    label: "Nodes",
    what: "The agent scan nodes this token enrolled, as listed under Registered scan nodes.",
    why: "Each agent appears as its own node with its own status.",
    example: "prod-cluster-ip-10-30-1-12, prod-cluster-ip-10-30-1-13, ...",
  },
  // src: frontend/components/cbom/sources/SchedulesCard.tsx:166, frontend/components/cbom/sources/SchedulesCard.tsx:166 — daily, weekly or monthly; charged like Start scan
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
  // src: frontend/components/cbom/sources/SchedulesCard.tsx:125, frontend/components/cbom/sources/SchedulesCard.tsx:125-127 — kept with the schedule
  "cbsrc.sched.soc": {
    label: "SOC agreement for schedules",
    what: "Confirm that your SOC has agreed the network ranges and scan windows for every scheduled run. It is kept with the schedule.",
    why: "Unattended network scans need standing SOC approval.",
    example: "Tick after the SOC approved weekly scans of 10.20.0.0/16.",
  },
  // src: frontend/components/cbom/sources/ChangesPanel.tsx:242, frontend/components/cbom/sources/ChangesPanel.tsx:242-246 — the previous complete run or a chosen one
  "cbsrc.compare.with": {
    label: "Compare with",
    what: "The run to compare this one with: by default each source's previous complete collection, or a run you choose. Partial or failed jobs show as not compared, never as everything removed.",
    why: "Comparing shows exactly what changed between two points in time.",
    example: "Run #38, before the TLS hardening change.",
  },
  // src: frontend/components/cbom/sources/SidebarSources.tsx:44 — off by default; adds the group's run and credits to the estimate
  "cbsrc.sidebar.include": {
    label: "Include CBOM Sources",
    what: "Also run a collection of this group of CBOM Sources with this scan. Off by default; turning it on adds that group's collection run and its credits to the estimate. Sources are managed on the CBOM Sources page.",
    why: "One action then covers the code and the infrastructure that runs it.",
    example: "Include servers: 3 sources with 31 targets add 6.20 credits (0.2 per target).",
  },
  // src: frontend/components/cbom/sources/SidebarSources.tsx:162-170 — required with network TLS
  "cbsrc.sidebar.soc": {
    label: "SOC agreement",
    what: "Confirm that your SOC has agreed the network ranges and scan windows. Required when network TLS is included.",
    why: "Active network probing without SOC agreement is often treated as an incident.",
    example: "Tick after the SOC acknowledged the ranges.",
  },
  // src: backend/utilities/cbom_sources/waves.py:44-60 — suggested_wave: 1 weakness Critical/High and exposed or HNDL, or any HNDL quantum-vulnerable asset; 2 other Critical/High weakness; 3 other weakness; 4 quantum-vulnerable only
  "cbsrc.waves.card": {
    label: "Remediation waves",
    what: "Each asset's suggested wave: 1 for a Critical or High weakness that is internet-exposed or harvest-now-decrypt-later, and for any harvest-now-decrypt-later quantum-vulnerable asset; 2 other Critical or High weaknesses; 3 other weaknesses; 4 post-quantum migration. Assign a wave, owner, target date and status; plans follow the asset to later runs and scans.",
    why: "Waves turn a long findings list into an ordered plan with owners and dates.",
    example: "Wave 1: RSA-2048 key exchange on api.bank.in:443, owner Payments, due 31 Dec.",
  },
  // src: frontend/components/cbom/sources/WavesControls.tsx:151-155 — hides assets without a wave
  "cbsrc.waves.only_planned": {
    label: "Only assets that need action",
    what: "Show only assets that have a wave, hiding those that need no action.",
    why: "Keeps the list to what someone has to fix.",
    example: "On: 1,284 assets narrow to 96.",
  },
  // src: frontend/components/cbom/sources/WavesControls.tsx:164-168 — selection for the bulk bar
  "cbsrc.waves.select": {
    label: "Select asset",
    what: "Select assets to assign together with the bar above.",
    why: "Assign a whole group to one owner and date in one step.",
    example: "Tick the 12 wave-1 certificates of api.bank.in.",
  },
  // src: frontend/components/cbom/sources/WavesControls.tsx:98-104 — set or keep the wave
  "cbsrc.waves.bulk_wave": {
    label: "Wave",
    what: "The wave to give the selected assets: 1 to 4, Use suggested (the wave worked out from impact and exposure), or Keep wave.",
    why: "Override the suggestion when you know better, for example a system due to be retired.",
    example: "Wave 2.",
  },
  // src: frontend/components/cbom/sources/WavesControls.tsx:106-107 — up to 128 characters
  "cbsrc.waves.bulk_owner": {
    label: "Owner",
    what: "Who fixes the selected assets, up to 128 characters. Blank keeps each one's owner.",
    why: "Each fix needs a named owner to happen.",
    example: "Payments platform team.",
  },
  // src: frontend/components/cbom/sources/WavesControls.tsx:109-110 — date
  "cbsrc.waves.bulk_date": {
    label: "Target date",
    what: "When the selected assets should be fixed by. Blank keeps each one's date.",
    why: "Dates let you track the plan against regulator deadlines.",
    example: "31 Mar 2027.",
  },
  // src: frontend/components/cbom/sources/WavesControls.tsx:29, frontend/components/cbom/sources/WavesControls.tsx:113-120 — open, in progress, done, risk accepted
  "cbsrc.waves.bulk_status": {
    label: "Status",
    what: "The status to set: Open, In progress, Done or Risk accepted; or Keep status.",
    why: "Done items should disappear from the next run; Risk accepted records a decision.",
    example: "In progress.",
  },
  // ────────────────────────────────────────────────────────────── CBOM Sources: network appliances, container images, CMDB import
  // src: frontend/components/cbom/sources/AppliancesSection.tsx:1-3, frontend/components/cbom/sources/AppliancesSection.tsx:60-63, backend/utilities/cbom_sources/kinds.py:714-715 — Cisco IOS/ASA, FortiOS over SSH; PAN-OS, F5 over API
  "cbsrc.app.card": {
    label: "Network appliances",
    what: "Read-only configuration pulls from routers, firewalls and load balancers through a scan node: Cisco IOS and ASA and FortiOS over SSH show commands, PAN-OS and F5 BIG-IP over API reads. TLS, SSH and IKE/IPsec settings and key sizes are inventoried.",
    why: "VPN tunnels and load balancers carry most traffic; weak IKE groups there are harvest-now-decrypt-later targets.",
    example: "fw-dc1 (FortiGate): IKE phase 1 uses DH group 14 (2048-bit MODP), quantum-vulnerable.",
  },
  // src: frontend/components/cbom/sources/AppliancesSection.tsx:29-36 — the appliance platform
  "cbsrc.app.col.vendor": {
    label: "Vendor",
    what: "The appliance platform and how it is read (SSH show commands or API).",
    why: "Each platform has its own read commands and credential type.",
    example: "Cisco ASA.",
  },
  // src: frontend/components/cbom/sources/AppliancesSection.tsx:218 — devices of the source
  "cbsrc.app.col.targets": {
    label: "Targets",
    what: "The devices this source reads, all with the same account.",
    why: "Group devices that share an account and platform into one source.",
    example: "3 devices.",
  },
  // src: frontend/components/cbom/sources/shared.tsx:78-88 — last connection test
  "cbsrc.col.test": {
    label: "Test",
    what: "The result of the last connection test: Not tested, Testing, Passed, Partly ready, Failed or Could not test.",
    why: "A source that has not passed a test is likely to fail its collection jobs.",
    example: "Passed.",
  },
  // src: frontend/components/cbom/sources/AppliancesSection.tsx:29-36, frontend/components/cbom/sources/AppliancesSection.tsx:201-212 — what is read on each platform
  "cbsrc.app.vendor": {
    label: "Vendor",
    what: "The platform of the devices. The hint lists exactly what is read: show commands for Cisco IOS, ASA and FortiOS; read-only API calls for PAN-OS and F5 BIG-IP.",
    why: "Only the listed reads are sent, so your change board can approve them up front.",
    example: "F5 BIG-IP: GET client-ssl profiles and key type and size only.",
  },
  // src: frontend/components/cbom/sources/AppliancesSection.tsx:215-216 — up to 64 characters
  "cbsrc.app.name": {
    label: "Name",
    what: "A name for this appliance source, up to 64 characters, shown in lists, run results and reports.",
    why: "Each finding records it as its source.",
    example: "dc1-firewalls.",
  },
  // src: frontend/components/cbom/sources/AppliancesSection.tsx:218-220 — one address or host name per line
  "cbsrc.app.devices": {
    label: "Devices",
    what: "The devices to read, one address or host name per line; all use the same account.",
    why: "Devices not listed keep their weak VPN settings unseen.",
    example: "10.20.0.1 and fw-dc1.bank.local.",
  },
  // src: frontend/components/cbom/sources/AppliancesSection.tsx:223-224 — default 22 for SSH, 443 for API
  "cbsrc.app.port": {
    label: "Port",
    what: "The management port: 22 by default for SSH platforms, 443 for API platforms.",
    why: "A management interface on a custom port fails the test until it is set here.",
    example: "8443 for a BIG-IP management port.",
  },
  // src: frontend/components/cbom/sources/AppliancesSection.tsx:227-228 — a read-only account, up to 64 characters
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
  // src: frontend/components/cbom/sources/AppliancesSection.tsx:233-234 — the node that reaches the management interface
  "cbsrc.app.node": {
    label: "Scan node",
    what: "The scan node that reaches the devices' management interfaces.",
    why: "Management networks are usually isolated; the node must sit where it can reach them.",
    example: "node-mgmt in the out-of-band network.",
  },
  // src: frontend/components/cbom/sources/AppliancesSection.tsx:237-240 — known_hosts lines, required for SSH
  "cbsrc.app.known_hosts": {
    label: "Pinned host key",
    what: "The devices' SSH host keys in known_hosts format. Required for SSH platforms.",
    why: "A device whose key does not match is refused before the password is sent.",
    example: "fw-dc1.bank.local ssh-rsa AAAAB3Nza...",
  },
  // src: frontend/components/cbom/sources/AppliancesSection.tsx:243-244 — PEM, for a privately issued management certificate
  "cbsrc.app.ca": {
    label: "CA certificate",
    what: "Optional PEM certificate of the CA that issued the management certificate of API platforms. The certificate is always verified.",
    why: "Needed when the management interface uses an internal CA.",
    example: "bank-root-ca.pem.",
  },
  // src: frontend/components/cbom/sources/ContainerImagesSection.tsx:1-5, frontend/components/cbom/sources/ContainerImagesSection.tsx:55-58 — pulled over HTTPS, 1 credit per image per run
  "cbsrc.img.card": {
    label: "Container images",
    what: "The scan node pulls images from your registry over HTTPS (verified by digest, never written to disk) and lists the crypto packages inside with package URLs. 1 credit per image per run.",
    why: "Images ship their own OpenSSL and crypto libraries, often older than the host's.",
    example: "registry.bank.in/payments/api:2.4.1 contains openssl 1.1.1k.",
  },
  // src: backend/utilities/cbom_sources/kinds.py:776, backend/utilities/cbom_sources/kinds.py:782 — up to 50 per source
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
  // src: frontend/components/cbom/sources/ContainerImagesSection.tsx:181-182 — up to 64 characters
  "cbsrc.img.name": {
    label: "Name",
    what: "A name for this image source, up to 64 characters, shown in lists, run results and reports.",
    why: "Each package found records it as its source.",
    example: "payments-images.",
  },
  // src: frontend/components/cbom/sources/ContainerImagesSection.tsx:184-185 — an agentless node that reaches the registry
  "cbsrc.img.node": {
    label: "Scan node",
    what: "An agentless scan node that reaches the registry over HTTPS.",
    why: "Host-agent nodes never pull images.",
    example: "node-dc1.",
  },
  // src: frontend/components/cbom/sources/ContainerImagesSection.tsx:187-189, backend/utilities/cbom_sources/kinds.py:776 — up to 50; registry/repository:tag or @sha256
  "cbsrc.img.refs": {
    label: "Images",
    what: "Up to 50 images, one per line: registry/repository:tag or @sha256:digest. Docker Hub is used when no registry is named.",
    why: "A digest pins exactly what was scanned; a tag may move.",
    example: "registry.bank.in/payments/api@sha256:4f1c...",
  },
  // src: frontend/components/cbom/sources/ContainerImagesSection.tsx:192-202 — anonymous or from a vault (admins)
  "cbsrc.img.cred": {
    label: "Registry credentials",
    what: "Anonymous for public pulls, or From a vault (team admins): the node reads the credential from your vault and sends it only to the registry's own host or its token service.",
    why: "The credential never passes through ZeroShield.",
    example: "From a vault for the private registry.bank.in.",
  },
  // src: frontend/components/cbom/sources/ContainerImagesSection.tsx:215-216 — up to 512 characters; under ZS_VAULT_PATH_PREFIX on the node
  "cbsrc.img.vault_path": {
    label: "Secret path",
    what: "Where the registry credential lives in your vault, up to 512 characters, under the prefix the node's operator allows (ZS_VAULT_PATH_PREFIX).",
    why: "The prefix keeps a source from reading arbitrary secrets through the node.",
    example: "secret/zs-cbom/registry/bank.",
  },
  // src: backend/utilities/cbom_sources/kinds.py:786 — 1 to 8,192 MB, default 2,048
  "cbsrc.img.max": {
    label: "Largest image",
    what: "The largest image to pull, compressed, 1 to 8,192 MB (default 2,048). Bigger images are reported as not read.",
    why: "Caps the node's bandwidth and time on one huge image.",
    example: "4096 for ML images with large CUDA layers.",
  },
  // src: frontend/components/cbom/sources/ContainerImagesSection.tsx:224-225 — only for a private CA
  "cbsrc.img.ca": {
    label: "Registry CA certificate",
    what: "Optional PEM certificate of the CA that issued the registry's certificate. The registry's certificate is always verified.",
    why: "Needed for an internal registry with a private CA.",
    example: "bank-root-ca.pem.",
  },
  // src: frontend/components/cbom/sources/CmdbImportDialog.tsx:1-4,45, frontend/components/cbom/sources/CmdbImportDialog.tsx:45-56 — existing sources keep how they connect
  "cbsrc.cmdb.updates": {
    label: "Metadata updates",
    what: "Existing sources whose owner, application, criticality, exposure, data classification or environment would change. How they connect is untouched, so running and queued jobs are kept.",
    why: "Keeps CBOM ownership in line with your CMDB without re-testing sources.",
    example: "dc-mumbai-linux: owner none → Payments platform team.",
  },
  // src: frontend/components/cbom/sources/CmdbImportDialog.tsx:1-4,58, frontend/components/cbom/sources/CmdbImportDialog.tsx:58-69 — new Linux server sources or network ranges
  "cbsrc.cmdb.creates": {
    label: "New sources",
    what: "Sources the import would create: hosts not yet in any server source become Linux server sources on the chosen node; CIDRs become network ranges.",
    why: "New sources still need a credential and a passing test before they are collected.",
    example: "cmdb-import-1 (14 Linux hosts) · owner: Cards ops.",
  },
  // src: frontend/components/cbom/sources/CmdbImportDialog.tsx:71-81 — left unchanged
  "cbsrc.cmdb.conflicts": {
    label: "Conflicts",
    what: "Rows that disagree with what is already set, for example a host in two sources with different owners. They are left unchanged.",
    why: "Resolve them in the CMDB or by hand so the right owner gets the findings.",
    example: "10.20.5.17: owner Payments in one source, Cards in another.",
  },
  // src: frontend/components/cbom/sources/CmdbImportDialog.tsx:83-93 — rows that could not be used
  "cbsrc.cmdb.skipped": {
    label: "Skipped or partly read rows",
    what: "CSV or CMDB rows that could not be used, or were only partly read, with the reason.",
    why: "Fix them at the source so the next import covers them.",
    example: "Row 37: criticality \"P1\" is not low, medium, high or critical.",
  },
  // src: frontend/components/cbom/sources/CmdbImportDialog.tsx:143-153 — CSV or ServiceNow CMDB
  "cbsrc.cmdb.source": {
    label: "Import from",
    what: "CSV file: columns host / fqdn / ip / cidr, owner, application, criticality, exposure, data_classification, environment, os. ServiceNow CMDB: reads the CMDB table set in Settings > Integrations (default cmdb_ci_server).",
    why: "Importing keeps owners and criticality in one place instead of typing them per source.",
    example: "ServiceNow CMDB, table cmdb_ci_server.",
  },
  // src: frontend/components/cbom/sources/CmdbImportDialog.tsx:155-171 — up to 5,000 rows and 2 MB, header row required
  "cbsrc.cmdb.csv": {
    label: "CSV",
    what: "The CSV to import, pasted or uploaded: up to 5,000 rows and 2 MB, with a header row.",
    why: "The header names the columns, so their order does not matter.",
    example: "host,owner,criticality\\napp-01.bank.local,Payments,high.",
  },
  // src: frontend/components/cbom/sources/CmdbImportDialog.tsx:1-4,174, frontend/components/cbom/sources/CmdbImportDialog.tsx:171-173 — new hosts become Linux server sources
  "cbsrc.cmdb.create": {
    label: "Create sources for new hosts",
    what: "Also create sources for hosts and CIDRs that are not in any source yet. Off: only existing sources are updated.",
    why: "Bringing every CMDB host into scope closes blind spots.",
    example: "On: 14 new hosts become a Linux server source on node-dc1.",
  },
  // src: frontend/components/cbom/sources/CmdbImportDialog.tsx:178-179 — the node that can reach the new hosts
  "cbsrc.cmdb.node": {
    label: "Scan node for new sources",
    what: "The scan node new sources use: it must reach the new hosts.",
    why: "A node that cannot reach them makes every new source fail its test.",
    example: "node-dc1.",
  },
  // src: frontend/components/cbom/sources/CmdbImportDialog.tsx:1-4,135, frontend/components/cbom/sources/CmdbImportDialog.tsx:135 — admins only; preview, then confirm
  "cbsrc.cmdb.dialog": {
    label: "Import sources and metadata from a CMDB",
    what: "Upload a CSV or pull the ServiceNow CMDB, preview what changes, then confirm. Team admins only.",
    why: "Nothing changes until you confirm the preview.",
    example: "Preview: 12 metadata updates, 1 new source, 2 conflicts.",
  },
  // ────────────────────────────────────────────────────────────── CBOM Sources: Fleet > SSH CA (components/cbom/sources/fleet/SshCaSection.tsx)
  // src: frontend/components/cbom/sources/fleet/SshCaSection.tsx:1-5, frontend/components/cbom/sources/fleet/SshCaSection.tsx:179-183 — short-lived per-job certificates for the node's own key
  "cbsrc.sshca.card": {
    label: "SSH certificate authority",
    what: "ZeroShield signs each scan node's own key into a short-lived certificate for every job (5 minutes by default), with principals zs-<team>-<group>, bound to the node's address and with no forwarding or terminal. Servers trust this CA for the zs-cbom login only; every certificate issued is listed below.",
    why: "Servers trust one CA instead of every node key, and a stolen certificate is useless within minutes.",
    example: "prod-servers-ca, Ed25519, 300-second certificates.",
  },
  // src: frontend/components/cbom/sources/fleet/SshCaSection.tsx:193-194 — up to 64 characters
  "cbsrc.sshca.name": {
    label: "Name",
    what: "A name for the CA, up to 64 characters.",
    why: "Linux sources pick their SSH CA by this name.",
    example: "prod-servers-ca.",
  },
  // src: frontend/components/cbom/sources/fleet/SshCaSection.tsx:196-203 — built in or HashiCorp Vault SSH engine
  "cbsrc.sshca.provider": {
    label: "Where the CA key lives",
    what: "Built in: ZeroShield holds the CA key, encrypted (with AWS KMS when this deployment has a key). Vault: your HashiCorp Vault SSH secrets engine signs and the key never leaves Vault.",
    why: "With Vault, the signing key stays under your own controls and audit.",
    example: "Vault, using the ssh-client-signer mount.",
  },
  // src: frontend/components/cbom/sources/fleet/SshCaSection.tsx:205-207 — 60 to 3,600 seconds; renewed during a job
  "cbsrc.sshca.ttl": {
    label: "Certificate lifetime",
    what: "How long each job certificate is valid, 60 to 3,600 seconds. A job renews its certificate before it runs out.",
    why: "Shorter lifetimes shrink the window in which a copied certificate works.",
    example: "300 seconds.",
  },
  // src: frontend/components/cbom/sources/fleet/SshCaSection.tsx:210-216 — Ed25519 or ECDSA P-256
  "cbsrc.sshca.alg": {
    label: "Key type",
    what: "The CA key's algorithm: Ed25519 (recommended) or ECDSA P-256.",
    why: "Both are widely supported by OpenSSH; neither is quantum-safe, so plan a rotation when post-quantum SSH keys are supported.",
    example: "Ed25519.",
  },
  // src: frontend/components/cbom/sources/fleet/SshCaSection.tsx:219-227 — AWS KMS or the deployment key
  "cbsrc.sshca.wrap": {
    label: "Key encryption",
    what: "How the built-in CA key is encrypted at rest: with AWS KMS when this deployment has a KMS key, otherwise with the deployment key (ENCRYPTION_KEY).",
    why: "KMS keeps the CA key unusable without access to your KMS key.",
    example: "AWS KMS.",
  },
  // src: frontend/components/cbom/sources/fleet/SshCaSection.tsx:230-235 — labels of the allowed KMS keys
  "cbsrc.sshca.kms": {
    label: "KMS key",
    what: "Which of this deployment's allowed AWS KMS keys wraps the CA key.",
    why: "Separate keys per environment limit the reach of one KMS policy.",
    example: "cbom-sshca-prod (default).",
  },
  // src: frontend/components/cbom/sources/fleet/SshCaSection.tsx:240-241 — https, the active node
  "cbsrc.sshca.vault_addr": {
    label: "Vault address",
    what: "The HTTPS address of your Vault's active node.",
    why: "Signing requests go only to this address.",
    example: "https://vault.bank.in:8200.",
  },
  // src: frontend/components/cbom/sources/fleet/SshCaSection.tsx:243-244 — the SSH secrets engine path
  "cbsrc.sshca.vault_mount": {
    label: "SSH engine mount",
    what: "The path where the SSH secrets engine is mounted in Vault.",
    why: "The token below is limited to signing under this mount.",
    example: "ssh-client-signer.",
  },
  // src: frontend/components/cbom/sources/fleet/SshCaSection.tsx:246-247 — allowed_critical_options must include source-address
  "cbsrc.sshca.vault_role": {
    label: "Signing role",
    what: "The Vault SSH role that signs. Its allowed_critical_options must include source-address and its default_extensions must be empty.",
    why: "Without source-address the certificates would work from any machine.",
    example: "zs-cbom-signer.",
  },
  // src: frontend/components/cbom/sources/fleet/SshCaSection.tsx:249-250 — write-only; may only call <mount>/sign/<role>
  "cbsrc.sshca.vault_token": {
    label: "Vault token",
    what: "A Vault token that may only call <mount>/sign/<role>. Write-only: it is never shown again.",
    why: "A token limited to signing cannot read secrets or change the CA.",
    example: "A periodic token with a policy allowing update on ssh-client-signer/sign/zs-cbom-signer.",
  },
  // src: frontend/components/cbom/sources/fleet/SshCaSection.tsx:48-53 — active, rotation, retired, revoked
  "cbsrc.sshca.col.state": {
    label: "State",
    what: "Active (signs), Rotation (trusted, not signing yet), Retired (still trusted during the overlap) or Revoked.",
    why: "Promote a rotation only once every server trusts the new key, or scan logins fail.",
    example: "Rotation: trusted, not signing yet.",
  },
  // src: frontend/components/cbom/sources/fleet/SshCaSection.tsx:287 — algorithm and fingerprint
  "cbsrc.sshca.col.key": {
    label: "Key",
    what: "The CA key's algorithm and SHA-256 fingerprint.",
    why: "Compare the fingerprint with TrustedUserCAKeys on a server to confirm it trusts this CA.",
    example: "ssh-ed25519 SHA256:3f9c...",
  },
  // src: frontend/components/cbom/sources/fleet/SshCaSection.tsx:280 — default certificate lifetime in seconds
  "cbsrc.sshca.col.lifetime": {
    label: "Lifetime",
    what: "The default lifetime of the certificates this CA issues, in seconds.",
    why: "Shorter is safer; jobs renew as needed.",
    example: "300 s.",
  },
  // src: frontend/components/cbom/sources/fleet/SshCaSection.tsx:289-292,280 — certificates issued by this CA
  "cbsrc.sshca.col.certs": {
    label: "Certificates",
    what: "How many certificates this CA has issued.",
    why: "Each one is listed in the certificate audit below.",
    example: "1,284.",
  },
  // src: frontend/components/cbom/sources/fleet/SshCaSection.tsx:328-329 — lowercase letters, digits, . _ -
  "cbsrc.sshca.group": {
    label: "Server group",
    what: "The server group for the principals file: certificates carry zs-<team>-<group>, and a server accepts only the groups in its file. Lowercase letters, digits, dots, underscores and dashes.",
    why: "Groups let production servers refuse certificates meant for test servers.",
    example: "prod.",
  },
  // src: frontend/components/cbom/sources/fleet/SshCaSection.tsx:342-347 — read trusted keys, KRL and principals only
  "cbsrc.sshca.trust_tokens": {
    label: "Trust tokens",
    what: "A trust token lets your servers or configuration management fetch this team's trusted keys, revocation list and principals, and nothing else. It is shown once.",
    why: "Servers keep their trust files current on their own, so rotations need no manual roll-out.",
    example: "prod-servers, used by 212 servers in the last 24 hours.",
  },
  // src: frontend/components/cbom/sources/fleet/SshCaSection.tsx:353-354 — up to 64 characters
  "cbsrc.sshca.token_name": {
    label: "Token name",
    what: "A name for the trust token, up to 64 characters.",
    why: "Name it after the servers that will use it, so you know what breaks if it is revoked.",
    example: "prod-servers.",
  },
  // src: frontend/components/cbom/sources/fleet/SshCaSection.tsx:363-366 — shown once; keep it root-only
  "cbsrc.sshca.new_token": {
    label: "Copy it now",
    what: "The new trust token is shown only once. Store it in a file only root can read and point ZS_TRUST_TOKEN at it.",
    why: "Anyone with the token can read your trusted keys and revocation list.",
    example: "/etc/zs-cbom/trust-token, mode 0600.",
  },
  // src: frontend/components/cbom/sources/fleet/SshCaSection.tsx:377 — the token's prefix
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
  // src: frontend/components/cbom/sources/fleet/SshCaSection.tsx:373 — last fetch
  "cbsrc.sshca.col.last_used": {
    label: "Last used",
    what: "When a server last fetched with this token.",
    why: "A token unused for weeks may belong to retired servers; revoke it.",
    example: "14 Nov 2026, 02:05 am IST.",
  },
  // src: frontend/components/cbom/sources/fleet/SshCaSection.tsx:380 — active or revoked
  "cbsrc.sshca.col.token_status": {
    label: "Status",
    what: "Whether the token still works: active, or revoked (servers using it get 401 and keep their current files).",
    why: "Revoke a token as soon as it may have leaked.",
    example: "Active.",
  },
  // src: frontend/components/cbom/sources/fleet/SshCaSection.tsx:411 — when the certificate was issued
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
  // src: frontend/components/cbom/sources/fleet/SshCaSection.tsx:409 — node, job, at claim or renewal
  "cbsrc.sshca.col.node_job": {
    label: "Node / job",
    what: "The scan node and job the certificate was issued for, and whether at the job's claim or as a renewal.",
    why: "Lets you trace every login back to a specific collection job.",
    example: "node #7 · job #4410 · at claim.",
  },
  // src: frontend/components/cbom/sources/fleet/SshCaSection.tsx:409 — valid_before
  "cbsrc.sshca.col.valid_until": {
    label: "Valid until",
    what: "When the certificate stops working.",
    why: "After this time it cannot be used even if copied.",
    example: "14 Nov 2026, 02:05:07 am IST.",
  },
  // src: frontend/components/cbom/sources/fleet/SshCaSection.tsx:54, frontend/components/cbom/sources/fleet/SshCaSection.tsx:409 — valid, expired, revoked
  "cbsrc.sshca.col.cert_status": {
    label: "Status",
    what: "valid, expired or revoked (in the revocation list; servers refuse it once they have the new list).",
    why: "Revoke a certificate if its node may be compromised before it expires.",
    example: "expired.",
  },
  // src: frontend/components/cbom/sources/fleet/SshCaSection.tsx:446-451 — promote before the readiness check passes
  "cbsrc.sshca.promote_now": {
    label: "Promote now",
    what: "Promote the new key now, before the readiness check shows every server has it. Servers that do not trust it yet refuse every scan login.",
    why: "Use only when you know every server already has the new trusted keys.",
    example: "Tick after your Ansible run pushed the new trusted keys everywhere.",
  },
  // src: frontend/components/cbom/sources/fleet/SshCaSection.tsx:461-466 — recorded in the audit, up to 512 characters
  "cbsrc.sshca.reason": {
    label: "Reason",
    what: "Why you are revoking, up to 512 characters. It is recorded in the audit.",
    why: "Auditors and teammates see why a CA, certificate or token was revoked.",
    example: "Node VM snapshot copied to an untrusted host.",
  },
  // ────────────────────────────────────────────────────────────── CBOM Sources: Review & Run, business criticality
  // src: backend/utilities/cbom_sources/posture.py:12-14, backend/utilities/cbom_sources/posture.py:43-47 — impact weight x criticality x exposure
  "cbsrc.rr.criticality": {
    label: "Business criticality and exposure",
    what: "Per source: business criticality (Low x0.5, Medium x1 by default, High x1.5, Critical x2) and internet exposure (from the collected facts, or set; internet-facing x1.5). A finding's risk score is its impact weight times both. Runs snapshot them when they start.",
    why: "Ranks the same weak cipher higher on a critical, internet-facing system than on an internal test box.",
    example: "High finding (7) on a Critical, internet-facing source: 7 x 2 x 1.5 = 21.",
  },
  // ────────────────────────────────────────────────────────────── Settings > Integrations (components/integrations/IntegrationsPage.tsx)
  // src: frontend/components/integrations/IntegrationsPage.tsx:139-140 — one record per finding; resolved when a later complete run no longer finds it
  "int.card.servicenow": {
    label: "ServiceNow",
    what: "Opens one ServiceNow record per new finding (de-duplicated by a correlation id) and resolves it when a later complete run no longer finds it. Also the source for the CMDB import on CBOM Sources.",
    why: "Findings land in the queue your teams already work from, and close themselves when fixed.",
    example: "INC0012345: RSA-1024 certificate on api.bank.in:443, assigned to Payments.",
  },
  // src: frontend/components/integrations/IntegrationsPage.tsx:133 — RFC 5424 with CEF or JSON
  "int.card.syslog": {
    label: "Syslog (SIEM)",
    what: "Sends every event as an RFC 5424 syslog message with a CEF or JSON payload to your SIEM or SOAR.",
    why: "Your SOC sees crypto findings next to other security alerts.",
    example: "A CEF event Finding opened, severity High, to ArcSight on 6514.",
  },
  // src: frontend/components/integrations/IntegrationsPage.tsx:134 — batched JSON events
  "int.card.splunk_hec": {
    label: "Splunk HEC",
    what: "Sends every event to a Splunk HTTP Event Collector, batched as JSON events.",
    why: "Lets you build Splunk dashboards and alerts on crypto findings.",
    example: "sourcetype zeroshield:cbom in index security.",
  },
  // src: frontend/components/integrations/IntegrationsPage.tsx:135 — HMAC-SHA256 over timestamp and body
  "int.card.webhook": {
    label: "Signed webhook",
    what: "POSTs every event as JSON to your receiver, signed with HMAC-SHA256 over the timestamp and the body.",
    why: "Any SOAR or in-house tool can act on events and prove they came from ZeroShield.",
    example: "A Certificate expiring event POSTed to https://soar.bank.in/hooks/zeroshield.",
  },
  // src: frontend/components/integrations/IntegrationsPage.tsx:136 — OSCAL 1.2.3 assessment results, schema-validated, signed
  "int.card.oscal": {
    label: "OSCAL push",
    what: "When a Sources run or a CBOM code scan finishes, pushes its OSCAL 1.2.3 assessment results (schema-validated) to your GRC tool, signed like the webhook.",
    why: "Auditors get machine-readable evidence without exports by hand.",
    example: "Run #42's assessment results pushed to https://grc.bank.in/api/oscal.",
  },
  // src: frontend/components/integrations/IntegrationsPage.tsx:289-291 — on or off per integration
  "int.enabled": {
    label: "Forward events",
    what: "On: events are queued and delivered to this destination. Off: nothing is sent; the settings are kept.",
    why: "Turn it off during a destination's maintenance instead of deleting the integration.",
    example: "Off while the SIEM is being migrated.",
  },
  // src: frontend/components/integrations/IntegrationsPage.tsx:55-58,73 — PEM; certificates are always verified
  "int.common.ca_pem": {
    label: "CA certificate",
    what: "Optional PEM certificate of the CA that signed the destination's certificate, when it is not publicly trusted. The destination's certificate is always verified.",
    why: "Without it, a destination with an internal CA fails every delivery on the TLS check.",
    example: "bank-root-ca.pem for siem.bank.local.",
  },
  // src: frontend/components/integrations/IntegrationsPage.tsx:79 — https://<instance>.service-now.com
  "int.sn.instance_url": {
    label: "Instance URL",
    what: "Your ServiceNow instance's address.",
    why: "Records are created only on this instance.",
    example: "https://bank.service-now.com.",
  },
  // src: frontend/components/integrations/IntegrationsPage.tsx:80 — incident or sn_vul_vulnerable_item
  "int.sn.table": {
    label: "Table",
    what: "The table records are created in: incident, or sn_vul_vulnerable_item with Vulnerability Response.",
    why: "Use the table your remediation teams work from.",
    example: "sn_vul_vulnerable_item.",
  },
  // src: frontend/components/integrations/IntegrationsPage.tsx:81 — user and password or OAuth client credentials
  "int.sn.auth": {
    label: "Authentication",
    what: "How ZeroShield signs in to ServiceNow: a user and password, or OAuth client credentials.",
    why: "OAuth credentials can be scoped and rotated without a user account.",
    example: "OAuth client credentials for the zeroshield-integration app.",
  },
  // src: frontend/components/integrations/IntegrationsPage.tsx:82 — basic authentication user
  "int.sn.username": {
    label: "User",
    what: "The ServiceNow user for basic authentication, with rights to create and update records in the table.",
    why: "A dedicated integration user makes the records' origin clear in audit history.",
    example: "svc_zeroshield.",
  },
  // src: frontend/components/integrations/IntegrationsPage.tsx:83 — OAuth client credentials
  "int.sn.client_id": {
    label: "OAuth client ID",
    what: "The client ID of the OAuth application registered in ServiceNow.",
    why: "Pairs with the client secret below.",
    example: "3f9c1e2a7b...",
  },
  // src: frontend/components/integrations/IntegrationsPage.tsx:84 — optional
  "int.sn.assignment_group": {
    label: "Assignment group",
    what: "Optional: the group new records are assigned to.",
    why: "Records without a group may sit unassigned.",
    example: "PKI Operations.",
  },
  // src: frontend/components/integrations/IntegrationsPage.tsx:85 — optional
  "int.sn.category": {
    label: "Category",
    what: "Optional: the category set on new records.",
    why: "Lets you filter and report crypto findings in ServiceNow.",
    example: "Security.",
  },
  // src: frontend/components/integrations/IntegrationsPage.tsx:86 — incident: 6 (Resolved)
  "int.sn.resolve_state": {
    label: "Resolved state value",
    what: "The state value set when a finding is no longer found by a later complete run.",
    why: "A wrong value leaves fixed findings open in ServiceNow.",
    example: "6 (Resolved) for incident.",
  },
  // src: frontend/components/integrations/IntegrationsPage.tsx:87 — close code on resolve
  "int.sn.close_code": {
    label: "Resolution code",
    what: "The resolution (close) code set when a record is resolved.",
    why: "Some instances refuse to resolve a record without a close code.",
    example: "Solution provided.",
  },
  // src: frontend/components/integrations/IntegrationsPage.tsx:88 — resolving always goes through
  "int.sn.min_severity": {
    label: "Open records from severity",
    what: "The lowest severity that opens a new record. Resolving a record always goes through.",
    why: "Keeps low findings out of the ticket queue while still closing records that exist.",
    example: "High and above.",
  },
  // src: frontend/components/integrations/IntegrationsPage.tsx:91 — one record per finding
  "int.sn.correlation_field": {
    label: "Correlation field",
    what: "The field that stores ZeroShield's finding id. Before creating a record, ZeroShield looks it up by this field, so each finding has one record.",
    why: "Prevents duplicates when a finding is seen in every run.",
    example: "correlation_id.",
  },
  // src: frontend/components/integrations/IntegrationsPage.tsx:93 — the table the CMDB import reads
  "int.sn.cmdb_table": {
    label: "CMDB table",
    what: "The CMDB table the CMDB import on CBOM Sources reads.",
    why: "Point it at the class that holds your servers.",
    example: "cmdb_ci_server.",
  },
  // src: frontend/components/integrations/IntegrationsPage.tsx:94 — encoded query, optional
  "int.sn.cmdb_query": {
    label: "CMDB filter",
    what: "Optional: a ServiceNow encoded query that limits which CMDB records are imported.",
    why: "Leaves decommissioned or non-production CIs out.",
    example: "operational_status=1.",
  },
  // src: frontend/components/integrations/IntegrationsPage.tsx:95 — fields tried in order
  "int.sn.cmdb_host": {
    label: "CMDB host fields",
    what: "The CMDB fields that hold the host, tried in order.",
    why: "The first non-empty field becomes the target the import matches or adds.",
    example: "fqdn, ip_address, host_name, name.",
  },
  // src: frontend/components/integrations/IntegrationsPage.tsx:96 — maps to the source owner
  "int.sn.cmdb_owner": {
    label: "CMDB owner field",
    what: "The CMDB field mapped to the source owner.",
    why: "Owners from the CMDB become the remediation owners.",
    example: "owned_by.",
  },
  // src: frontend/components/integrations/IntegrationsPage.tsx:97 — maps to the source application
  "int.sn.cmdb_application": {
    label: "CMDB application field",
    what: "The CMDB field mapped to the source application.",
    why: "Groups findings by the application they affect.",
    example: "u_application.",
  },
  // src: frontend/components/integrations/IntegrationsPage.tsx:98 — maps to the source environment
  "int.sn.cmdb_environment": {
    label: "CMDB environment field",
    what: "The CMDB field mapped to the source environment.",
    why: "Separates production from test in plans and reports.",
    example: "used_for.",
  },
  // src: frontend/components/integrations/IntegrationsPage.tsx:99 — optional; maps to business criticality
  "int.sn.cmdb_criticality": {
    label: "CMDB criticality field",
    what: "Optional: the CMDB field mapped to business criticality (low, medium, high or critical).",
    why: "Criticality scales the risk score of every finding of the source.",
    example: "busines_criticality.",
  },
  // src: frontend/components/integrations/IntegrationsPage.tsx:100 — optional; maps to internet exposure
  "int.sn.cmdb_exposure": {
    label: "CMDB exposure field",
    what: "Optional: the CMDB field mapped to internet exposure.",
    why: "Internet-facing multiplies the risk score by 1.5.",
    example: "u_internet_facing.",
  },
  // src: frontend/components/integrations/IntegrationsPage.tsx:101 — optional
  "int.sn.cmdb_classification": {
    label: "CMDB data classification field",
    what: "Optional: the CMDB field mapped to the data classification (public, internal, confidential, restricted).",
    why: "Sensitive data under weak crypto is migrated first.",
    example: "u_data_classification.",
  },
  // src: frontend/components/integrations/IntegrationsPage.tsx:105 — syslog collector
  "int.sys.host": {
    label: "Collector host",
    what: "The hostname or address of your syslog collector.",
    why: "Every event is sent here.",
    example: "siem.bank.local.",
  },
  // src: frontend/components/integrations/IntegrationsPage.tsx:106 — TLS, TCP, UDP
  "int.sys.transport": {
    label: "Transport",
    what: "TLS (RFC 5425, port 6514), TCP with octet counting, or UDP (RFC 5426, no delivery confirmation).",
    why: "Only TLS protects the events in transit; UDP may lose them silently.",
    example: "TLS to siem.bank.local on 6514.",
  },
  // src: frontend/components/integrations/IntegrationsPage.tsx:91 — default 6514 for TLS, 514 for TCP and UDP
  "int.sys.port": {
    label: "Port",
    what: "Optional: the collector's port. Default 6514 for TLS, 514 for TCP and UDP.",
    why: "A wrong port fails the test event.",
    example: "6514.",
  },
  // src: frontend/components/integrations/IntegrationsPage.tsx:109 — CEF or JSON
  "int.sys.format": {
    label: "Message format",
    what: "The payload format: CEF (ArcSight) or JSON.",
    why: "Pick the one your SIEM parses without a custom parser.",
    example: "CEF for ArcSight; JSON for Elastic.",
  },
  // src: frontend/components/integrations/IntegrationsPage.tsx:110 — syslog facility number
  "int.sys.facility": {
    label: "Facility",
    what: "The syslog facility number set on each message; 16 is local0.",
    why: "Lets the collector route ZeroShield events to their own file or index.",
    example: "16 (local0).",
  },
  // src: frontend/components/integrations/IntegrationsPage.tsx:111 — the HOSTNAME field
  "int.sys.sender": {
    label: "Sender name",
    what: "The name put in the HOSTNAME field of each message.",
    why: "Identifies the events as ZeroShield's in the SIEM.",
    example: "zeroshield.",
  },
  // src: frontend/components/integrations/IntegrationsPage.tsx:115 — https
  "int.hec.url": {
    label: "HEC URL",
    what: "The address of your Splunk HTTP Event Collector.",
    why: "Events are posted only here.",
    example: "https://splunk.bank.local:8088.",
  },
  // src: frontend/components/integrations/IntegrationsPage.tsx:116 — optional
  "int.hec.index": {
    label: "Index",
    what: "Optional: the Splunk index to write to. Blank uses the token's default index.",
    why: "Keeps crypto events in the index your SOC searches.",
    example: "security.",
  },
  // src: frontend/components/integrations/IntegrationsPage.tsx:117 — sourcetype of each event
  "int.hec.sourcetype": {
    label: "Sourcetype",
    what: "The sourcetype set on each event.",
    why: "Splunk searches and field extraction key off the sourcetype.",
    example: "zeroshield:cbom.",
  },
  // src: frontend/components/integrations/IntegrationsPage.tsx:118 — source of each event
  "int.hec.source": {
    label: "Source",
    what: "The source set on each event.",
    why: "Tells events from different ZeroShield teams or deployments apart.",
    example: "zeroshield-prod.",
  },
  // src: frontend/components/integrations/IntegrationsPage.tsx:122 — https
  "int.webhook.url": {
    label: "Receiver URL",
    what: "The HTTPS address that receives the signed JSON events.",
    why: "Events are posted only here.",
    example: "https://soar.bank.local/hooks/zeroshield.",
  },
  // src: frontend/components/integrations/IntegrationsPage.tsx:126 — https
  "int.oscal.url": {
    label: "GRC endpoint URL",
    what: "The HTTPS address of your GRC tool's OSCAL endpoint.",
    why: "Assessment results are pushed only here.",
    example: "https://grc.bank.local/api/oscal.",
  },
  // src: frontend/components/integrations/IntegrationsPage.tsx:148, frontend/components/integrations/IntegrationsPage.tsx:325-328 — write-only
  "int.secret.password": {
    label: "Password",
    what: "The ServiceNow user's password. Encrypted at rest and never shown again; changing the URL or user clears it unless you enter it again.",
    why: "Clearing it on change keeps it from going to a host it was not meant for.",
    example: "The svc_zeroshield password.",
  },
  // src: frontend/components/integrations/IntegrationsPage.tsx:148, frontend/components/integrations/IntegrationsPage.tsx:325-328,150 — write-only
  "int.secret.client_secret": {
    label: "OAuth client secret",
    what: "The OAuth application's client secret. Encrypted at rest and never shown again.",
    why: "With the client ID it obtains tokens to create records.",
    example: "The secret shown when the OAuth app was created.",
  },
  // src: frontend/components/integrations/IntegrationsPage.tsx:153, frontend/components/integrations/IntegrationsPage.tsx:325-328,153 — write-only
  "int.secret.hec_token": {
    label: "HEC token",
    what: "The Splunk HEC token. Encrypted at rest and never shown again.",
    why: "Anyone with it can write events to your Splunk; scope it to one index.",
    example: "A token created under Data inputs > HTTP Event Collector.",
  },
  // src: frontend/components/integrations/IntegrationsPage.tsx:154, frontend/components/integrations/IntegrationsPage.tsx:325-328,154 — 16 or more characters; write-only
  "int.secret.signing": {
    label: "Signing secret",
    what: "The shared secret, 16 characters or more, used to sign each request (HMAC-SHA256). Generate creates one; copy it to your receiver before saving, as it is never shown again.",
    why: "Your receiver uses it to reject requests not sent by ZeroShield.",
    example: "A 43-character random value from Generate.",
  },
  // src: frontend/components/integrations/IntegrationsPage.tsx:31-40,354, frontend/components/integrations/IntegrationsPage.tsx:351-364 — which events are sent
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
  // src: frontend/components/integrations/IntegrationsPage.tsx:432-439 — one integration or all
  "int.log.filter_kind": {
    label: "Integration filter",
    what: "Show deliveries of one integration, or of all.",
    why: "Retry all needs one integration chosen.",
    example: "ServiceNow.",
  },
  // src: frontend/components/integrations/IntegrationsPage.tsx:440-446 — pending, delivered, dead-lettered
  "int.log.filter_status": {
    label: "Status filter",
    what: "Show deliveries by status: pending, delivered or dead-lettered.",
    why: "Dead-lettered events were not received and may need a retry.",
    example: "Dead-lettered.",
  },
  // src: frontend/components/integrations/IntegrationsPage.tsx:464 — when the event was queued
  "int.log.col.queued": {
    label: "Queued",
    what: "When the event was queued for this destination.",
    why: "Events are delivered oldest first.",
    example: "14 Nov 2026, 02:31 am IST.",
  },
  // src: frontend/components/integrations/IntegrationsPage.tsx:465 — destination
  "int.log.col.integration": {
    label: "Integration",
    what: "The destination the event is for.",
    why: "Each destination has its own queue.",
    example: "Splunk HEC.",
  },
  // src: frontend/components/integrations/IntegrationsPage.tsx:31-40, frontend/components/integrations/IntegrationsPage.tsx:466 — event type
  "int.log.col.event": {
    label: "Event",
    what: "What happened: finding opened or resolved, asset added or removed, certificate renewed or expiring, scheduled run skipped, run or scan finished.",
    why: "Lets you check a specific finding reached the destination.",
    example: "Finding resolved.",
  },
  // src: frontend/components/integrations/IntegrationsPage.tsx:467 — pending, delivered, dead
  "int.log.col.status": {
    label: "Status",
    what: "Pending (queued or backing off), delivered, or dead-lettered (refused for good, or still undelivered after the maximum age).",
    why: "Dead-lettered events need fixing at the destination, then a retry.",
    example: "Pending: next attempt in 4 minutes.",
  },
  // src: backend/utilities/integrations/dispatch.py:46, frontend/components/integrations/IntegrationsPage.tsx:468 — delivery attempts
  "int.log.col.attempts": {
    label: "Attempts",
    what: "How many times delivery was tried.",
    why: "Many attempts point at a destination that is down or refusing the credentials.",
    example: "3: two timeouts, then delivered.",
  },
  // src: frontend/components/integrations/IntegrationsPage.tsx:469 — last response or error
  "int.log.col.result": {
    label: "Result",
    what: "The destination's last answer or the error.",
    why: "Names the exact cause to fix at the destination.",
    example: "HTTP 401: the HEC token is disabled.",
  },
  // ────────────────────────────────────────────────────────────── CBOM code-scan results (components/CbomResults.tsx)
  // src: backend/utilities/cbom_sources/cbom_metrics.py:166-174, backend/utilities/dashboard/scan.py:1207-1208 — every row of the inventory table: findings and clean inventory
  "cbom.res.kpi.assets": {
    label: "Crypto assets",
    what: "Every cryptographic asset this scan found: algorithms, keys, certificates, protocols and libraries in use, whether or not it is a finding.",
    why: "This is your cryptographic bill of materials; everything else on the page is a view of it.",
    example: "57 assets: 41 clean (such as AES-256-GCM) and 16 findings.",
  },
  // src: backend/utilities/cbom_sources/cbom_metrics.py:122-129 — crypto_strength weak
  "cbom.res.kpi.weak": {
    label: "Weak",
    what: "Assets whose cryptographic strength is weak today: broken or deprecated algorithms and too-short keys.",
    why: "Weak crypto can be attacked now, without a quantum computer.",
    example: "MD5 password hashing in auth/legacy.py.",
  },
  // src: backend/utilities/cbom_sources/cbom_metrics.py:130-135 — the Quantum column's verdict
  "cbom.res.kpi.qv": {
    label: "Quantum vulnerable",
    what: "Assets that a large quantum computer could break: public-key algorithms such as RSA, Diffie-Hellman and elliptic curves (ECDH, ECDSA).",
    why: "Data encrypted with them today can be recorded now and decrypted later (harvest now, decrypt later).",
    example: "RSA-2048 key exchange on api.bank.in:443: a future quantum computer could recover the key, so recorded traffic is at risk.",
  },
  // src: backend/utilities/cbom_sources/cbom_metrics.py:136-137 — algorithm_type certificate
  "cbom.res.kpi.certs": {
    label: "Certificates",
    what: "X.509 certificates found in the code and files of this scan.",
    why: "Certificates expire and carry keys and signature algorithms that need migrating.",
    example: "3: two in config/tls, one test certificate in fixtures.",
  },
  // src: backend/utilities/cbom_sources/cbom_metrics.py:138-139 — algorithm_type key or secret
  "cbom.res.kpi.keys": {
    label: "Keys",
    what: "Keys and secrets found: private keys, symmetric keys and key material in code or files.",
    why: "A key committed to a repository should be treated as exposed and rotated.",
    example: "A PEM private key in deploy/certs/server.key.",
  },
  // src: backend/utilities/cbom_sources/cbom_metrics.py:29-43, backend/utilities/cbom_sources/cbom_metrics.py:175-179, frontend/utils/cbomReadiness.ts:19-21 — quantum-safe share of judged assets; n/a when none judged
  "cbom.res.kpi.ready": {
    label: "Quantum ready",
    what: "The share of judged assets that are quantum-safe: post-quantum, hybrid or symmetric with enough margin. Assets that are quantum-vulnerable or broken today count against it; assets without a quantum verdict (hashes, settings) are left out. n/a when no asset was judged.",
    why: "It tracks your post-quantum migration in one number.",
    example: "12 judged: 9 safe, 2 RSA, 1 DES: 9 / 12 = 75%.",
  },
  // src: backend/utilities/cbom_sources/cbom_metrics.py:26, backend/utilities/cbom_sources/cbom_metrics.py:82-88 — 0-10 over findings: critical 9, high 7, medium 5, low 2
  "cbom.res.kpi.avg_risk": {
    label: "Avg risk score",
    what: "The average risk over this scan's findings, 0 to 10: Critical 9, High 7, Medium 5, Low 2. Clean inventory is left out. One decimal.",
    why: "A quick severity summary that can be compared across scans.",
    example: "1 Critical and 1 Low: (9 + 2) / 2 = 5.5.",
  },
  // src: backend/utilities/dashboard/scan.py:1233-1239 — finding rows by status
  "cbom.res.remediation": {
    label: "Remediation progress",
    what: "This scan's findings by the status your team set: Fixed, In progress, Not started, Ignored, with a count and a share each.",
    why: "Shows how far the fixing has got.",
    example: "16 findings: 4 Fixed (25%), 2 In progress, 10 Not started.",
  },
  // src: backend/utilities/cbom_sources/cbom_metrics.py:146-147 — owasp_top_10 values of the findings
  "cbom.res.owasp": {
    label: "OWASP Top 10 issues",
    what: "How many findings map to each OWASP Top 10 category; most crypto findings fall under A02 Cryptographic Failures.",
    why: "Lets you report crypto findings in the framework your AppSec team uses.",
    example: "A02:2021 Cryptographic Failures: 14.",
  },
  // src: backend/utilities/cbom_sources/cbom_metrics.py:182-185 — findings by severity
  "cbom.res.severity": {
    label: "Risk metrics",
    what: "This scan's findings by impact: Critical, High, Medium and Low.",
    why: "Fix Critical and High first.",
    example: "Critical 1, High 5, Medium 7, Low 3.",
  },
  // src: backend/utilities/cbom_sources/cbom_metrics.py:148-149, backend/utilities/dashboard/scan.py:1213-1224 — controls the findings map to, and framework fails
  "cbom.res.compliance": {
    label: "Compliance controls",
    what: "Findings mapped to compliance controls and frameworks (for example CERT-In, RBI, NIST, PCI DSS): the 10 with the most findings.",
    why: "Shows which audit requirements the crypto weaknesses put at risk.",
    example: "PCI DSS 4.2.1 (strong cryptography in transit): 6.",
  },
  // src: backend/utilities/cbom_sources/cbom_metrics.py:116-120 — algorithm_type of every row
  "cbom.res.algo_types": {
    label: "Algorithm types",
    what: "Every asset by type of cryptography: symmetric cipher, asymmetric, hash, signature, key exchange, certificate, key, protocol and others.",
    why: "Shows where your crypto is concentrated and which migration work dominates.",
    example: "hash 18, symmetric 12, asymmetric 9, certificate 3.",
  },
  // src: backend/utilities/cbom_sources/cbom_metrics.py:121-129 — weak, moderate, strong, quantum_safe
  "cbom.res.strength": {
    label: "Crypto strength",
    what: "Every asset by strength today: weak, moderate, strong or quantum-safe.",
    why: "Weak and moderate assets are the near-term fixes.",
    example: "weak 4, moderate 6, strong 40, quantum-safe 2.",
  },
  // src: backend/utilities/cbom_sources/cbom_metrics.py:100-135 — quantum-safe, quantum-vulnerable, broken today
  "cbom.res.quantum": {
    label: "Quantum readiness",
    what: "Every judged asset by its quantum verdict: quantum-safe, quantum-vulnerable (public-key crypto a quantum computer breaks), or broken today (already weak, such as MD5 or DES).",
    why: "Quantum-vulnerable assets are your post-quantum migration list.",
    example: "safe 30, quantum-vulnerable 9, broken today 3.",
  },
  // src: frontend/components/cbom/results/CbomDashboardCharts.tsx:94, backend/utilities/dashboard/bom_risk_score.py:101-120 — top 24 by score
  "cbom.res.risk_scores": {
    label: "Risk scores per finding",
    what: "The 24 highest-scoring findings, highest first (F1 is the highest). Each score is 0 to 10: the impact's base plus additions for weak strength, quantum vulnerability and the finding's codes.",
    why: "Shows whether risk is concentrated in a few findings or spread out.",
    example: "F1: RSA-1024 signing key, 9.8.",
  },
  // src: backend/utilities/dashboard/scan.py:1230-1231, backend/utilities/dashboard/remediation_metrics.py:17-90 — from the status of this scan's findings
  "cbom.res.remed.section": {
    label: "Remediation metrics",
    what: "Measured from the status your team sets on this scan's findings. The targets are fixed goals shown for comparison.",
    why: "Shows whether fixes keep pace with what the scans find.",
    example: "Mark a finding Fixed in the table below and these numbers update.",
  },
  // src: frontend/components/CbomResults.tsx:699 — the CycloneDX import report
  "cbom.res.import_notes": {
    label: "About the uploaded CBOM file",
    what: "What happened when your uploaded CycloneDX CBOM was read: how many cryptographic assets were imported, and which components were skipped as not crypto, unreadable, duplicate or past the limit.",
    why: "Skipped components are missing from the results, so check them.",
    example: "40 of 42 cryptographic assets imported · CycloneDX 1.6 · 2 unreadable.",
  },
  // src: frontend/components/CbomResults.tsx:724 — coverage notes of the scan
  "cbom.res.coverage": {
    label: "What this scan covered",
    what: "Which files and languages the scan read and what it skipped, with the reason.",
    why: "Skipped files are not in the inventory, so a clean result may be incomplete.",
    example: "312 files read; 14 skipped as larger than the size limit.",
  },
  // src: frontend/components/CbomResults.tsx:843 — an uploaded CBOM file
  "cbom.res.input": {
    label: "Input",
    what: "This scan read an uploaded CycloneDX CBOM file instead of source code.",
    why: "Results are only as complete as the file.",
    example: "CBOM file.",
  },
  // src: frontend/components/CbomResults.tsx:940 — finding rows; clean inventory is not listed here
  "cbom.res.findings": {
    label: "Cryptographic findings",
    what: "This scan's findings, one per row, each with a status your team sets. Clean assets (for example AES-GCM or SHA-256) are in the charts and the CycloneDX download, not in this table.",
    why: "Each row is something to fix, accept or plan for migration.",
    example: "RSA-2048 in src/crypto/keys.py:42, High, quantum-vulnerable, Not started.",
  },
  // src: frontend/components/CbomResults.tsx:266 — algorithm, description, location or id
  "cbom.res.search": {
    label: "Search",
    what: "Shows only the findings whose algorithm, description, location or id contains this text (upper or lower case does not matter).",
    why: "Find every use of one algorithm or file quickly.",
    example: "\"rsa\" keeps RSA-2048 and RSA-1024 findings.",
  },
  // src: frontend/components/CbomResults.tsx:994 — tiers on the 0-10 risk score
  "cbom.res.filter.risk": {
    label: "Risk score filter",
    what: "Shows only findings whose risk score (0 to 10) is in a tier: Critical 9 or more, High 7 to 9, Medium 5 to 7, Low under 5.",
    why: "Focus on the findings that score highest.",
    example: "High keeps a finding scored 7.6 and hides one scored 9.4.",
  },
  // src: frontend/components/CbomResults.tsx:1007 — exact crypto_strength
  "cbom.res.filter.strength": {
    label: "Strength filter",
    what: "Shows only findings of one strength: weak, moderate, strong or quantum-safe.",
    why: "Weak findings are exploitable today.",
    example: "Weak.",
  },
  // src: frontend/components/CbomResults.tsx:1019 — exact algorithm_type
  "cbom.res.filter.type": {
    label: "Type filter",
    what: "Shows only findings of one algorithm type, from the types found in this scan.",
    why: "Plan migration work one type at a time.",
    example: "certificate.",
  },
  // src: frontend/components/cbom/quantumFilter.ts:10-29 — safe, broken today, vulnerable
  "cbom.res.filter.quantum": {
    label: "Quantum filter",
    what: "Shows only findings that are quantum-safe, broken today (weak even without a quantum computer, such as MD5) or quantum-vulnerable.",
    why: "Vulnerable gives your post-quantum migration list; Broken today the fixes that cannot wait.",
    example: "Vulnerable: the RSA and ECDH findings.",
  },
  // src: frontend/components/CbomResults.tsx:1063 — selects the rows shown
  "cbom.res.select_all": {
    label: "Select all",
    what: "Selects every finding the table shows (after search and filters), for the actions above the table: change their status or file Jira tickets.",
    why: "Handle a group of similar findings in one step.",
    example: "Filter Type: certificate, select all, mark In progress.",
  },
  // src: frontend/components/CbomResults.tsx:1066 — algorithm name
  "cbom.res.col.algorithm": {
    label: "Algorithm",
    what: "The algorithm, key, certificate or protocol found, as named in the code or file. Click it for the details and the suggested fix.",
    why: "Names exactly what to replace.",
    example: "RSA-2048.",
  },
  // src: frontend/components/CbomResults.tsx:1067 — algorithm_type
  "cbom.res.col.type": {
    label: "Type",
    what: "The kind of cryptography: symmetric, asymmetric, hash, signature, key exchange, certificate, key, protocol or other.",
    why: "Each type has its own replacement path.",
    example: "asymmetric.",
  },
  // src: frontend/components/CbomResults.tsx:1069, backend/utilities/cbom_sources/cbom_metrics.py:121-129 — weak, moderate, strong, quantum-safe
  "cbom.res.col.strength": {
    label: "Strength",
    what: "How strong it is today: weak (broken or deprecated), moderate, strong, or quantum-safe.",
    why: "Weak is exploitable now; moderate is due for an upgrade.",
    example: "weak for SHA-1 signatures.",
  },
  // src: frontend/components/cbom/quantumFilter.ts:10-29 — safe, broken today, vulnerable
  "cbom.res.col.quantum": {
    label: "Quantum",
    what: "Whether a quantum computer breaks it: Quantum-safe, Vulnerable (RSA, Diffie-Hellman, elliptic curves) or Broken today (weak even without one).",
    why: "Vulnerable assets need a post-quantum replacement such as ML-KEM or ML-DSA.",
    example: "Vulnerable for ECDSA P-256 signing.",
  },
  // src: backend/utilities/dashboard/bom_risk_score.py:101-120 — 0-10 per finding
  "cbom.res.col.risk": {
    label: "Risk score",
    what: "This finding's risk, 0 to 10: the impact's base plus additions for weak strength, quantum vulnerability and its finding codes.",
    why: "Orders findings of the same impact by how much they matter.",
    example: "9.8 for an RSA-1024 signing key.",
  },
  // src: frontend/components/CbomResults.tsx:1073 — file and line
  "cbom.res.col.location": {
    label: "Location",
    what: "Where it was found: the file and line, or the component in an uploaded CBOM.",
    why: "Takes you straight to the code to change.",
    example: "src/crypto/keys.py:42.",
  },
  // src: backend/utilities/dashboard/scan.py:1256, backend/utilities/cbom_sources/cbom_metrics.py:186-188 — the 10 highest risk scores
  "cbom.res.top": {
    label: "Top cryptographic risks",
    what: "The 10 findings with the highest risk scores in this scan.",
    why: "Start here when you have time for only a few fixes.",
    example: "RSA-1024 signing key, weak, not quantum-safe, Critical.",
  },
  // src: frontend/components/CbomResults.tsx:1206 — QuantumBadge yesNo: Yes, No, Broken today (weak and quantum-safe), or a dash when quantum readiness does not apply
  "cbom.res.col.quantum_safe": {
    label: "Quantum safe",
    what: "Whether the asset is quantum-safe: Yes, No (needs a post-quantum replacement), Broken today (weak even without a quantum computer, such as MD5), or a dash when quantum readiness does not apply to it.",
    why: "No means it needs a post-quantum replacement.",
    example: "No for RSA-2048; Broken today for MD5.",
  },
  // ────────────────────────────────────────────────────────────── CBOM crypto-asset charts (components/cbom/CbomCryptoCharts.tsx, CertCalendar.tsx)
  // src: frontend/components/cbom/CbomCryptoCharts.tsx:308-313 — algorithms by primitive
  "cbom.chart.algorithms": {
    label: "Algorithm distribution",
    what: "Cryptographic algorithms found, grouped by primitive: block cipher, hash, signature, key agreement, public-key encryption and others.",
    why: "Shows which primitives your migration has to cover and how often each is used.",
    example: "signature 14, hash 11, key agreement 6.",
  },
  // src: frontend/components/cbom/CbomCryptoCharts.tsx:346-351 — weak or deprecated crypto by category
  "cbom.chart.weak": {
    label: "Weak-crypto findings",
    what: "Weak or deprecated cryptography by category, coloured by severity (High red, Medium orange).",
    why: "These can be attacked today and are the first fixes.",
    example: "Deprecated hash (SHA-1): 4 High.",
  },
  // src: frontend/components/cbom/CbomCryptoCharts.tsx:374-387 — PqcReadinessGauge counts every row of the page (quantumFilter.inventoryRows) by the Quantum column verdict (quantumCounts); distributions.pqc (NIST levels) only when the page has no rows
  "cbom.chart.pqc": {
    label: "PQC readiness",
    what: "The quantum-ready share of every crypto asset on the page (findings and clean inventory), by the same verdict as the table's Quantum column: quantum-safe counts as ready; quantum-vulnerable and broken today (weak even without a quantum computer) do not. Only when the page has no rows does it fall back to the NIST quantum security levels stored with the scan.",
    why: "One view of how much of your crypto survives a quantum computer.",
    example: "12 judged: 9 safe, 2 RSA (vulnerable), 1 DES (broken today): 9 / 12 = 75%.",
  },
  // src: frontend/components/cbom/CbomCryptoCharts.tsx:590-603 — NIST level 0 public-key assets
  "cbom.chart.qv": {
    label: "Quantum-vulnerable algorithms",
    what: "Public-key algorithms a cryptographically relevant quantum computer breaks (NIST level 0), each with where it is used.",
    why: "Data protected by them can be harvested now and decrypted later.",
    example: "RSA-2048 key exchange on api.bank.in:443: a future quantum computer could recover the key; harvest-now-decrypt-later applies.",
  },
  // src: frontend/components/cbom/CbomCryptoCharts.tsx:606-615 — no NIST level 0 assets
  "cbom.chart.qv_none": {
    label: "No quantum-vulnerable algorithms",
    what: "No algorithm in this inventory is broken by a quantum computer at its parameter size.",
    why: "Keep scanning: new code can add RSA or ECDH again.",
    example: "Only AES-256-GCM, SHA-384 and ML-KEM-768 found.",
  },
  // src: frontend/components/cbom/CbomCryptoCharts.tsx:700-712 — NIST replacement per algorithm against CNSA 2.0
  "cbom.chart.roadmap": {
    label: "PQC migration roadmap",
    what: "The NIST-standardised replacement for each quantum-vulnerable algorithm, against the CNSA 2.0 timeline.",
    why: "Turns the inventory into a migration plan with dates regulators recognise.",
    example: "RSA-2048 signatures → ML-DSA-65; ECDH P-256 → ML-KEM-768.",
  },
  // src: frontend/components/cbom/CbomCryptoCharts.tsx:273-278,719, frontend/components/cbom/CbomCryptoCharts.tsx:716-725 — 2025 signing, 2030 networking, 2033 OS, 2035 all NSS
  "cbom.chart.cnsa": {
    label: "CNSA 2.0 transition milestones",
    what: "The NSA CNSA 2.0 dates by which systems should use quantum-resistant algorithms: software and firmware signing 2025, networking and traditional protocols 2030, operating systems 2033, all national security systems 2035.",
    why: "Many regulators and vendors plan against these dates.",
    example: "A VPN gateway falls under networking: 2030.",
  },
  // src: frontend/components/cbom/CbomCryptoCharts.tsx:743-750 — replacement per algorithm
  "cbom.chart.replacements": {
    label: "Recommended replacements",
    what: "For each quantum-vulnerable algorithm found, the recommended post-quantum replacement and where the old one is used.",
    why: "Gives each owner a concrete target, not just a finding.",
    example: "ECDSA P-256 code signing → ML-DSA-65 (FIPS 204).",
  },
  // src: frontend/components/cbom/CbomCryptoCharts.tsx:906-913,949, aibom/src/aibom/cbom/weakness.py:38 — two bars, Valid and Expired; Near expiry is a badge in the list (aibom/src/aibom/cbom/weakness.py:38, 90 days)
  "cbom.chart.cert_expiry": {
    label: "Certificate expiry",
    what: "X.509 certificates as two bars, Valid and Expired, with the certificates and related key or keystore material listed below; a certificate expiring within 90 days carries a Near expiry badge in the list.",
    why: "An expired certificate breaks a service; a long-lived one delays migration to post-quantum signatures.",
    example: "18 Valid and 2 Expired; 3 of the valid ones show Near expiry (within 90 days).",
  },
  // src: frontend/components/cbom/CbomCryptoCharts.tsx:1094-1099 — transport-security protocols in use
  "cbom.chart.protocols": {
    label: "Protocol / TLS",
    what: "Transport-security protocols and versions found in use: TLS, SSH, IPsec and others.",
    why: "Old versions such as TLS 1.0 or SSLv3 are exploitable today.",
    example: "TLS 1.2: 9, TLS 1.3: 4, TLS 1.0: 1.",
  },
  // src: frontend/components/cbom/CbomCryptoCharts.tsx:1142-1147 — CycloneDX asset classes
  "cbom.chart.asset_types": {
    label: "Asset types",
    what: "The crypto inventory by CycloneDX asset class: algorithm, certificate, protocol, related crypto material (keys, secrets).",
    why: "Mirrors the CBOM file you can download.",
    example: "algorithm 40, certificate 6, protocol 5, related material 3.",
  },
  // src: frontend/components/cbom/CertCalendar.tsx:100, frontend/components/cbom/CertCalendar.tsx:95-99 — month calendar, 30/60/90 days
  "cbom.cal.expiry": {
    label: "Certificate expiry calendar",
    what: "A month calendar of certificate expiry dates (UTC), coloured for 30, 60 and 90 days ahead. Choose a day to list its certificates; arrow keys move by day and week, Page Up and Page Down change the month.",
    why: "Renewals planned ahead avoid outages.",
    example: "Three certificates expire on 2 Dec: api.bank.in, mail.bank.in, vpn.bank.in.",
  },
  // ────────────────────────────────────────────────────────────── crypto-agility and quantum-risk grade (components/cbom/grade, moved from grade/tips.ts, #126)
  // src: backend/utilities/cbom_sources/agility.py:76-82 (CLASS_TEXT["configurable"])
  "cbom.agility.configurable": {
    label: "Configurable",
    what: "The owner fixes it by changing a setting, policy, key or certificate with the software, hardware and services already deployed. No code change, no new release.",
    why: "The quickest kind of fix: no code change or new release needed.",
    example: "nginx accepts TLS 1.0: set `ssl_protocols TLSv1.2 TLSv1.3;` and reload. Windows SCHANNEL: set the `TLS 1.0\\Server\\Enabled` registry value to 0.",
  },
  // src: backend/utilities/cbom_sources/agility.py:83-88 (CLASS_TEXT["code-fixed"])
  "cbom.agility.code_fixed": {
    label: "Code-fixed",
    what: "The team's own source code or build must change, then be rebuilt, tested and released (includes a dependency or base-image bump in the team's own build).",
    why: "Needs a development cycle, so plan it into a release.",
    example: "Java code calls `KeyPairGenerator.initialize(1024)`: change it to 3072 (or a post-quantum signature algorithm when the platform has it) and ship a release.",
  },
  // src: backend/utilities/cbom_sources/agility.py:89-95 (CLASS_TEXT["vendor-fixed"])
  "cbom.agility.vendor_fixed": {
    label: "Vendor-fixed",
    what: "The cryptography lives in a third party's product or service (OS distribution, commercial software, SaaS, cloud service, CA ecosystem). Only the vendor can change it; the owner installs the update when it exists, or asks for it.",
    why: "You depend on the vendor's roadmap; ask early and track it.",
    example: "A SaaS provider's API still accepts TLS 1.0; or an OpenSSL 3.0 server cannot offer a post-quantum key exchange until the distribution ships OpenSSL 3.5.",
  },
  // src: backend/utilities/cbom_sources/agility.py:96-101 (CLASS_TEXT["hardware-fixed"])
  "cbom.agility.hardware_fixed": {
    label: "Hardware-fixed",
    what: "The cryptography is bound to a device: HSM, TPM, smart card, network appliance or OT device. It needs a firmware update or a hardware replacement.",
    why: "Firmware or hardware changes take budget and long lead times.",
    example: "An HSM whose firmware has no post-quantum signature algorithm keeps RSA root keys until the firmware is upgraded or the HSM replaced.",
  },
  // src: backend/utilities/cbom_sources/agility.py:102-106 (CLASS_TEXT["unknown"]), :392-407 (asset_class: floor)
  "cbom.agility.unknown": {
    label: "Unknown",
    what: "A fact that decides the class was not read (key provider of a Windows certificate, type of a PKCS#11 token, a code with no row). Never treated as the easiest class; shows the class it is at least.",
    why: "Until the missing fact is read, plan for the class it is at least.",
    example: "A Windows certificate with a private key, read by a node that does not report the key provider yet.",
  },
  // src: backend/utilities/cbom_sources/agility.py:112-113 (INFERRED_TEXT), :406-407 (confidence observed | inferred)
  "cbom.agility.inferred": {
    label: "Likely (inferred)",
    what: "Likely: no fact the product read decides this class; it is the table's default for a capability code (the platform must implement the algorithm), never easier than the evidence allows.",
    why: "An inferred class may change once more evidence is collected.",
    example: "NO_PQ_KEX on a TLS endpoint: the TLS library version is not visible from the network, so the class is vendor-fixed (inferred) until host evidence says otherwise.",
  },
  // src: backend/utilities/cbom_sources/agility.py:47 (SELF_FIXABLE), :562-566 (self_fixable_pct), :621-640 (RunAgility.result)
  "cbom.agility.self_fixable": {
    label: "Self-fixable share",
    what: "Assets whose hardest finding is configurable or code-fixed, out of the assets with one of the four fix classes. Unknown and none are left out of both numbers. Computed from this run's stored findings when the page is read.",
    why: "Shows how much of the work your own team can do without waiting on others.",
    example: "30 configurable, 10 code-fixed, 50 vendor-fixed, 10 hardware-fixed: 40 of 100, 40% self-fixable.",
  },
  // src: backend/utilities/cbom_sources/agility.py:50 (PQ_CODES), :483-485 (excluding_pq), posture fix_classes_excl_pq
  "cbom.agility.excl_pq": {
    label: "Excluding post-quantum",
    what: "The same assets, classed without the four post-quantum migration codes (QUANTUM_VULNERABLE, NO_PQ_KEX, SSH_NO_PQ_KEX, IKE_NO_PQ): what is hard to fix among today's weaknesses only.",
    why: "Separates today's fixes from the longer post-quantum migration.",
    example: "An RSA-2048 certificate whose only code is QUANTUM_VULNERABLE counts as none here.",
  },
  // src: backend/utilities/cbom_sources/kinds.py:59-60,73 (operated_by us | vendor | null), backend/utilities/cbom_sources/agility.py:230-235 (R-VENDOR)
  "cbom.source.operated_by": {
    label: "Operated by",
    what: "Who runs what this source reaches: your team (the default when not set) or a vendor (a SaaS or managed service). Every finding of a vendor-operated source is at least vendor-fixed. A run keeps the value the source had when the run started.",
    why: "Vendor-operated systems need the vendor to fix them, which changes how you plan.",
    example: "A managed database whose TLS settings only the provider can change: set Vendor.",
  },
  // src: backend/utilities/cbom_sources/qgrade.py:46-99 (FORMULA_TEXT), :768-814 (RunGrades: counts and items)
  "cbom.qgrade.distribution": {
    label: "Quantum risk grade",
    what: "Each asset of the run graded by the signed model shown under \"How grades are computed\": the PQC class, internet exposure, trust-anchor status and the Mosca inequality X + Y > Z. No grade means nothing to grade (no public-key cryptography). The grade uses the team's Mosca settings as they are now.",
    why: "Ranks assets by quantum risk so migration starts where data is most exposed.",
    example: "A quantum-vulnerable internet-facing TLS endpoint with X 10 + Y 5 > Z 12 grades Critical.",
  },
  // ────────────────────────────────────────────────────────────── CBOM code results: crypto-agility column
  // src: backend/utilities/cbom_sources/agility.py:76-113 — configurable, code-fixed, vendor-fixed, hardware-fixed, unknown (CLASS_TEXT)
  "cbom.res.col.fix_class": {
    label: "Fix class",
    what: "Who can fix this finding and how: Configurable (a setting, policy, key or certificate), Code-fixed (your code or build changes), Vendor-fixed (only the vendor can change it), Hardware-fixed (firmware or a new device), or Unknown (a deciding fact was not read). Likely means the class is inferred.",
    why: "It tells you whether a fix is a config change this week or a vendor roadmap item.",
    example: "Code-fixed: KeyPairGenerator.initialize(1024) in src/crypto/keys.py.",
  },
  // ────────────────────────────────────────────────────────────── CBOM: list empty state and test-lab node warning
  // src: frontend/app/[team_id]/cbom/page.tsx:1014-1022 — the merged table of code scans and Sources runs is empty
  "cbom.list.empty": {
    label: "No scans or runs yet",
    what: "This table lists both CBOM code scans and CBOM Sources runs; this team has neither yet. A code scan reads a repository, zip or CBOM file; a Sources run reads servers, clusters, databases, cloud accounts and networks.",
    why: "Each feeds the same inventory, so start with whichever holds your most sensitive crypto.",
    example: "Create a CBOM scan of payments-api, then start a Sources run of the Mumbai servers.",
  },
  // src: frontend/components/cbom/sources/NodeInstall.tsx:41, frontend/components/cbom/sources/NodeInstall.tsx:37-43 — ZS_ALLOW_INSECURE_HTTP
  "cbsrc.nodes.lab_only": {
    label: "Test lab only",
    what: "This install command sets ZS_ALLOW_INSECURE_HTTP=1 because the API is plain HTTP: the node's credentials and the decrypted secrets of every job travel unencrypted.",
    why: "Anyone on the network path could read them; serve the API over HTTPS for anything but a closed test lab.",
    example: "A lab on 192.168.56.0/24 with no other users; never a production network.",
  },
  // ────────────────────────────────────────────────────────────── CBOM list: code scans and Sources runs in one table (CB-38 #117)
  // src: frontend/app/[team_id]/cbom/page.tsx:1112-1136, backend/utilities/cbom_sources/run_list.py:1-6 — code scans and Sources runs in one table
  "cbom.table.title": {
    label: "Title",
    what: "The scan's title, or for a CBOM Sources run \"Sources run #<id>\" with the names of its sources and a Sources run badge. Click it to open the results.",
    why: "Code scans and infrastructure runs land in one list, so the badge tells them apart.",
    example: "Sources run #42 · dc-mumbai-linux, aws-prod.",
  },
  // src: frontend/app/[team_id]/cbom/page.tsx:142-152, contracts/cbom/status_buckets.json:1 — code-scan statuses; a run's queued, running, done, partial, failed, cancelled
  "cbom.table.status": {
    label: "Status",
    what: "A code scan: Not started, Pending, Started (with progress), Retry, Success, Failure or Cancelled. A Sources run: Pending (queued), Started (running, with jobs done of total), Success (done), Partial (some jobs failed or expired; the results that were collected open like a success), Failure or Cancelled.",
    why: "A Partial run's results miss the sources whose jobs did not finish.",
    example: "Partial · 3/4 jobs: one database job expired.",
  },
  // src: frontend/app/[team_id]/cbom/page.tsx:1159-1190,1044, frontend/components/cbom/results/resultRows.ts:360-365 — repository, zip, or the run's sources and counts
  "cbom.table.source": {
    label: "Repo / Source",
    what: "For a code scan, the repository (or Zip file). For a Sources run, the sources it collected from, with how many assets it found and endpoints it probed.",
    why: "Tells you what each row covers before you open it.",
    example: "dc-mumbai-linux, aws-prod · 1,284 assets · 12 endpoints.",
  },
  // src: backend/utilities/cbom_sources/run_list.py:232-233, frontend/components/cbom/results/resultRows.ts:367-370 — charged; refunded shown below
  "cbom.table.credits": {
    label: "Credits",
    what: "Credits charged for the scan or run. For a run, credits refunded for jobs that failed, expired or were cancelled are shown below in brackets.",
    why: "You pay only for the jobs that completed.",
    example: "12.4 (1 refunded).",
  },
  // ────────────────────────────────────────────────────────────── CBOM results: AI remediation assistant, crypto-agility and quantum-risk headings
  // src: frontend/components/cbom/results/AiRemediationPanel.tsx:1-5,72, frontend/components/cbom/results/aiPanelLogic.ts:22-35 — shown only when available; every answer validated against the knowledge base
  "cbom.ai.panel": {
    label: "AI assistant",
    what: "Explain describes this finding in plain words; Plan gives ordered remediation steps; Ask a question answers about this finding only. Answers come from the configured model (AWS Bedrock, or an on-prem model) grounded in ZeroShield's knowledge base: every step cites it, and an answer that fails validation is withheld. The line beside it names the only outbound host.",
    why: "It turns a finding into concrete steps for your stack, without sending data anywhere but the named endpoint.",
    example: "Plan for RSA-2048 on api.bank.in:443: enable hybrid X25519MLKEM768, rotate to an ML-DSA certificate, cited KB steps.",
  },
  // src: frontend/components/cbom/results/aiPanelLogic.ts:7, frontend/components/cbom/results/AiRemediationPanel.tsx:86-95 — up to 500 characters, about this finding
  "cbom.ai.question": {
    label: "Your question",
    what: "A question about this finding, up to 500 characters. The answer uses only this finding and the knowledge base.",
    why: "Lets you ask how a fix applies to your own setup.",
    example: "Which of these steps applies to an nginx reverse proxy?",
  },
  // src: backend/utilities/cbom_sources/agility.py:76-113, frontend/components/cbom/grade/Agility.tsx:150-160 — the hardest fix class of each asset
  "cbom.agility.section": {
    label: "How hard is this to fix?",
    what: "Crypto-agility: each asset by the hardest fix class among its findings, Configurable, Code-fixed, Vendor-fixed, Hardware-fixed or Unknown, and the share your own team can fix.",
    why: "Separates what you can change this sprint from what waits on a vendor or new hardware.",
    example: "40 of 100 assets self-fixable: 30 configurable, 10 code-fixed.",
  },
  // ────────────────────────────────────────────────────────────── CBOM Sources run results page (components/cbom/results/*, CB-38 #120)
  // src: frontend/components/cbom/results/RunSections.tsx:211-213 — jobs, skipped sources, provenance
  "cbom.run.covered": {
    label: "Collection jobs and targets",
    what: "Every job of the run with where it ran and how it ended, the sources skipped when it started, per source what was collected, and each target's outcome.",
    why: "A finding list is only as complete as what was read; this shows what the run could and could not read.",
    example: "9 jobs: 8 done, 1 expired on node-dr1; dc-mumbai-windows skipped (node offline).",
  },
  // src: frontend/components/cbom/results/RunSections.tsx:217-231 — per source: kind, runner, outcome, assets, endpoints, duration, credits
  "cbom.run.provenance": {
    label: "Provenance per source",
    what: "For each source of the run: its kind, where it ran (a scan node or ZeroShield's cloud), its outcome, the assets collected (not counting the Not collected rows), endpoints probed, duration and credits.",
    why: "Lets an auditor trace every asset back to the job that read it.",
    example: "dc-mumbai-linux · Linux servers · node-dc1 · success · 212 assets · 0 endpoints · 4 min · 51.20.",
  },
  // src: frontend/components/cbom/results/RunSections.tsx:228 — the source kind
  "cbom.run.col.kind": {
    label: "Kind",
    what: "The kind of source: Linux servers, database, AWS account, network range and so on.",
    why: "Each kind is read differently and has its own blind spots.",
    example: "AWS account.",
  },
  // src: frontend/components/cbom/results/RunSections.tsx:230 — job outcome
  "cbom.run.col.outcome": {
    label: "Outcome",
    what: "How the source's job ended: success, partial (some targets or checks could not be read), failed, expired or cancelled.",
    why: "A partial or failed outcome means some of that source's crypto is missing from the results.",
    example: "partial: 2 of 254 servers refused the login.",
  },
  // src: frontend/components/cbom/results/RunSections.tsx:231 — collected assets only
  "cbom.run.col.assets_collected": {
    label: "Assets (excl. not collected)",
    what: "Assets collected from this source. Rows that only record a part the job could not read (Not collected) are left out; the jobs table above counts them.",
    why: "Separates what was actually read from what was attempted.",
    example: "212 assets collected.",
  },
  // src: frontend/components/cbom/results/RunSections.tsx:232 — TLS/SSH endpoints probed
  "cbom.run.col.endpoints": {
    label: "Endpoints probed",
    what: "How many network endpoints (address and port) the job probed with a TLS or SSH handshake.",
    why: "Shows how much of a network range answered.",
    example: "48 endpoints on 10.20.0.0/24.",
  },
  // src: frontend/components/cbom/results/RunSections.tsx:233 — job duration
  "cbom.run.col.duration": {
    label: "Duration",
    what: "How long the source's job ran, from claim to result.",
    why: "A very long job may hit timeouts; consider splitting the source.",
    example: "4 min 12 s.",
  },
  // src: frontend/components/cbom/results/RunSections.tsx:234, backend/utilities/cbom_sources/planning.py:25 — credits of the source's job
  "cbom.run.col.credits": {
    label: "Credits",
    what: "The credits charged for this source's job (0.2 per server target, 1 per database, 2 per cluster, 4 per cloud account, 1 per /24).",
    why: "Shows where the run's cost went.",
    example: "51.20 for 256 server targets.",
  },
  // src: frontend/components/cbom/results/RunSections.tsx:349-356 — within this run's scope
  "cbom.run.certs": {
    label: "Orphaned and unmanaged certificates",
    what: "Within this run's scope: orphaned certificates are stored somewhere but presented by no endpoint the run read; unmanaged ones are held by no managing system the run saw (ACM, cert-manager, AD CS, Key Vault and similar).",
    why: "Orphaned certificates are clutter that can be stolen; unmanaged ones expire without anyone being told.",
    example: "3 orphaned (old keystore copies), 5 unmanaged (hand-installed on web servers).",
  },
  // src: frontend/components/cbom/results/RunSections.tsx:358 — stored, presented by no endpoint read
  "cbom.run.certs.orphaned": {
    label: "Orphaned certificates",
    what: "Certificates found in files, keystores or secrets that no endpoint read by this run presents.",
    why: "A forgotten certificate with its private key is a credential waiting to be misused.",
    example: "/opt/app/old/server.p12, CN=api-old.bank.in.",
  },
  // src: frontend/components/cbom/results/RunSections.tsx:355 — no managing system saw them
  "cbom.run.certs.unmanaged": {
    label: "Unmanaged certificates",
    what: "Certificates the run found that no certificate manager in this run's scope (ACM, cert-manager, AD CS, Key Vault and similar) holds.",
    why: "Nothing renews or reports on them, so they expire unnoticed.",
    example: "CN=intranet.bank.local installed by hand on web-07.",
  },
  // src: frontend/components/cbom/results/RunSections.tsx:312 — certificate subject
  "cbom.run.cert.subject": {
    label: "Subject",
    what: "The certificate's subject: whom it was issued to.",
    why: "Identifies the service the certificate belongs to.",
    example: "CN=api.bank.in, O=Bank Ltd.",
  },
  // src: frontend/components/cbom/results/RunSections.tsx:313 — certificate issuer
  "cbom.run.cert.issuer": {
    label: "Issuer",
    what: "The CA that issued the certificate.",
    why: "An unexpected issuer can mean a certificate bought outside policy.",
    example: "CN=BANK-ISSUING-CA.",
  },
  // src: frontend/components/cbom/results/RunSections.tsx:314 — not_after
  "cbom.run.cert.expires": {
    label: "Expires",
    what: "When the certificate stops being valid.",
    why: "Expired certificates break services; long-lived ones delay migration.",
    example: "2 Dec 2026.",
  },
  // src: frontend/components/cbom/results/RunSections.tsx:315 — where it was found
  "cbom.run.cert.location": {
    label: "Location",
    what: "Where the run found the certificate: a file path, keystore, secret or endpoint.",
    why: "Tells you where to remove or renew it.",
    example: "web-07:/etc/ssl/intranet.pem.",
  },
  // src: frontend/components/cbom/results/RunSections.tsx:316 — the source that found it
  "cbom.run.cert.source": {
    label: "Source",
    what: "The source whose job found the certificate.",
    why: "Points to the owner of the system.",
    example: "dc-mumbai-linux.",
  },
  // src: frontend/components/cbom/results/RunSections.tsx:365-373 — drift against each source's previous complete collection
  "cbom.run.changes": {
    label: "Changes",
    what: "What changed against each source's previous complete collection: assets added, removed or changed. Partial or failed collections are not compared.",
    why: "Drift shows new weak crypto, and fixes that landed, as soon as they happen.",
    example: "+3 certificates, -1 SSH host key, 2 changed.",
  },
  // src: frontend/components/cbom/results/RunSections.tsx:416-435, backend/utilities/cbom_sources/waves.py:44-60 — wave counts of the run's assets
  "cbom.run.waves": {
    label: "Remediation waves",
    what: "This run's assets per remediation wave (1 most urgent to 4 post-quantum migration). Select findings in the table below to assign a wave, owner, target date or status; plans follow the asset to later runs.",
    why: "Turns the findings into an ordered plan with owners and dates.",
    example: "Wave 1: 4 · Wave 2: 11 · Wave 3: 30 · Wave 4: 52.",
  },
  // src: frontend/components/cbom/results/RunSections.tsx:446-475 — CERT-In, RBI, SEBI CSCRF, NIST, CNSA 2.0
  "cbom.run.compliance": {
    label: "Compliance mapping",
    what: "Regulatory clauses this run's findings touch, per framework (CERT-In, RBI, SEBI CSCRF, NIST, CNSA 2.0), with the number of assets and finding codes per clause. From the knowledge base, no AI.",
    why: "Shows auditors exactly which requirements each weakness affects.",
    example: "RBI · 3 clauses: 4.2 Encryption of data in transit, 12 assets, WEAK_TLS_VERSION.",
  },
  // src: frontend/components/cbom/results/RunSections.tsx:515-531, backend/utilities/cbom_sources/posture.py:43-47 — impact x criticality x exposure
  "cbom.run.top_risks": {
    label: "Top cryptographic risks",
    what: "The run's riskiest assets, ranked by priority = impact weight x the source's business criticality x its internet exposure, from the run posture.",
    why: "Puts the fixes that cut the most risk first.",
    example: "Priority 21: RSA-1024 on api.bank.in:443, High, critical source, internet-facing, HNDL.",
  },
  // src: backend/utilities/cbom_sources/posture.py:43-47, backend/utilities/cbom_sources/posture.py:496-497 — impact x criticality x exposure
  "cbom.run.col.priority": {
    label: "Priority",
    what: "Impact weight (Critical 10, High 7, Medium 4, Low 1) x business criticality (0.5 to 2) x exposure (1.5 internet-facing, else 1).",
    why: "Ranks the same weakness higher on critical, exposed systems.",
    example: "7 x 2 x 1.5 = 21.",
  },
  // src: frontend/components/cbom/results/RunSections.tsx:525 — the asset
  "cbom.run.col.asset": {
    label: "Asset",
    what: "The cryptographic asset: an endpoint, key, certificate or library, with where it is.",
    why: "Names exactly what to change.",
    example: "api.bank.in:443 TLS.",
  },
  // src: backend/utilities/cbom_sources/posture.py:44 — the source's business criticality
  "cbom.run.col.criticality": {
    label: "Criticality",
    what: "The business criticality of the asset's source when the run started: low, medium, high or critical.",
    why: "Critical systems rank higher.",
    example: "critical.",
  },
  // src: backend/utilities/cbom_sources/posture.py:47, backend/utilities/cbom_sources/posture.py:398 — from facts or the source's override
  "cbom.run.col.exposure": {
    label: "Exposure",
    what: "Whether the asset is internet-facing, internal or unknown, from the collected facts or the source's override. Hover for the basis.",
    why: "Internet-facing assets are attacked first.",
    example: "Internet-facing (public load balancer).",
  },
  // src: backend/utilities/cbom_sources/posture.py:8-9 — harvest now, decrypt later
  "cbom.run.col.hndl": {
    label: "HNDL",
    what: "Harvest now, decrypt later: the asset's key exchange is quantum-vulnerable, so traffic recorded today could be decrypted by a future quantum computer.",
    why: "Long-lived secrets on these channels are already at risk.",
    example: "HNDL on vpn.bank.in (IKE with DH group 14).",
  },
  // src: frontend/components/cbom/results/RunFindingsTable.tsx:165-170 — the run's assets, Findings or All assets
  "cbom.run.findings": {
    label: "Cryptographic findings",
    what: "Findings: the assets of this run with a finding; select rows to change their status or plan a wave, click a row for its explanation. All assets: every asset collected, including clean ones and the parts it could not read (Not collected).",
    why: "Each row is something to fix, accept or plan for migration.",
    example: "RSA-2048 on api.bank.in:443 · High · quantum-vulnerable · Wave 1 · Not started.",
  },
  // src: frontend/components/cbom/results/RunFindingsTable.tsx:173-182 — view=findings or all
  "cbom.run.view": {
    label: "Findings or all assets",
    what: "Switch between the assets with a finding and every asset the run collected (clean ones and Not collected rows included).",
    why: "All assets is the complete inventory; Findings is the work list.",
    example: "Findings (96) · All assets (1,284).",
  },
  // src: frontend/components/cbom/results/RunFindingsTable.tsx:216-220 — location, algorithm or finding
  "cbom.run.search": {
    label: "Search",
    what: "Shows only rows whose location, algorithm or finding text contains this text.",
    why: "Finds every asset of one host or algorithm quickly.",
    example: "\"api.bank.in\" keeps that host's endpoints and certificates.",
  },
  // src: frontend/components/cbom/results/RunFindingsTable.tsx:222-228 — Critical, High, Medium, Low
  "cbom.run.filter.impact": {
    label: "Impact filter",
    what: "Shows only rows of one impact: Critical, High, Medium or Low.",
    why: "Focuses on the most serious findings.",
    example: "Critical.",
  },
  // src: frontend/components/cbom/results/RunFindingsTable.tsx:229-237,241 — asset type
  "cbom.run.filter.type": {
    label: "Type filter",
    what: "Shows only one type of asset: TLS endpoint, certificate, key, SSH host key, library and others.",
    why: "Plan migration one asset type at a time.",
    example: "Certificate.",
  },
  // src: frontend/components/cbom/results/RunFindingsTable.tsx:238-245,249 — quantum-vulnerable only
  "cbom.run.filter.quantum": {
    label: "Quantum filter",
    what: "Shows only quantum-vulnerable assets.",
    why: "This is your post-quantum migration list.",
    example: "Quantum-vulnerable.",
  },
  // src: frontend/components/cbom/results/RunFindingsTable.tsx:247-253,260 — one source
  "cbom.run.filter.source": {
    label: "Source filter",
    what: "Shows only the assets of one source of the run.",
    why: "Hand one source's list to its owner.",
    example: "dc-mumbai-linux.",
  },
  // src: frontend/components/cbom/results/RunFindingsTable.tsx:256-262,272 — Not started, In progress, Fixed, Ignored
  "cbom.run.filter.status": {
    label: "Status filter",
    what: "Shows only findings with one status: Not started, In progress, Fixed or Ignored.",
    why: "Track what is still open.",
    example: "Not started.",
  },
  // src: frontend/components/cbom/results/RunFindingsTable.tsx:324 — host, port, path
  "cbom.run.col.where": {
    label: "Where",
    what: "Where the asset is: host and port, file path, keystore or cloud resource.",
    why: "Takes you straight to the system to change.",
    example: "api.bank.in:443.",
  },
  // src: frontend/components/cbom/results/RunFindingsTable.tsx:311 — the finding text
  "cbom.run.col.finding": {
    label: "Finding",
    what: "What is wrong with the asset, from the knowledge base.",
    why: "Explains why it is a finding before you open it.",
    example: "TLS 1.0 accepted; key exchange quantum-vulnerable.",
  },
  // src: frontend/components/cbom/results/RunFindingsTable.tsx:329 — the source
  "cbom.run.col.source": {
    label: "Source",
    what: "The source whose job collected this asset.",
    why: "Points to the owner of the system.",
    example: "dc-mumbai-linux.",
  },
  // src: backend/utilities/cbom_sources/waves.py:44-60 — suggested or assigned wave
  "cbom.run.col.wave": {
    label: "Wave",
    what: "The remediation wave: the one your team assigned, or the suggested one (1 most urgent to 4 post-quantum migration), with owner and target date when set.",
    why: "Turns findings into an ordered plan.",
    example: "Wave 1 · Payments · 31 Dec.",
  },
  // src: contracts/cbom/status_buckets.json:2 — open, in progress, done, accepted risk
  "cbom.run.col.status": {
    label: "Status",
    what: "The finding's status from its remediation plan: Not started, In progress, Fixed or Ignored (risk accepted).",
    why: "Fixed and Ignored findings leave the open backlog.",
    example: "In progress.",
  },
  // src: backend/utilities/cbom_sources/qgrade.py:51-104 — Q0..Q4
  "cbom.run.col.qgrade": {
    label: "Quantum risk",
    what: "The asset's quantum risk grade, Q1 Critical to Q4 Low, or Q0 Unknown when a deciding fact or the team's Mosca settings are missing.",
    why: "Ranks post-quantum migration by how soon the data is at risk.",
    example: "Q1 Critical: quantum-vulnerable, internet-facing, X + Y > Z.",
  },
  // src: frontend/components/cbom/results/RunSections.tsx:492-496 — the rows of the current table page
  "cbom.run.risk_scores": {
    label: "Risk scores on this table page",
    what: "The risk score (0 to 10) of the rows on the findings table's current page and filter, highest first, at most 24. It never counts the whole run.",
    why: "Shows whether this page's risk is concentrated in a few rows.",
    example: "F1: RSA-1024 signing key, 9.8.",
  },
  // src: frontend/components/cbom/results/RunSections.tsx:128-135 — CycloneDX JSON and XML, OSCAL
  "cbom.run.downloads": {
    label: "Downloads",
    what: "The run's CBOM as CycloneDX 1.6 JSON or XML (schema-valid), and OSCAL 1.2.3 assessment results for a GRC tool once the run has finished.",
    why: "Hands the inventory to auditors and other tools in standard formats.",
    example: "CycloneDX JSON (1,284) for the auditor's CBOM request.",
  },
  // src: frontend/components/cbom/results/RunFindingDialog.tsx:85 — asset type
  "cbom.run.f.type": {
    label: "Type",
    what: "The kind of asset: TLS endpoint, certificate, key, SSH host key, library and others.",
    why: "Each type has its own replacement path.",
    example: "TLS endpoint.",
  },
  // src: frontend/components/cbom/results/RunFindingDialog.tsx:81-83 — weak, moderate, strong, quantum-safe
  "cbom.run.f.strength": {
    label: "Crypto strength",
    what: "How strong the cryptography is today: weak, moderate, strong or quantum-safe.",
    why: "Weak is exploitable now.",
    example: "weak.",
  },
  // src: frontend/components/cbom/results/RunFindingDialog.tsx:89 — bits
  "cbom.run.f.key_size": {
    label: "Key size",
    what: "The key length in bits, when the asset has one.",
    why: "Short keys can be broken without a quantum computer.",
    example: "1024 bits.",
  },
  // src: frontend/components/cbom/results/RunFindingDialog.tsx:85-89 — quantum verdict
  "cbom.run.f.quantum": {
    label: "Quantum",
    what: "Whether a quantum computer breaks it: quantum-vulnerable, quantum-safe or broken today.",
    why: "Quantum-vulnerable assets need a post-quantum replacement.",
    example: "Quantum-vulnerable.",
  },
  // src: frontend/components/cbom/results/RunFindingDialog.tsx:90-92 — impact as collected
  "cbom.run.f.impact": {
    label: "Impact",
    what: "The impact the asset was judged with when it was collected: Critical, High, Medium, Low, or Info for clean inventory.",
    why: "Fix Critical and High first.",
    example: "High.",
  },
  // src: frontend/components/cbom/results/RunFindingDialog.tsx:93-97 — 0-10
  "cbom.run.f.risk": {
    label: "Risk score",
    what: "The asset's risk score, 0 to 10, from its impact, findings, strength and quantum verdict.",
    why: "Orders findings of the same impact.",
    example: "8.6 out of 10.",
  },
  // src: frontend/components/cbom/results/RunFindingDialog.tsx:98-102 — remediation status
  "cbom.run.f.status": {
    label: "Status",
    what: "The status of the asset's remediation plan: Not started, In progress, Fixed or Ignored.",
    why: "Shows whether anyone is working on it.",
    example: "In progress.",
  },
  // src: frontend/components/cbom/results/RunFindingDialog.tsx:106-112 — linked Jira ticket
  "cbom.run.f.ticket": {
    label: "Ticket",
    what: "The Jira ticket filed for this asset, if any.",
    why: "Follow the fix in your team's tracker.",
    example: "SEC-1423.",
  },
  // src: frontend/components/cbom/results/RunFindingDialog.tsx:116-123 — where it is
  "cbom.run.f.location": {
    label: "Location",
    what: "Exactly where the asset is: host and port, file path, keystore or cloud resource.",
    why: "Takes you to the system to change.",
    example: "web-07:/etc/ssl/intranet.pem.",
  },
  // src: frontend/components/cbom/results/RunFindingDialog.tsx:126-127 — the finding text
  "cbom.run.f.finding": {
    label: "Finding",
    what: "What is wrong, from the knowledge base.",
    why: "Explains the risk in plain words.",
    example: "Key exchange uses RSA: quantum-vulnerable.",
  },
  // src: frontend/components/cbom/results/RunFindingDialog.tsx:129-130 — extra description
  "cbom.run.f.description": {
    label: "Description",
    what: "More detail about the asset and the finding.",
    why: "Context helps choose the right fix.",
    example: "Endpoint offers TLS 1.0-1.2 with RSA key exchange.",
  },
  // src: frontend/components/cbom/results/RunFindingDialog.tsx:134-170 — source, job, node
  "cbom.run.f.origin": {
    label: "Where it came from",
    what: "The source, job and scan node (or cloud) that collected this asset, and when.",
    why: "Lets you trace and re-check the evidence.",
    example: "dc-mumbai-linux · job #4410 · node-dc1 · 13 Nov 23:10.",
  },
  // ────────────────────────────────────────────────────────────── CBOM Sources: in-tab run results and posture (components/cbom/sources/RunResults.tsx, RunPosture.tsx)
  // src: frontend/components/cbom/sources/RunResults.tsx:127-132 — each target's outcome
  "cbom.run.targets": {
    label: "Targets",
    what: "Each target the run's jobs tried, with its outcome: read, unreachable, login failed and so on.",
    why: "Targets that could not be read are blind spots in this run.",
    example: "10.20.0.17 · unreachable (port 22 filtered).",
  },
  // src: frontend/components/cbom/sources/RunResults.tsx:386-399,355 — assets with a wave can be selected
  "cbom.run.col.select_wave": {
    label: "Select for wave assignment",
    what: "Select assets that have a remediation wave, to assign a wave, owner, target date or status together.",
    why: "Plans a group of similar assets in one step.",
    example: "Tick the 12 certificates of api.bank.in, set Wave 2.",
  },
  // src: backend/utilities/cbom_sources/posture.py:3-5 — quantum-vulnerable class
  "cbom.run.col.qv": {
    label: "Quantum-vulnerable",
    what: "Whether the asset was judged quantum-vulnerable when it was collected: public-key cryptography a quantum computer breaks (RSA, DH, elliptic curves).",
    why: "These assets need a post-quantum replacement.",
    example: "Yes for ECDHE P-256 key exchange.",
  },
  // src: backend/utilities/cbom_sources/posture.py:1-15 — HNDL, Mosca, risk score, compliance, from the knowledge base
  "cbom.run.posture": {
    label: "Post-quantum and risk posture",
    what: "The run's posture from the knowledge base (no AI): harvest-now-decrypt-later exposure, the Mosca test X + Y > Z with your team's values, risk scores and the regulatory clauses touched.",
    why: "Turns the inventory into the questions a board and a regulator ask.",
    example: "14 HNDL endpoints; with X 10, Y 3, Z 10 the data is at risk now.",
  },
  // src: frontend/components/cbom/sources/RunPosture.tsx:108-112,170,144, backend/utilities/cbom_sources/posture.py:10-11 — X, Y, Z in years, 0-100, team admins
  "cbom.run.mosca": {
    label: "Mosca inputs",
    what: "The team's Mosca values in whole years, 0 to 100: X how long data must stay secret, Y how long migration takes, Z years until a cryptographically relevant quantum computer. Team admins only; blank clears.",
    why: "X + Y > Z means data protected by quantum-vulnerable crypto is already at risk.",
    example: "X 10, Y 5, Z 12: 15 > 12, migration is overdue.",
  },
  // ────────────────────────────────────────────────────────────── CBOM Sources: Review & Run, grade inputs (components/cbom/sources/GradeInputsCard.tsx)
  // src: frontend/components/cbom/sources/GradeInputsCard.tsx:3-4, frontend/components/cbom/sources/GradeInputsCard.tsx:29-70 — Mosca X/Y/Z, per-source data lifetime, Q0 gaps; recorded at Start
  "cbsrc.rr.grade_inputs": {
    label: "Grade inputs",
    what: "What the next run's quantum risk grades use, recorded when you start it: the team's Mosca X, Y and Z, each source's own data lifetime (its X), and the evidence Q0 gaps. Later changes apply to new runs only.",
    why: "Without X, Y and Z, quantum-vulnerable assets grade as Unknown, and the record lets an old run's grade be explained later.",
    example: "X 10, Y 3, Z 12; Core banking DB keeps data 25 y; 2 Q0 gaps.",
  },
  // ────────────────────────────────────────────────────────────── CBOM: quantum risk register, Q0 gaps and agility baseline (CB-23, CB-25; components/cbom/grade)
  // src: backend/utilities/cbom_sources/risk_register.py:1-11, frontend/app/[team_id]/cbom/page.tsx:844 — one row per estate asset, current grade
  "cbom.reg.section": {
    label: "Quantum risk register",
    what: "Every asset of the team once, however many sources see it, with its current quantum risk grade: the team's Mosca inputs now, each source's data lifetime and exposure now, the current grade model. Worst grade first; filter and download the rows as CSV.",
    why: "The CISO view: one list to plan migration from and report on, not one list per run.",
    example: "2,140 assets: 37 Q1 Critical, 210 Q2 High, 18 Q0 Unknown.",
  },
  // src: backend/utilities/cbom_sources/risk_register.py:3-6 — the worst known grade over the asset's observations
  "cbom.reg.col.grade": {
    label: "Grade",
    what: "The asset's quantum risk grade, Q1 Critical to Q4 Low, or Q0 Unknown when no observation could be graded. Seen by several sources, the worst known grade wins. Also a filter.",
    why: "Q1 and Q2 assets are where data is exposed first.",
    example: "Q1 Critical: an internet-facing RSA key exchange with X + Y > Z.",
  },
  // src: backend/utilities/cbom_sources/risk_register.py:146-148, backend/utilities/cbom_sources/heatmap.py:88-102 — HEAT.algorithm_family of the asset's algorithm
  "cbom.reg.col.family": {
    label: "Family",
    what: "The algorithm family of the asset, such as RSA, Elliptic curve, AES or Post-quantum, as the heatmap groups it. Also a filter.",
    why: "Migration work is planned per family: every RSA key needs the same replacement.",
    example: "RSA, for an RSA-2048 TLS key.",
  },
  // src: backend/utilities/cbom_sources/risk_register.py:146, backend/utilities/cbom_sources/qgrade.py:357-361, backend/utilities/cbom_sources/posture.py:47 — internet, internal or unknown, with the source's override
  "cbom.reg.col.exposure": {
    label: "Exposure",
    what: "Whether the asset is reachable from the internet, internal only, or unknown, from its address, the collector's facts and the source's exposure setting. Also a filter.",
    why: "Internet-facing assets are the ones whose traffic can be recorded today and decrypted later.",
    example: "Internet: 203.0.113.10:443.",
  },
  // src: backend/utilities/cbom_sources/risk_register.py:263-265 — source name, application, number of sources
  "cbom.reg.col.source": {
    label: "Source",
    what: "The source that saw the asset most recently, how many more see it, and its application when the source has one.",
    why: "Tells the owner where the asset lives and who reads it.",
    example: "Network TLS DC1 (+2 more), Netbanking.",
  },
  // src: backend/utilities/cbom_sources/risk_register.py:267 — observed_at of the latest observation
  "cbom.reg.col.last_observed": {
    label: "Last observed",
    what: "When a collection last read the asset. An asset missing from its source's latest collection is marked \"not read in the latest collection\".",
    why: "An old date means the grade rests on old data.",
    example: "14 Nov 2026, 09:12.",
  },
  // src: backend/utilities/cbom_sources/risk_register.py:51-53 — CSV_COLUMNS, filtered rows
  "cbom.reg.csv": {
    label: "Download CSV",
    what: "The register rows that match the filters as a CSV file: key, grade and reason, asset, family, exposure, source, application, presence, sources and last observed.",
    why: "For the board pack, the regulator or a spreadsheet of owners.",
    example: "register.csv with the 37 Q1 Critical rows.",
  },
  // ────────────────────────────────────────────────────────────── CBOM: Q0 gaps of the quantum risk register (CB-23 PR-A)
  // src: backend/utilities/cbom_sources/q0register.py:1-16, frontend/components/cbom/grade/Q0Gaps.tsx:3-6 — evidence, scope, asset and inputs items
  "cbom.q0.section": {
    label: "Q0 gaps",
    what: "Everything the quantum risk register cannot grade yet (Q0 Unknown), grouped by reason: evidence areas and vendors at E0, scope a collection could not read, assets the product could not grade, and missing Mosca inputs. Each opening is tracked until it closes.",
    why: "A Q0 item is a blind spot, never assumed safe; closing them is how the register becomes complete.",
    example: "Evidence at E0 (6): payment HSM vendor has not answered.",
  },
  // src: backend/utilities/cbom_sources/q0register.py:3-5, frontend/components/cbom/grade/Q0Gaps.tsx:110-118 — open while closed_at is empty
  "cbom.q0.status": {
    label: "Open / Closed",
    what: "Open: gaps that are still Q0 now. Closed: gaps that left Q0, each with its cause and the grade it closed to. A gap that comes back opens a new row.",
    why: "Closed gaps are the audit trail of what was resolved and how.",
    example: "Open (18) · Closed (42).",
  },
  // src: backend/utilities/cbom_sources/q0register.py:454 — from opened_at to closed_at, or to now
  "cbom.q0.col.age": {
    label: "Age",
    what: "How long the gap has been open, or was open before it closed, in days.",
    why: "Old gaps are the ones to chase first.",
    example: "47 days.",
  },
  // src: backend/utilities/cbom_sources/q0register.py:3-5 — opened_at of this opening
  "cbom.q0.col.opened": {
    label: "Opened",
    what: "When this gap opened: the evidence turned E0, a collection could not read the scope, or the asset graded Q0.",
    why: "Ties the gap to the run or the change that caused it.",
    example: "28 Sep 2026, 10:04.",
  },
  // src: backend/utilities/cbom_sources/q0register.py:117-118 — closed_at, close_cause, closed_grade
  "cbom.q0.col.closed": {
    label: "Closed",
    what: "When the gap closed; a dash while it is open.",
    why: "Shows when the blind spot was resolved.",
    example: "12 Nov 2026, 18:30.",
  },
  // src: backend/utilities/cbom_sources/q0register.py:18-25, frontend/components/cbom/grade/q0gaps.ts:83-89 — closing causes
  "cbom.q0.col.cause": {
    label: "Cause",
    what: "Why the gap closed: evidence answered or renewed, the vendor or source removed, read again in a later collection, Mosca inputs set, or the grade model changed. Shown with the grade it closed to.",
    why: "Closures other than a grade-model change are sent to your integrations as drift events.",
    example: "Read again in a later collection, now Q3 Medium.",
  },
  // ────────────────────────────────────────────────────────────── CBOM: crypto-agility baseline of the team (CB-25)
  // src: backend/utilities/cbom_sources/agility_rollup.py:1-21, frontend/components/cbom/grade/AgilityBaseline.tsx:3-6 — current estate, one asset per cross-source identity
  "cbom.agility.baseline": {
    label: "Agility baseline",
    what: "How hard the team's current estate is to fix, by fix class: every asset of each source's latest collection and each repository's latest code scan, plus the evidence items with a class. An asset several sources see counts once, at its hardest class.",
    why: "The enterprise number to track over time: how much of the crypto your own team can change.",
    example: "1,200 assets, 46% self-fixable; Core banking is mostly vendor-fixed.",
  },
  // src: backend/utilities/cbom_sources/agility_rollup.py:16-21 — application, else source; repository; evidence groups
  "cbom.agility.system": {
    label: "System",
    what: "Where an asset belongs: the source's application when it has one, else the source itself; a code scan's repository; or the evidence groups Third parties and Key management. An asset counts in the system of its latest observation, so the systems add up to the team's counts.",
    why: "Owners plan by system, not by source.",
    example: "Netbanking (application).",
  },
  // src: backend/utilities/cbom_sources/agility_rollup.py:16-17 — the hardest class across the system's assets
  "cbom.agility.hardest": {
    label: "Hardest",
    what: "The hardest fix class among the system's assets.",
    why: "One hardware-fixed asset can hold a whole system's migration back.",
    example: "Vendor-fixed.",
  },
  // src: backend/utilities/cbom_sources/agility_rollup.py:19-20 — configurable + code-fixed over the four classes
  "cbom.agility.system_self_fixable": {
    label: "Self-fixable",
    what: "The system's configurable and code-fixed assets out of those with one of the four fix classes; Unknown and none are left out.",
    why: "Shows which systems your team can migrate without a vendor or new hardware.",
    example: "80%: 16 of 20 assets.",
  },
  // src: frontend/components/cbom/grade/AgilityBaseline.tsx:213-220 — drill-down by class and system
  "cbom.agility.drill": {
    label: "Fix class",
    what: "Lists the assets of one fix class, or every class, for the whole team or the system you opened.",
    why: "Gives the concrete asset list behind each count.",
    example: "Hardware-fixed assets of Card switch.",
  },
  // src: frontend/components/cbom/grade/AgilityBaseline.tsx:104, backend/utilities/cbom_sources/agility_rollup.py:83-89 — the codes that decided the class
  "cbom.agility.why_codes": {
    label: "Why",
    what: "The finding codes that decided the asset's fix class. An asset seen several times is classed on all its observations' codes together.",
    why: "Tells the owner what to change, not just how hard it is.",
    example: "WEAK_PROTOCOL, NO_PQ_KEX.",
  },
  // src: backend/utilities/cbom_sources/agility_rollup.py:12-17, frontend/components/cbom/grade/AgilityBaseline.tsx:106 — observations merged into one asset
  "cbom.agility.seen_by": {
    label: "Seen by",
    what: "How many observations, from Sources collections and code scans, were merged into this one asset. Hover for their names.",
    why: "An asset several sources see is counted once, not once per source.",
    example: "3 (Network TLS DC1, Servers DC1, repo payments@main).",
  },
  // ────────────────────────────────────────────────────────────── CBOM run results: Ticketing tab (CB-38 PR-4)
  // src: backend/utilities/cbom_sources/run_tickets.py:1-22, frontend/components/cbom/results/RunTicketingTab.tsx:3-6,191 — one issue per asset across runs
  "cbom.run.tickets": {
    label: "Jira tickets for this run",
    what: "Creates one Jira issue per selected finding with the team's Jira connection. An asset that already has an issue, from this run or an earlier run of the same source, keeps it and no duplicate is opened. Each result shows created, existing, failed or deferred (retry).",
    why: "Puts the fixes in the tracker your owners already work from.",
    example: "12 selected: 9 created (SEC-1501 to SEC-1509), 3 existing.",
  },
  // src: backend/utilities/cbom_sources/run_tickets.py:3-5, frontend/components/cbom/results/runTicketing.ts:26-33 — key or numeric id, team admin
  "cbom.run.tickets.project": {
    label: "Jira project for CBOM Sources",
    what: "The Jira project, by key or numeric id, for the tickets of every Sources run of the team. Only a team admin sets it; leave it empty to stop creating tickets. Jira credentials stay in Team settings.",
    why: "Tickets land where the owners of the infrastructure work.",
    example: "SEC, or 10000.",
  },
  // src: backend/utilities/cbom_sources/run_tickets.py:54, frontend/components/cbom/results/RunTicketingTab.tsx:107-110 — default Task
  "cbom.run.tickets.issue_type": {
    label: "Issue type",
    what: "The Jira issue type of the tickets, up to 64 characters. Task when left empty.",
    why: "Some projects only accept their own issue types, such as Bug or Vulnerability.",
    example: "Vulnerability.",
  },
  // src: frontend/components/cbom/results/RunTicketingTab.tsx:256-260, backend/utilities/cbom_sources/run_tickets.py:18-20 — findings without a ticket on this page
  "cbom.run.tickets.select": {
    label: "Select findings",
    what: "Selects every finding on this page that has no Jira issue yet. Clean inventory and coverage notes are not findings and cannot be ticketed.",
    why: "Ticket a page of findings in one step.",
    example: "100 on this page, 88 without a ticket: 88 selected.",
  },
  // ────────────────────────────────────────────────────────────── CBOM Sources: network sweep totals (#234) and the node image pull (#233)
  // src: frontend/components/cbom/sources/NetworkTab.tsx:935-948, frontend/components/cbom/sources/networkEstimate.ts:18-36 — unique addresses over enabled ranges
  "cbsrc.net.before_first": {
    label: "Before the first run",
    what: "What the first sweep will cover: the unique addresses across the enabled ranges, after the never-scan list, times the ports listed. Disabled ranges are not swept and not counted. A discovery sweep on each scan node with ranges finds the open ports first.",
    why: "Check the size before you tell your SOC and start the run.",
    example: "4,096 unique addresses across 2 enabled ranges after the never-scan list, 6 ports. 1 disabled range is not counted.",
  },
  // src: frontend/components/cbom/sources/logic.ts:612-634, frontend/components/cbom/sources/ScanNodesTab.tsx:488-498 — docker pull or helm from the public registry
  "cbsrc.nodes.registry_pull": {
    label: "Install with one command",
    what: "When ZeroShield publishes the node image in a public registry, one command pulls the pinned release and starts the node (Docker), or installs the Helm chart from that registry. No registry login is needed. Hosts without access to the registry use the downloaded files below instead.",
    why: "The quickest install on a host with internet access; the pinned version matches this ZeroShield.",
    example: "docker pull ghcr.io/… && docker run … on the scan host.",
  },
  // ────────────────────────────────────────────────────────────── CBOM run results: quantum readiness chart of a run
  // src: frontend/components/cbom/results/model.ts:100-128, backend/utilities/cbom_sources/posture.py:3-7 — Safe = hybrid + quantum-safe + grover-weakened; Vulnerable = quantum-vulnerable
  "cbom.run.quantum": {
    label: "Quantum readiness",
    what: "The run's assets with a quantum verdict, from the run's posture: Safe counts the hybrid, quantum-safe and grover-weakened classes, Vulnerable the quantum-vulnerable class. Assets with no verdict (unknown, not applicable) are left out. A run has no Broken today bar.",
    why: "Same counts as the Quantum ready card and the posture section, so the numbers on the page agree.",
    example: "Safe 412, Vulnerable 168.",
  },
  // ────────────────────────────────────────────────────────────── CBOM Sources: node install without the public registry (#233)
  // src: backend/routers/cbom_node_artifacts.py:26-33, frontend/components/cbom/sources/ScanNodesTab.tsx:312-322,501 — one paste with curl or wget, or the downloaded files
  "cbsrc.nodes.files_install": {
    label: "Air-gapped install",
    what: "For a host that cannot reach the public registry: one paste that downloads this node's files from ZeroShield, checks their SHA-256 and installs them (curl, or wget), or the same install from files you downloaded in the browser. The download links work only for this node and only until it registers or its token is replaced or expires.",
    why: "Installs the same pinned release on a host with no internet access.",
    example: "Copy the files to the host, then run the install command shown below them.",
  },
  // ────────────────────────────────────────────────────────────── CBOM run results on the one results template (#239, #124)
  // src: frontend/components/cbom/results/RunDeliverablesMenu.tsx:20-45,83 — VEX, HMAC signature, evidence zip, PDF report
  "cbom.run.deliverables": {
    label: "VEX, Signature, Evidence pack, PDF Report",
    what: "The run's CycloneDX 1.6 VEX (exploitable, in triage, resolved or will-not-fix from the remediation plan), an HMAC-SHA256 signature over the exact bytes of the CycloneDX JSON download, an evidence pack (zip of CycloneDX JSON and XML, OSCAL, VEX, signature and PDF with a sha256 manifest) and a PDF report. While the run is collecting, each file says it holds what was collected so far.",
    why: "The documents an auditor or a regulator asks for, built from the same data as this page.",
    example: "Evidence pack for the RBI inspection: one zip with its sha256 manifest.",
  },
  // src: frontend/components/cbom/results/RunSections.tsx:163-192 — verifyCbomRunSignature; the key stays on the server
  "cbom.run.verify": {
    label: "Verify file",
    what: "Checks a CycloneDX JSON file you downloaded from this run against the run's signature. The signing key stays on the server; the result says whether the file is unchanged.",
    why: "Proves a file someone sends you is the run's real CBOM, not an edited copy.",
    example: "Verified: this file is the run's signed CycloneDX JSON, unchanged.",
  },
  // src: frontend/components/cbom/results/RunFindingDialog.tsx:138-150, frontend/components/cbom/results/model.ts:587-615 — the item's owasp_top_10, else the knowledge-base entries (findingChips)
  "cbom.run.f.owasp": {
    label: "OWASP Top 10",
    what: "The OWASP Top 10 categories this finding maps to: the scan's own mapping when it sent one, else the categories of the asset's knowledge-base entries. Most cryptographic findings fall under A02 Cryptographic Failures.",
    why: "Lets application security teams file the finding under the category they track.",
    example: "A02:2021 Cryptographic Failures.",
  },
  // src: frontend/components/cbom/results/RunFindingDialog.tsx:151-160, frontend/components/cbom/results/model.ts:587-615 — the item's compliance_controls, else the knowledge-base entries (findingChips)
  "cbom.run.f.compliance": {
    label: "Compliance controls",
    what: "The compliance controls this finding maps to, such as PCI DSS requirements, ISO 27001 clauses or RBI and CERT-In items: the scan's own mapping, else those of the asset's knowledge-base entries.",
    why: "Shows which audit requirement the fix closes.",
    example: "PCI DSS 4.2.1 (strong cryptography in transit).",
  },
  // src: frontend/components/cbom/results/RunFindingDialog.tsx:161-166, frontend/components/cbom/results/model.ts:587-615 — the item's suggested_fix, else the knowledge-base remediation summary (findingChips)
  "cbom.run.f.suggested_fix": {
    label: "Suggested fix",
    what: "The fix suggested for this finding: the scan's own suggestion when it gave one, else the remediation summary of the asset's knowledge-base entry (no AI).",
    why: "A starting point for the owner's change.",
    example: "Disable TLS 1.0 and 1.1; allow TLS 1.2 and 1.3 only.",
  },
  // ────────────────────────────────────────────────────────────── CBOM Sources: scan node network requirements (#243)
  // src: frontend/components/cbom/sources/logic.ts:543-549 — outbound HTTPS to the API; registry, build kits and cloud APIs
  "cbsrc.nodes.network_req": {
    label: "Network requirements",
    what: "What needs network access: the scan node only needs outbound HTTPS to the ZeroShield API and direct reach to your targets. Pulling the image from a public registry needs that registry; building the OVA or AMI kits needs internet; cloud and identity sources are read from ZeroShield's servers.",
    why: "Tells your network team which firewall rules to open, and that nothing calls in.",
    example: "Allow node-dc1 out to the ZeroShield API on 443; no inbound rule.",
  },
  // ────────────────────────────────────────────────────────────── CBOM Sources: Fleet > Credentials (F1.2, PR #81)
  // src: frontend/components/cbom/sources/fleet/CredentialsSection.tsx:3-6, backend/utilities/cbom_sources/fleet/credentials.py:1-7 — logins policies hand to managed sources; secrets write-only
  "fleet.cred.section": {
    label: "Credentials",
    what: "Logins that fleet policies give to the managed sources they create: how to sign in to a Linux host over SSH, and the secret if the type stores one. Secrets are encrypted and never shown again.",
    why: "One credential serves every host a policy matches, so a fleet of thousands needs no per-host setup.",
    example: "linux-fleet: SSH certificate and key, login zs-cbom on port 22, used by 14 managed sources.",
  },
  // src: backend/utilities/cbom_sources/fleet/credentials.py:73 — 1 to 64 characters
  "fleet.cred.name": {
    label: "Name",
    what: "A name for this credential, 1 to 64 characters, shown when you choose one in a policy.",
    why: "Policies pick credentials by name.",
    example: "linux-fleet.",
  },
  // src: frontend/components/cbom/sources/fleet/CredentialsSection.tsx:36-43, backend/utilities/cbom_sources/fleet/credentials.py:3-7 — node key, password, SSH certificate, vault, SSH CA
  "fleet.cred.type": {
    label: "Type",
    what: "How the scan node signs in: its own node key (nothing stored here), a password (host keys must be pinned), an SSH certificate and key, or a secret read from a vault. SSH CA credentials are made in the SSH CA section. The type cannot change once added.",
    why: "Decides which secret is stored and where it may be used.",
    example: "SSH certificate and key.",
  },
  // src: backend/utilities/cbom_sources/fleet/credentials.py:27 — login_user, up to 64 characters
  "fleet.cred.login": {
    label: "Login",
    what: "The account the scan node signs in with on each host, up to 64 characters.",
    why: "Use a dedicated read-only account so the scan can be audited and limited.",
    example: "zs-cbom.",
  },
  // src: backend/utilities/cbom_sources/fleet/credentials.py:28 — 1 to 65535, default 22
  "fleet.cred.port": {
    label: "Port",
    what: "The SSH port on the hosts, 1 to 65535.",
    why: "Hosts that run SSH on another port are unreachable on 22.",
    example: "22, or 2222 where SSH was moved.",
  },
  // src: frontend/components/cbom/sources/fleet/CredentialsSection.tsx:156-164, backend/utilities/cbom_sources/fleet/credentials.py:29-30 — pinned or trust on first use
  "fleet.cred.pinned": {
    label: "Pin host keys",
    what: "Pinned: the node only accepts the host keys listed below. Off: it trusts each host's key the first time and then expects the same key (trust on first use). A password credential is always pinned.",
    why: "Pinning stops a password or session from going to a host that impersonates the real one.",
    example: "On for the PCI segment, with its known_hosts lines pasted.",
  },
  // src: frontend/components/cbom/sources/fleet/CredentialsSection.tsx:165-169, backend/utilities/cbom_sources/fleet/credentials.py:30 — pinned host keys
  "fleet.cred.known_hosts": {
    label: "known_hosts lines",
    what: "The hosts' public keys in OpenSSH known_hosts format, one per line. Required when host keys are pinned.",
    why: "Only hosts whose key is listed are accepted.",
    example: "web-01.bank.local ssh-ed25519 AAAAC3Nza… (one line per host).",
  },
  // src: frontend/components/cbom/sources/fleet/CredentialsSection.tsx:170-174, backend/utilities/cbom_sources/fleet/credentials.py:21 — encrypted, write-only; re-entered when the login changes
  "fleet.cred.password": {
    label: "Password",
    what: "The account's password. Encrypted at rest and never shown again; leave it blank on edit to keep it. Changing the login, port, host keys or vault asks for it again.",
    why: "A password for one login never follows the credential to another one.",
    example: "The password of zs-cbom.",
  },
  // src: frontend/components/cbom/sources/fleet/CredentialsSection.tsx:175-183, backend/utilities/cbom_sources/fleet/credentials.py:21 — ssh_certificate with private_key
  "fleet.cred.cert": {
    label: "SSH certificate",
    what: "The OpenSSH user certificate signed by your SSH CA for the login account. Stored encrypted with the private key below; never shown again.",
    why: "Short-lived certificates avoid copying a long-lived key to every host.",
    example: "ssh-ed25519-cert-v01@openssh.com AAAA… zs-cbom.",
  },
  // src: frontend/components/cbom/sources/fleet/CredentialsSection.tsx:180-182, backend/utilities/cbom_sources/fleet/credentials.py:21 — encrypted, write-only
  "fleet.cred.key": {
    label: "Private key",
    what: "The private key that belongs to the SSH certificate. Encrypted at rest and sent only to the scan node that runs the job; never shown again.",
    why: "The certificate is useless without it, so keep it read-only on the hosts' side.",
    example: "The OpenSSH private key that matches zs-cbom-cert.pub.",
  },
  // src: frontend/components/cbom/sources/fleet/CredentialsSection.tsx:185-197, backend/utilities/cbom_sources/kinds.py:81-83 — VaultRef provider
  "fleet.cred.vault": {
    label: "Vault",
    what: "Where the scan node reads the secret at run time: HashiCorp Vault, CyberArk, AWS Secrets Manager or Azure Key Vault. Nothing secret is stored in ZeroShield.",
    why: "Keeps the secret in the vault your team already rotates and audits.",
    example: "HashiCorp.",
  },
  // src: backend/utilities/cbom_sources/kinds.py:83 — 1 to 512 characters
  "fleet.cred.vault_path": {
    label: "Secret path",
    what: "The path of the secret in the vault, 1 to 512 characters.",
    why: "The node reads exactly this secret and nothing else.",
    example: "secret/data/cbom/zs-cbom.",
  },
  // src: frontend/components/cbom/sources/fleet/CredentialsSection.tsx:278 — credential_type
  "fleet.cred.col.type": {
    label: "Type",
    what: "The credential's type: node_key, password, ssh_cert, vault or ssh_ca.",
    why: "Tells you at a glance which secret, if any, is stored.",
    example: "ssh_cert.",
  },
  // src: frontend/components/cbom/sources/fleet/CredentialsSection.tsx:279 — login_user:port
  "fleet.cred.col.login": {
    label: "Login",
    what: "The login account and SSH port the credential uses.",
    why: "Shows which account the hosts must allow.",
    example: "zs-cbom:22.",
  },
  // src: frontend/components/cbom/sources/fleet/CredentialsSection.tsx:264, backend/utilities/cbom_sources/fleet/credentials.py:5-7 — secrets_set, names only
  "fleet.cred.col.secrets": {
    label: "Secrets stored",
    what: "Which secrets are stored for this credential, by name only; the values are never shown.",
    why: "Confirms the secret is in place without exposing it.",
    example: "ssh_certificate, private_key.",
  },
  // src: frontend/components/cbom/sources/fleet/CredentialsSection.tsx:265 — managed_sources
  "fleet.cred.col.managed": {
    label: "Managed sources",
    what: "How many managed sources, created by policies, use this credential now.",
    why: "Deleting or changing a credential affects every one of them.",
    example: "14 managed sources.",
  },
  // ────────────────────────────────────────────────────────────── CBOM Sources: Fleet > Inventory (F1.2, PR #81)
  // src: frontend/components/cbom/sources/fleet/InventorySection.tsx:3-4, backend/utilities/cbom_sources/fleet/policy.py:1-14 — targets from inventory sources, each with its policy decision
  "fleet.inv.section": {
    label: "Inventory",
    what: "Every host, database, cluster, certificate, key and secret your inventory sources list (a CSV or JSON import, an AWS account, the API), each with the policy decision on it: collect, never scan or not collected, which policy won and why.",
    why: "Shows which part of the estate the fleet policies cover and which part nothing collects.",
    example: "4,210 targets: 3,980 collect, 120 never scan, 110 not collected (no policy matches).",
  },
  // src: backend/utilities/cbom_sources/fleet/inventory_sources.py:7-12 — CSV with a header row, or JSON
  "fleet.inv.import_format": {
    label: "Format",
    what: "CSV with a header row (external_id, kind, address, addresses, hostname, account_id, region, platform, tags, tag:<key> and handle: or attr: columns) or JSON (a list of objects, or {\"targets\": [...]}). Unknown CSV columns are refused. Picked from the file name when you choose a file.",
    why: "A typo in a column name must not silently drop a tag a policy depends on.",
    example: "CSV exported from your CMDB.",
  },
  // src: frontend/components/cbom/sources/fleet/InventorySection.tsx:82-87, backend/utilities/cbom_sources/fleet/inventory_sources.py:29 — up to 10,000 rows
  "fleet.inv.import_file": {
    label: "File",
    what: "A .csv or .json file of up to 10,000 targets; its content is loaded into the box below. Importing the same file again changes nothing; targets it no longer lists are marked missing.",
    why: "Keeps the inventory in step with your CMDB export.",
    example: "cmdb-linux-2026-11.csv.",
  },
  // src: frontend/components/cbom/sources/fleet/InventorySection.tsx:113-125, backend/utilities/cbom_sources/fleet/inventory_sources.py:13 — external_id defaults to hostname, else address
  "fleet.inv.import_content": {
    label: "Content",
    what: "The rows to import, pasted or loaded from the file. external_id defaults to the hostname, else the address; kind defaults to linux_host. Preview shows what would change without saving.",
    why: "Check the preview before an import marks hosts missing.",
    example: "A header external_id,kind,address,tag:env and a row web-01,linux_host,10.0.1.5,prod.",
  },
  // src: backend/utilities/cbom_sources/fleet/schemas.py:43 — 1 to 64 characters
  "fleet.inv.aws_name": {
    label: "Name",
    what: "A name for this AWS inventory source, 1 to 64 characters.",
    why: "Each target shows the source that lists it.",
    example: "aws-payments-prod.",
  },
  // src: backend/utilities/cbom_sources/fleet/aws_inventory.py:1-8 — the validated read-only role; list and describe calls only
  "fleet.inv.aws_account": {
    label: "AWS account",
    what: "The AWS account, added and validated on Cloud & Identity, whose read-only role lists the resources. Only list and describe calls are made: no secret value or key material is read.",
    why: "Discovery reuses the role you already approved; no new credential is needed.",
    example: "payments-prod · 111122223333.",
  },
  // src: backend/utilities/cbom_sources/fleet/aws_inventory.py:32,40 — 1 to 20 regions
  "fleet.inv.aws_regions": {
    label: "Regions",
    what: "The regions to list, comma-separated, 1 to 20.",
    why: "Resources in a region not listed here are not discovered.",
    example: "ap-south-1, ap-south-2.",
  },
  // src: frontend/components/cbom/sources/fleet/InventorySection.tsx:48,217-232, backend/utilities/cbom_sources/fleet/aws_inventory.py:10-14 — names and tags only; a status per region and service
  "fleet.inv.aws_services": {
    label: "Services",
    what: "Which AWS services to list: EC2, RDS, EKS, load balancers, ACM certificates, KMS keys and Secrets Manager secrets (names and tags only). Each region and service gets a status; only a fully read one can mark vanished targets missing.",
    why: "Leave out services your role may not list, so they do not show as denied.",
    example: "ec2, rds and acm only.",
  },
  // src: backend/utilities/cbom_sources/fleet/schemas.py:45 — 15 minutes to 7 days
  "fleet.inv.aws_every": {
    label: "Sync every (minutes)",
    what: "How often the account is listed again, from 15 minutes to 7 days (10,080 minutes).",
    why: "New and removed hosts reach the policies at the next sync.",
    example: "60 minutes.",
  },
  // src: frontend/components/cbom/sources/fleet/InventorySection.tsx:325 — CSV, JSON, API or AWS with its regions
  "fleet.inv.col.kind": {
    label: "Kind",
    what: "Where the source's targets come from: an import (CSV or JSON), the API, or an AWS account with its regions.",
    why: "AWS sources sync themselves; imports change only when you import again.",
    example: "AWS · ap-south-1, us-east-1.",
  },
  // src: frontend/components/cbom/sources/fleet/InventorySection.tsx:311 — target_count
  "fleet.inv.col.targets": {
    label: "Targets",
    what: "How many targets this source lists now.",
    why: "A sudden drop usually means a sync could not read part of the account.",
    example: "1,240.",
  },
  // src: frontend/components/cbom/sources/fleet/InventorySection.tsx:327-332,312, backend/utilities/cbom_sources/fleet/aws_inventory.py:10-14 — status, time, error, scopes not read
  "fleet.inv.col.last_sync": {
    label: "Last sync",
    what: "The result and time of the last sync or import, its error if any, and the regions and services it could not read (access denied, region not enabled and so on).",
    why: "Targets in a scope that was not read are not marked missing, and may be out of date.",
    example: "partial · 14 Nov 2026, 09:00 · Not read: us-east-1 rds (access denied).",
  },
  // src: frontend/components/cbom/sources/fleet/InventorySection.tsx:462-475 — name, address or ID; applied when typing pauses
  "fleet.inv.search": {
    label: "Search",
    what: "Finds targets by name, address or external ID; the list updates when you pause typing.",
    why: "Jump to one host in an inventory of thousands.",
    example: "web-01.",
  },
  // src: frontend/components/cbom/sources/fleet/InventorySection.tsx:462-464 — a key may contain colons
  "fleet.inv.tag_key": {
    label: "Tag key",
    what: "Shows only targets that have this tag key. A key may contain colons.",
    why: "Check what a tag policy will match before you write it.",
    example: "env, or aws:cloudformation:stack-name.",
  },
  // src: frontend/components/cbom/sources/fleet/InventorySection.tsx:486-489 — with a tag key; any value when empty
  "fleet.inv.tag_value": {
    label: "Tag value",
    what: "With a tag key: shows only targets whose tag has this value. Empty means any value.",
    why: "Narrows the list to one environment or owner.",
    example: "prod.",
  },
  // src: frontend/components/cbom/sources/fleet/InventorySection.tsx:43-47 — target kinds
  "fleet.inv.kind": {
    label: "Kind",
    what: "Shows only one kind of target: Linux or Windows host, database, Kubernetes, load balancer, certificate, KMS key, secret or other. Policies collect Linux hosts; the other kinds are listed for the inventory.",
    why: "See how much of each kind the inventory holds.",
    example: "Linux host.",
  },
  // src: backend/utilities/cbom_sources/fleet/policy.py:3-12 — collect, never scan, unmanaged
  "fleet.inv.decision": {
    label: "Decision",
    what: "Shows only targets with one decision: Collect (a policy collects it), Never scan (a never-scan policy or the team's never-scan list), or Not collected (no policy matches, or something the policy needs is not usable).",
    why: "Not collected is the list of hosts nothing reads yet.",
    example: "Not collected: 110 targets.",
  },
  // src: frontend/components/cbom/sources/fleet/InventorySection.tsx:508-517, backend/utilities/cbom_sources/fleet/policy.py:9-11 — missing for more than 7 days is not collected
  "fleet.inv.missing": {
    label: "Missing",
    what: "Present: targets the last sync or import listed. Missing: targets a fully read sync or a re-import no longer lists. A target missing for more than 7 days is not collected.",
    why: "Missing hosts were often decommissioned; check before you chase them.",
    example: "Missing: 6 targets since 2 Nov.",
  },
  // src: frontend/components/cbom/sources/fleet/InventorySection.tsx:546-551 — name, address and external ID; click for the detail
  "fleet.inv.col.target": {
    label: "Target",
    what: "The target's host name or address and its external ID. Click a row for its decision, every matching policy, addresses and tags.",
    why: "The detail shows why a policy did or did not win.",
    example: "web-01 · 10.0.1.5 · i-0abc123.",
  },
  // src: frontend/components/cbom/sources/fleet/InventorySection.tsx:552 — KIND_LABEL
  "fleet.inv.col.kind_t": {
    label: "Kind",
    what: "What the target is: Linux host, Windows host, database, Kubernetes, load balancer, certificate, KMS key, secret or other.",
    why: "Policies collect Linux hosts over SSH; other kinds are inventory only.",
    example: "Linux host.",
  },
  // src: frontend/components/cbom/sources/fleet/InventorySection.tsx:553-560, backend/utilities/cbom_sources/fleet/policy.py:19 — keys compared lower-cased, values exactly
  "fleet.inv.col.tags": {
    label: "Tags",
    what: "The target's tags as key=value (the first four). Policies match tag keys lower-cased and values exactly.",
    why: "Tags are what policies select on.",
    example: "env=prod, owner=payments.",
  },
  // src: frontend/components/cbom/sources/fleet/InventorySection.tsx:538 — region and account
  "fleet.inv.col.where": {
    label: "Where",
    what: "The cloud region and account of the target, when it came from a cloud source.",
    why: "Policies can select on region and account_id too.",
    example: "ap-south-1 · 111122223333.",
  },
  // src: frontend/components/cbom/sources/fleet/InventorySection.tsx:562-571,539, backend/utilities/cbom_sources/fleet/policy.py:3-14 — the first matching policy wins
  "fleet.inv.col.decision": {
    label: "Decision (which policy won)",
    what: "Collect, Never scan or Not collected, the policy that won (highest priority, then the older one) and the reason. Waiting for a running job means its managed source changes when that job ends.",
    why: "Shows exactly which rule decides each host, so overlaps are easy to spot.",
    example: "Collect · prod-weekly won (priority 200) over linux-default.",
  },
  // ────────────────────────────────────────────────────────────── CBOM Sources: Fleet > Policies (F1.2, PR #81)
  // src: frontend/components/cbom/sources/fleet/PoliciesSection.tsx:3-5, backend/utilities/cbom_sources/fleet/policy.py:1-14 — first match by priority wins; never-scan list overrides
  "fleet.pol.section": {
    label: "Policies",
    what: "Rules that decide how each inventory target is collected: a selector over tags and fields, and an action (collect over SSH with a credential, scan node and schedule, or never scan). The highest-priority match wins, then the older policy; the team's never-scan list overrides every policy. Apply policies creates and updates the managed sources and schedules.",
    why: "Thousands of hosts are covered by a few rules instead of one source per host.",
    example: "pci (priority 500): never scan; prod-weekly (200): collect weekly; linux-default (0): collect monthly.",
  },
  // src: backend/utilities/cbom_sources/fleet/schemas.py:69 — 1 to 64 characters
  "fleet.pol.name": {
    label: "Name",
    what: "A name for the policy, 1 to 64 characters, shown on each target it wins.",
    why: "The targets table names the policy that decided each host.",
    example: "prod-weekly.",
  },
  // src: backend/utilities/cbom_sources/fleet/schemas.py:71, backend/utilities/cbom_sources/fleet/policy.py:6-7 — 0 to 1,000,000; higher wins, then the older policy
  "fleet.pol.priority": {
    label: "Priority",
    what: "0 to 1,000,000. When several policies match a target, the highest priority wins; on a tie the older policy wins.",
    why: "Put exceptions, such as never scan for PCI hosts, above the broad rules.",
    example: "500 for pci, 100 for the default.",
  },
  // src: backend/utilities/cbom_sources/fleet/policy.py:17-19 — all / any / not, leaves on tags and fields, at most 20
  "fleet.pol.selector": {
    label: "Targets it matches",
    what: "The conditions a target must meet: on a tag (any key) or a field (kind, account_id, region, platform). No condition matches every target. At most 20 conditions; no regular expressions.",
    why: "Decides which hosts this policy governs.",
    example: "env is prod and region starts with ap-.",
  },
  // src: frontend/components/cbom/sources/fleet/PoliciesSection.tsx:129-151, backend/utilities/cbom_sources/fleet/policy.py:17-19 — tag or field; keys lower-cased, values exact
  "fleet.pol.condition": {
    label: "Condition",
    what: "What the condition tests: a tag, by key (compared lower-cased), or a field: kind, account_id, region or platform.",
    why: "Tags carry your own grouping; fields come from the inventory source.",
    example: "Tag env, or Field region.",
  },
  // src: frontend/components/cbom/sources/fleet/PoliciesSection.tsx:153-162, frontend/components/cbom/sources/fleet/fleetLogic.ts:81-87 — is, is not, is one of, is set, starts with
  "fleet.pol.operator": {
    label: "Operator",
    what: "How the value is compared: is, is not, is one of (comma-separated, up to 50 values), is set (any value), or starts with. Values are compared exactly.",
    why: "Pick the narrowest test that matches what you mean.",
    example: "env is one of prod, dr.",
  },
  // src: frontend/components/cbom/sources/fleet/PoliciesSection.tsx:250-261, backend/utilities/cbom_sources/fleet/policy.py:17 — all or any
  "fleet.pol.combine": {
    label: "Combine conditions",
    what: "All conditions must hold, or any one is enough.",
    why: "Changes how many targets the policy matches; preview it before saving.",
    example: "All: env is prod and platform is ubuntu.",
  },
  // src: frontend/components/cbom/sources/fleet/PoliciesSection.tsx:277-281, backend/utilities/cbom_sources/fleet/policy.py:17-19 — the selector grammar
  "fleet.pol.selector_json": {
    label: "Selector (JSON)",
    what: "A selector that uses not or nesting is edited as JSON: {\"all\": [...]}, {\"any\": [...]}, {\"not\": {...}} and leaves {\"tag\": k, \"op\": op, \"value\": v} or {\"field\": f, \"op\": op, \"value\": v}. At most 20 leaves, 6 levels deep.",
    why: "Expresses exclusions the simple form cannot.",
    example: "env is prod but not tagged pci: {\"all\": [{\"tag\": \"env\", \"op\": \"eq\", \"value\": \"prod\"}, {\"not\": {\"tag\": \"pci\", \"op\": \"exists\"}}]}.",
  },
  // src: backend/utilities/cbom_sources/fleet/policy.py:8-12 — collect, never scan, or not collected with the reason
  "fleet.pol.action": {
    label: "What happens to them",
    what: "Collect the matched targets over SSH with the credential, scan node, tier, batch size and schedule below, or never scan them. A target that cannot be collected (not a Linux host, no address, a deleted credential or node, missing for over 7 days) is listed as not collected with the reason.",
    why: "Decides what a run does with every host this policy wins.",
    example: "Collect weekly on Sunday 02:00 through node-dc1.",
  },
  // src: backend/utilities/cbom_sources/fleet/policy.py:8 — a never-scan winner gives never_scan
  "fleet.pol.never_scan": {
    label: "Never scan them",
    what: "Targets this policy wins are never collected, whatever lower-priority policies say.",
    why: "Keeps sensitive systems out of every scan by rule, not by hand.",
    example: "tag pci is set: never scan.",
  },
  // src: frontend/components/cbom/sources/fleet/PoliciesSection.tsx:294-303 — from Fleet > Credentials
  "fleet.pol.credential": {
    label: "Credential (SSH)",
    what: "The credential the managed sources sign in with. Add one in Credentials below.",
    why: "Without a usable credential the targets are not collected.",
    example: "linux-fleet · ssh_cert.",
  },
  // src: frontend/components/cbom/sources/fleet/PoliciesSection.tsx:180-182,304-306 — agentless nodes only
  "fleet.pol.node": {
    label: "Scan node",
    what: "The agentless scan node, in a segment that reaches these hosts, that runs the collection.",
    why: "The node must reach every matched host on the SSH port.",
    example: "node-dc1.",
  },
  // src: frontend/components/cbom/sources/fleet/PoliciesSection.tsx:307-315, backend/utilities/cbom_sources/fleet/policy.py:275-278 — 1 or 2
  "fleet.pol.tier": {
    label: "Tier",
    what: "Tier 1 reads without sudo. Tier 2 also runs the read-only sudo lines published on the Servers tab, for files only root can read.",
    why: "Tier 2 finds more (private key files, service configs) but needs the sudoers lines on each host.",
    example: "Tier 2 on hosts where the sudoers file is rolled out.",
  },
  // src: backend/utilities/cbom_sources/fleet/policy.py:279-282, backend/utilities/cbom_sources/fleet/materialize.py:7-9 — 25 to 1,000 targets per managed source
  "fleet.pol.batch": {
    label: "Batch size",
    what: "How many targets go into one managed source, 25 to 1,000. A target keeps its managed source while its policy, credential and node stay the same.",
    why: "Smaller batches spread the work over more jobs; larger ones mean fewer sources to watch.",
    example: "100 targets per managed source.",
  },
  // src: backend/utilities/cbom_sources/fleet/policy.py:287-297, backend/utilities/cbom_sources/fleet/materialize.py:322,373 — daily, weekly or monthly in the team's scan window time zone
  "fleet.pol.schedule": {
    label: "Schedule",
    what: "When the policy's managed sources are collected: on demand, daily, weekly or monthly, at a time in the team's scan window time zone. One managed schedule per policy.",
    why: "Keeps the inventory current without starting runs by hand.",
    example: "Weekly, Sunday at 02:00.",
  },
  // src: backend/utilities/cbom_sources/fleet/policy.py:298-304 — HH:MM, 24 hour
  "fleet.pol.time": {
    label: "Time",
    what: "The time of day the scheduled run starts, 24-hour HH:MM.",
    why: "Pick a quiet hour for the hosts and the network.",
    example: "02:00.",
  },
  // src: backend/utilities/cbom_sources/fleet/policy.py:305-310 — Monday to Sunday
  "fleet.pol.weekday": {
    label: "Day",
    what: "The day of the week a weekly schedule runs.",
    why: "Avoid your change-window days.",
    example: "Sunday.",
  },
  // src: backend/utilities/cbom_sources/fleet/policy.py:312-314 — 1 to 28
  "fleet.pol.monthday": {
    label: "Day of month",
    what: "The day of the month a monthly schedule runs, 1 to 28, so every month has it.",
    why: "Line the run up with your monthly reporting.",
    example: "1, the first of each month.",
  },
  // src: frontend/components/cbom/sources/fleet/PoliciesSection.tsx:485-493 — name, priority, disabled
  "fleet.pol.col.policy": {
    label: "Policy",
    what: "The policy's name and priority, in the order the policies apply; Disabled when it is switched off.",
    why: "The first matching policy in this order wins.",
    example: "1. pci · priority 500.",
  },
  // src: frontend/components/cbom/sources/fleet/PoliciesSection.tsx:475, frontend/components/cbom/sources/fleet/fleetLogic.ts:153-155 — the selector in words
  "fleet.pol.col.matches": {
    label: "Matches",
    what: "The policy's selector in words.",
    why: "Read what the policy covers without opening it.",
    example: "env is prod and region starts with ap-.",
  },
  // src: frontend/components/cbom/sources/fleet/PoliciesSection.tsx:476 — actionText
  "fleet.pol.col.does": {
    label: "Does",
    what: "The policy's action in words: never scan, or collect with which credential, node, tier and schedule.",
    why: "Shows what happens to the targets it wins.",
    example: "Collect over SSH with linux-fleet on node-dc1, tier 1, weekly.",
  },
  // src: frontend/components/cbom/sources/fleet/PoliciesSection.tsx:477, backend/utilities/cbom_sources/fleet/policy.py:6-7 — won by this policy / matched by its selector
  "fleet.pol.col.targets": {
    label: "Targets (won / matched)",
    what: "Targets this policy decides (won) over targets its selector matches. Matched but not won means a higher-priority policy or the never-scan list decided them.",
    why: "A big gap between the two shows policies overlapping.",
    example: "1,180 / 1,240.",
  },
} as const satisfies Record<string, InfoTipEntry>;

export type InfoTipId = keyof typeof INFO_TIPS;
