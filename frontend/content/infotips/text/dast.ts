/**
 * (i) tip text of the "dast" area (ids: dast.*), loaded on demand by
 * content/infotips/load.ts. The label of each tip is in content/infotips/labels.ts; the rules for the text are in
 * content/infotips/index.ts (checked by content/infotips.test.ts).
 */
import type { TipAreaText } from "../types";

const TEXT = {
  // ────────────────────────────────────────────────────────────── DAST: scan configuration (components/dast-options-sidebar.tsx)
  // src: backend/utilities/dast/ssrf.py:1-12, backend/utilities/dast/ssrf.py:79-82 — http/https; scope = the target's host; private/metadata addresses refused unless the operator allows them
  "dast.cfg.target_url": {
    what: "The web application to test, starting with http:// or https://. Its host is the scan's scope: the login URL and additional URLs must be on the same host. Hosts that resolve to private, loopback or cloud-metadata addresses are refused unless your administrator allowed them.",
    why: "The scan only tests this host, so the URL sets both what is tested and what is left alone.",
    example: "https://staging.shop.example.com.",
  },
  // src: RabbitMQ/dast_worker/helpers/agent/scan_config.py:17-75 — URL workers 10 / 5 / 2 and longer timeouts when slower
  "dast.cfg.speed": {
    what: "How hard the scan pushes the target. Fast tests 10 URLs at a time with short timeouts, Medium 5, Slow 2 with the longest timeouts (gentlest on a fragile server). Your administrator can change the worker counts.",
    why: "Faster scans finish sooner but load your application more.",
    example: "Slow for a small staging server that falls over under load.",
  },
  // src: RabbitMQ/dast_worker/helpers/crawler/crawler.py:48-50, RabbitMQ/dast_worker/helpers/agent/main.py:373 — the crawler stops at max_urls; credits 0.08 per URL
  "dast.cfg.max_urls": {
    what: "The most pages the crawler collects from the target before testing. Each URL tested costs 0.08 credits, so this also caps the price (additional URLs come on top).",
    why: "It caps both what is tested and the most the scan can cost.",
    example: "100 URLs: at most 8 credits.",
  },
  // src: RabbitMQ/dast_worker/helpers/agent/main.py:72-73, RabbitMQ/dast_worker/helpers/checks/nuclei/basic_templates.py:11-37 — all five fields required; a headless browser signs in with them
  "dast.cfg.auth": {
    what: "How the scanner signs in: a headless browser opens the login URL, types the username and password into the fields found by their XPaths and clicks the submit button. All fields are required, so the pages behind the login are tested too.",
    why: "Most vulnerabilities hide behind the login; without it only public pages are tested.",
    example: "Login URL https://shop.example.com/login with a test account.",
  },
  // src: backend/utilities/dast/ssrf.py:79-82, RabbitMQ/dast_worker/helpers/checks/nuclei/basic_templates.py:11-21 — opened first; must be on the target's host
  "dast.cfg.login_url": {
    what: "The page with the sign-in form. It must be on the same host as the target URL.",
    why: "The scanner signs in here; a wrong page means it tests only public pages.",
    example: "https://shop.example.com/login.",
  },
  // src: RabbitMQ/dast_worker/helpers/checks/nuclei/construct_temp.py:10-27, RabbitMQ/dast_worker/helpers/checks/nuclei/basic_templates.py:21-31 — XPath of the input clicked and typed into
  "dast.cfg.xpath_user": {
    what: "An XPath that finds the username (or email) input on the login page. In the browser: right-click the field, Inspect, then Copy > Copy XPath.",
    why: "Without the right field the sign-in fails and logged-in pages go untested.",
    example: "//input[@name='email'].",
  },
  // src: RabbitMQ/dast_worker/helpers/checks/nuclei/construct_temp.py:10-27, RabbitMQ/dast_worker/helpers/checks/nuclei/basic_templates.py:31-37 — XPath of the password input
  "dast.cfg.xpath_pass": {
    what: "An XPath that finds the password input on the login page.",
    why: "Without the right field the sign-in fails and logged-in pages go untested.",
    example: "//input[@type='password'].",
  },
  // src: RabbitMQ/dast_worker/helpers/checks/nuclei/construct_temp.py:10-27 — XPath of the button clicked to submit
  "dast.cfg.xpath_submit": {
    what: "An XPath that finds the button the scanner clicks to sign in.",
    why: "Without the right button the sign-in never completes.",
    example: "//button[@type='submit'].",
  },
  // src: RabbitMQ/dast_worker/helpers/agent/context.py:4-10, backend/utilities/scan/format_input.py:165-181 — sent to the worker for the sign-in; redacted from the scan's stored settings
  "dast.cfg.username": {
    what: "The account the scanner signs in with. Use a test account: the scan submits forms and tries attacks while signed in.",
    why: "The scan acts as this user, so a test account keeps real data safe.",
    example: "dast-test@shop.example.com.",
  },
  // src: RabbitMQ/dast_worker/helpers/agent/context.py:4-10, backend/utilities/scan/credit_estimate.py:29-30 — sent to the worker; never part of the stored estimate digest
  "dast.cfg.password": {
    what: "The password of that test account. It is sent to the scan worker for the sign-in and is not shown again.",
    why: "Needed to sign in; use a test account's password, never a real user's.",
    example: "The password of dast-test@shop.example.com.",
  },
  // src: RabbitMQ/dast_worker/helpers/crawler/crawler.py:60-63, backend/utilities/dast/ssrf.py:79-82 — always added to the crawl; must be on the target's host
  "dast.cfg.additional_urls": {
    what: "Pages to test even if the crawler does not find them (they are added to the crawl). They must be on the target's host. Each one costs 0.08 credits like any other URL.",
    why: "Pages no link leads to are otherwise never tested.",
    example: "https://shop.example.com/admin/reports (linked from nowhere).",
  },
  // src: RabbitMQ/dast_worker/helpers/crawler/crawler.py:51-56, RabbitMQ/dast_worker/helpers/crawler/crawler.py:108-123 — include or exclude, not both; * matches anything, searched anywhere in the URL
  "dast.cfg.url_patterns": {
    what: "Either Include (test only crawled URLs that match) or Exclude (skip URLs that match), not both. In a pattern * matches anything, and the pattern may match any part of the URL. Additional URLs are always tested.",
    why: "Keeps the scan away from pages such as logout or delete, or focuses it on one area.",
    example: "Exclude https://shop.example.com/logout* so the scan does not sign itself out.",
  },
  // src: RabbitMQ/dast_worker/helpers/agent/main.py:350-375, backend/utilities/scan/estimate_scan.py:193 — the estimate crawls the target now; 0.08 credits per URL found
  "dast.cfg.estimate": {
    what: "Crawls the target now (real requests to your site) to count the URLs the scan would test, and prices them at 0.08 credits each. Nothing is charged until you start the scan.",
    why: "Shows the price before any credits are charged; the crawl sends real requests to your site.",
    example: "The crawl finds 60 URLs: 4.8 credits.",
  },

  // ────────────────────────────────────────────────────────────── DAST: automatic profiles (components/dast/DastProfilesTab.tsx, DastScheduleFields.tsx)
  // src: backend/utilities/dast/schemas.py:40-56, backend/utilities/dast/dispatch.py:115-121 — profile title; each run is titled "<title> (<trigger>)"
  "dast.profile.title": {
    what: "A name for this saved DAST setup. Each run it starts appears in the scan list as \"<title> (<how it started>)\".",
    why: "Lets you tell runs of different profiles apart in the scan list.",
    example: "Shop staging nightly.",
  },
  // src: backend/routers/dast_profiles.py:112-155, backend/routers/dast_profiles.py:253-274, backend/utilities/dast/beat.py:71, backend/routers/cicd.py:99, backend/utilities/dast/dispatch.py:84-121 — saved settings run by schedule, Run now or CI; each run is a new scan charged up front
  "dast.profile.form": {
    what: "Saved DAST settings (target, sign-in, limits, schedule) that can run without you: on its schedule, with Run now, or from your CI pipeline. Each run becomes a new scan in the list and is charged Max URLs x 0.08 credits when it starts.",
    why: "Saved settings let scans repeat without you, for regular coverage.",
    example: "A profile for staging that runs every night at 02:00 IST.",
  },
  // src: backend/routers/dast_profiles.py:253-274, backend/utilities/dast/dispatch.py:89-90, backend/utilities/dast/schedule.py:1 — Run now; skipped while a run is in flight; next run in IST
  "dast.profile.list": {
    what: "Your team's DAST profiles with their schedule, next run (IST) and last scan. Run now starts a new scan at once; a run is skipped while the profile's previous run is still in progress.",
    why: "Shows what runs automatically, and when.",
    example: "\"Shop staging · daily 02:00 IST · next 12 Nov 2026, 02:00 am IST\".",
  },
  // src: frontend/components/dast/DastScheduleFields.tsx:190-216, backend/utilities/dast/schemas.py:37 — the five selects write the cron expression
  "dast.profile.cron_builder": {
    what: "Pick minute, hour, day, month and weekday from lists; the builder writes the matching cron expression below. Every means any value.",
    why: "Builds a valid schedule without writing cron syntax by hand.",
    example: "Minute 0, Hour 9, Weekday Monday gives 0 9 * * 1.",
  },
  // src: backend/utilities/dast/schemas.py:46, backend/utilities/dast/credits.py:4-6, backend/utilities/dast/dispatch.py:103 — 1-10,000; every run is charged max_urls x 0.08 up front
  "dast.profile.max_urls": {
    what: "The most pages a run crawls and tests, from 1 to 10,000. An automatic run is charged Max URLs x 0.08 credits when it starts (no estimate crawl), whatever it then finds.",
    why: "It caps both how much each run tests and what each run costs.",
    example: "200 URLs: each run costs 16 credits.",
  },
  // src: backend/utilities/dast/dispatch.py:84-88, backend/utilities/dast/schemas.py:55 — runs refused without consent
  "dast.profile.consent": {
    what: "Confirms you are allowed to attack-test this target. A DAST scan sends real attack payloads; without this confirmation the profile cannot be saved or run.",
    why: "Attack-testing a site you are not allowed to test can be illegal and disrupt its owner.",
    example: "Tick it for your own staging site, never for a third-party site.",
  },
  // src: backend/utilities/dast/schedule.py:1-24, backend/utilities/dast/dispatch.py:89-90 — next_run_at computed in Asia/Kolkata; a run in flight makes the next one skip
  "dast.profile.schedule": {
    what: "When the profile runs by itself: off, hourly, every N hours, daily, weekdays, weekly, monthly, once, or a cron expression. Times are India Standard Time. A run is skipped if the previous one is still in progress.",
    why: "Regular runs catch new vulnerabilities soon after each release.",
    example: "Weekdays at 02:00 IST.",
  },
  // src: backend/utilities/dast/schemas.py:33, backend/utilities/dast/schedule.py:1 — 1 to 24 hours
  "dast.profile.interval": {
    what: "Hours between runs, from 1 to 24 (IST clock).",
    why: "Shorter intervals catch changes sooner but cost more credits.",
    example: "6 runs four times a day.",
  },
  // src: backend/utilities/dast/schemas.py:34, backend/utilities/dast/schedule.py:1 — 0-6 weekday
  "dast.profile.weekday": {
    what: "The day of the week a weekly schedule runs on (IST).",
    why: "Pick a quiet day so the scan does not load the site at peak hours.",
    example: "Sunday.",
  },
  // src: backend/utilities/dast/schemas.py:35 — 1 to 28, so every month has the day
  "dast.profile.monthday": {
    what: "The day a monthly schedule runs on, from 1 to 28 so that every month has it (IST).",
    why: "Align it with your release or patch cycle.",
    example: "1 runs on the first of each month.",
  },
  // src: backend/utilities/dast/schemas.py:36, backend/utilities/dast/schedule.py:1 — a single run at that IST time
  "dast.profile.once_at": {
    what: "The date and time (IST) of a single run.",
    why: "Lets you schedule one test, for example after a release, without staying online.",
    example: "15 Nov 2026, 23:00.",
  },
  // src: backend/utilities/dast/schemas.py:32, backend/utilities/dast/schedule.py:26-34 — HH:MM, clamped to 00:00-23:59
  "dast.profile.times": {
    what: "The times of day (24-hour HH:MM, IST) the schedule runs. You can add several.",
    why: "Choose hours when test traffic will not disturb users.",
    example: "02:00 and 14:00.",
  },
  // src: backend/utilities/dast/schemas.py:37, backend/utilities/dast/schedule.py:1 — 5-field cron evaluated in IST, 0 = Sunday
  "dast.profile.cron": {
    what: "A 5-field cron expression (minute, hour, day of month, month, day of week) evaluated in IST, with 0 = Sunday. The builder above fills it for you.",
    why: "Gives full control over complex schedules.",
    example: "0 9 * * 1-5 runs at 09:00 IST Monday to Friday.",
  },

  // ────────────────────────────────────────────────────────────── DAST: list page (app/[team_id]/dast/page.tsx)
  // src: backend/utilities/dashboard/scan_list.py:216, backend/utilities/dashboard/scan_list.py:291 — successful DAST scans
  "dast.kpi.total_scans": {
    what: "DAST scans of this team that finished successfully, manual and automatic.",
    why: "Shows how often your web applications are tested.",
    example: "A nightly profile that ran 7 times adds 7.",
  },
  // src: backend/utilities/dashboard/scan_list.py:251-256, backend/utilities/dashboard/scan_list.py:284-295 — stored findings of DAST scans by impact
  "dast.kpi.severity": {
    what: "Findings of all DAST scans with this severity (Critical, High, Medium or Low), counted from the stored findings. A finding without a severity counts as Low.",
    why: "Critical and High findings in a live application are the most urgent.",
    example: "Total high 4: four High findings across all runs.",
  },
  // src: backend/utilities/dashboard/risk_rollup.py:1-17,123-149, backend/utilities/dashboard/risk_scale.py:76-95, frontend/utils/riskPosture.ts:22-28, frontend/app/[team_id]/dast/page.tsx:275-278 — risk_rollup.team_posture: the latest successful scan per target, then risk_scale.posture over every DAST finding
  "dast.kpi.avg_risk": {
    what: "The current risk: the findings of the latest successful scan of each target URL (scheme and host in any case; path and query as typed), scored as one: 0-100: 4 × (10 per Critical, 5 per High, 2 per Medium, 1 per Low), set by the worst severity: any Critical 70+, any High 50–69, Medium at most 49, Low only 29. Grades: A <15, B 15–29, C 30–49, D 50–69, F 70+.",
    why: "One number and grade to compare web-application risk over time, as every product shows it.",
    example: "Two targets, the latest scan of each with one High: 4 × 10 = 40, raised to 50 by the High, grade D (High risk).",
  },
  // src: backend/utilities/dashboard/scan_list.py:251-256, backend/utilities/dashboard/scan_list.py:299 — totals per impact
  "dast.chart.severity": {
    what: "All DAST findings by severity: Critical, High, Medium, Low.",
    why: "Critical and High findings are the ones to fix first.",
    example: "Critical 0, High 4, Medium 9, Low 12.",
  },
  // src: backend/utilities/dashboard/scan_list.py:234-248 — successful scans' findings on the scan's creation date (UTC)
  "dast.chart.over_time": {
    what: "Findings of successful DAST scans by severity, on the day (UTC) each scan was created.",
    why: "Shows whether your applications are getting safer.",
    example: "A nightly run on 7 Nov with 2 Medium findings adds 2 to Medium on 7 Nov.",
  },
  // src: backend/utilities/dashboard/scan_list.py:88-101, backend/utilities/dashboard/scan_list.py:271-273, backend/utilities/dashboard/scan_list.py:301 — 12 categories
  "dast.chart.posture": {
    what: "Findings in 12 web-security categories: injection, XSS and client side, authentication, authorization, session and state, file and resource, server-side execution, information disclosure, crypto and transport, security headers, API security, denial of service.",
    why: "Shows which web-security areas have the most problems.",
    example: "Security headers 8: eight findings about missing or weak headers.",
  },
  // src: backend/utilities/dashboard/scan_list.py:69-80, backend/utilities/dashboard/scan_list.py:266-269, backend/utilities/dashboard/scan_list.py:302 — the ten OWASP 2021 keys
  "dast.chart.owasp": {
    what: "Findings per OWASP Top 10 (2021) category, A01 to A10. A finding mapped to two categories counts in both.",
    why: "Lets you report findings in the framework most teams and auditors use.",
    example: "A03 Injection 3, A05 Security Misconfiguration 6.",
  },
  // src: backend/utilities/dashboard/scan_list.py:81-87, backend/utilities/dashboard/scan_list.py:274-276, backend/utilities/dashboard/scan_list.py:303-306 — five categories, mean of 10/7.5/5/2.5
  "dast.chart.risk_by_category": {
    what: "The average risk score (Critical 10, High 7.5, Medium 5, Low 2.5) of the findings in five categories: injection, XSS and client side, authentication, authorization, session and state.",
    why: "Shows which kind of weakness carries the most risk.",
    example: "Injection 8.8: the injection findings are mostly Critical or High.",
  },
  // src: backend/utilities/dashboard/scan_list.py:103, backend/utilities/dashboard/scan_list.py:278-282, backend/utilities/dashboard/scan_list.py:307-310 — by the scanner's confidence; missing counts as low
  "dast.chart.risk_by_confidence": {
    what: "The average risk score of findings grouped by how sure the scanner is that each one is real: high, medium or low confidence (unknown counts as low).",
    why: "High-confidence findings are the least likely to be false positives.",
    example: "High confidence 7.5: the certain findings are mostly High.",
  },
  // src: backend/utilities/dashboard/scan_list.py:102, backend/utilities/dashboard/scan_list.py:261-264, backend/utilities/dashboard/scan_list.py:311 — references to PCI DSS, ISO 27001-27004
  "dast.chart.compliance": {
    what: "How many compliance-control references the findings have for PCI DSS and ISO 27001, 27002, 27003 and 27004.",
    why: "Shows which audit requirements your web findings touch.",
    example: "PCI DSS 5: findings map to five PCI DSS controls in total.",
  },
  // src: backend/utilities/db/scan_list_item.py:386-395 — counts per impact of a successful scan
  "dast.table.vulns": {
    what: "This scan's findings by severity: Critical (red), High (orange), Medium (amber), Low (blue). Counted once the scan succeeded.",
    why: "Shows at a glance how serious this scan's findings are.",
    example: "0 red, 1 orange, 3 amber, 5 blue.",
  },
  // src: backend/utilities/db/scan_list_item.py:440 — target_url from the settings of the scan
  "dast.table.target": {
    what: "The site this scan tested.",
    why: "Tells you which site the findings belong to.",
    example: "https://staging.shop.example.com.",
  },
  // src: backend/utilities/db/scan_list_item.py:392-402, RabbitMQ/dast_worker/helpers/crawler/crawler.py:40-71 — URLs the crawler kept for testing
  "dast.table.urls": {
    what: "How many URLs the scan tested: the pages the crawler kept after your patterns, plus the additional URLs.",
    why: "Few URLs tested means much of the site was not covered.",
    example: "48 URLs tested.",
  },
  // src: backend/utilities/db/scan_list_item.py:432, RabbitMQ/dast_worker/helpers/crawler/crawler.py:79-106 — tested / (tested + dropped by the patterns)
  "dast.table.coverage": {
    what: "Tested URLs as a share of all crawled URLs, after your include or exclude patterns dropped some. 100% when no pattern removed anything.",
    why: "Low coverage means your patterns or limits left crawled pages untested.",
    example: "45 tested, 5 excluded by a pattern: 90.0%.",
  },
} as const satisfies TipAreaText;

export default TEXT;
