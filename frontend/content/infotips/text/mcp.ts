/**
 * (i) tip text of the "mcp" area (ids: mcp.*), loaded on demand by
 * content/infotips/load.ts. The label of each tip is in content/infotips/labels.ts; the rules for the text are in
 * content/infotips/index.ts (checked by content/infotips.test.ts).
 */
import type { TipAreaText } from "../types";

const TEXT = {
  // ────────────────────────────────────────────────────────────── MCP: scan configuration (components/mcp-options-sidebar.tsx)
  // src: backend/utilities/db/schemas.py:159-169, RabbitMQ/worker/helpers/tools/mcp_agent/context.py:5-9 — the MCP server endpoint the worker connects to
  "mcp.cfg.server_url": {
    what: "The address of the MCP (Model Context Protocol) server to test. The scan connects to it, lists its tools, prompts and resources, and checks each one for risks such as prompt injection or dangerous capabilities.",
    why: "The scan tests only this server, so the address sets what is checked.",
    example: "https://mcp.example.com/mcp.",
  },
  // src: backend/utilities/db/schemas.py:161, RabbitMQ/worker/helpers/tools/mcp_agent/context.py:7 — httpstreamable or sse
  "mcp.cfg.server_mode": {
    what: "The transport the server speaks: Streamable HTTP (the current MCP standard) or SSE (Server-Sent Events, the older one). Pick what the server documents.",
    why: "The wrong transport means the scan cannot talk to the server.",
    example: "Streamable HTTP for a server whose endpoint ends in /mcp.",
  },
  // src: backend/utilities/db/schemas.py:163, backend/utilities/dashboard/scan_list.py:1326-1329 — a label used by the Environment Risk Analysis chart
  "mcp.cfg.environment": {
    what: "Which environment the server belongs to: Development, Staging or Production. A label for the dashboard's Environment Risk Analysis; it does not change the tests.",
    why: "Lets you tell production servers from test ones in charts.",
    example: "Production for the server your agents use live.",
  },
  // src: backend/utilities/db/schemas.py:162, RabbitMQ/worker/helpers/tools/mcp_agent/context.py:8-9 — JSON object of HTTP headers sent with every request
  "mcp.cfg.headers": {
    what: "Extra HTTP headers sent with every request to the server, as a JSON object, typically for authentication.",
    why: "Servers that require authentication refuse the scan without them.",
    example: "{\"Authorization\": \"Bearer <token>\"}.",
  },
  // src: RabbitMQ/worker/helpers/tools/mcp_agent/main.py:253-285, backend/utilities/scan/estimate_scan.py:210 — connects now; 0.005 credits per tool, prompt and resource
  "mcp.cfg.estimate": {
    what: "Connects to the server now, lists its tools, prompts and resources, and prices each at 0.005 credits, rounded to 0.01. Nothing is charged until you start the scan.",
    why: "Shows the price before any credits are charged; it connects to the server now.",
    example: "40 tools, 4 prompts, 6 resources: 0.25 credits.",
  },

  // ────────────────────────────────────────────────────────────── MCP: list page (app/[team_id]/mcp/page.tsx)
  // src: backend/utilities/dashboard/scan_list.py:1371 — every MCP scan in any status
  "mcp.kpi.total_scans": {
    what: "All MCP scans of this team, in any status.",
    why: "Shows how much MCP testing your team has done.",
    example: "8 scans: 6 succeeded, 1 running, 1 failed.",
  },
  // src: backend/utilities/dashboard/scan_list.py:1320-1325, backend/utilities/dashboard/scan_list.py:1372 — critical findings of all scans
  "mcp.kpi.critical": {
    what: "Findings rated Critical across the tools, prompts and resources of all MCP scans.",
    why: "Critical MCP issues can let an AI agent act beyond its intended reach.",
    example: "A tool that runs shell commands from model input.",
  },
  // src: backend/utilities/dashboard/scan_list.py:1346-1349, backend/utilities/dashboard/scan_list.py:1368 — each finding weight/4*10, averaged
  "mcp.kpi.avg_risk": {
    what: "Average over all MCP findings, 0 to 10: Critical counts 10, High 7.5, Medium 5, Low 2.5.",
    why: "One number to compare MCP risk over time.",
    example: "One Critical and one Medium: 7.5.",
  },
  // src: backend/utilities/dashboard/scan_list.py:1293-1294, backend/utilities/dashboard/scan_list.py:1369 — status started
  "mcp.kpi.active": {
    what: "MCP scans a worker is running now.",
    why: "Results for these scans are not complete yet.",
    example: "2 while two servers are being tested.",
  },
  // src: backend/utilities/dashboard/scan_list.py:1243-1248, backend/utilities/dashboard/scan_list.py:1375 — findings marked fixed in the last 7 x 24 h
  "mcp.kpi.resolved": {
    what: "MCP findings marked Fixed in the last 7 days (the last 168 hours). Ignored findings are not counted.",
    why: "Shows whether the team is fixing what scans find.",
    example: "5 findings fixed this week.",
  },
  // src: backend/utilities/dashboard/scan_list.py:1291-1300 — started / success / failure; everything else (incl. pending) counts as not started
  "mcp.chart.status": {
    what: "MCP scans by status: Started, Success, Failure, and Not started (which also counts queued and cancelled scans).",
    why: "Failures or stuck scans point to connection or setup problems.",
    example: "6 Success, 1 Started, 1 Failure.",
  },
  // src: backend/utilities/dashboard/scan_list.py:1348-1351, backend/routers/scans.py:88 — per server: average of weight/4*10; scans come newest first, so the earliest scan's value is kept
  "mcp.chart.risk_trend": {
    what: "For each MCP server, the average risk score (0 to 10: Critical 10, High 7.5, Medium 5, Low 2.5) of its scan's findings. A server scanned several times shows one value, from its earliest scan (the list is read newest first and later rows overwrite).",
    why: "Shows which servers are getting riskier.",
    example: "mcp.example.com 6.3.",
  },
  // src: backend/utilities/dashboard/scan_list.py:1352-1356 — findings by severity on the scan's creation date (UTC)
  "mcp.chart.risks_over_time": {
    what: "MCP findings by severity, on the day (UTC) each scan was created.",
    why: "Shows whether MCP risk is growing or shrinking.",
    example: "A scan created on 9 Nov with 3 High findings adds 3 to High on 9 Nov.",
  },
  // src: backend/utilities/dashboard/scan_list.py:1307-1325 — totals per impact
  "mcp.chart.severity": {
    what: "All MCP findings by severity: Critical, High, Medium, Low.",
    why: "Critical and High findings are the ones to fix first.",
    example: "Critical 1, High 5, Medium 9, Low 2.",
  },
  // src: backend/utilities/dashboard/scan_list.py:1326-1329 — findings counted by the scan's environment label
  "mcp.chart.environment": {
    what: "How many findings come from servers labelled Development, Staging or Production (the environment chosen when each scan was configured).",
    why: "Production findings matter most because real users and data are involved.",
    example: "Production 7 means seven findings on production servers.",
  },
  // src: backend/utilities/dashboard/scan_list.py:1330-1345 — compliance-control references per standard
  "mcp.chart.compliance": {
    what: "How many compliance-control references the MCP findings have per standard.",
    why: "Shows which standards your MCP findings touch.",
    example: "ISO 27001 9, PCI DSS 3.",
  },
  // src: backend/utilities/dashboard/scan_list.py:1378, backend/utilities/dashboard/finding_metrics.py:18-40 — stored findings by status
  "mcp.chart.remediation": {
    what: "MCP findings by the status your team set: Not started, In progress, Fixed, Ignored.",
    why: "Shows how far the team has got with fixing.",
    example: "Fixed 5, Not started 12.",
  },
  // src: backend/utilities/dashboard/scan_list.py:1256-1259, backend/utilities/dashboard/scan_list.py:1286-1289, backend/utilities/dashboard/scan_list.py:1346-1347 — by the resource category of each finding
  "mcp.chart.asset_category": {
    what: "Findings by what the affected tool, prompt or resource gives access to: web, file system, code execution, database, search, vector store, document store.",
    why: "Tools that reach files, code or the network are the most dangerous to misuse.",
    example: "Code execution 3: three findings on tools that can run code.",
  },
  // src: backend/utilities/dashboard/scan_list.py:1357-1359, RabbitMQ/worker/scan_worker.py:157-164 — duration_of_scan per server
  "mcp.chart.duration": {
    what: "How long each server's MCP scan took, in seconds, from the worker starting to results. A server scanned several times shows its earliest scan.",
    why: "A sudden change can signal a server that grew or misbehaves.",
    example: "mcp.example.com 95.",
  },
  // src: backend/utilities/dashboard/scan_list.py:1261-1264, backend/utilities/dashboard/scan_list.py:1348-1349, backend/utilities/dashboard/scan_list.py:1363-1366 — average weight/4*10 per category
  "mcp.chart.posture": {
    what: "The average risk score (0 to 10: Critical 10, High 7.5, Medium 5, Low 2.5) of the findings in each asset category; 0 where there are none.",
    why: "Shows which areas carry the most risk.",
    example: "File system 8.8: its findings are mostly Critical or High.",
  },
  // src: backend/utilities/dashboard/finding_metrics.py:89-125, backend/utilities/dashboard/scan_list.py:1379-1380 — per resolution date
  "mcp.chart.mttr": {
    what: "For each day (UTC), the average time between a finding being recorded and being marked Fixed or Ignored, for the findings resolved that day.",
    why: "Shows whether fixes are getting faster.",
    example: "Two findings fixed on 8 Nov after 1 and 3 days: 2 days on 8 Nov.",
  },
  // src: backend/utilities/dashboard/scan_list.py:1389-1400 — per scan date: findings and those marked ignored
  "mcp.chart.effectiveness": {
    what: "Per scan date, the findings the scans produced and how many of them your team marked Ignored (treated as false positives).",
    why: "Many ignored findings can mean noisy results that need tuning.",
    example: "10 findings on 5 Nov, 2 ignored.",
  },
  // src: backend/utilities/dashboard/scan_list.py:1382-1388 — 100 minus the framework's share of that day's references
  "mcp.chart.compliance_trend": {
    what: "Per scan date and standard: 100 minus that standard's share of the day's compliance-control references. A relative measure, not an audit score.",
    why: "Shows whether compliance is improving over time.",
    example: "PCI DSS has 3 of 10 references on 5 Nov: 70.",
  },
  // src: backend/utilities/dashboard/scan_list.py:1401-1420 — resolved findings by days from creation to fixed/ignored, 30-day buckets
  "mcp.chart.age": {
    what: "Resolved findings (Fixed or Ignored) grouped by how many days they stayed open, in 30-day buckets up to 210 days. Open findings are not shown.",
    why: "Findings that stayed open long show where fixing is slow.",
    example: "A finding fixed after 45 days counts in 30-60 days.",
  },
  // src: backend/utilities/db/scan_list_item.py:282 — host part of the server URL
  "mcp.table.server": {
    what: "A short name for the MCP server, taken from its URL's host.",
    why: "Tells you which server the findings belong to.",
    example: "example for https://mcp.example.com.",
  },
  // src: backend/utilities/db/scan_list_item.py:205-266, backend/utilities/db/scan_list_item.py:556-559, backend/utilities/dashboard/risk_scale.py:16,25-31, frontend/app/[team_id]/mcp/page.tsx:1007-1011,949 — the mean of 10/7.5/5/2.5 per finding, one decimal (the app's one 0-10 scale, risk_scale, #35); 0 without findings
  "mcp.table.risk": {
    what: "This scan's severity-weighted average, 0 to 10, on the same scale as the dashboard: Critical 10, High 7.5, Medium 5, Low 2.5, averaged over its findings and rounded to one decimal. 0 when it found nothing or did not succeed.",
    why: "Lets you compare scans by overall severity.",
    example: "1 High and 1 Low finding: (7.5 + 2.5) / 2 = 5.0.",
  },
  // src: backend/utilities/db/scan_list_item.py:204-215, backend/utilities/db/scan_list_item.py:284-289 — tools, prompts and resources the server exposed
  "mcp.table.discovery": {
    what: "What the scan found on the server: T tools, P prompts, R resources.",
    why: "Shows how much the server exposes to an AI agent.",
    example: "T: 40 P: 4 R: 6.",
  },
  // src: backend/utilities/db/scan_list_item.py:249-261 — tools/prompts/resources rated high or critical
  "mcp.table.risky": {
    what: "Tools, prompts and resources the scan rated High or Critical risk.",
    why: "These are the tools, prompts or resources to review first.",
    example: "3: two tools and one resource.",
  },
  // src: backend/utilities/db/scan_list_item.py:217-245 — counts per impact of a successful scan
  "mcp.table.vulns": {
    what: "This scan's findings by severity: Critical (red), High (orange), Medium (amber), Low (blue). Counted once the scan succeeded.",
    why: "Shows at a glance how serious this scan's findings are.",
    example: "1 red, 2 orange, 0 amber, 4 blue.",
  },
} as const satisfies TipAreaText;

export default TEXT;
