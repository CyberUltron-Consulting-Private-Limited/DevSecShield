/**
 * (i) tip text of the "team" area (ids: team.*), loaded on demand by
 * content/infotips/load.ts. The label of each tip is in content/infotips/labels.ts; the rules for the text are in
 * content/infotips/index.ts (checked by content/infotips.test.ts).
 */
import type { TipAreaText } from "../types";

const TEXT = {
  // ────────────────────────────────────────────────────────────── Team dashboard (app/[team_id]/page.tsx, backend/utilities/dashboard/team.py)
  // src: backend/utilities/dashboard/team.py:86-97, backend/utilities/dashboard/team.py:113-134 — every scan of the team plus its CBOM Sources runs
  "team.section.activity": {
    what: "Scans of every product in this team, plus CBOM Sources collection runs, counted together.",
    why: "Shows how actively the team is testing across products.",
    example: "A SAST scan and a CBOM Sources run both count as one scan each.",
  },
  // src: backend/utilities/dashboard/team.py:173-190 — stored findings of all scans + Sources findings not already found by a code scan
  "team.kpi.findings": {
    what: "Findings stored for all scans of this team, in any product, plus CBOM Sources findings that no code scan already reported.",
    why: "Sizes the team's total security backlog.",
    example: "40 SAST + 12 SCA + 8 CBOM findings: 60.",
  },
  // src: backend/utilities/dashboard/team.py:13, backend/utilities/dashboard/team.py:114-134, backend/utilities/dashboard/team.py:196 — STARTED/RETRY scans + running Sources runs
  "team.kpi.started": {
    what: "Scans running now (started or retrying), plus CBOM Sources runs in progress.",
    why: "Results for these are not complete yet.",
    example: "2 while a DAST scan and a Sources run are working.",
  },
  // src: backend/utilities/dashboard/team.py:13, backend/utilities/dashboard/team.py:114-134, backend/utilities/dashboard/team.py:197 — SUCCESS scans + done/partial Sources runs
  "team.kpi.completed": {
    what: "Scans that finished successfully, plus CBOM Sources runs that finished (fully or partly).",
    why: "Shows how many scans and runs produced results.",
    example: "30 completed scans across all products.",
  },
  // src: backend/utilities/dashboard/team.py:13, backend/utilities/dashboard/team.py:114-134, backend/utilities/dashboard/team.py:198 — NOT_STARTED/PENDING scans + queued Sources runs
  "team.kpi.not_started": {
    what: "Scans created but not running yet (never started, or queued for a worker), plus queued CBOM Sources runs.",
    why: "Scans that never ran give no coverage.",
    example: "A scan you created and never estimated counts here.",
  },
  // src: backend/utilities/dashboard/team.py:174-177, backend/utilities/dashboard/team.py:190 — status fixed (or a fixed date) + Sources findings whose remediation is done
  "team.kpi.fixed": {
    what: "Findings your team marked Fixed, plus CBOM Sources findings whose remediation is done.",
    why: "Shows how much of the backlog the team has closed.",
    example: "15 of 60 findings fixed.",
  },
  // src: backend/utilities/dashboard/team.py:191-193 — fixed / total * 100
  "team.kpi.remediation": {
    what: "Fixed findings as a percentage of all findings of the team.",
    why: "One number for how much of what was found has been fixed.",
    example: "15 fixed of 60: 25.0%.",
  },
  // src: backend/utilities/dashboard/team.py:226-236 — scans created in the last 30 days by type; Sources runs count as CBOM
  "team.chart.activity": {
    what: "Scans created in the last 30 days, per product (SAST, SCA + SBOM, IaC, DAST, CBOM, AI BOM, MCP, LLM). CBOM Sources runs count as CBOM.",
    why: "Shows which products the team uses, and which it neglects.",
    example: "SAST 12, DAST 4, CBOM 3.",
  },
  // src: backend/utilities/dashboard/team.py:237-290 — high and critical findings of scans created in the last 30 days
  "team.chart.severity30": {
    what: "High and Critical findings of the scans created in the last 30 days (Medium and Low are not counted here). A CBOM asset seen twice counts once.",
    why: "Shows the serious findings of the last month at a glance.",
    example: "Critical 3, High 17.",
  },
  // src: backend/utilities/dashboard/team.py:199-205, frontend/app/[team_id]/page.tsx:463 — scans by creation date
  "team.chart.daily": {
    what: "How many scans the team created each day, all products together, in any status.",
    why: "Shows how regularly the team scans.",
    example: "7 scans on 10 Nov.",
  },
  // src: backend/utilities/dashboard/team.py:13, backend/utilities/dashboard/team.py:114-134 — four buckets over scans and Sources runs
  "team.chart.status": {
    what: "All scans and CBOM Sources runs by state: Not started (including queued), Running (including retrying), Completed, Failed.",
    why: "Failures or stuck scans point to setup or capacity problems.",
    example: "Completed 30, Failed 2, Running 1.",
  },
  // src: backend/utilities/dashboard/team.py:135-170 — findings of all products and their status changes over time
  "team.section.findings": {
    what: "Findings of all products and what your team did with them, day by day (dates in UTC).",
    why: "Finding issues matters only if they get fixed; this shows the trend.",
    example: "A spike of fixes after a remediation sprint.",
  },
  // src: backend/utilities/dashboard/team.py:141-163 — per day: findings created (by current status), plus fixes and ignores on their own dates
  "team.chart.remediations_per_day": {
    what: "For each day: the findings recorded that day by their current status, plus the findings marked Fixed and Ignored that day.",
    why: "Shows whether fixing keeps pace with finding.",
    example: "10 Nov: 8 new (5 Not started, 3 In progress), 4 fixed.",
  },
  // src: backend/utilities/dashboard/team.py:150-153 — by creation date
  "team.chart.findings_per_day": {
    what: "How many findings were recorded each day, across all products.",
    why: "Spikes usually follow new scans or new code.",
    example: "25 findings on the day a large SAST scan finished.",
  },
  // src: backend/utilities/dashboard/team.py:157-159 — by fixed date
  "team.chart.fixes_per_day": {
    what: "How many findings were marked Fixed each day.",
    why: "Shows the team's fixing rhythm.",
    example: "6 fixes on 9 Nov.",
  },
  // src: backend/utilities/dashboard/team.py:160-162 — by ignored date
  "team.chart.false_positives": {
    what: "How many findings were marked Ignored each day: the findings your team judged false positives or accepted risks.",
    why: "Many ignored findings may point to noisy scan settings.",
    example: "3 ignored on 8 Nov.",
  },
  // src: backend/utilities/dashboard/team.py:89, frontend/app/[team_id]/page.tsx:821-834 — CI/CD integrations by creation date
  "team.section.integrations": {
    what: "CI/CD integrations your team created, by creation date.",
    why: "Shows which pipelines scan automatically.",
    example: "2 integrations created on 1 Nov.",
  },
} as const satisfies TipAreaText;

export default TEXT;
