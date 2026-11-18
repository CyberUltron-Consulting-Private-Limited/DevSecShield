/**
 * (i) tip text of the "iac" area (ids: iac.*), loaded on demand by
 * content/infotips/load.ts. The label of each tip is in content/infotips/labels.ts; the rules for the text are in
 * content/infotips/index.ts (checked by content/infotips.test.ts).
 */
import type { TipAreaText } from "../types";

const TEXT = {
  // ────────────────────────────────────────────────────────────── IaC: scan configuration (components/iac-options-sidebar.tsx)
  // src: RabbitMQ/worker/helpers/tools/iac_agent/main.py:56-88, RabbitMQ/worker/helpers/context/codebase_context.py:59-93, RabbitMQ/worker/helpers/context/codebase_context.py:119-170, RabbitMQ/worker/helpers/context/codebase_context.py:245-250 — no pattern: every file of the formats; patterns and extensions of all formats are merged; the path inside the repository, every name, whole names at any depth, * and a ** name are globs (#37, #45)
  "iac.cfg.include": {
    what: "Only files of this format whose path inside the repository matches a pattern are analysed. A pattern is one or more whole folder or file names, one per box, at any depth; * stands for any characters within a name, a box holding ** for any number of folders. No pattern means every file of the format, but the patterns of all formats in the scan are combined: next to Terraform, give each other format a pattern.",
    why: "Files that match no pattern are not analysed, so a wrong pattern hides misconfigurations.",
    example: "\"charts\" includes every charts folder; \"deploy\" / \"k8s\" includes deploy/k8s; \"k8s*\" also includes k8s-prod.",
  },

  // ────────────────────────────────────────────────────────────── IaC: scan configuration (components/iac-options-sidebar.tsx)
  // src: backend/utilities/dashboard/scan_list.py:541-557, backend/utilities/db/scan_list_item.py:148 — stored as a label; the worker does not read it
  "iac.cfg.environment": {
    what: "Which environment this infrastructure code is for: Development, Staging or Production. It is a label for your dashboards (the environment filter and heatmap); it does not change what the scan checks.",
    why: "Lets you tell production findings from test ones in lists and charts.",
    example: "Production for the Terraform that deploys your live VPC.",
  },
  // src: RabbitMQ/worker/helpers/tools/iac_agent/main.py:56-82 — one mode per context; each mode reads its file types
  "iac.cfg.contexts": {
    what: "The kinds of infrastructure code in the repository, one context each. Each kind reads its own files: Terraform .tf/.tfvars/.tfstate/.tf.json, Kubernetes and Helm .yaml/.yml, Ansible .yml/.yaml/.ini, CloudFormation .yaml/.yml/.json, Pulumi and CDK their program files.",
    why: "Each format is read only if it has a context, so a missing one is a blind spot.",
    example: "A repository with Terraform and Helm charts: add both contexts.",
  },
  // src: RabbitMQ/worker/helpers/tools/iac_agent/main.py:56-88, RabbitMQ/worker/helpers/context/codebase_context.py:245-250 — the format decides the extensions; Terraform adds its own .tf patterns; the other formats' include patterns narrow their files (merged across formats: see iac.cfg.include)
  "iac.cfg.context_type": {
    what: "The infrastructure format of this context; it decides which file extensions are read. Terraform needs no pattern: its files are found by extension anywhere. For the other formats, the include patterns below narrow which files are read.",
    why: "The format decides which files are read.",
    example: "Kubernetes, with the include pattern \"k8s\".",
  },
  // src: RabbitMQ/worker/helpers/tools/iac_agent/main.py:207-227, backend/utilities/scan/estimate_scan.py:210 — 1 credit per 0.5 MB of matched files, rounded to 0.01
  "iac.cfg.estimate": {
    what: "Measures the infrastructure files the contexts match and prices the scan at 2 credits per MB, rounded to 0.01. Nothing is charged until you start the scan.",
    why: "Shows the price before any credits are charged.",
    example: "400 KB of Terraform: about 0.78 credits.",
  },

  // ────────────────────────────────────────────────────────────── IaC: list page (app/[team_id]/iac/page.tsx)
  // src: backend/utilities/dashboard/scan_list.py:575 — successful IaC scans
  "iac.kpi.total_scans": {
    what: "IaC scans of this team that finished successfully.",
    why: "Shows how much of your infrastructure code has been checked.",
    example: "12 scans run, 2 failed: 10.",
  },
  // src: backend/utilities/dashboard/scan_list.py:456-480, backend/utilities/dashboard/scan_list.py:576 — findings of successful scans
  "iac.kpi.total_issues": {
    what: "Misconfigurations found by all successful IaC scans, added up.",
    why: "Sizes the misconfiguration backlog.",
    example: "An S3 bucket without encryption is one issue.",
  },
  // src: backend/utilities/dashboard/scan_list.py:466-478, backend/utilities/dashboard/scan_list.py:577 — impact critical
  "iac.kpi.critical": {
    what: "Of those, the issues rated Critical.",
    why: "Critical misconfigurations, such as public storage, are the first to fix.",
    example: "A security group open to 0.0.0.0/0 on SSH.",
  },
  // src: backend/utilities/dashboard/scan_list.py:564-569, backend/utilities/dashboard/remediation_metrics.py:43-80 — mean of fixed/ignored time minus creation, in days
  "iac.kpi.mttr": {
    what: "Mean time to remediate: the average time, in days, from when an issue was recorded to when it was marked Fixed or Ignored.",
    why: "A long time to fix leaves misconfigurations deployed.",
    example: "One issue fixed after 1 day and one after 3 days: 2.0.",
  },
  // src: backend/utilities/dashboard/scan_list.py:509-518, backend/utilities/dashboard/scan_list.py:570 — per scan included / (included + excluded) files, averaged
  "iac.kpi.coverage": {
    what: "For each successful scan, the share of candidate files that were analysed (analysed divided by analysed plus excluded), averaged over the scans.",
    why: "Low coverage means some infrastructure files were not checked.",
    example: "Two scans with 100% and 80%: 90.0%.",
  },
  // src: backend/utilities/dashboard/scan_list.py:493-507, backend/utilities/dashboard/scan_list.py:580 — compliance-control references with a standard
  "iac.kpi.policy": {
    what: "How many compliance-control references (PCI DSS, ISO 27001 and others) the issues map to, added up.",
    why: "Shows how many audit requirements the misconfigurations touch.",
    example: "One issue mapped to 2 controls: 2.",
  },
  // src: backend/utilities/dashboard/scan_list.py:520-526, backend/utilities/dashboard/scan_list.py:571 — 0-10, weights 4/3/2/1, averaged over issues
  "iac.kpi.avg_risk": {
    what: "Severity-weighted average of all issues of successful scans, from 0 to 10: Critical 4, High 3, Medium 2, Low 1, the average weight divided by 4 and multiplied by 10.",
    why: "One number to compare infrastructure risk over time.",
    example: "Half Critical, half Low: (4+1)/2 = 2.5, so 6.3.",
  },
  // src: backend/utilities/dashboard/scan_list.py:466-478, backend/utilities/dashboard/scan_list.py:584-589 — totals per impact
  "iac.chart.severity": {
    what: "Issues of successful IaC scans by severity: Critical, High, Medium and Low.",
    why: "Critical and High issues are the ones to fix first.",
    example: "Critical 1, High 6, Medium 10, Low 3.",
  },
  // src: backend/utilities/dashboard/scan_list.py:464, backend/utilities/dashboard/scan_list.py:482-486 — per creation date (UTC)
  "iac.chart.over_time": {
    what: "Issues of successful scans by severity, on the day (UTC) each scan was created.",
    why: "Shows whether misconfigurations are growing or shrinking.",
    example: "A scan created on 4 Nov with 3 High issues adds 3 to High on 4 Nov.",
  },
  // src: backend/utilities/dashboard/scan_list.py:488-491, backend/utilities/dashboard/scan_list.py:593-606 — issues per category; the six categories always shown
  "iac.chart.posture": {
    what: "Issues per security category: Network Security, Data Protection, Access Control, Logging and Monitoring, Secret Management, Audit and Compliance (and any other category found).",
    why: "Shows which security areas have the most problems.",
    example: "Network Security 7 means seven issues about firewalls, ports or routing.",
  },
  // src: backend/utilities/dashboard/scan_list.py:615-622, backend/utilities/dashboard/finding_metrics.py:18-40 — stored findings by status
  "iac.chart.pipeline": {
    what: "Issues by the status your team set on them: Fixed, In progress, Not started, Ignored, each as a share of all issues found.",
    why: "Shows how far the team has got with fixing issues.",
    example: "20 issues, 5 marked Fixed: Fixed 25%.",
  },
  // src: backend/utilities/dashboard/scan_list.py:493-507, backend/utilities/dashboard/scan_list.py:609, frontend/app/[team_id]/iac/page.tsx:469 — references per standard, share of all references
  "iac.chart.compliance": {
    what: "How many compliance-control references the issues have per standard, and that standard's share of all references. It is not a pass rate.",
    why: "Shows which standards your infrastructure issues affect most.",
    example: "PCI DSS 6 of 10 references: 60.0%.",
  },
  // src: backend/utilities/dashboard/scan_list.py:541-562 — successful scans with results counted per (environment, IaC type)
  "iac.chart.heatmap": {
    what: "How many successful scans covered each IaC type (rows) in each environment (columns). The environment is the one chosen when the scan was configured.",
    why: "Shows which environments and formats are scanned, and which are not.",
    example: "Kubernetes × production = 3: three production scans had a Kubernetes context.",
  },
  // src: backend/utilities/dashboard/finding_metrics.py:89-125, backend/utilities/dashboard/scan_list.py:624-625 — per resolution date, average time to fix or ignore
  "iac.chart.mttr_per_day": {
    what: "For each day (UTC), the average time to remediate of the issues marked Fixed or Ignored that day, in days.",
    why: "Shows whether fixes are getting faster or slower.",
    example: "Two issues fixed on 6 Nov after 1 and 2 days: 1.5 on 6 Nov.",
  },
  // src: backend/utilities/dashboard/scan_list.py:528-539 — one count per scan and IaC type, not per resource
  "iac.chart.providers": {
    what: "How many successful scans included each IaC type (Terraform, Kubernetes, Helm, …). It counts scans per type, not individual cloud resources.",
    why: "Shows which infrastructure formats your scans cover.",
    example: "Terraform 8, Kubernetes 3.",
  },
  // src: frontend/app/[team_id]/iac/page.tsx:715-718,874, backend/utilities/db/scan_list_item.py:148 — matches the scan's environment label
  "iac.filter.environment": {
    what: "Shows only scans configured for one environment: Development, Staging or Production.",
    why: "Separates production results from development and staging.",
    example: "Production lists only scans labelled Production.",
  },
  // src: backend/utilities/db/scan_list_item.py:145 — the IaC context types of the scan
  "iac.table.provider": {
    what: "The IaC types this scan read (its contexts), such as Terraform or Kubernetes.",
    why: "Tells you which infrastructure formats this scan covered.",
    example: "terraform, helm.",
  },
  // src: backend/utilities/db/scan_list_item.py:148 — environment label from the scan's settings
  "iac.table.environment": {
    what: "The environment chosen when the scan was configured. It is a label only.",
    why: "Tells you which environment the results apply to.",
    example: "staging.",
  },
  // src: backend/utilities/db/scan_list_item.py:94-109 — counts per impact of a successful scan
  "iac.table.vulns": {
    what: "This scan's issues by severity: Critical (red), High (orange), Medium (amber), Low (blue). Counted once the scan succeeded.",
    why: "Shows at a glance how serious this scan's issues are.",
    example: "1 red, 2 orange, 4 amber, 0 blue.",
  },
} as const satisfies TipAreaText;

export default TEXT;
