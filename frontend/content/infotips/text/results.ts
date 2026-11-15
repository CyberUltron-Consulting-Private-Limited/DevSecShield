/**
 * (i) tip text of the "results" area (ids: results.*), loaded on demand by
 * content/infotips/load.ts. The label of each tip is in content/infotips/labels.ts; the rules for the text are in
 * content/infotips/index.ts (checked by content/infotips.test.ts).
 */
import type { TipAreaText } from "../types";

const TEXT = {
  // ────────────────────────────────────────────────────────────── results views, shared (components/SASTResults.tsx, SbomResults.tsx, finding-selection-menu.tsx)
  // src: backend/utilities/dashboard/scan_metadata.py:73-101, backend/utilities/dashboard/scan_metadata.py:120-124 — repo_url from the scan's settings
  "results.meta.repository": {
    what: "The address of the repository this scan cloned. Hover for the full address when it is cut short.",
    why: "Tells you which code the findings belong to.",
    example: "https://github.com/acme/payments-api.",
  },
  // src: backend/utilities/dashboard/scan_metadata.py:76-77, backend/utilities/dashboard/scan_metadata.py:122-123, RabbitMQ/worker/helpers/context/scan_context.py:89 — the branch from the scan's settings (SAST shows main when none was given)
  "results.meta.branch": {
    what: "The branch that was cloned and scanned. A zip upload or an uploaded SBOM file has no branch, so the card is not shown for them.",
    why: "Findings apply to this branch only.",
    example: "release/2026.11.",
  },
  // src: backend/utilities/dashboard/scan_metadata.py:75, backend/utilities/dashboard/scan_metadata.py:13, frontend/components/SbomResults.tsx:1104 — zip_file_used, sbom_file_used (SCA + SBOM), else a repository
  "results.meta.source": {
    what: "Where the scanned input came from: a repository that was cloned, a ZIP upload, or (SCA + SBOM only) an SBOM file you uploaded.",
    why: "Tells you where the scanned input came from.",
    example: "ZIP upload for a scan started from payments-api.zip.",
  },
  // src: backend/utilities/db/findings.py:29-42, backend/utilities/celery/create_findings.py:10-48, backend/routers/scans.py:1203-1254 — the scan's stored findings, one per row, each with a status the team sets
  "results.findings": {
    what: "This scan's findings, one per row, each with a status your team sets. Click a title for the details; select rows to file Jira tickets; use Action to set a finding's status.",
    why: "Each row is something to fix, accept or track.",
    example: "\"SQL injection in orders.py\", High, Not started.",
  },
  // src: frontend/components/SASTResults.tsx:1083, frontend/components/SbomResults.tsx:1189 — exact match on the finding's impact
  "results.filter.impact": {
    what: "Shows only the findings of one impact (severity): Critical, High, Medium or Low. It filters the findings already loaded in this page.",
    why: "Focuses the table on the most serious findings.",
    example: "Choose Critical to see only the Critical findings.",
  },
  // src: frontend/components/SASTResults.tsx:793-798,1164, frontend/components/SbomResults.tsx:844-850,1272, backend/routers/scans.py:1151-1174 — selects the rows shown (after search and filters); the selection menu files them in Jira
  "results.select_all": {
    what: "Selects every finding the table shows (after search and filters). The selected findings can then be filed in Jira from the Actions menu above the table.",
    why: "Lets you act on a whole group of findings at once.",
    example: "Filter Impact to Critical, select all, then Actions > Create Jira ticket.",
  },
  // src: backend/routers/scans.py:1203-1254, backend/utilities/db/finding_state.py:20-35, backend/utilities/dashboard/remediation_metrics.py:17-90 — fixed sets fixed_at and closes the Jira issue; ignored sets ignored_at; the remediation metrics read these
  "results.finding.action": {
    what: "Sets a finding's status. Fixed records when it was fixed and closes its Jira issue, if it has one. Ignored records when it was dismissed. In progress and Not started only change the status. The remediation metrics are computed from these statuses.",
    why: "Statuses drive the remediation metrics and close linked Jira issues.",
    example: "Mark a false positive Ignored: it leaves the high-priority backlog.",
  },
  // src: backend/new_models.py:131, backend/utilities/db/schemas.py:15-17, backend/routers/scans.py:1230-1249 — finding_status not_started (new), in_progress, fixed, ignored
  "results.table.status": {
    what: "The status your team set on this finding: Not started (every finding starts here), In progress, Fixed or Ignored. Change it with Action.",
    why: "Shows what the team decided about each finding.",
    example: "In progress while a fix is in review.",
  },
  // src: RabbitMQ/worker/helpers/context/schema.py:18, backend/utilities/db/findings.py:87-105, backend/utilities/db/findings.py:129-153 — impact as stored with the finding
  "results.table.impact": {
    what: "The severity the scan's analysis gave this finding: Critical, High, Medium or Low.",
    why: "Fix Critical and High first.",
    example: "High for a vulnerable dependency with a known remote exploit.",
  },
  // src: frontend/components/SASTResults.tsx:650-655,1172, frontend/components/SbomResults.tsx:150-155,1282 — number of entries in the finding's owasp_top_10
  "results.table.owasp": {
    what: "How many OWASP Top 10 categories this finding maps to. Click the title to see which.",
    why: "Lets you report findings in the OWASP framework.",
    example: "1: A03:2021 Injection.",
  },
  // src: frontend/components/SASTResults.tsx:650-655,1173, frontend/components/SbomResults.tsx:150-155,1283 — number of entries in the finding's compliance_controls
  "results.table.compliance": {
    what: "How many compliance controls (for example PCI DSS requirements or ISO 27001 clauses) this finding maps to. Click the title to see which.",
    why: "Shows which audit requirements a finding touches.",
    example: "3: PCI DSS 6.2.4, ISO 27001 A.8.28 and ISO 27002 8.28.",
  },
  // src: frontend/components/finding-selection-menu.tsx:44-119, backend/routers/scans.py:1122-1174 — one Jira issue per selected stored finding (a finding with an issue keeps it); needs a successful scan, the scan's Jira project and the team's Jira connection
  "results.selection.actions": {
    what: "Acts on the selected findings. Create Jira ticket files one Jira issue per finding in the project set on this scan's Ticketing integrations tab; a finding that already has an issue is not filed again. Some results pages also set the status of all selected findings here.",
    why: "Turns selected findings into tracked work in one step.",
    example: "Select 3 Critical findings, Create Jira ticket: 3 issues in project SEC.",
  },
} as const satisfies TipAreaText;

export default TEXT;
