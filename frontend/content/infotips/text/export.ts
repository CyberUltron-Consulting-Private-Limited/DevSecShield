/**
 * (i) tip text of the "export" area (ids: export.*): the PDF export dialog (components/reports/ExportPdfDialog.tsx) of
 * every scan type, of a CBOM Sources run and the deliverables' cover options. Loaded on demand by
 * content/infotips/load.ts. The options are the contract of backend/utilities/pdf/report_options.py (mirrored and
 * parity-tested in frontend/utils/reportOptions.ts); a word that means something else in a run report has its own id.
 */
import type { TipAreaText } from "../types";

const TEXT = {
  // ────────────────────────────────────────────────────────────── The dialog
  // src: backend/utilities/pdf/report_options.py:1-12, backend/utilities/pdf/report_options.py:53-58 — no option: today's report; a key the family does not take is refused (422)
  "export.dialog": {
    what: "Chooses what this PDF report holds: a preset or your own sections, which severities and finding statuses, a client name and title for the cover, the classification label and whether code snippets are printed. The Full preset with every severity and status ticked downloads the full report, exactly as before; the preset, sections, label and snippet switch you used last are remembered in this browser.",
    why: "A client or a board often needs a shorter, filtered or labelled report; a filtered PDF says so on its first page and in its footer.",
    example: "Executive preset, Critical and High only, prepared for Acme Bank.",
  },
  // src: backend/utilities/pdf/report_options.py:53-57, frontend/utils/reportOptions.ts:280-295 — deliverables take prepared_for and label only; the name is kept for this page session only
  "export.dialog.deliverable": {
    what: "Sets the cover of the team-wide deliverables you download from this menu next: who they are prepared for and their classification label. The label is remembered in this browser; the client name is kept only until you leave or reload the page.",
    why: "The ten deliverables are usually downloaded one after another for one client, so their cover options are set once instead of per document.",
    example: "Prepared for Acme Bank, label Restricted, then download #1 to #10.",
  },

  // ────────────────────────────────────────────────────────────── Preset and sections
  // src: backend/utilities/pdf/report_options.py:30-42, backend/utilities/pdf/report_options.py:43-52 — presets expand to sections, intersected with the type's sections
  "export.preset.scan": {
    what: "Executive: the summary and the compliance appendices. Technical: the summary, findings catalog, finding details, remediation, mappings and scan notes. Full: every section (the report as it has always been). Custom: the sections you tick. A scan type keeps only the sections it has.",
    why: "Management reads two pages; engineers need every finding with its fix. One click picks the right shape.",
    example: "Executive for the board pack, Technical for the development team.",
  },
  // src: backend/utilities/pdf/report_options.py:30-42 (run presets) — executive = summary + posture, technical = summary + catalog
  "export.preset.run": {
    what: "Executive: the run summary and its posture tables. Technical: the summary and the findings catalog. Full: every section, including provenance (the report as it has always been). Custom: the sections you tick.",
    why: "A run report can be long; a preset keeps only what its reader needs.",
    example: "Executive for the CISO, Full for the audit file.",
  },
  // src: backend/utilities/pdf/report_options.py:28, frontend/utils/reportOptions.ts:17 — summary; the masthead is always printed
  "export.section.scan.summary": {
    what: "The executive summary: risk overview, key figures and the priority note. Without it the report still opens with its masthead, which lists what was left out.",
    why: "The summary is what most readers read; leave it out only for a findings-only annex.",
    example: "Untick for an appendix that only lists findings.",
  },
  // src: backend/utilities/pdf/report_options.py:28 — catalog
  "export.section.scan.catalog": {
    what: "The findings catalog: one line per finding with its number, severity and title. Findings keep their original number when a filter hides others.",
    why: "The catalog is the index the details and tickets refer to.",
    example: "#17 High: hard-coded password in config.py.",
  },
  // src: backend/utilities/pdf/report_options.py:28 — details (remediation and mappings print inside them)
  "export.section.scan.details": {
    what: "A card per finding: where it is, what was found and the evidence. Remediation and standards mappings are printed inside these cards.",
    why: "Engineers fix from the details; an executive summary does not need them.",
    example: "Finding #17 with its file, line and code snippet.",
  },
  // src: backend/utilities/pdf/report_options.py:28 — remediation, part of details
  "export.section.scan.remediation": {
    what: "How to fix each finding, printed inside its details card.",
    why: "Leave it in for the people who fix; leave it out for a report that only states exposure.",
    example: "Move the password to a secret store and rotate it.",
  },
  // src: backend/utilities/pdf/report_options.py:28 — mappings, part of details
  "export.section.scan.mappings": {
    what: "The standards each finding maps to (CWE, OWASP and similar references), printed inside its details card.",
    why: "Auditors and compliance teams trace findings to the standards they report against.",
    example: "CWE-798, OWASP A07:2021.",
  },
  // src: backend/utilities/pdf/report_options.py:43-52 — compliance exists for SCA + SBOM, AI BOM and CBOM only
  "export.section.scan.compliance": {
    what: "The RBI and CERT-In compliance appendices. Only the BOM scans (SCA + SBOM, AI BOM, CBOM) have them, so other scan types do not show this box.",
    why: "Regulated clients file these appendices with their regulator or auditor.",
    example: "The CERT-In SBOM minimum elements appendix of an SCA + SBOM scan.",
  },
  // src: backend/utilities/pdf/report_options.py:43-52 — inventory exists for SCA + SBOM only
  "export.section.scan.inventory": {
    what: "The SBOM's package tables: every component with its version and licence. Only SCA + SBOM scans have them.",
    why: "The inventory can run to many pages; a vulnerability report for management rarely needs it.",
    example: "Leave out the 40-page package list from a summary for the client.",
  },
  // src: backend/utilities/pdf/report_options.py:43-52 — notes: SAST "Scan Notes", MCP "Scan Errors", CBOM notes
  "export.section.scan.notes": {
    what: "What the scan itself recorded: SAST scan notes, MCP scan errors and CBOM scan notes.",
    why: "Notes explain gaps in coverage; a client-facing summary may not need them.",
    example: "A note that one folder could not be parsed.",
  },
  // src: backend/utilities/pdf/report_options.py:29 — run summary
  "export.section.run.summary": {
    what: "The run's summary: what was collected, the readiness grade and the key figures. Without it the masthead still says what was left out.",
    why: "It is the page most readers of a run report read.",
    example: "Untick for an annex that only lists findings.",
  },
  // src: backend/utilities/pdf/report_options.py:29 — posture: run identity, algorithm family, certificate expiry, top risks, compliance and VEX tables
  "export.section.run.posture": {
    what: "The run's posture tables: run identity, algorithms by family, certificate expiry, top risks, compliance clauses and VEX.",
    why: "These tables show the cryptographic estate at a glance; the executive preset keeps them.",
    example: "Certificates expiring in the next 30 days by source.",
  },
  // src: backend/utilities/pdf/report_options.py:29 — catalog of a run (first 500 matching findings)
  "export.section.run.catalog": {
    what: "The run's findings, one row per asset finding (the first 500 that match the filters, with how many matched).",
    why: "Engineers work through the findings; management usually does not need the list.",
    example: "TLS 1.0 accepted on 10.0.0.1:443.",
  },
  // src: backend/utilities/pdf/report_options.py:29 — provenance
  "export.section.run.provenance": {
    what: "Where each asset was collected: the source, scan node and job behind it.",
    why: "Auditors check that the evidence came from the systems in scope.",
    example: "Collected by scan node lab-node, job #7, source F5 lab.",
  },

  // ────────────────────────────────────────────────────────────── Filters
  // src: backend/utilities/pdf/report_options.py:24, backend/utilities/pdf/report_options.py:134-137 — the KPI buckets; all five = no filter
  "export.severities": {
    what: "Only findings of the chosen severities are printed. The buckets are the dashboard's: Critical, High, Medium, Low, and Other for everything else. All five chosen means no filter; the PDF then says Showing N of M findings.",
    why: "A short report of the urgent findings gets read; the scope block keeps it from passing for the full scan.",
    example: "Critical and High only for the board.",
  },
  // src: backend/utilities/pdf/report_options.py:25, backend/utilities/pdf/report_options.py:225-228 — status filter; all four = no filter
  "export.status.not_started": {
    what: "Prints findings nobody has started on. Untick it to leave them out. With a status filter the report says when the statuses were read; a scan whose statuses cannot be matched is refused rather than guessed.",
    why: "Open findings are what a remediation plan is about.",
    example: "Only Not started and In progress for the open-items list.",
  },
  // src: backend/utilities/pdf/report_options.py:25 — in_progress
  "export.status.in_progress": {
    what: "Prints findings someone is working on. Untick it to leave them out of the report.",
    why: "Shows the client what is already being fixed.",
    example: "Untick to list only work that has not started.",
  },
  // src: backend/utilities/pdf/report_options.py:25 — fixed
  "export.status.fixed": {
    what: "Prints findings marked fixed. Untick it to leave them out; the scope block then counts how many were excluded.",
    why: "A re-test report may show only what is still open.",
    example: "Excluded: 9 Fixed.",
  },
  // src: backend/utilities/pdf/report_options.py:25 — ignored
  "export.status.ignored": {
    what: "Prints findings marked ignored (accepted or false positive). Untick it to leave them out; the scope block says how many were excluded.",
    why: "Ignored findings can distract a client, but an auditor may want to see them.",
    example: "Excluded: 4 Ignored.",
  },

  // ────────────────────────────────────────────────────────────── Cover and privacy
  // src: backend/utilities/pdf/report_options.py:59, backend/utilities/pdf/report_options.py:150-163, frontend/utils/reportOptions.ts:139 — 120 characters, one line, cp1252
  "export.prepared_for": {
    what: "The client named on the cover as Prepared for. Up to 120 characters on one line, Latin letters only for now (accents and the euro sign are fine; other scripts are refused). Never remembered in this browser.",
    why: "A named report is ready to send; the name is not stored so it cannot leak into another client's report.",
    example: "Acme Bank Ltd.",
  },
  // src: backend/utilities/pdf/report_options.py:53-58, backend/utilities/pdf/report_options.py:150-163 — deliverables take prepared_for (masthead right column)
  "export.prepared_for.deliverable": {
    what: "The client named in each deliverable's masthead, under the team logo. Up to 120 characters on one line, Latin letters only for now. Kept only until you leave or reload this page.",
    why: "The deliverables go to one client in a batch; the name is not stored so a later batch does not inherit it.",
    example: "Acme Bank Ltd.",
  },
  // src: backend/utilities/pdf/report_options.py:60, backend/utilities/pdf/report_options.py:150-163 — 140 characters
  "export.title": {
    what: "Replaces the report's usual title on the cover. Up to 140 characters on one line, Latin letters only for now. Empty keeps the usual title. Never remembered.",
    why: "A title that names the engagement makes the PDF easy to file.",
    example: "Q4 2026 application security review.",
  },
  // src: backend/utilities/pdf/report_options.py:26-27 — labels and the text printed in every page header
  "export.label": {
    what: "The classification printed in every page header: Confidential (the default), Internal or Restricted. Public prints no label. Remembered in this browser for the next report.",
    why: "The label tells readers how to handle the document under your information-classification policy.",
    example: "Restricted for a report that names production hosts.",
  },
  // src: backend/utilities/pdf/report_options.py:236-241 — hide_evidence removes the EVIDENCE block and snippet lines only
  "export.hide_evidence": {
    what: "Leaves out each finding's evidence block and code snippet lines; everything else, including file paths and line numbers, is printed. It does not redact secrets elsewhere in the text.",
    why: "Snippets can contain source code or secrets the recipient should not get.",
    example: "On for a report sent outside the company.",
  },
} as const satisfies TipAreaText;

export default TEXT;
