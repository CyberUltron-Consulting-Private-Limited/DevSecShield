/**
 * CBOM and SBOM compliance matrices follow the team's regulatory profile (teamApplicability.ts, backend
 * bom_applicability.py): the frameworks that do not bind the team are left out and the India chip is named after the
 * regulators left. Without the server's view the matrices render as before (codeModeSnapshot.test.ts pins that).
 * Run (frontend/): npx --yes tsx@4.23.15 --test components/compliance/teamApplicability.test.ts
 */
import "../cbom/results/__tests__/cssStub";
import assert from "node:assert/strict";
import fs from "node:fs";
import path from "node:path";
import { test } from "node:test";
import React from "react";
import { renderToStaticMarkup } from "react-dom/server";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";

import { FRAMEWORK_GROUPS_CBOM_WITH_INDIA, FRAMEWORK_GROUPS_SBOM_WITH_INDIA } from "./frameworkLabels";
import {
  ComplianceApplicabilityContext,
  applicabilityNote,
  bindingCompliance,
  groupsForFrameworks,
  teamCompliance,
  type ComplianceApplicability,
} from "./teamApplicability";
import { CbomCryptoCharts } from "../cbom/CbomCryptoCharts";
import { DISTRIBUTIONS, FINDINGS, GRAPH } from "../cbom/results/__tests__/codeModeFixtures";

const REPORT = { pass: 1, fail: 1, na: 0, coverage: 0.5, requirements: [] };
const CBOM = {
  nist_800_57: REPORT, cert_in_cbom: REPORT, sebi_cscrf_cbom: REPORT, rbi_free_ai_protection: REPORT, eu_dora: REPORT,
  disclaimer: "Advisory.",
};
const SBOM = { cert_in_sbom: REPORT, sebi_cscrf_sbom: REPORT, rbi_free_ai_supply: REPORT, ntia_minimum_elements: REPORT,
  disclaimer: "Advisory." };
// a commercial bank SEBI does not regulate (backend bom_applicability.page_view)
const BANK_CBOM: ComplianceApplicability = {
  regulatory_profile: { entity: "bank", jurisdiction: "IN", flags: [] },
  basis: "Commercial bank in India, not SEBI-regulated",
  binding: ["nist_800_57", "cert_in_cbom", "rbi_free_ai_protection"],
  not_applicable: [{ framework: "sebi_cscrf_cbom", label: "SEBI CSCRF" }, { framework: "eu_dora", label: "EU DORA" }],
};
const BANK_SBOM: ComplianceApplicability = { ...BANK_CBOM, binding: ["cert_in_sbom", "rbi_free_ai_supply", "ntia_minimum_elements"],
  not_applicable: [{ framework: "sebi_cscrf_sbom", label: "SEBI CSCRF" }] };

const india = (groups: { id: string; label: string; keys: string[] }[]) => groups.find((g) => g.id === "india");

test("chips are named after the regulators of the frameworks shown", () => {
  assert.equal(india(groupsForFrameworks(FRAMEWORK_GROUPS_CBOM_WITH_INDIA, ["cert_in_cbom"]))?.label, "India / CERT-In");
  assert.equal(india(groupsForFrameworks(FRAMEWORK_GROUPS_CBOM_WITH_INDIA, ["cert_in_cbom", "sebi_cscrf_cbom"]))?.label,
    "India / CERT-In / SEBI");
  assert.equal(india(groupsForFrameworks(FRAMEWORK_GROUPS_SBOM_WITH_INDIA, ["nist_ssdf"])), undefined);
  // the other chips are unchanged
  assert.deepEqual(groupsForFrameworks(FRAMEWORK_GROUPS_CBOM_WITH_INDIA, []).map((g) => g.id), ["all", "quantum", "baseline", "regulatory"]);
});

test("the view keeps the binding frameworks and the disclaimer; no view changes nothing", () => {
  assert.deepEqual(Object.keys(bindingCompliance(CBOM, BANK_CBOM) ?? {}),
    ["nist_800_57", "cert_in_cbom", "rbi_free_ai_protection", "disclaimer"]);
  assert.equal(bindingCompliance(CBOM, null), CBOM);
  const none = teamCompliance(CBOM, FRAMEWORK_GROUPS_CBOM_WITH_INDIA, null);
  assert.equal(none.compliance, CBOM);
  assert.equal(none.groups, FRAMEWORK_GROUPS_CBOM_WITH_INDIA);
  assert.equal(none.note, null);
  assert.equal(applicabilityNote(BANK_CBOM),
    "Frameworks shown for this team's regulatory profile (Commercial bank in India, not SEBI-regulated). Not applicable to it: SEBI CSCRF, EU DORA.");
  assert.equal(applicabilityNote({ regulatory_profile: null, binding: [] }),
    "Team regulatory profile: regulated entity not set. Every framework is shown.");
});

const render = (el: React.ReactElement) =>
  renderToStaticMarkup(React.createElement(QueryClientProvider, { client: new QueryClient() }, el));

const charts = (view: ComplianceApplicability | null) => render(React.createElement(
  ComplianceApplicabilityContext.Provider, { value: view },
  React.createElement(CbomCryptoCharts, { distributions: DISTRIBUTIONS, graph: GRAPH, compliance: CBOM as never,
    findings: FINDINGS, inventory: FINDINGS, readinessScope: "code" }),
));

test("the CBOM code-scan matrix: a bank SEBI does not regulate reads India / CERT-In, without SEBI CSCRF", () => {
  const before = charts(null);
  assert.match(before, />India \/ CERT-In \/ SEBI</);
  const html = charts(BANK_CBOM);
  assert.match(html, />India \/ CERT-In</);
  assert.doesNotMatch(html, /India \/ CERT-In \/ SEBI/);
  // the matrix (a chart, not in static markup) gets the binding frameworks only; the note names the others
  assert.match(html, /data-testid="cbom-applicability-note">Frameworks shown for this team&#x27;s regulatory profile \(Commercial bank in India, not SEBI-regulated\)\. Not applicable to it: SEBI CSCRF, EU DORA\.</);
  assert.doesNotMatch(before, /applicability-note/);
  // the rest of the charts render the same markup as without the view
  // everything before the compliance section (useId ids differ under the extra provider)
  const cut = (s: string) => {
    const end = s.lastIndexOf('<div class="grid grid-cols-1 gap-6">', s.indexOf("Crypto compliance readiness"));
    return s.slice(0, end).replace(/_R_[0-9a-z]+_/g, "_R_");
  };
  const [a, b] = [cut(html), cut(before)];
  let i = 0;
  while (i < a.length && a[i] === b[i]) i++;
  assert.equal(a, b, `first difference at ${i}: …${a.slice(Math.max(0, i - 200), i + 200)}… vs …${b.slice(Math.max(0, i - 200), i + 200)}…`);
});

test("the SBOM matrix: same filtering and chip naming", async () => {
  const { SbomComplianceCoverage } = await import("../SbomResults");
  const html = render(React.createElement(SbomComplianceCoverage, { compliance: SBOM as never, view: BANK_SBOM }));
  assert.match(html, />India \/ CERT-In</);
  assert.doesNotMatch(html, /India \/ CERT-In \/ SEBI/);
  assert.match(html, /data-testid="sbom-applicability-note">[^<]*Not applicable to it: SEBI CSCRF\.</);
  const before = render(React.createElement(SbomComplianceCoverage, { compliance: SBOM as never }));
  assert.match(before, />India \/ CERT-In \/ SEBI</);
  assert.doesNotMatch(before, /applicability-note/);
});

test("a Sources run's compliance section: the same chip and note from its /parity view", () => {
  const run = (view: ComplianceApplicability | null) => render(React.createElement(
    ComplianceApplicabilityContext.Provider, { value: view },
    React.createElement(CbomCryptoCharts, { distributions: null, parts: ["compliance"], variant: "run", compliance: CBOM as never,
      findings: [], inventory: [], showCodeHeatmap: false, readinessScope: "run" }),
  ));
  const before = run(null);
  assert.match(before, />India \/ CERT-In \/ SEBI</);
  assert.doesNotMatch(before, /applicability-note/);
  const html = run(BANK_CBOM);
  assert.match(html, />India \/ CERT-In</);
  assert.doesNotMatch(html, /India \/ CERT-In \/ SEBI/);
  assert.match(html, /data-testid="cbom-applicability-note">[^<]*Not applicable to it: SEBI CSCRF, EU DORA\.</);
});

test("the run page provides the /parity view to its compliance section", () => {
  const src = fs.readFileSync(path.join(__dirname, "..", "CbomResults.tsx"), "utf8");
  assert.match(src, /<ComplianceApplicabilityContext\.Provider value=\{cbomApplicability\}><ComplianceView ctx=\{ctx\} \/>/);
  // a run's scanMetadata is /parity's, so cbomApplicability reads its compliance_applicability
  assert.match(src, /const scanMetadata = run \? run\.parity\?\.scan_metadata \?\? null : scanMetadataProp;/);
});
