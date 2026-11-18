/**
 * Results redesign B3: the shared components the run finding dialog changed render EXACTLY as on the base commit
 * (fbf79f7e) wherever the new props are not passed: KbFindingDetails (code-scan Standards tab, Sources drawer: default
 * "cards"), the CBOM RemediationPanel (code dialog: default "tabs"), AssetDetailPanel (split into exported parts) and
 * <InfoTip> without an Explanations drawer provider. The snapshot was taken by rendering the base versions of these
 * files with this same script (UPDATE_SNAPSHOT=1 against the base files).
 * Run (frontend/): npx --yes tsx@4.23.15 components/cbom/results/sharedCodeMode.test.ts
 */
import assert from "node:assert/strict";
import { existsSync, readFileSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import React from "react";
import { renderToStaticMarkup } from "react-dom/server";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";

import KbFindingDetails from "@/components/cbom/KbFindingDetails";
import RemediationPanel from "@/components/RemediationPanel";
import { AssetDetailPanel } from "@/components/cbom/sources/RunPosture";
import { cbomSourcesKeys } from "@/components/cbom/sources/keys";
import { InfoTip } from "@/components/ui/info-tip";
import { TooltipProvider } from "@/components/ui/tooltip";
import type { KbFindingDetail, RemediationData } from "@/utils/backend_api";

const h = React.createElement;
// useId values depend on the tree: every case renders in its own root
const render = (el: React.ReactElement, client = new QueryClient()) =>
  renderToStaticMarkup(h(QueryClientProvider, { client }, h(TooltipProvider, null, el)));

const kb = (code: string, extra: Partial<KbFindingDetail> = {}): KbFindingDetail => ({
  code, title: `Title ${code}`, observed: `observed ${code}`, description: `why ${code}`, attack: `attack ${code}`, impact: "i",
  category: "c", pqc: "quantum-vulnerable",
  cwe: [{ id: "CWE-327", name: "Broken crypto", url: "https://cwe.mitre.org/327" }],
  owasp_2021: [{ id: "A02:2021", label: "A02:2021 Cryptographic Failures", basis: "b" }], owasp_2025: [],
  cves: [{ id: "CVE-2014-3566", url: "https://nvd.nist.gov/x", cvss: { version: "3.1", score: 3.4, severity: "LOW" }, matched_on: "finding type", summary: "POODLE" }],
  standards: ["NIST SP 800-52r2"],
  compliance: [{ framework: "RBI", id: "para 16", text: "Strong ciphers.", source: "https://rbi.org.in/x", note: "Applies to banks" }],
  remediation: { summary: `fix ${code}`, steps: [{ platform: "nginx", how: "ssl_protocols TLSv1.2 TLSv1.3;" }] },
  verify: [{ label: "Protocols", command: "nmap --script ssl-enum-ciphers -p 443 host" }], references: [], ...extra,
} as unknown as KbFindingDetail);
const details = [kb("PROTO_SSLv3"), kb("PROTO_TLS10")];

const remediation = {
  source: "knowledge_base", status: "completed", engine: "kb-1", kb_version: "2026.11.15.6", generated_at: "2026-11-15T10:00:00Z",
  fix: { description: "Use TLS 1.2+", confidence: 80, language: "text", original_code: "", fixed_code: "", validation_notes: "", references: [] },
  code_fix: { version: "1", available: false, kind: "config", language: "", original_code: "", fixed_code: "", diff: "", confidence: 0,
    summary: "Disable SSLv3", rules: [], notes: [], warnings: [], commands: [] },
  diff: "",
  exploit_demo: { code: "PROTO_SSLv3", family: "legacy-protocol", difficulty: "moderate", attack_vector: "network", safety: "Local only.",
    description: "Downgrade.", poc: null, impact_demonstration: "Run the commands.", prerequisites: "Read access.",
    verify: [{ label: "Protocols", command: "nmap host" }] },
  details,
} as unknown as RemediationData;

const assetClient = () => {
  const client = new QueryClient();
  client.setQueryData(cbomSourcesKeys.asset(1, 5), {
    id: 5, type: "certificate", pqc_class: "quantum-vulnerable", pqc_class_basis: "observed", pqc_class_basis_text: "RSA 2048 key",
    pqc_class_read_elsewhere: 9, hndl: true, criticality: "high", exposure: "internet", exposure_basis: "public IP 1.2.3.4",
    exposure_factor: 1.5, details, agility: null, standards: [], correlation: null,
    library: { package: "openssl", package_version: "1.0.2k", library: "OpenSSL", upstream_version: "1.0.2",
      eol: { branch: "1.0.2", passed: true, date: "2019-12-31" }, eol_as_of: "2026-11-01", eol_today: { branch: "1.0.2", passed: true, date: "2019-12-31" },
      cves: ["CVE-1"], cve_details: [{ id: "CVE-1", url: "https://nvd/x", cvss: { score: 7.5 } }] },
  });
  return client;
};

const cases: Record<string, () => string> = {
  kbCards: () => render(h(KbFindingDetails, { details })),
  kbCardsMerged: () => render(h(KbFindingDetails, { details, mergedStandards: true })),
  kbCardsNoRemediation: () => render(h(KbFindingDetails, { details, showRemediation: false })),
  kbEmpty: () => render(h(KbFindingDetails, { details: [] })),
  // the code dialog: no scan to load from (scanId 0) and a stored knowledge-base result
  remediationCode: () => render(h(RemediationPanel, { teamId: "1", scanType: "cbom", scanId: 0, findingId: "", existingRemediation: remediation })),
  remediationCodeNoStandards: () => render(h(RemediationPanel, { teamId: "1", scanType: "cbom", scanId: 0, findingId: "", existingRemediation: remediation, standardsTab: false })),
  assetDetail: () => render(h(AssetDetailPanel, { teamId: 1, assetId: 5 }), assetClient()),
  assetDetailMerged: () => render(h(AssetDetailPanel, { teamId: 1, assetId: 5, mergedStandards: true }), assetClient()),
  infoTip: () => render(h(InfoTip, { id: "cbom.run.f.type" })),
};

const snapFile = join(__dirname, "__tests__", "sharedCodeMode.base.json");
const now = Object.fromEntries(Object.entries(cases).map(([k, f]) => [k, f()]));
if (process.env.UPDATE_SNAPSHOT === "1") {
  writeFileSync(snapFile, JSON.stringify(now, null, 1) + "\n");
  console.log(`wrote ${snapFile}`);
} else {
  assert.ok(existsSync(snapFile), "base snapshot missing");
  const base = JSON.parse(readFileSync(snapFile, "utf8")) as Record<string, string>;
  for (const k of Object.keys(cases)) assert.equal(now[k], base[k], `${k}: output differs from the base commit`);
  // not vacuous: the cases render real content
  assert.ok(now.kbCards.includes("How it is attacked") && now.remediationCode.includes("Remediation, fix code and exploit demo"));
  assert.ok(now.assetDetail.includes('data-testid="asset-detail-5"') && now.assetDetail.includes("asset-library-eol"));
  console.log("shared components: code-mode output equals the base commit");
}
