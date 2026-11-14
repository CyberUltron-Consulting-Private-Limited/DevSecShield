/**
 * #270 compliance mapping view-model: per-framework verdicts from the six requirement verdict types, readable labels
 * (one helper, KB titles), the drill-down filters (a clause's finding codes, a requirement's assets) and the same
 * section on the one template for code scans and runs.
 * Run (frontend/): npx --yes tsx@4.23.15 components/cbom/results/complianceSummary.test.ts
 */
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import path from "node:path";

import {
  buildComplianceSummary,
  codeLabel,
  codeTitles,
  emptyCounts,
  ENGINE_KEYS,
  frameworkVerdict,
  MAX_DRILL_IDS,
  runAssetId,
  runDrillFilters,
  verdictSegments,
} from "./complianceSummary";
import { complianceRows, DEFAULT_FILTERS, filtersToParams, hasActiveFilters } from "./model";

import { ENGINE, MAPPING } from "./complianceFixtures";

// ---------------------------------------------------------------- labels: one helper, KB titles
const titles = codeTitles(MAPPING, [{ code: "SSH_NO_PQ_KEX", title: "No post-quantum SSH key exchange" }]);
assert.equal(codeLabel("SSH_DH_SHA1", titles), "SHA-1 based SSH key exchange");
assert.equal(codeLabel("SSH_NO_PQ_KEX", titles), "No post-quantum SSH key exchange", "posture top_codes titles count too");
assert.equal(codeLabel("RSA_LT_2048", titles), "RSA LT 2048", "unknown code: words, never the raw underscore code");
assert.equal(codeLabel("X", { X: "X" }), "X");

// ---------------------------------------------------------------- verdicts (six types -> pass / fail / partial / not assessed)
const c = (o: Partial<ReturnType<typeof emptyCounts>>) => ({ ...emptyCounts(), ...o });
assert.equal(frameworkVerdict(c({ pass: 3 }), { hasEngine: true, clausesTouched: 0 }), "pass");
assert.equal(frameworkVerdict(c({ pass: 1, pass_with_evidence: 1 }), { hasEngine: true, clausesTouched: 0 }), "pass");
assert.equal(frameworkVerdict(c({ fail: 2 }), { hasEngine: true, clausesTouched: 0 }), "fail");
assert.equal(frameworkVerdict(c({ fail: 2, na: 3 }), { hasEngine: true, clausesTouched: 4 }), "fail");
assert.equal(frameworkVerdict(c({ pass: 2, fail: 1 }), { hasEngine: true, clausesTouched: 0 }), "partial");
assert.equal(frameworkVerdict(c({ pass: 2, not_bom_evidenceable: 1 }), { hasEngine: true, clausesTouched: 0 }), "partial", "evidence still owed");
assert.equal(frameworkVerdict(c({ pass: 3 }), { hasEngine: true, clausesTouched: 2 }), "partial", "checks pass but findings breach its clauses");
assert.equal(frameworkVerdict(c({ out_of_scope: 4 }), { hasEngine: true, clausesTouched: 0 }), "not_assessed");
assert.equal(frameworkVerdict(c({ not_bom_evidenceable: 2, na: 1 }), { hasEngine: true, clausesTouched: 0 }), "not_assessed");
assert.equal(frameworkVerdict(emptyCounts(), { hasEngine: false, clausesTouched: 0 }), "not_assessed");
assert.equal(frameworkVerdict(emptyCounts(), { hasEngine: false, clausesTouched: 1 }), "fail", "no engine: the KB says its findings breach the clause");

// ---------------------------------------------------------------- a run: engine + KB clauses
const run = buildComplianceSummary({ engine: ENGINE, mapping: MAPPING });
assert.deepEqual(run.map((f) => f.framework), ["CERT-In", "RBI", "SEBI CSCRF", "NIST", "CNSA 2.0"], "the mapping's order");
const by = Object.fromEntries(run.map((f) => [f.framework, f]));
assert.equal(by["CERT-In"].verdict, "partial", "CERT-In checks pass, but two clauses are breached");
assert.equal(by.RBI.verdict, "fail", "no RBI engine framework in this report: clauses touched -> fail");
assert.equal(by["SEBI CSCRF"].verdict, "not_assessed");
assert.equal(by.NIST.verdict, "partial");
assert.equal(by["CNSA 2.0"].verdict, "fail");
// NIST aggregates its four engine frameworks (only two present) and nothing else (EU CRA is not NIST)
assert.deepEqual(by.NIST.counts, { pass: 3, pass_with_evidence: 0, fail: 1, out_of_scope: 0, not_bom_evidenceable: 1, na: 1 });
assert.equal(by.NIST.requirements, 6);
assert.deepEqual(by.NIST.engineFrameworks, ["NIST SP 800-57", "FIPS 140-3"]);
assert.ok(ENGINE_KEYS.NIST.every((k) => k.startsWith("nist_") || k === "fips_140_3"));
// counts are the API's, never added up here (the clause counts overlap)
assert.equal(by["CERT-In"].assets, 4);
assert.equal(by["CERT-In"].clausesTouched, 2);
assert.equal(by.RBI.assets, 2);
assert.deepEqual(by["CERT-In"].drill, { kind: "codes", codes: ["NO_PQ_KEX", "QUANTUM_VULNERABLE", "WEAK_CIPHER"], label: "CERT-In · every clause" });
// clause rows: readable one-line summary, fixes, regulation text kept for the collapsed block, codes drill-down
const sha1 = by.NIST.clauses[0];
assert.equal(sha1.summary, "SHA-1 based SSH key exchange, Weak cipher suites accepted");
assert.ok(!/[A-Z]+_[A-Z0-9_]+/.test(sha1.summary), "no raw finding code in the summary");
assert.deepEqual(sha1.fixes.map((f) => f.label), ["SHA-1 based SSH key exchange", "Weak cipher suites accepted"]);
assert.equal(sha1.quote, "Digital signature generation: Disallowed ...");
assert.equal(sha1.verdict, "fail");
assert.deepEqual(sha1.drill, { kind: "codes", codes: ["SSH_DH_SHA1", "WEAK_CIPHER"], label: "NIST · SP 800-131A Rev. 2, Sec. 9 Table 8 (SHA-1)" });
assert.equal(by.RBI.clauses[0].note, "Applies to REs other than commercial banks");
assert.equal(by.RBI.clauses[0].fixes.length, 1, "one fix per distinct remediation");
// a framework the KB does not touch lists the engine's open requirements instead (fail and needs-evidence)
assert.deepEqual(by["CNSA 2.0"].clauses.map((x) => [x.id, x.verdict, x.assets, x.origin]), [["CNSA-1", "fail", 2, "engine"], ["CNSA-2", "fail", 1, "engine"]]);
assert.equal(by["CNSA 2.0"].assets, 3, "distinct refs of the failing requirements");
assert.deepEqual(by["CNSA 2.0"].drill, { kind: "refs", refs: ["zs-asset-11", "crypto-algo-rsa", "zs-asset-13"], label: "CNSA 2.0 · failing requirements" });
assert.equal(by["CNSA 2.0"].clauses[0].quote, "RSA is not CNSA 2.0");

// ---------------------------------------------------------------- a code scan: engine only, fixes from its findings
const findings = [
  { id: "f1", bom_ref: "crypto-algo-rsa", title: "RSA-1024", algorithm_name: "RSA", suggested_fix: "Use RSA-3072 or ML-DSA." },
  { id: "f2", bom_ref: "crypto-algo-md5", title: "MD5", algorithm_name: "MD5", suggested_fix: "Use SHA-256." },
];
const scan = buildComplianceSummary({ engine: ENGINE, mapping: null, findings });
const sb = Object.fromEntries(scan.map((f) => [f.framework, f]));
assert.deepEqual(scan.map((f) => f.framework), ["CERT-In", "SEBI CSCRF", "NIST", "CNSA 2.0"], "frameworks the checks judged; no KB clauses");
assert.equal(sb["CERT-In"].verdict, "pass");
assert.equal(sb.NIST.verdict, "partial");
assert.deepEqual(sb.NIST.clauses.map((x) => [x.id, x.verdict]), [["57-3", "fail"], ["57-4", "not_bom_evidenceable"]]);
assert.deepEqual(sb.NIST.drill, { kind: "refs", refs: ["zs-asset-11", "zs-asset-12"], label: "NIST · failing requirements" });
assert.deepEqual(sb["CNSA 2.0"].clauses[0].fixes, [{ label: "RSA", fix: "Use RSA-3072 or ML-DSA." }], "How to fix from the findings behind the requirement");
assert.equal(sb["CERT-In"].drill, null, "nothing failing: no drill-down, count 0");
assert.equal(sb["CERT-In"].assets, 0);
assert.deepEqual(buildComplianceSummary({ engine: null, mapping: [] }), [], "a legacy scan: no section");

// ---------------------------------------------------------------- the compact chart
const seg = verdictSegments(by.NIST.counts);
assert.deepEqual(seg.map((s) => s.verdict), ["pass", "fail", "not_bom_evidenceable", "na"], "verdict order, zeros left out");
assert.equal(Math.round(seg.reduce((n, s) => n + s.pct, 0)), 100);
assert.deepEqual(verdictSegments(emptyCounts()), []);

// ---------------------------------------------------------------- drill-down: the run table's server-side filter
assert.equal(runAssetId("zs-asset-42"), 42);
assert.equal(runAssetId("crypto-algo-rsa"), null);
assert.equal(runAssetId("zs-asset-0"), null);
assert.equal(runAssetId("zs-asset-99999999999"), null);
const codesDrill = runDrillFilters(sha1.drill!);
assert.equal(codesDrill.truncated, false);
assert.deepEqual(codesDrill.patch.codes, ["SSH_DH_SHA1", "WEAK_CIPHER"]);
assert.equal(codesDrill.patch.view, "all", "the All view: the clause counts every collected asset with the code");
assert.ok("impact" in codesDrill.patch && codesDrill.patch.impact === undefined, "other filters cleared");
const filters = { ...DEFAULT_FILTERS, ...codesDrill.patch };
assert.deepEqual(filtersToParams(filters), { view: "all", page: 1, page_size: 50, code: "SSH_DH_SHA1,WEAK_CIPHER" });
assert.equal(hasActiveFilters(filters), true, "the table shows the filtered total and Clear filters");
const refsDrill = runDrillFilters(by["CNSA 2.0"].drill!);
assert.deepEqual(refsDrill.patch.asset_ids, [11, 13], "only the run's zs-asset refs");
assert.equal(refsDrill.patch.codes, undefined, "a refs drill replaces a codes drill");
assert.deepEqual(filtersToParams({ ...DEFAULT_FILTERS, ...refsDrill.patch }), { view: "all", page: 1, page_size: 50, asset_id: "11,13" });
const many = runDrillFilters({ kind: "refs", refs: Array.from({ length: 600 }, (_, i) => `zs-asset-${i + 1}`), label: "x" });
assert.equal(many.patch.asset_ids!.length, MAX_DRILL_IDS);
assert.equal(many.truncated, true);
assert.equal(hasActiveFilters(DEFAULT_FILTERS), false);

// ---------------------------------------------------------------- the posture fallback keeps the framework count
const rows = complianceRows(null, { compliance: [{ framework: "NIST", assets: 5, clauses: [{ id: "A", text: "t", source: "s", assets: 5, codes: ["X"] }] }] });
assert.equal(rows.rows[0].assets, 5);

// ---------------------------------------------------------------- one template: the section for code scans and runs
const template = readFileSync(path.join(__dirname, "..", "..", "CbomResults.tsx"), "utf8");
assert.ok(!template.includes("RunComplianceSection"), "the run-only text wall is gone");
assert.match(template, /\{\(!run \|\| run\.plan\.compliance\.show\) && \(\n\s*<ComplianceMappingSection frameworks=\{complianceMapping\.frameworks\} onDrill=\{handleComplianceDrill\}/);
assert.match(template, /engine: cryptoCompliance,/, "the verdicts come from the same tri-state report on both");
assert.match(template, /const \{ patch, truncated \} = runDrillFilters\(target\);\n\s*run\.onFilters\(patch\);/, "run: server-side table filter");
assert.match(template, /\} else if \(target\.kind === "refs"\) \{\n\s*handleViewRelatedFindings\(target\.refs\);/, "code scan: the existing related-assets filter");
const table = readFileSync(path.join(__dirname, "RunFindingsTable.tsx"), "utf8");
assert.match(table, /codes: undefined, asset_ids: undefined, drill_label: undefined, page: 1 \}\);/, "Clear filters clears the drill-down");

console.log("complianceSummary.test.ts: ok");
