/**
 * Staging QA round 2 on D3 (CBOM code-scan results page): round-2 item 01 risk KPI, G-D3-6 broken today, N1 certificates,
 * N2 weak-crypto bars, N4 mean time to remediate, N7 clauses touched.
 * Run: npx --yes tsx components/cbom/results/d3Qa2.test.ts
 */
import "./__tests__/cssStub";
import assert from "node:assert/strict";
import fs from "node:fs";
import path from "node:path";

import { isBrokenToday, matchesQuantumFilter, quantumCounts } from "../quantumFilter";
import { scanCertificates, teamCertificatesHref } from "../certificates/scanCertificates";
import { weaknessBars } from "../CbomCryptoCharts";
import { buildComplianceSummary } from "./complianceSummary";
import { KPI_TILES, mttrText, riskScoreText } from "./CbomDashboardCharts";

type Card = Parameters<typeof riskScoreText>[0];
const card = (extra: Partial<Card>): Card => ({
  total_crypto_assets: 11, total_crypto_vulnerabilities: 4, total_weak_algorithms: 1, total_quantum_vulnerable: 0,
  total_certificates: 0, total_keys: 0, quantum_readiness_score: 88.9, average_risk_score: 5.2, ...extra,
} as Card);

// round-2 item 01: the risk tile shows the API's engine score, grade and words, never the 0-10 average
const tile = KPI_TILES.find((t) => t.key === "avg_risk")!;
const c = card({ risk_score: 36, risk_grade: "C", risk_label: "Elevated risk" });
assert.equal(tile.label, "Risk score");
assert.equal(tile.value(c), "36 · C");
assert.equal(tile.hint?.(c), "of 100 · Elevated risk");
assert.equal(riskScoreText(card({})), "N/A", "an API without the score shows N/A, never the average");
// re-review 6064703319 (5): a scan or run that did not succeed has no score: "—", never "0 · A"
assert.equal(riskScoreText(card({ risk_score: null, risk_grade: null, risk_posture_status: "not_scored" })), "—");
assert.equal(riskScoreText(card({ risk_score: 0, risk_grade: "A", risk_label: "Low risk" })), "0 · A");

// the backend fixture's engine score is what the tile prints (PDF / API / UI agree; backend test_cbom_d3_qa2)
const fixture = JSON.parse(fs.readFileSync(path.join(__dirname, "../../../../backend/tests/fixtures/cbom_d3_bank_scandata.json"), "utf8"));
const scores = fixture.cbom_scores;
assert.equal(riskScoreText(card({ risk_score: scores.risk_normalized, risk_grade: scores.risk_grade, risk_label: scores.risk_label })),
  `${scores.risk_normalized} · ${scores.risk_grade}`);

// G-D3-6: MD5 is "Broken today" whether stored before (quantum_safe true) or after (false + quantum_vulnerable false)
const md5Old = { quantum_safe: true, crypto_strength: "weak" };
const md5New = { quantum_safe: false, quantum_vulnerable: false, crypto_strength: "weak" };
const rsa1024 = { quantum_safe: false, quantum_vulnerable: true, crypto_strength: "weak" };
const rsa1024Old = { quantum_safe: false, crypto_strength: "weak" };
assert.ok(isBrokenToday(md5Old) && isBrokenToday(md5New));
assert.ok(!isBrokenToday(rsa1024) && !isBrokenToday(rsa1024Old));
assert.ok(!matchesQuantumFilter(md5New, "vulnerable") && matchesQuantumFilter(md5New, "broken"));
assert.deepEqual(quantumCounts([md5New, rsa1024]), { safe: 0, broken: 1, vulnerable: 1, judged: 2, readinessPct: 0 });

// N1: a code scan's certificates are its own rows; the team estate is one link away
assert.deepEqual(scanCertificates([{ title: "AES", algorithm_type: "block-cipher" }, null, "x"]), []);
const certs = scanCertificates([{ title: "CN=api", algorithm_type: "certificate", location: "certs/api.pem" },
  { title: "k", asset_type: "certificate" }, { title: "MD5", algorithm_type: "hash" }]);
assert.equal(certs.length, 2);
assert.equal(teamCertificatesHref(7), "/7/cbom");
const results = fs.readFileSync(path.join(__dirname, "../../CbomResults.tsx"), "utf8");
assert.match(results, /run \? <CertHygieneSection teamId=\{tid\} \/> : <ScanCertificates teamId=\{tid\} rows=\{allRows\} \/>/);

// N2: bars split by the engine's impact; a scan without it uses the code's usual impact (Medium codes orange)
const bars = weaknessBars({ WEAK_KDF_COST: 1, STATIC_SALT: 1, WEAK_ALGORITHM: 2 },
  { WEAK_KDF_COST: { Low: 1 }, STATIC_SALT: { Medium: 1 }, WEAK_ALGORITHM: { High: 1, Low: 1 } });
const byCode = Object.fromEntries(bars.map((b) => [b.code, b]));
assert.deepEqual([byCode.WEAK_KDF_COST.High, byCode.WEAK_KDF_COST.Medium, byCode.WEAK_KDF_COST.Low], [0, 0, 1]);
assert.deepEqual([byCode.STATIC_SALT.High, byCode.STATIC_SALT.Medium], [0, 1]);
assert.deepEqual([byCode.WEAK_ALGORITHM.High, byCode.WEAK_ALGORITHM.Low], [1, 1]);
const legacy = Object.fromEntries(weaknessBars({ STATIC_SALT: 2, WEAK_ALGORITHM: 1 }, undefined).map((b) => [b.code, b]));
assert.equal(legacy.STATIC_SALT.Medium, 2);
assert.equal(legacy.WEAK_ALGORITHM.High, 1);

// N4: no fixed finding, no mean time to remediate
assert.equal(mttrText(0, 0), "—");
assert.equal(mttrText(0.01, undefined), "—");
assert.equal(mttrText(0.01, 2), "<0.1 days");
assert.equal(mttrText(2.25, 1), "2.3 days");
const charts = fs.readFileSync(path.join(__dirname, "CbomDashboardCharts.tsx"), "utf8");
assert.match(charts, /padding=\{\{ left: 16, right: 16 \}\}/, "the first risk-score label (F1) is drawn whole");

// N7: a code scan (engine requirements only) counts its failing requirements as the clauses touched
const summary = buildComplianceSummary({
  engine: { cert_in_cbom: { pass: 20, fail: 2, pass_with_evidence: 0, out_of_scope: 0, not_bom_evidenceable: 3, na: 0,
    requirements: [
      { id: "T9-Algorithms-Classical-Security-Level", title: "x", verdict: "fail", refs: ["a", "b"] },
      { id: "T9-Keys-Size", title: "y", verdict: "fail", refs: ["c"] },
      { id: "8.4.1.1", title: "z", verdict: "not_bom_evidenceable", refs: [] },
    ] } } as never,
  mapping: [],
  findings: [],
});
const certIn = summary.find((f) => f.framework === "CERT-In")!;
assert.equal(certIn.clausesTouched, 2);
assert.equal(certIn.assets, 3);

console.log("d3Qa2.test.ts: ok");
