/**
 * Hermetic tests for the CBOM results Quantum column / filter rule.
 * Run: npx --yes tsx components/cbom/quantumFilter.test.ts
 */
import assert from "node:assert/strict";
import fs from "node:fs";
import path from "node:path";
import { inventoryRows, isBrokenToday, matchesQuantumFilter, quantumCounts, round1 } from "./quantumFilter";

// rows as the lab scan returned them (u2-zip-full-opts)
const md5 = { quantum_safe: true, crypto_strength: "weak" };
const aesGcm = { quantum_safe: true, crypto_strength: "strong" };
const rsa1024 = { quantum_safe: false, crypto_strength: "weak" };
const library = { quantum_safe: null, crypto_strength: "weak" };

assert.equal(isBrokenToday(md5), true);
assert.equal(isBrokenToday({ quantum_safe: true, crypto_strength: "WEAK" }), true);
assert.equal(isBrokenToday(aesGcm), false);
assert.equal(isBrokenToday(rsa1024), false);

assert.equal(matchesQuantumFilter(md5, "safe"), false, "a row the column calls 'Broken today' is not Quantum-Safe");
assert.equal(matchesQuantumFilter(aesGcm, "safe"), true);
assert.equal(matchesQuantumFilter(md5, "broken"), true);
assert.equal(matchesQuantumFilter(aesGcm, "broken"), false);
assert.equal(matchesQuantumFilter(rsa1024, "vulnerable"), true);
assert.equal(matchesQuantumFilter(library, "safe"), false);
assert.equal(matchesQuantumFilter(library, "vulnerable"), false);
for (const f of [md5, aesGcm, rsa1024, library]) assert.equal(matchesQuantumFilter(f, "all"), true);
console.log("quantumFilter tests passed");

// PQC readiness gauge (a lab scan showed 77 % with MD5 and DES counted as quantum-safe): broken today is not ready
{
  const des = { quantum_safe: true, crypto_strength: "weak" };
  const c = quantumCounts([md5, des, aesGcm, rsa1024, library]);
  assert.deepEqual(c, { safe: 1, broken: 2, vulnerable: 1, judged: 4, readinessPct: 25 });
  assert.equal(quantumCounts([library]).readinessPct, null, "nothing judged is n/a, not 0 %");
  assert.equal(quantumCounts([aesGcm, aesGcm, rsa1024]).readinessPct, 66.7);
  const charts = fs.readFileSync(path.join(__dirname, "CbomCryptoCharts.tsx"), "utf8");
  assert.ok(charts.includes("<PqcReadinessGauge pqc={distributions.pqc} rows={inventory ?? findings} />"),
    "gauge counts every row of the scan (findings when the page has no row list)");
  assert.ok(charts.includes("Broken today: {broken}"), "gauge legend lists Broken today");
}
console.log("quantumCounts tests passed");

// Lab UI r1 F3: scan #51's page said 0 % (the finding rows only) where the PDF and the scan list said 10 % (every
// row: 2 clean quantum-safe rows). The same stored rows, as GET scan data serves them (page_rows), must give the
// numbers the backend gives (backend tests/test_cbom_readiness_parity.py reads the same fixture).
{
  type Case = { name: string; rows: unknown[]; page_rows: Record<string, unknown>[];
    expected: { rows: number; findings: number; safe: number; broken: number; vulnerable: number; judged: number; readiness: number } };
  const fixture = JSON.parse(fs.readFileSync(path.join(__dirname, "../../../backend/tests/fixtures/cbom_readiness_parity.json"), "utf8")) as { cases: Case[] };
  assert.ok(fixture.cases.length >= 3);
  for (const c of fixture.cases) {
    const findings = c.page_rows.filter((r) => Array.isArray(r.finding_codes) && (r.finding_codes as unknown[]).length > 0);
    assert.equal(findings.length, c.expected.findings, c.name);
    const counts = quantumCounts(inventoryRows(c.page_rows, findings));
    assert.deepEqual(counts, { safe: c.expected.safe, broken: c.expected.broken, vulnerable: c.expected.vulnerable,
      judged: c.expected.judged, readinessPct: c.expected.readiness }, c.name);
  }
  const scan51 = fixture.cases[0];
  const onlyFindings = scan51.page_rows.filter((r) => (r.finding_codes as unknown[]).length > 0);
  assert.equal(quantumCounts(onlyFindings).readinessPct, 0, "the old page: findings only, 0 %");
  // no row list (legacy GET shape): the findings
  assert.equal(inventoryRows({ cbom_distributions: {} }, onlyFindings), onlyFindings);
  assert.equal(inventoryRows([], onlyFindings), onlyFindings);
  // Python's round(x, 1): a tie goes to even; every other value to nearest
  assert.deepEqual([round1(6.25), round1(93.75), round1(12.5), round1(66.66666666666667), round1(0.15), round1(10)],
    [6.2, 93.8, 12.5, 66.7, 0.1, 10]);
  const results = fs.readFileSync(path.join(__dirname, "..", "CbomResults.tsx"), "utf8");
  assert.ok(results.includes("const allRows = useMemo(() => inventoryRows(data, findingsList ?? []), [data, findingsList]);"));
  assert.ok(results.includes("inventory={allRows}"), "the results page hands every row to the gauge");
}
console.log("readiness parity tests passed");
