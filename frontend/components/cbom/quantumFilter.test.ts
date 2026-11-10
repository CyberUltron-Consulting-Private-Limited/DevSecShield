/**
 * Hermetic tests for the CBOM results Quantum column / filter rule.
 * Run: npx --yes tsx components/cbom/quantumFilter.test.ts
 */
import assert from "node:assert/strict";
import fs from "node:fs";
import path from "node:path";
import { isBrokenToday, matchesQuantumFilter, quantumCounts } from "./quantumFilter";

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
  assert.ok(charts.includes("<PqcReadinessGauge pqc={distributions.pqc} rows={findings} />"), "gauge counts the table rows");
  assert.ok(charts.includes("Broken today: {broken}"), "gauge legend lists Broken today");
}
console.log("quantumCounts tests passed");
