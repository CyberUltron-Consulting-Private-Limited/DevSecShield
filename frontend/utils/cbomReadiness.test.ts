/**
 * rev4 L1: unjudged quantum readiness (the backend's quantum_readiness_judged=false, score 0) is "n/a" in a neutral
 * colour on the scan page and the scan list, as the scan PDF and the team roll-up print it, never a red "0%".
 * Run: npx --yes tsx utils/cbomReadiness.test.ts
 */
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import path from "node:path";
import { readinessJudged, readinessText, readinessTone } from "./cbomReadiness";

// what scan.py / scan_list.py send when only hashes, certificates or protocols were found
const unjudged = { quantum_readiness_score: 0, quantum_readiness_judged: false };
assert.equal(readinessJudged(unjudged), false);
assert.equal(readinessText(unjudged), "n/a");
assert.equal(readinessTone(unjudged), "none");

// judged, including a real 0 % (every graded asset is quantum-vulnerable)
assert.equal(readinessText({ quantum_readiness_score: 0, quantum_readiness_judged: true }), "0%");
assert.equal(readinessTone({ quantum_readiness_score: 0, quantum_readiness_judged: true }), "poor");
assert.equal(readinessText({ quantum_readiness_score: 66.7, quantum_readiness_judged: true }), "66.7%");
assert.equal(readinessTone({ quantum_readiness_score: 66.7, quantum_readiness_judged: true }), "fair");
assert.equal(readinessTone({ quantum_readiness_score: 70, quantum_readiness_judged: true }), "good");
// an older API response without the flag keeps its score
assert.equal(readinessText({ quantum_readiness_score: 25 }), "25%");

// both cards use these helpers (the scan page printed `${score}%`, the list page coloured 0 red)
const root = process.cwd();
const scanPage = readFileSync(path.join(root, "components", "CbomResults.tsx"), "utf8");
const listPage = readFileSync(path.join(root, "app", "[team_id]", "cbom", "page.tsx"), "utf8");
assert.ok(!scanPage.includes("`${cardData.quantum_readiness_score}%`"), "scan page prints the raw score");
assert.match(scanPage, /label: "Quantum ready", value: readinessText\(cardData\)/);
assert.ok(!listPage.includes("{card.quantum_readiness_score}%"), "scan list prints the raw score");
assert.match(listPage, /\{readinessText\(card\)\}/);
assert.match(listPage, /READINESS_BOX\[readinessTone\(card\)\]/);

console.log("cbomReadiness.test.ts: ok");
