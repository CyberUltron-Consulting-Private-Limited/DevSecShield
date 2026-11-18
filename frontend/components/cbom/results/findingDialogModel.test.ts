/**
 * Pure helpers of the run finding dialog (results redesign F7): severity frame, risk ring, location table, numbered
 * suggested fix, control framework cards, issue rows and evidence codes.
 * Run (frontend/): npx --yes tsx@4.23.15 components/cbom/results/findingDialogModel.test.ts
 */
import assert from "node:assert/strict";

import {
  FRAME_CLASS,
  controlGroups,
  evidenceCodes,
  fixSteps,
  issueRows,
  locationRows,
  riskRingClass,
  riskRingFraction,
  severityTone,
} from "./findingDialogModel";

assert.equal(severityTone("Critical"), "critical");
assert.equal(severityTone("HIGH"), "high");
assert.equal(severityTone(null), "info");
assert.equal(severityTone("Info"), "info");
for (const tone of Object.values(FRAME_CLASS)) {
  assert.match(tone, /border-t-4/, "top edge");
  assert.match(tone, /dark:border-t-/, "a dark variant");
}

assert.ok(Math.abs(riskRingFraction(8.7) - 0.87) < 1e-9);
assert.equal(riskRingFraction(12), 1);
assert.equal(riskRingFraction(null), 0);
assert.equal(riskRingClass(9.1), "stroke-red-500");
assert.equal(riskRingClass(7), "stroke-orange-500");
assert.match(riskRingClass(undefined), /zinc/);

// location: target, host:port and what follows; the stored string is printed by the dialog as it is
assert.deepEqual(locationRows({ location: "10.232.0.64:443#client-ssl /Common/legacy-vip", target: "lb01" }), [
  ["Target", "lb01"], ["Host", "10.232.0.64"], ["Port", "443"], ["Detail", "client-ssl /Common/legacy-vip"],
]);
assert.deepEqual(locationRows({ location: "10.0.0.5:443", target: "10.0.0.5" }), [["Target", "10.0.0.5"], ["Port", "443"]]);
assert.deepEqual(locationRows({ location: "[2001:db8::1]:8443", target: null }), [["Host", "[2001:db8::1]"], ["Port", "8443"]]);
assert.deepEqual(locationRows({ location: "/etc/ssl/api.pem", target: null }), [], "a path: only the stored string");
assert.deepEqual(locationRows({ location: "/etc/ssl/api.pem", target: "/etc/ssl/api.pem" }), []);
assert.deepEqual(locationRows({ location: "C:\\keys\\a.pfx", target: "win01" }), [["Target", "win01"]], "a drive letter is no host");

// suggested fix: one step per issue, deduplicated, the row's own fix first when it is not one of them
const d = (summary: string) => ({ remediation: { summary, steps: [] } });
assert.deepEqual(fixSteps([d("Disable SSLv3."), d("Allow TLS 1.2+."), d("Disable SSLv3.")], "Disable SSLv3."), ["Disable SSLv3.", "Allow TLS 1.2+."]);
assert.deepEqual(fixSteps([d("A")], "Use B"), ["Use B", "A"]);
assert.deepEqual(fixSteps(undefined, "Only fix"), ["Only fix"]);
assert.deepEqual(fixSteps([], null), []);

// controls grouped by framework
assert.deepEqual(controlGroups([["ISO27001_A10_CRYPTOGRAPHY", "x"], ["NIST80053_SC", "y"], ["CUSTOM", "Custom control"]], {
  ISO27001_A10_CRYPTOGRAPHY: "ISO 27001 - A.10 Cryptography", NIST80053_SC: "NIST 800-53 - System and Communications Protection",
}), [
  { framework: "ISO 27001", items: [{ key: "ISO27001_A10_CRYPTOGRAPHY", label: "A.10 Cryptography" }] },
  { framework: "NIST 800-53", items: [{ key: "NIST80053_SC", label: "System and Communications Protection" }] },
  { framework: "Other controls", items: [{ key: "CUSTOM", label: "Custom control" }] },
]);

assert.deepEqual(issueRows([{ code: "A", title: "Ta", observed: "seen" }, { code: "B", title: "Tb" }]),
  [{ code: "A", title: "Ta", observed: "seen" }, { code: "B", title: "Tb", observed: null }]);
assert.deepEqual(issueRows(undefined), []);

// every finding code of the row, tied to its issue when the KB knows it (and KB codes the row does not list)
assert.deepEqual(evidenceCodes(["PROTO_SSLv3", "X"], [{ code: "PROTO_SSLv3", title: "SSLv3 accepted" }, { code: "WEAK", title: "Weak" }]), [
  { code: "PROTO_SSLv3", title: "SSLv3 accepted" }, { code: "X", title: null }, { code: "WEAK", title: "Weak" },
]);

console.log("finding dialog model tests passed");
