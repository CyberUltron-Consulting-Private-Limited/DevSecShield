// Run: npx --yes tsx components/cbom/heatmapLogic.test.ts
import assert from "node:assert/strict";

import { algorithmFamily, codeHeatmap, daysLeft, expiryBand, groupByDay, isFindingRow, monthGrid } from "./heatmapLogic";

// the same table as backend heatmap.algorithm_family
assert.equal(algorithmFamily(["RSA"], "certificate"), "RSA");
assert.equal(algorithmFamily([null, "X25519MLKEM768"], "tls_endpoint"), "Post-quantum");
assert.equal(algorithmFamily(["x25519"], "tls_endpoint"), "Elliptic curve");
assert.equal(algorithmFamily(["ssh-ed25519"], "ssh_host_key"), "EdDSA");
assert.equal(algorithmFamily(["ssh-dss"], "ssh_host_key"), "DSA");
assert.equal(algorithmFamily(["DES-CBC3-SHA"], "tls_endpoint"), "DES / 3DES");
assert.equal(algorithmFamily(["md5WithRSAEncryption"], "certificate"), "RSA");
assert.equal(algorithmFamily([null], "tls_endpoint"), "Protocol (no key data)");
assert.equal(algorithmFamily([null], "crypto_library"), "Library");
assert.equal(algorithmFamily(["3DES-CBC"], "algorithm"), "DES / 3DES");
assert.equal(algorithmFamily(["AES-256-GCM"], "algorithm"), "AES");
assert.equal(algorithmFamily(["static-iv (iv, app.py)"], "related-crypto-material"), "Other");

assert.equal(isFindingRow({ title: "legacy" }), true);
assert.equal(isFindingRow({ title: "AES", finding_codes: [] }), false);
assert.equal(isFindingRow({ title: "RSA", finding_codes: [], quantum_vulnerable: true }), true);

const heat = codeHeatmap([
  { title: "RSA-1024", asset_type: "algorithm", impact: "High", finding_codes: ["WEAK_ALGORITHM"] },
  { title: "RSA-2048", asset_type: "algorithm", impact: "Low", finding_codes: ["QUANTUM_VULNERABLE"] },
  { title: "AES-256-GCM", asset_type: "algorithm", finding_codes: [] },
  { title: "cert.pem", algorithm_name: "RSA", asset_type: "certificate", impact: "Critical", finding_codes: ["CERT_EXPIRED"] },
]);
assert.deepEqual(heat.rows, ["RSA", "AES"]);
assert.deepEqual(heat.columns, ["algorithm", "certificate"]);
const rsaAlgo = heat.cells.find((c) => c.row === "RSA" && c.column === "algorithm")!;
assert.equal(rsaAlgo.count, 2);
assert.equal(rsaAlgo.worst, "High");
assert.equal(heat.cells.find((c) => c.row === "AES")!.worst, "none");

assert.equal(expiryBand(-1), "expired");
assert.equal(expiryBand(0), "30");
assert.equal(expiryBand(45), "60");
assert.equal(expiryBand(90), "90");
assert.equal(expiryBand(91), "later");
assert.equal(daysLeft(new Date("2026-12-01T00:00:00Z"), new Date("2026-11-01T00:00:00Z")), 30);

const nov = monthGrid(2026, 10); // November 2026 starts on a Sunday
assert.equal(nov[0].filter(Boolean).length, 1);
assert.equal(nov[0][6]!.getUTCDate(), 1);
assert.equal(nov.flat().filter(Boolean).length, 30);
assert.ok(nov.every((week) => week.length === 7));

const byDay = groupByDay([{ not_after: "2026-11-14T10:00:00Z" }, { not_after: "2026-11-14T23:59:59Z" }, { not_after: null }]);
assert.deepEqual([...byDay.keys()], ["2026-11-14"]);
assert.equal(byDay.get("2026-11-14")!.length, 2);

console.log("heatmapLogic tests passed");
