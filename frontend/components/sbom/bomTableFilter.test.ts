/**
 * FIX-C1 (audit G-D4-5): the SBOM table must not look empty by default.
 * Staging SBOM #8 (5 components, 0 vulnerable) showed "No components match this search" because the table opened on
 * "Vulnerable only".
 * Run: npx tsx --test components/sbom/bomTableFilter.test.ts
 */
import assert from "node:assert/strict";
import fs from "node:fs";
import path from "node:path";
import { test } from "node:test";

import { DEFAULT_BOM_VIEW, emptyBomMessage, filterBomRows } from "./bomTableFilter";
import { inventoryRowsFromCycloneDx } from "../../utils/sbomInventory";

const bom = {
  bomFormat: "CycloneDX",
  specVersion: "1.6",
  metadata: { timestamp: "2026-11-23T10:00:00Z", component: { "bom-ref": "root", name: "peva3/SmarterRouter" } },
  components: [
    { "bom-ref": "pkg:github/actions/checkout@v4", name: "actions/checkout", version: "v4", purl: "pkg:github/actions/checkout@v4" },
    { "bom-ref": "pkg:pypi/fastapi@0.109.0", name: "fastapi", version: "0.109.0", purl: "pkg:pypi/fastapi@0.109.0" },
    { "bom-ref": "pkg:pypi/jinja2@2.9.6", name: "jinja2", version: "2.9.6", purl: "pkg:pypi/jinja2@2.9.6" },
  ],
  dependencies: [{ ref: "root", dependsOn: ["pkg:github/actions/checkout@v4", "pkg:pypi/fastapi@0.109.0", "pkg:pypi/jinja2@2.9.6"] }],
  vulnerabilities: [] as unknown[],
};

test("the table opens on every component", () => {
  assert.equal(DEFAULT_BOM_VIEW, "all");
  const rows = inventoryRowsFromCycloneDx(bom);
  assert.equal(filterBomRows(rows, "", DEFAULT_BOM_VIEW).length, 3);
});

test("the vulnerable filter still works and says why it is empty", () => {
  const clean = inventoryRowsFromCycloneDx(bom);
  assert.equal(filterBomRows(clean, "", "vulnerable").length, 0);
  assert.equal(emptyBomMessage("vulnerable", "", clean.length), "None of the 3 components has a known vulnerability");
  const vulnerable = inventoryRowsFromCycloneDx({
    ...bom,
    vulnerabilities: [{ id: "GHSA-462w-v97r-4m45", affects: [{ ref: "pkg:pypi/jinja2@2.9.6" }] }],
  });
  assert.deepEqual(filterBomRows(vulnerable, "", "vulnerable").map((r) => r.name), ["jinja2"]);
  assert.deepEqual(filterBomRows(vulnerable, "fast", "all").map((r) => r.name), ["fastapi"]);
});

test("the component uses the shared default and shows both views", () => {
  const src = fs.readFileSync(path.join(__dirname, "SbomBillOfMaterialsTable.tsx"), "utf8");
  assert.match(src, /useState<BomView>\(DEFAULT_BOM_VIEW\)/);
  assert.doesNotMatch(src, /useState\(true\)/);
  assert.match(src, /data-testid="sbom-view-all"/);
  assert.match(src, /data-testid="sbom-view-vulnerable"/);
});

test("licence and hash coverage are counted like the PDF's minimum-elements table (review 6032108510 M-1)", async () => {
  const { bomCoverage } = await import("../../utils/sbomInventory");
  const offline = {
    ...bom,
    metadata: { ...bom.metadata, properties: [{ name: "dss:registry", value: "off: no registry lookup" }] },
    components: [
      { ...bom.components[0], licenses: [{ license: { id: "MIT" } }] },
      { ...bom.components[1], licenses: [{ license: { id: "LicenseRef-not-declared" } }], hashes: [{ alg: "SHA-256", content: "ab" }] },
      { ...bom.components[2] },
      { name: "" },
    ],
  };
  assert.deepEqual(bomCoverage(offline), { total: 3, licensed: 1, hashed: 1, registry: "off: no registry lookup" });
  assert.deepEqual(bomCoverage(null), { total: 0, licensed: 0, hashed: 0, registry: "" });
});
