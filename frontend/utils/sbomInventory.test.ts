/**
 * Hermetic tests for the Software bill of materials table rows.
 * Run: npx --yes tsx utils/sbomInventory.test.ts
 */
import assert from "node:assert/strict";
import {
  inventoryRowsFromCycloneDx,
  overallComplianceFromBom,
} from "./sbomInventory";

const bom = {
  bomFormat: "CycloneDX",
  specVersion: "1.6",
  metadata: {
    timestamp: "2026-08-10T06:22:34Z",
    authors: [{ name: "DevSecShield" }],
    component: { "bom-ref": "app", name: "juice-shop", type: "application" },
    properties: [{ name: "dss:compliance", value: "fail" }],
  },
  components: [
    {
      "bom-ref": "pkg:maven/org.springframework/spring-core@5.3.18",
      type: "library",
      name: "Spring Framework—Spring Core",
      version: "5.3.18",
      purl: "pkg:maven/org.springframework/spring-core@5.3.18",
      supplier: { name: "VMware Tanzu" },
      licenses: [{ license: { id: "Apache-2.0" } }],
      hashes: [{ alg: "SHA-256", content: "abc123" }],
      properties: [{ name: "dss:compliance", value: "fail" }],
    },
    {
      "bom-ref": "pkg:maven/com.github.ben-manes.caffeine/caffeine@2.9.3",
      type: "library",
      name: "Caffeine",
      version: "2.9.3",
      purl: "pkg:maven/com.github.ben-manes.caffeine/caffeine@2.9.3",
      licenses: [{ license: { id: "Apache-2.0" } }],
      properties: [{ name: "dss:compliance", value: "pass" }],
    },
  ],
  dependencies: [
    {
      ref: "app",
      dependsOn: ["pkg:maven/org.springframework/spring-core@5.3.18"],
    },
    {
      ref: "pkg:maven/org.springframework/spring-core@5.3.18",
      dependsOn: ["pkg:maven/com.github.ben-manes.caffeine/caffeine@2.9.3"],
    },
  ],
  vulnerabilities: [
    {
      id: "CVE-2022-22971",
      affects: [{ ref: "pkg:maven/org.springframework/spring-core@5.3.18" }],
    },
    {
      id: "CVE-2022-22970",
      affects: [{ ref: "pkg:maven/org.springframework/spring-core@5.3.18" }],
    },
  ],
};

assert.equal(overallComplianceFromBom(bom), "fail");

const rows = inventoryRowsFromCycloneDx(bom);
assert.equal(rows.length, 2);

const spring = rows[0];
assert.equal(spring.name, "Spring Framework—Spring Core");
assert.equal(spring.supplier, "VMware Tanzu");
assert.equal(spring.version, "5.3.18");
assert.equal(spring.uniqueId, "Apache-2.0");
assert.equal(spring.relationship, "Included in juice-shop");
assert.ok(spring.subDependencies.includes("Caffeine"));
assert.equal(spring.subSubDependencies, "None");
assert.equal(spring.hash, "SHA-256:abc123");
assert.equal(spring.author, "—");
assert.ok(spring.cves.includes("CVE-2022-22971"));
assert.ok(spring.cves.includes("CVE-2022-22970"));
assert.equal(spring.dateAdded, "08.10.26");
assert.equal(spring.status, "fail");

const caffeine = rows[1];
assert.equal(caffeine.name, "Caffeine");
assert.equal(caffeine.cves, "N/A");
assert.equal(caffeine.status, "pass");
assert.equal(caffeine.relationship, "Included in Spring Framework—Spring Core");

{
  const duped = inventoryRowsFromCycloneDx({
    metadata: {
      timestamp: "2026-08-10T06:22:34Z",
      authors: [{ name: "DevSecShield" }],
      component: { name: "requests", "bom-ref": "app" },
      properties: [{ name: "dss:compliance", value: "fail" }],
    },
    components: [
      {
        name: "actions/checkout",
        version: "v7.0.0",
        purl: "pkg:github/actions/checkout@v7.0.0?package-id=aaa",
        licenses: [{ license: { id: "MIT" } }],
        author: "actions",
        supplier: { name: "GitHub" },
        evidence: { occurrences: [{ location: "/.github/workflows/lint.yml" }] },
        properties: [{ name: "dss:compliance", value: "pass" }],
      },
      {
        name: "actions/checkout",
        version: "v7.0.0",
        purl: "pkg:github/actions/checkout@v7.0.0?package-id=bbb",
        evidence: { occurrences: [{ location: "/.github/workflows/codeql-analysis.yml" }] },
        properties: [{ name: "dss:compliance", value: "pass" }],
      },
      {
        name: "actions/checkout",
        version: "9c091bb21b7c1c1d1991bb908d89e4e9dddfe3e0",
        purl: "pkg:github/actions/checkout@9c091bb21b7c1c1d1991bb908d89e4e9dddfe3e0",
        licenses: [{ license: { id: "MIT" } }],
        hashes: [{ alg: "SHA-1", content: "9c091bb21b7c1c1d1991bb908d89e4e9dddfe3e0" }],
        evidence: { occurrences: [{ location: "/.github/workflows/run-tests.yml" }] },
        properties: [{ name: "dss:compliance", value: "pass" }],
      },
    ],
  });
  assert.equal(duped.length, 2);
  const tag = duped.find((r) => r.version === "v7.0.0");
  const sha = duped.find((r) => r.version.includes("commit"));
  assert.ok(tag);
  assert.ok(sha);
  assert.equal(tag!.name, "actions/checkout");
  assert.equal(tag!.supplier, "GitHub");
  assert.equal(tag!.author, "actions");
  assert.equal(tag!.uniqueId, "MIT");
  assert.ok(tag!.relationship.includes("lint.yml"));
  assert.ok(tag!.relationship.includes("codeql-analysis.yml"));
  assert.equal(sha!.version, "9c091bb (commit)");
  assert.ok(sha!.hash.startsWith("SHA-1:"));
  assert.ok(sha!.relationship.includes("run-tests.yml"));
}

{
  const filled = inventoryRowsFromCycloneDx({
    metadata: {
      timestamp: "2026-08-18T12:00:00Z",
      component: { name: "RiskPilot", "bom-ref": "app" },
      properties: [{ name: "dss:compliance", value: "pass" }],
    },
    components: [
      {
        name: "azure-core",
        version: "1.36.0 (python)",
        purl: "pkg:pypi/azure-core@1.36.0",
        supplier: { name: "PyPI" },
        author: "Microsoft Corporation",
        licenses: [{ license: { id: "MIT" } }],
        hashes: [{ alg: "SHA-256", content: "fee9923a3a753e94a259563429f3644aaf05c486" }],
        properties: [
          { name: "dss:compliance", value: "pass" },
          { name: "declared:depends", value: "aiohttp, requests" },
        ],
      },
      {
        name: "aiohttp",
        version: "3.13.0",
        purl: "pkg:pypi/aiohttp@3.13.0",
        supplier: { name: "PyPI" },
        author: "aiohttp team",
        licenses: [{ license: { id: "Apache-2.0" } }],
        hashes: [{ alg: "SHA-256", content: "ca69ec38adf5cadc0123456789abcdef" }],
        properties: [
          { name: "dss:compliance", value: "pass" },
          { name: "declared:depends", value: "aiosignal, attrs" },
        ],
      },
      {
        name: "protobuf",
        version: "6.32.1",
        purl: "pkg:pypi/protobuf@6.32.1",
        supplier: { name: "PyPI" },
        author: "protobuf",
        licenses: [{ license: { id: "BSD-3-Clause" } }],
        hashes: [{ alg: "SHA-256", content: "a8a32a84bc9f2aad0123456789abcdef" }],
        properties: [
          { name: "dss:compliance", value: "pass" },
          { name: "declared:depends", value: "" },
        ],
      },
    ],
    dependencies: [
      {
        ref: "pkg:pypi/azure-core@1.36.0",
        dependsOn: ["pkg:pypi/aiohttp@3.13.0"],
      },
    ],
  });
  const azure = filled.find((r) => r.name === "azure-core")!;
  assert.equal(azure.supplier, "PyPI");
  assert.equal(azure.version, "1.36.0");
  assert.equal(azure.uniqueId, "MIT");
  assert.equal(azure.author, "Microsoft Corporation");
  assert.ok(azure.hash.startsWith("SHA-256:"));
  assert.ok(azure.subDependencies.includes("aiohttp"));
  assert.ok(azure.subSubDependencies.includes("aiosignal"));
  assert.equal(azure.cves, "N/A");
  const proto = filled.find((r) => r.name === "protobuf")!;
  assert.equal(proto.subDependencies, "None");
  assert.equal(proto.subSubDependencies, "None");
}

{
  const ghLeaf = inventoryRowsFromCycloneDx({
    metadata: {
      timestamp: "2026-08-18T12:00:00Z",
      component: { name: "flask", "bom-ref": "app" },
      properties: [{ name: "dss:compliance", value: "pass" }],
    },
    components: [
      {
        name: "astral-sh/setup-uv",
        version: "v9.0.0",
        purl: "pkg:github/astral-sh/setup-uv@v9.0.0",
        author: "astral-sh",
        supplier: { name: "GitHub" },
        licenses: [{ license: { id: "MIT" } }],
        hashes: [{ alg: "SHA-1", content: "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb" }],
        properties: [
          { name: "dss:compliance", value: "pass" },
          { name: "declared:depends", value: "" },
        ],
      },
    ],
  });
  assert.equal(ghLeaf[0].subDependencies, "None");
  assert.equal(ghLeaf[0].subSubDependencies, "None");
  assert.notEqual(ghLeaf[0].subDependencies, "—");
}

const empty = inventoryRowsFromCycloneDx({ components: [] });
assert.deepEqual(empty, []);

console.log("sbomInventory.test.ts: ok");
