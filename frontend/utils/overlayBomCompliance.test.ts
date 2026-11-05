/**
 * Hermetic tests: CycloneDX download overlay keeps one Pass/Fail field.
 * Run: npx --yes tsx utils/overlayBomCompliance.test.ts
 */
import assert from "node:assert/strict";
import { overlayBomCompliance } from "./overlayBomCompliance";

const messy = {
  bomFormat: "CycloneDX",
  specVersion: "1.6",
  metadata: {
    timestamp: "2026-08-10T06:22:34Z",
    properties: [
      { name: "dss:compliance.disclaimer", value: "long rbi sebi dump" },
      { name: "dss:compliance.cert_in_sbom.verdict", value: "fail" },
      { name: "dss:compliance.rbi_free_ai_supply.coverage", value: "0.8" },
      { name: "syft:image:mediaType", value: "noise" },
    ],
  },
  components: [
    {
      name: "flask",
      version: "3.0.0",
      purl: "pkg:pypi/flask@3.0.0",
      type: "library",
      properties: [
        { name: "syft:package:foundBy", value: "python" },
        { name: "dss:compliant", value: "true" },
        { name: "dss:impact", value: "Low" },
        { name: "dss:license_type", value: "permissive" },
      ],
    },
  ],
};

const compliance = {
  disclaimer: "advisory",
  cert_in_sbom: { pass: 2, fail: 1, coverage: 0.67 },
  sebi_cscrf_sbom: { pass: 1, fail: 0, coverage: 1 },
};

const out = overlayBomCompliance(messy, compliance) as {
  metadata: { properties: Array<{ name: string; value: string }> };
  components: Array<{ properties?: Array<{ name: string; value: string }> }>;
};

const metaNames = out.metadata.properties.map((p) => p.name);
assert.deepEqual(metaNames, ["dss:compliance"]);
assert.equal(out.metadata.properties[0].value, "fail");

const compNames = (out.components[0].properties || []).map((p) => p.name);
assert.deepEqual(compNames, ["dss:compliance"]);

const cryptoKept = overlayBomCompliance(
  {
    bomFormat: "CycloneDX",
    components: [
      {
        name: "AES-256",
        type: "cryptographic-asset",
        cryptoProperties: { assetType: "algorithm" },
        properties: [
          { name: "crypto:primitive", value: "block-cipher" },
          { name: "dss:compliance.overall", value: "pass" },
        ],
      },
    ],
  },
  { nist_800_57: { pass: 1, fail: 0 } },
) as {
  components: Array<{
    cryptoProperties?: { assetType: string };
    properties?: Array<{ name: string }>;
  }>;
};
assert.equal(cryptoKept.components[0].cryptoProperties?.assetType, "algorithm");
assert.ok(
  (cryptoKept.components[0].properties || []).some((p) => p.name === "crypto:primitive"),
);
assert.ok(
  !(cryptoKept.components[0].properties || []).some((p) =>
    String(p.name).startsWith("dss:compliance."),
  ),
);

{
  const grouped = overlayBomCompliance(
    {
      bomFormat: "CycloneDX",
      components: [
        {
          name: "actions/checkout",
          version: "v7.0.0",
          purl: "pkg:github/actions/checkout@v7.0.0?package-id=aaa",
          properties: [{ name: "syft:location:0:path", value: "/.github/workflows/lint.yml" }],
        },
        {
          name: "actions/checkout",
          version: "v7.0.0",
          purl: "pkg:github/actions/checkout@v7.0.0?package-id=bbb",
          properties: [
            { name: "syft:location:0:path", value: "/.github/workflows/codeql-analysis.yml" },
          ],
        },
        {
          name: "actions/checkout",
          version: "9c091bb21b7c1c1d1991bb908d89e4e9dddfe3e0",
          purl: "pkg:github/actions/checkout@9c091bb21b7c1c1d1991bb908d89e4e9dddfe3e0?package-id=ccc",
        },
      ],
    },
    { ntia_minimum_elements: { pass: 1, fail: 0 } },
  ) as {
    components: Array<{
      version?: string;
      purl?: string;
      evidence?: { occurrences?: Array<{ location?: string }> };
    }>;
  };
  assert.equal(grouped.components.length, 2);
  const tag = grouped.components.find((c) => c.version === "v7.0.0");
  assert.equal(tag?.purl, "pkg:github/actions/checkout@v7.0.0");
  const locs = (tag?.evidence?.occurrences || []).map((o) => o.location).sort();
  assert.deepEqual(locs, [
    "/.github/workflows/codeql-analysis.yml",
    "/.github/workflows/lint.yml",
  ]);
}

{
  // Two MD5 calls in two files are two crypto assets: never merged by name@version, bom-refs kept (rev4 H2: the
  // merge dropped crypto-algo-md5-src-b-py, so a dependency or finding pointing at it dangled).
  const md5 = (file: string) => ({
    type: "cryptographic-asset",
    "bom-ref": `crypto-algo-md5-src-${file}-py`,
    name: "MD5",
    cryptoProperties: { assetType: "algorithm", algorithmProperties: { primitive: "hash" } },
    evidence: { occurrences: [{ location: `src/${file}.py`, line: 3 }] },
    properties: [{ name: "crypto:quantumVulnerable", value: "false" }],
  });
  const out = overlayBomCompliance(
    {
      bomFormat: "CycloneDX",
      components: [
        md5("a"),
        { type: "library", "bom-ref": "lib-x", name: "x", version: "1" },
        md5("b"),
        { type: "library", "bom-ref": "lib-x-2", name: "x", version: "1" },
      ],
    },
    { nist_800_57: { pass: 1, fail: 0 } },
  ) as {
    components: Array<{ "bom-ref"?: string; type?: string; evidence?: { occurrences?: Array<{ location?: string; line?: number }> } }>;
  };
  assert.deepEqual(
    out.components.map((c) => c["bom-ref"]),
    ["crypto-algo-md5-src-a-py", "lib-x", "crypto-algo-md5-src-b-py"],
    "crypto assets keep their slot and bom-ref; identical libraries still fold",
  );
  assert.deepEqual(out.components[2].evidence?.occurrences, [{ location: "src/b.py", line: 3 }]);
}

console.log("overlayBomCompliance.test.ts: ok");
