import assert from "node:assert/strict";
import {
  enrichPqcMigrationFromFindings,
  groupPqcMigrationRows,
  pqcAccordionDefaultCollapsed,
  pqcDescription,
  pqcHowToFix,
  pqcMigrationGroupKey,
  type PqcMigrationRowLike,
} from "./pqcMigrationGroup";

function row(
  partial: Partial<PqcMigrationRowLike> & { name: string },
): PqcMigrationRowLike {
  return {
    primitive: "signature",
    key_size: null,
    curve: null,
    nist_quantum_security_level: 0,
    migration_target: "ML-DSA (FIPS 204)",
    migration_roadmap: "ML-DSA-65",
    impact: "Medium",
    location: "a.py",
    bom_ref: `crypto-algo-${partial.name}-a-py`,
    ...partial,
  };
}

{
  const groups = groupPqcMigrationRows([
    row({ name: "Ed25519", curve: "Ed25519", location: "a.py", bom_ref: "r1" }),
    row({ name: "Ed25519", curve: "ed25519", location: "b.py", bom_ref: "r2" }),
    row({ name: "Ed25519", curve: "ED25519", location: "c.py", bom_ref: "r3" }),
  ]);
  assert.equal(groups.length, 1);
  assert.equal(groups[0].instances.length, 3);
}

{
  const groups = groupPqcMigrationRows([
    row({
      name: "ECDH",
      curve: "SECP384R1",
      migration_roadmap: "ML-KEM-1024",
      bom_ref: "a",
    }),
    row({
      name: "ECDH",
      curve: "SECP256R1",
      migration_roadmap: "ML-KEM-768",
      bom_ref: "b",
    }),
  ]);
  assert.equal(groups.length, 2);
}

{
  const groups = groupPqcMigrationRows([
    row({ name: "RSA", key_size: "2048", impact: "Medium", bom_ref: "m" }),
    row({ name: "RSA", key_size: "2048", impact: "High", bom_ref: "h" }),
  ]);
  assert.equal(groups.length, 1);
  assert.equal(groups[0].maxImpact, "High");
  assert.equal(
    pqcMigrationGroupKey(row({ name: "RSA", key_size: "2048" })),
    "RSA|2048||ML-DSA-65",
  );
}

{
  const many = Array.from({ length: 30 }, (_, i) =>
    row({ name: `A${i}`, bom_ref: `r${i}`, migration_roadmap: `T${i}` }),
  );
  const groups = groupPqcMigrationRows(many);
  assert.equal(pqcAccordionDefaultCollapsed(groups, many.length), true);
  assert.equal(pqcAccordionDefaultCollapsed(groups.slice(0, 2), 3), false);
}

{
  // Legacy migration (no location) joins quantum-vulnerable findings by name
  const legacy = [
    row({ name: "Ed25519", location: "", bom_ref: null, curve: "ed25519" }),
    row({ name: "Ed25519", location: null, bom_ref: null, curve: "ed25519" }),
    row({ name: "RSA", location: "", bom_ref: null, key_size: "2048" }),
  ];
  const findings = [
    {
      algorithm_name: "Ed25519",
      location: "src/cryptography/hazmat/primitives/asymmetric/ed25519.py",
      quantum_safe: false,
      description: "qv ed",
      suggested_fix: "migrate",
    },
    {
      algorithm_name: "Ed25519",
      location: "src/cryptography/hazmat/_oid.py",
      quantum_safe: false,
    },
    {
      algorithm_name: "RSA",
      location: "src/cryptography/hazmat/primitives/asymmetric/rsa.py",
      quantum_vulnerable: true,
    },
    // AES must not be consumed (not q-v)
    { algorithm_name: "AES", location: "aes.py", quantum_safe: true },
  ];
  const enriched = enrichPqcMigrationFromFindings(legacy, findings);
  assert.equal(
    enriched[0].location,
    "src/cryptography/hazmat/_oid.py",
    "sorted by location — _oid before asymmetric",
  );
  assert.equal(
    enriched[1].location,
    "src/cryptography/hazmat/primitives/asymmetric/ed25519.py",
  );
  assert.equal(
    enriched[2].location,
    "src/cryptography/hazmat/primitives/asymmetric/rsa.py",
  );
  // Description backfill comes from the matched finding (ed25519.py has "qv ed")
  assert.ok((enriched[1].description || "").includes("qv"));
  // Already-populated rows stay untouched
  const keep = enrichPqcMigrationFromFindings(
    [row({ name: "Ed25519", location: "already.py", bom_ref: "keep-me" })],
    findings,
  );
  assert.equal(keep[0].location, "already.py");
  assert.equal(keep[0].bom_ref, "keep-me");
  // No inventing when findings empty
  const empty = enrichPqcMigrationFromFindings(legacy, []);
  assert.equal((empty[0].location || "").trim(), "");
}

{
  // HoverCard fallbacks: never "—" when roadmap/target exist; construct description
  const legacySparse = row({
    name: "RSA",
    key_size: "2048",
    primitive: "pke",
    description: "",
    suggested_fix: "",
    location: "",
    bom_ref: null,
  });
  const fix = pqcHowToFix(legacySparse);
  assert.notEqual(fix, "—");
  assert.ok(fix.includes("ML-DSA-65") || fix.includes("ML-DSA"));
  const desc = pqcDescription(legacySparse);
  assert.notEqual(desc, "—");
  assert.ok(desc.includes("Quantum-vulnerable"));
  assert.ok(desc.includes("RSA"));
  assert.ok(desc.includes("2048"));
  // Prefer explicit suggested_fix when present
  assert.equal(
    pqcHowToFix(row({ name: "X", suggested_fix: "Do the thing" })),
    "Do the thing",
  );
  assert.equal(
    pqcDescription(row({ name: "X", description: "Exact finding text" })),
    "Exact finding text",
  );
}

console.log("pqcMigrationGroup.test.ts: ok");
