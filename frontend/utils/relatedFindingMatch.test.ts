/**
 * Hermetic tests for relatedFindingMatch (CERT-In "View related findings").
 * Run: npx --yes tsx utils/relatedFindingMatch.test.ts
 */
import assert from "node:assert/strict";
import {
  buildRefAliasMap,
  countRelatedFindings,
  expandRefCandidates,
  findingMatchesRelatedRefs,
  filterFindingsByRelatedRefs,
  hyphenateLocation,
} from "./relatedFindingMatch";

// --- expandRefCandidates ---
{
  const c = expandRefCandidates("modelref-gpt-4o");
  assert.ok(c.includes("modelref-gpt-4o"));
  assert.ok(c.includes("gpt-4o"));
}

{
  const c = expandRefCandidates("pkg:pypi/cryptography@41.0.0");
  assert.ok(c.some((x) => x.includes("cryptography")));
  assert.ok(c.includes("pkg:pypi/cryptography@41.0.0"));
}

{
  const c = expandRefCandidates("crypto-algo-dsa-jwt-utils-py");
  assert.ok(c.includes("crypto-algo-dsa-jwt-utils-py"));
  assert.ok(c.includes("dsa-jwt-utils-py") || c.includes("dsa"));
}

// --- hyphenateLocation ---
assert.equal(hyphenateLocation("jwt/utils.py"), "jwt-utils-py");
assert.equal(
  hyphenateLocation("tests/keys/testkey_rsa.cer"),
  "tests-keys-testkey-rsa-cer",
);

// --- CBOM: bom-ref vs Mongo id finding (live #94 shape) ---
{
  const finding = {
    id: "6a785fdd5a481e32dc1d4aa4",
    algorithm_name: "testkey_rsa.cer",
    title: "testkey_rsa.cer",
    location: "tests/keys/testkey_rsa.cer",
    description: "Expired X.509 certificate testkey_rsa.cer",
  };
  const ref = "crypto-cert-tests-keys-testkey-rsa-cer-cert";
  assert.equal(
    findingMatchesRelatedRefs(finding, [ref]),
    true,
    "location hyphenation should match CBOM cert bom-ref",
  );
  assert.equal(
    findingMatchesRelatedRefs(finding, [ref], {
      aliases: { [ref]: "testkey_rsa.cer" },
    }),
    true,
    "alias label should match algorithm_name",
  );
  // old broken logic would fail:
  assert.equal(finding.id.toLowerCase() === ref.toLowerCase(), false);
  assert.equal(finding.algorithm_name.toLowerCase().includes(ref.toLowerCase()), false);
}

{
  const finding = {
    id: "6a785fdd5a481e32dc1d4aa5",
    algorithm_name: "DSA",
    title: "DSA",
    location: "jwt/utils.py",
  };
  assert.equal(
    findingMatchesRelatedRefs(finding, ["crypto-algo-dsa-jwt-utils-py"]),
    true,
  );
}

// --- AIBOM modelref ---
{
  const finding = {
    id: "6a7861d25a481e32dc1d4adc",
    asset_name: "gpt-4o",
    title: "gpt-4o",
    location: "",
  };
  assert.equal(
    findingMatchesRelatedRefs(finding, ["modelref-gpt-4o"]),
    true,
  );
  assert.equal(
    findingMatchesRelatedRefs(finding, ["modelref-babbage-002"]),
    false,
  );
  // must not treat gpt-4o as a match for bare gpt-4 (or vice versa via reverse includes)
  assert.equal(
    findingMatchesRelatedRefs(
      { id: "1", asset_name: "gpt-4", title: "gpt-4" },
      ["modelref-gpt-4o"],
    ),
    false,
  );
  assert.equal(
    findingMatchesRelatedRefs(
      { id: "2", asset_name: "gpt-4o-mini", title: "gpt-4o-mini" },
      ["modelref-gpt-4o"],
    ),
    false,
  );
}

// --- CBOM rsa must not match bare RSA algorithm from cert path tokens ---
{
  assert.equal(
    findingMatchesRelatedRefs(
      { id: "x", algorithm_name: "RSA", title: "RSA", location: "jwt/algorithms.py" },
      ["crypto-cert-tests-keys-testkey-rsa-cer-cert"],
    ),
    false,
  );
}

// --- SBOM index refs ---
{
  const findings = [
    { id: "a", title: "Inventory: actions/cache", dependency: "actions/cache==v6.1.0" },
    { id: "b", title: "starlette DoS", dependency: "starlette@1.0.0" },
  ];
  // fabricate index 1 as sbom-dep-1
  const filtered = filterFindingsByRelatedRefs(findings, ["sbom-dep-1"]);
  assert.equal(filtered.length, 1);
  assert.equal(filtered[0].id, "b");
}

// --- sbom-dep-99 must NOT match id/title containing only "9" ---
{
  const list = Array.from({ length: 100 }, (_, i) =>
    i === 99
      ? { id: "real-99", title: "starlette DoS", dependency: "starlette@1.0.0" }
      : { id: String(i), title: `row-${i}` },
  );
  const filtered = filterFindingsByRelatedRefs(list, ["sbom-dep-99"]);
  assert.equal(filtered.length, 1);
  assert.equal(filtered[0].id, "real-99");
}

// --- exact id still works (normal / legacy) ---
{
  const finding = { id: "crypto-algo-rsa-app-py", algorithm_name: "RSA", location: "app.py" };
  assert.equal(
    findingMatchesRelatedRefs(finding, ["crypto-algo-rsa-app-py"]),
    true,
  );
}

// --- unrelated finding must not match ---
{
  const finding = {
    id: "xyz",
    algorithm_name: "AES-GCM",
    location: "crypto/aes.py",
  };
  assert.equal(
    findingMatchesRelatedRefs(finding, ["crypto-cert-tests-keys-testkey-rsa-cer-cert"]),
    false,
  );
}

// --- empty refs = no filter (caller handles) ---
assert.equal(findingMatchesRelatedRefs({ id: "x" }, []), true);

// --- exact bom_ref join (PQC charts → findings Dialog) ---
{
  const finding = {
    id: "mongo-object-id",
    bom_ref: "crypto-algo-rsa-2048-crypto-app-py",
    algorithm_name: "RSA-2048",
    location: "crypto_app.py",
  };
  assert.equal(
    findingMatchesRelatedRefs(finding, ["crypto-algo-rsa-2048-crypto-app-py"]),
    true,
  );
  assert.equal(
    findingMatchesRelatedRefs(finding, ["crypto-algo-other-file-py"]),
    false,
  );
}

// --- buildRefAliasMap ---
{
  const map = buildRefAliasMap([
    { id: "modelref-gpt-4o", label: "gpt-4o" },
    { id: "", label: "skip" },
  ]);
  assert.equal(map["modelref-gpt-4o"], "gpt-4o");
  assert.equal(map[""], undefined);
}

// --- search must stay independent: helper only does ref match ---
{
  const finding = {
    id: "1",
    algorithm_name: "SSH",
    location: "jwt/utils.py",
    description: "protocol",
  };
  // ref filter alone
  assert.equal(
    findingMatchesRelatedRefs(finding, ["crypto-protocol-ssh-jwt-utils-py"]),
    true,
  );
}

// --- countRelatedFindings: honest UI count (never refs.length) ---
{
  const findings = [
    { id: "a", component_name: "gpt-4o", title: "gpt-4o" },
    { id: "b", component_name: "claude-3", title: "claude-3" },
    { id: "c", component_name: "other", title: "other" },
  ];
  const refs = [
    "modelref-gpt-4o",
    "modelref-claude-3",
    // inventory-only refs that do not resolve to findings
    ...Array.from({ length: 48 }, (_, i) => `lib-phantom-${i}`),
  ];
  assert.equal(refs.length, 50, "simulates posture [:50] cap");
  assert.equal(
    countRelatedFindings(findings, refs, {
      aliases: {
        "modelref-gpt-4o": "gpt-4o",
        "modelref-claude-3": "claude-3",
      },
    }),
    2,
    "count must equal filter hits, not refs.length",
  );
  assert.equal(countRelatedFindings(findings, []), 0);
  assert.equal(countRelatedFindings(null, refs), 0);
}

console.log("relatedFindingMatch.test.ts: all passed");
