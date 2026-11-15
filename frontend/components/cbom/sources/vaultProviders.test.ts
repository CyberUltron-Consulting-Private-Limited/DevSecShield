// Run: npx --yes tsx components/cbom/sources/vaultProviders.test.ts
// #364: CyberArk and Azure Key Vault are offered as "not available yet" (disabled, not hidden) in every credential form,
// the node-side settings are shown per provider, and the source forms warn when the chosen node reports it cannot
// read the vault (the same checks and wording as the CMDB import's pre-check, vault_support.node_problem). #365: both
// KV v2 forms of the prefix are accepted.
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { join } from "node:path";

import type { CbomNodeVault } from "@/utils/backend_api";

import { NODE_SETTINGS, VAULT_PROVIDERS, nodeVaultProblem, unavailableProblem } from "./vaultProviders";

assert.deepEqual(VAULT_PROVIDERS.map((p) => [p.value, p.available, p.optionLabel]), [
  ["hashicorp", true, "HashiCorp Vault"],
  ["aws_secrets_manager", true, "AWS Secrets Manager"],
  ["cyberark", false, "CyberArk (not available yet)"],
  ["azure_key_vault", false, "Azure Key Vault (not available yet)"],
]);
// the backend's own refusal (vault_support.unavailable_problem)
assert.equal(unavailableProblem("cyberark"),
  "CyberArk is not available yet: no scan node version reads it; use HashiCorp Vault or AWS Secrets Manager");
assert.equal(unavailableProblem("hashicorp"), null);

// what the customer sets on the node, per provider (scan_node/README.md "Vault credentials")
assert.deepEqual(NODE_SETTINGS.hashicorp?.map((s) => s.name), ["ZS_VAULT_PATH_PREFIX", "VAULT_ADDR", "VAULT_TOKEN", "ZS_VAULT_CA_FILE"]);
assert.deepEqual(NODE_SETTINGS.aws_secrets_manager?.map((s) => s.name), ["ZS_VAULT_PATH_PREFIX", "AWS role"]);
assert.match(NODE_SETTINGS.aws_secrets_manager![1].what, /secretsmanager:GetSecretValue/);
assert.equal(NODE_SETTINGS.cyberark, undefined);

const ready: CbomNodeVault = { enabled: true, providers: ["hashicorp", "aws_secrets_manager"], prefix: "secret/cbom",
  setup: { hashicorp: "ready", aws_secrets_manager: "ready" } };
const node = (vault?: CbomNodeVault) => ({ name: "mum-01", vault });

// #365: either KV v2 form of the path passes the node's prefix (reported without data/)
assert.equal(nodeVaultProblem(node(ready), "hashicorp", "secret/data/cbom/pg1"), null);
assert.equal(nodeVaultProblem(node(ready), "hashicorp", "secret/cbom/pg1"), null);
assert.equal(nodeVaultProblem(node(ready), "hashicorp", "secret/data/other/pg1"),
  "the path is outside the prefix scan node mum-01 allows (secret/cbom/... or secret/data/cbom/...)");
assert.equal(nodeVaultProblem(node(ready), "hashicorp", "secret/data/cbom"),
  "the path is outside the prefix scan node mum-01 allows (secret/cbom/... or secret/data/cbom/...)");
// AWS secret names are read as written (no data/ rewrite), so they are left to the node
assert.equal(nodeVaultProblem(node(ready), "aws_secrets_manager", "cbom/pg1"), null);
assert.equal(nodeVaultProblem(node({ ...ready, enabled: false }), "hashicorp", "secret/cbom/pg1"),
  "scan node mum-01 has vault use off: its operator sets ZS_VAULT_PATH_PREFIX (and, for HashiCorp Vault, VAULT_ADDR and VAULT_TOKEN) on the node");
assert.equal(nodeVaultProblem(node({ ...ready, providers: ["hashicorp"] }), "aws_secrets_manager", "cbom/pg1"),
  "scan node mum-01 cannot read AWS Secrets Manager (update the node to a version that does)");
assert.equal(nodeVaultProblem(node({ ...ready, setup: { hashicorp: "VAULT_ADDR and VAULT_TOKEN are not set on this scan node" } }),
  "hashicorp", "secret/cbom/pg1"),
  "scan node mum-01 is not set up for HashiCorp Vault: VAULT_ADDR and VAULT_TOKEN are not set on this scan node");
// a node that has not reported is not warned about
assert.equal(nodeVaultProblem(node(undefined), "hashicorp", "x/y"), null);
assert.equal(nodeVaultProblem(node({ enabled: null, providers: null, prefix: null, setup: {} }), "hashicorp", "x/y"), null);
assert.equal(nodeVaultProblem(null, "hashicorp", "x/y"), null);

// every form takes the shared list (disabled "not available yet" items, not its own copy) and shows the node settings
const here = join(process.cwd(), "components/cbom/sources");
for (const [file, panel] of [
  ["ServersTab.tsx", true], ["ClustersDatabasesTab.tsx", true], ["CmdbImportDialog.tsx", true],
  ["fleet/CredentialsSection.tsx", true],
] as const) {
  const text = readFileSync(join(here, file), "utf8");
  assert.doesNotMatch(text, /value: "cyberark"|value="cyberark"/, `${file} keeps its own vault list`);
  assert.match(text, /VAULT_PROVIDERS\.map/, `${file} does not use the shared vault list`);
  assert.match(text, /disabled=\{!p\.available\}/, `${file} does not mark unavailable vaults`);
  if (panel) assert.match(text, /<VaultNodeSettings/, `${file} does not show the node-side vault settings`);
}

console.log("vaultProviders: ok");
