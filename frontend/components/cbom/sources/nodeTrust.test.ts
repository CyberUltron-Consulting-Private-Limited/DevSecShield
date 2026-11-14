/**
 * CB-15: the "Add scan node" wizard's trust options for the ZeroShield API: a private CA bundle (ZS_CA_FILE) and an
 * mTLS client certificate (ZS_CLIENT_CERT / ZS_CLIENT_KEY) in every command (Docker, Helm, AMI, OVA, the registry and
 * one-paste variants); every generated shell command is checked with `bash -n`. And the legacy-node upgrade text.
 * Run (frontend/): npx --yes tsx@4.23.15 components/cbom/sources/nodeTrust.test.ts
 */
import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";

import {
  TRUST_PATHS,
  TRUST_SECRETS,
  activeTrust,
  installCommand,
  onePasteInstall,
  registryInstall,
  trustEnvLines,
  trustProblem,
  vmTrustFiles,
  type InstallLinks,
} from "./logic";
import { upgradeText } from "./ScanNodesTab";

const base = { token: "zsr_tok", apiUrl: "https://api.bank.internal", image: "localhost/zeroshield/cbom-scan-node:1.2.0",
  name: "dc-01", pull: true };
const ca = { caFile: "/etc/pki/zs-ca.pem" };
const both = { ...ca, clientCert: "/etc/pki/zs-node.crt", clientKey: "/etc/pki/zs-node.key" };
const bashOk = (code: string) => execFileSync("bash", ["-n"], { input: code }); // throws on a syntax error

// validation
assert.equal(trustProblem(null), null);
assert.equal(trustProblem({ caFile: "" }), null);
assert.match(trustProblem({ clientCert: "/a.crt" }) ?? "", /both the client certificate and its key/);
assert.match(trustProblem({ caFile: "ca.pem" }) ?? "", /absolute path/);
assert.match(trustProblem({ caFile: "/etc/my ca.pem" }) ?? "", /without spaces/);
assert.match(trustProblem({ caFile: "/etc/ca'.pem" }) ?? "", /quotes/);
assert.equal(activeTrust({ caFile: "relative.pem" }), null); // invalid: nothing emitted
assert.equal(activeTrust({ caFile: " " }), null);

// no trust: every command is exactly what it was
for (const method of ["docker", "helm", "ami", "ova"] as const) {
  assert.equal(installCommand(method, { ...base, trust: null }), installCommand(method, base), method);
  assert.equal(installCommand(method, { ...base, trust: { caFile: "bad" } }), installCommand(method, base), method);
}

// Docker: env + read-only bind mounts, before the volume and the image
const docker = installCommand("docker", { ...base, trust: both });
assert.ok(docker.includes(`  -e ZS_CA_FILE=${TRUST_PATHS.ca} -v /etc/pki/zs-ca.pem:${TRUST_PATHS.ca}:ro \\`));
assert.ok(docker.includes(`  -e ZS_CLIENT_CERT=${TRUST_PATHS.cert} -v /etc/pki/zs-node.crt:${TRUST_PATHS.cert}:ro \\`));
assert.ok(docker.includes(`  -e ZS_CLIENT_KEY=${TRUST_PATHS.key} -v /etc/pki/zs-node.key:${TRUST_PATHS.key}:ro \\`));
assert.ok(docker.trimEnd().endsWith(base.image));
const dockerLines = docker.split("\n");
assert.ok(dockerLines.findIndex((l) => l.includes("ZS_CA_FILE")) < dockerLines.findIndex((l) => l.includes(":/var/lib/zs-node")));
bashOk(docker);
const caOnly = installCommand("docker", { ...base, trust: ca });
assert.ok(caOnly.includes("ZS_CA_FILE") && !caOnly.includes("ZS_CLIENT_"));
bashOk(caOnly);

// Helm: the Secrets first (chained), then the chart values
const helm = installCommand("helm", { ...base, trust: both });
assert.ok(helm.includes(`kubectl -n zs-cbom create secret generic ${TRUST_SECRETS.ca} --from-file=ca.pem=/etc/pki/zs-ca.pem`));
assert.ok(helm.includes(`kubectl -n zs-cbom create secret tls ${TRUST_SECRETS.client} --cert=/etc/pki/zs-node.crt --key=/etc/pki/zs-node.key`));
assert.ok(helm.includes(`--set trust.caSecret=${TRUST_SECRETS.ca}`) && helm.includes(`--set trust.clientSecret=${TRUST_SECRETS.client}`));
assert.ok(helm.indexOf("create secret") < helm.indexOf("helm upgrade --install"));
for (const line of helm.split("\n").filter((l) => l.startsWith("kubectl"))) assert.ok(line.endsWith("&& \\"), line);
bashOk(helm);

// AMI: the env file gets the variables; where the files go is said, never the key in user data
const ami = installCommand("ami", { ...base, trust: both });
for (const line of trustEnvLines(both)) assert.ok(ami.includes(`      ${line}`), line);
assert.ok(ami.includes("never in user data") && !ami.includes("/etc/pki/zs-node.key"));
assert.deepEqual(trustEnvLines(ca), [`ZS_CA_FILE=${TRUST_PATHS.ca}`]);
assert.equal(vmTrustFiles(both).length, 2);

// OVA: instructions as comments after the vApp properties
const ova = installCommand("ova", { ...base, trust: both });
assert.ok(ova.includes(`#   ZS_CA_FILE=${TRUST_PATHS.ca}`) && ova.includes("#   sudo systemctl restart zs-scan-node"));

// the registry and one-paste variants carry the same options
const reg = registryInstall("docker", { pull_image_ref: "ghcr.io/x/cbom-scan-node:1.2.0" } as never,
  { token: "zsr_tok", apiUrl: "https://api.bank.internal", name: "dc-01", trust: both });
assert.ok(reg && reg.includes("ZS_CLIENT_KEY") && reg.includes("ZS_CA_FILE"));
bashOk(reg!);
const links: InstallLinks = { version: "1.2.0", expires_at: null, files: [
  { kind: "image", filename: "cbom-scan-node-1.2.0.tar.gz", size: 1, sha256: "a".repeat(64), url: "/1/cbom/node-artifacts/image?node_ticket=t" },
  { kind: "helm-chart", filename: "cbom-scan-node-1.2.0.tgz", size: 1, sha256: "b".repeat(64), url: "/1/cbom/node-artifacts/helm-chart?node_ticket=t" },
] };
const paste = onePasteInstall("helm", links, { ...base, trust: both });
assert.ok(paste && paste.includes(`--set trust.clientSecret=${TRUST_SECRETS.client}`));
bashOk(paste!);
const pasteDocker = onePasteInstall("docker", links, { ...base, trust: ca });
assert.ok(pasteDocker && pasteDocker.includes("ZS_CA_FILE"));
bashOk(pasteDocker!);

// upgrade path text
assert.match(upgradeText({ name: "dc-01", pool_id: null }), /install command shown next.*signs every request/);
assert.match(upgradeText({ name: "agent-7", pool_id: 3 }), /agent pool token.*signs every request/);

console.log("nodeTrust.test.ts: ok");
