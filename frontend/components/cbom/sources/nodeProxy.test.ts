/**
 * #196 / #199: the "Add scan node" wizard's proxy settings reach the node in every command.
 * - #196: when the proxy inspects TLS and its CA was uploaded, the node trusts that CA for the ZeroShield API
 *   (ZS_CA_FILE, the CB-15 path): Docker bind mount, Helm trust.caSecret, AMI / OVA env and file. With a private API
 *   CA as well, the two are bundled into one file.
 * - #199: a proxy that needs a login: the command asks for the password on the host (read -s), writes user:password
 *   to zs-proxy-auth (umask 077, then 0400 for the node's user), and the node reads it with ZS_PROXY_AUTH_FILE. The
 *   password is never in the command, the env, docker inspect or the shell history; the downloads read the file
 *   through a config (curl -K -, wget --config), never on the command line.
 * Every generated shell command is checked with `bash -n`.
 * Run (frontend/): npx --yes tsx@4.23.15 components/cbom/sources/nodeProxy.test.ts
 */
import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";

import {
  CA_BUNDLE_FILE,
  PROXY_AUTH_FILE,
  TRUST_PATHS,
  TRUST_SECRETS,
  fetchCommand,
  installCommand,
  onePasteInstall,
  proxyAuthCreate,
  registryInstall,
  type InstallLinks,
} from "./logic";

const base = { token: "zsr_tok", apiUrl: "https://api.bank.internal", image: "localhost/zeroshield/cbom-scan-node:1.2.0",
  name: "dc-01", pull: true, proxyUrl: "http://mitm.bank.local:8080" };
const proxyCa = { ...base, caFile: "zs-proxy-ca.pem" };
const login = { ...base, proxyUser: "svc-zs" };
const bashOk = (code: string) => execFileSync("bash", ["-n"], { input: code }); // throws on a syntax error

// ----------------------------------------------------------------------------- #196 the proxy CA reaches the node
{
  const docker = installCommand("docker", proxyCa);
  bashOk(docker);
  assert.ok(docker.includes(`  -e ZS_CA_FILE=${TRUST_PATHS.ca} -v "$PWD/zs-proxy-ca.pem":${TRUST_PATHS.ca}:ro \\`), docker);
  assert.ok(docker.includes("  -e HTTPS_PROXY='http://mitm.bank.local:8080' \\"));
  // dev: only HTTPS_PROXY, so a node behind an inspecting proxy failed with CERTIFICATE_VERIFY_FAILED
  const both = installCommand("docker", { ...proxyCa, trust: { caFile: "/etc/pki/zs-ca.pem" } });
  bashOk(both);
  assert.ok(both.includes(`cat /etc/pki/zs-ca.pem ./zs-proxy-ca.pem > ${CA_BUNDLE_FILE} && \\`), both);
  assert.ok(both.includes(`-v "$PWD/${CA_BUNDLE_FILE}":${TRUST_PATHS.ca}:ro`) && !both.includes("-v /etc/pki/zs-ca.pem:"));
  assert.ok(both.indexOf("cat /etc/pki") < both.indexOf("docker run"));

  const helm = installCommand("helm", proxyCa);
  bashOk(helm);
  assert.ok(helm.includes(`kubectl -n zs-cbom create secret generic ${TRUST_SECRETS.ca} --from-file=ca.pem=./zs-proxy-ca.pem `), helm);
  assert.ok(helm.includes(`  --set trust.caSecret=${TRUST_SECRETS.ca} \\`));

  const ami = installCommand("ami", proxyCa);
  assert.ok(ami.includes(`      ZS_CA_FILE=${TRUST_PATHS.ca}`) && ami.includes(`#   ${TRUST_PATHS.ca}: your proxy's CA (zs-proxy-ca.pem)`), ami);
  const ova = installCommand("ova", proxyCa);
  assert.ok(ova.includes(`#   ZS_CA_FILE=${TRUST_PATHS.ca}`) && ova.includes("your proxy's CA (zs-proxy-ca.pem)"), ova);

  // no proxy CA (no TLS inspection): nothing changes
  const plain = installCommand("docker", base);
  assert.ok(!plain.includes("ZS_CA_FILE") && !plain.includes(PROXY_AUTH_FILE));
}

// ----------------------------------------------------------------------------- #199 the proxy login, never the password
{
  const make = proxyAuthCreate("svc-zs");
  assert.deepEqual(make.slice(1), [
    "read -rsp 'Password of proxy user svc-zs: ' ZS_PROXY_PW && echo && \\",
    `( umask 077 && printf '%s:%s\\n' 'svc-zs' "$ZS_PROXY_PW" > ${PROXY_AUTH_FILE} ) && unset ZS_PROXY_PW && \\`,
  ]);
  assert.deepEqual(proxyAuthCreate(null), []);

  const docker = installCommand("docker", login);
  bashOk(docker);
  assert.ok(docker.startsWith("# The proxy password stays on this host"), docker);
  assert.ok(docker.includes(`chmod 0400 ${PROXY_AUTH_FILE} && sudo chown 10001 ${PROXY_AUTH_FILE} && \\`));
  assert.ok(docker.includes(`  -e ZS_PROXY_AUTH_FILE=${TRUST_PATHS.proxyAuth} -v "$PWD/${PROXY_AUTH_FILE}":${TRUST_PATHS.proxyAuth}:ro \\`));
  assert.ok(docker.indexOf("read -rsp") < docker.indexOf("docker run") && !/HTTPS_PROXY=[^\n]*@/.test(docker));

  const helm = installCommand("helm", login);
  bashOk(helm);
  assert.ok(helm.includes(`kubectl -n zs-cbom create secret generic ${TRUST_SECRETS.proxyAuth} --from-file=auth=${PROXY_AUTH_FILE} `), helm);
  assert.ok(helm.includes(`rm -f ${PROXY_AUTH_FILE} && \\`) && helm.includes(`  --set proxyAuthSecret=${TRUST_SECRETS.proxyAuth} \\`));
  assert.ok(helm.indexOf("read -rsp") < helm.indexOf("create secret generic zs-node-proxy-auth"));

  const ami = installCommand("ami", login);
  assert.ok(ami.includes(`      ZS_PROXY_AUTH_FILE=${TRUST_PATHS.proxyAuth}`) && !ami.includes("read -rsp"), ami); // never in user data
  assert.ok(ami.includes(`#   ${TRUST_PATHS.proxyAuth}: one line svc-zs:<proxy password>`));
  const ova = installCommand("ova", login);
  assert.ok(ova.includes(`#   ZS_PROXY_AUTH_FILE=${TRUST_PATHS.proxyAuth}`), ova);

  // a registry image (docker pull / helm oci://) asks the same way
  const artifacts = { pull_image_ref: "ghcr.io/zs/cbom-scan-node:1.2.0", pull_chart_ref: "oci://ghcr.io/zs/charts/cbom-scan-node",
    pull_chart_version: "1.2.0" } as unknown as Parameters<typeof registryInstall>[1];
  for (const method of ["docker", "helm"] as const) {
    const code = registryInstall(method, artifacts, login)!;
    bashOk(code);
    assert.ok(code.startsWith("# The proxy password stays on this host") && code.includes("ZS_PROXY") , `${method}: ${code}`);
  }
}

// ----------------------------------------------------------------------------- the downloads through that proxy
{
  const file = { kind: "image", filename: "zs-node.tar", size: 1, sha256: "a".repeat(64), url: "/1/cbom/node-artifacts/image?node_ticket=t" } as const;
  const curl = fetchCommand(file, { ...login });
  bashOk(curl);
  assert.equal(curl, `sed 's/[\\\\"]/\\\\&/g; s/^/proxy-user = "/; s/$/"/' ${PROXY_AUTH_FILE} | curl -fsSL -K - --proto '=https' `
    + `--proxy 'http://mitm.bank.local:8080' 'https://api.bank.internal/1/cbom/node-artifacts/image?node_ticket=t' -o zs-node.tar `
    + `&& echo '${"a".repeat(64)}  zs-node.tar' | sha256sum -c -`);
  const wget = fetchCommand(file, { ...login, fetcher: "wget" });
  bashOk(wget);
  assert.ok(wget.startsWith(`wget -q --config=<(awk -F: '{print "proxy_user = " $1; sub(/^[^:]*:/, ""); print "proxy_password = " $0}' ${PROXY_AUTH_FILE})`), wget);
  // no proxy, or a proxy without a login: unchanged
  assert.ok(!fetchCommand(file, { apiUrl: base.apiUrl, proxyUser: "svc-zs" }).includes(PROXY_AUTH_FILE));
  assert.ok(!fetchCommand(file, { apiUrl: base.apiUrl, proxyUrl: base.proxyUrl }).includes("-K -"));

  const links: InstallLinks = { version: "1.2.0", expires_at: null, files: [{ ...file }] };
  const paste = onePasteInstall("docker", links, { ...login, ...proxyCa, proxyUser: "svc-zs" })!;
  bashOk(paste);
  const lines = paste.split("\n");
  const at = (needle: string) => lines.findIndex((l) => l.includes(needle));
  assert.ok(at("read -rsp") < at("curl -fsSL") && at("curl -fsSL") < at("sudo chown 10001") && at("sudo chown") < at("docker run"), paste);
  assert.ok(paste.includes("--cacert 'zs-proxy-ca.pem'") && paste.includes(`-v "$PWD/zs-proxy-ca.pem":${TRUST_PATHS.ca}:ro`));
}

console.log("nodeProxy.test.ts: ok");
