// Run: npx --yes tsx components/cbom/sources/logic.test.ts
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { join } from "node:path";

import {
  DEPLOY_SUPPORT,
  ago,
  ansibleSnippet,
  blankSecretError,
  countHours,
  csvFirstColumn,
  defaultWindow,
  EXPOSURE_CHOICES,
  exposureFrom,
  formatDay,
  helmAgentCommand,
  installCommand,
  nodeInstallNames,
  normalizeGrid,
  setCell,
  shQuote,
  splitLines,
  SUDOERS_DOWNLOAD,
  withMetadata,
  zoneFileHostnames,
} from "./logic";

// lines and CSV
assert.deepEqual(splitLines("﻿10.0.0.1\r\n\n# comment\napp-01 # trailing\n"), ["10.0.0.1", "app-01"]);
assert.deepEqual(csvFirstColumn("ip,owner\n10.0.0.1,ops\n\"10.0.0.2\";x\n"), ["10.0.0.1", "10.0.0.2"]);

// window grid
const grid = defaultWindow();
assert.equal(countHours(grid), 35);
assert.equal(grid[0][22], true);
assert.equal(grid[1][0], true);
assert.equal(grid[0][0], false);
assert.equal(countHours(setCell(grid, 6, 12, true)), 36);
assert.equal(countHours(normalizeGrid("junk")), 0);

// shell quoting cannot be broken out of
assert.equal(shQuote("a'b"), `'a'"'"'b'`);
const cmd = installCommand("docker", { token: "zsr_x'; rm -rf /", apiUrl: "https://api", image: "img:1", name: "n" });
assert.ok(cmd.includes(`ZS_REGISTRATION_TOKEN='zsr_x'"'"'; rm -rf /'`));
assert.ok(!installCommand("docker", { token: "t", apiUrl: "u", image: "i", name: "n" }).includes("HTTPS_PROXY"));
assert.ok(installCommand("helm", { token: "t", apiUrl: "u", image: "reg/x:2.0", name: "n", proxyUrl: "http://p:8080" }).includes("image.tag='2.0'"));
assert.ok(ansibleSnippet("ssh-ed25519 AAAA zs", "zs-cbom").includes("key: 'ssh-ed25519 AAAA zs'"));

// Lab UI round 5 (u1): every node gets its own container, state volume and Helm release.  With one fixed name a
// second node on the same host could not start (name taken) or, renamed, reused the first node's volume and ran as
// the first node while the new one never registered.
assert.deepEqual(nodeInstallNames("DC Mumbai 01"), { container: "zs-scan-node-dc-mumbai-01", volume: "zs-node-dc-mumbai-01", release: "zs-scan-node-dc-mumbai-01" });
assert.deepEqual(nodeInstallNames("u1-node"), { container: "zs-scan-node-u1-node", volume: "zs-node-u1-node", release: "zs-scan-node-u1-node" });
assert.equal(nodeInstallNames("._-").container, "zs-scan-node");
assert.ok(/^[a-z0-9-]{1,53}$/.test(nodeInstallNames("x".repeat(64)).release) && !nodeInstallNames("a".repeat(39) + " b").release.endsWith("-"));
{
  const one = installCommand("docker", { token: "t1", apiUrl: "https://api", image: "img:1", name: "dc-mumbai-01" });
  const two = installCommand("docker", { token: "t2", apiUrl: "https://api", image: "img:1", name: "dmz.pune" });
  assert.ok(one.startsWith("docker run -d --name zs-scan-node-dc-mumbai-01 ") && one.includes("-v zs-node-dc-mumbai-01:/var/lib/zs-node"));
  assert.ok(two.startsWith("docker run -d --name zs-scan-node-dmz-pune ") && two.includes("-v zs-node-dmz-pune:/var/lib/zs-node"));
  const h1 = installCommand("helm", { token: "t", apiUrl: "u", image: "reg/x:2.0", name: "dc-mumbai-01" });
  const h2 = installCommand("helm", { token: "t", apiUrl: "u", image: "reg/x:2.0", name: "dmz.pune" });
  assert.ok(h1.startsWith("helm upgrade --install zs-scan-node-dc-mumbai-01 ") && h2.startsWith("helm upgrade --install zs-scan-node-dmz-pune "));
}

// Helm: every value the UI sets exists in the chart (deploy/helm/cbom-scan-node/values.yaml), for the Deployment and
// for the agent DaemonSet, and the pool token is quoted like the registration token
{
  // run from frontend/ (see the first line)
  const values = readFileSync(join(process.cwd(), "..", "deploy", "helm", "cbom-scan-node", "values.yaml"), "utf8");
  const has = (path: string) => {
    let indent = -1;
    let rest = values.split("\n");
    for (const key of path.split(".")) {
      const at = rest.findIndex((line) => new RegExp(`^ {${indent + 1},}${key}:`).test(line));
      if (at < 0) return false;
      indent = rest[at].search(/\S/);
      rest = rest.slice(at + 1);
    }
    return true;
  };
  const deploy = installCommand("helm", { token: "zsr_t", apiUrl: "https://api", image: "reg/x:1.0", name: "n", proxyUrl: "http://p:3128" });
  const agent = helmAgentCommand({ poolToken: "zsp_x'; id", apiUrl: "https://api", image: "reg/x:1.0", proxyUrl: "http://p:3128" });
  for (const command of [deploy, agent]) {
    for (const m of command.matchAll(/--set ([A-Za-z.]+)=/g)) assert.ok(has(m[1]), `chart has no value ${m[1]}`);
  }
  assert.ok(agent.includes(`agent.poolToken='zsp_x'"'"'; id'`) && agent.includes("deployment.enabled=false"));
  assert.ok(DEPLOY_SUPPORT.docker.proven && DEPLOY_SUPPORT.helm.proven && !DEPLOY_SUPPORT.ami.proven && !DEPLOY_SUPPORT.ova.proven);
}

// zone files
const zone = `$ORIGIN bank.example.\n@ IN A 10.0.0.1\nwww IN A 10.0.0.2\n  IN AAAA ::1\napi.bank.example. IN CNAME www\n*.wild IN A 10.0.0.3\nmail IN MX 10 mx\n`;
assert.deepEqual(zoneFileHostnames(zone).sort(), ["api.bank.example", "bank.example", "www.bank.example"]);

// relative times use the server clock
assert.equal(ago("2026-10-31T10:00:00Z", "2026-10-31T10:00:30Z"), "30 s ago");
assert.equal(ago(null, null), "Never");
assert.equal(formatDay("bad"), "—");

// source metadata: exposure override (Cloud & Identity tab metadata dialog, Review & Run)
assert.equal(exposureFrom({ exposure: "internet" }), "internet");
assert.equal(exposureFrom({ exposure: "public" }), "auto");
assert.equal(exposureFrom(null), "auto");
assert.deepEqual(EXPOSURE_CHOICES.map((c) => c.value), ["auto", "internet", "internal", "unknown"]);
const cloudConfig = { role_arn: "arn:aws:iam::111122223333:role/R", regions: ["eu-west-1"], owner: "old", exposure: "internal" };
assert.deepEqual(withMetadata(cloudConfig, { owner: "payments", application: null }, "auto"), {
  role_arn: "arn:aws:iam::111122223333:role/R", regions: ["eu-west-1"], owner: "payments", application: null, exposure: null,
});
assert.equal(withMetadata(null, {}, "internet").exposure, "internet");

// Lab UI round 5 (u1): the sudoers download must save under the name its own install line uses.  Chromium names an
// extensionless text/plain blob "zs-cbom.txt", so `sudo install -m 0440 zs-cbom ...` failed on the downloaded file.
{
  const template = readFileSync(join(process.cwd(), "..", "backend", "utilities", "cbom_sources", "templates.py"), "utf8");
  const installed = template.match(/sudo install -m 0440 (\S+) \/etc\/sudoers\.d\//);
  assert.ok(installed, "the sudoers template has an install line");
  assert.equal(SUDOERS_DOWNLOAD.filename, installed![1]);
  assert.ok(!SUDOERS_DOWNLOAD.type.startsWith("text/"), "a text/* type makes Chromium append .txt");
}

// Lab UI round 5 (u1): editing a password source and changing its pinned host keys without typing the password again
// passed the form's check, then the server refused the save (400) and the only sign was a 1.5 s toast.
assert.equal(blankSecretError(false, false, "Enter the password"), "Enter the password");
assert.equal(blankSecretError(true, false, "Enter the password"), null); // stored and nothing that guards it changed
assert.match(blankSecretError(true, true, "Enter the password") ?? "", /^Enter it again: .*host key check/);

console.log("logic.test.ts: all checks passed");
