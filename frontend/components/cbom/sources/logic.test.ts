// Run: npx --yes tsx components/cbom/sources/logic.test.ts
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { join } from "node:path";

import {
  DEPLOY_SUPPORT,
  ago,
  ansibleSnippet,
  countHours,
  csvFirstColumn,
  defaultWindow,
  EXPOSURE_CHOICES,
  exposureFrom,
  formatDay,
  helmAgentCommand,
  installCommand,
  normalizeGrid,
  offlineImageSteps,
  setCell,
  shQuote,
  splitLines,
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

// a site that cannot pull the node image: the file from `make node-image`, its sha256 check, then docker load
{
  const docker = offlineImageSteps("docker", "registry.zeroshield.ai/cbom/scan-node:1.0")!;
  assert.ok(docker.includes("make node-image VERSION=1.0"));
  const check = docker.indexOf("sha256sum -c scan-node-1.0.tar.gz.sha256");
  const load = docker.indexOf("docker load -i scan-node-1.0.tar.gz");
  assert.ok(check >= 0 && load > check, "the checksum is checked before the image is loaded");
  assert.ok(!docker.includes("docker tag"), "the archive already carries the published name");
  const helm = offlineImageSteps("helm", "registry.zeroshield.ai/cbom/scan-node:1.0")!;
  assert.ok(helm.includes("docker push <your-registry>/cbom/scan-node:1.0") && helm.includes("./deploy/helm/cbom-scan-node"));
  // a site that set NEXT_PUBLIC_CBOM_NODE_IMAGE: the loaded image is re-tagged to the name the command runs
  assert.ok(offlineImageSteps("docker", "mirror.bank.local/zs/scan-node:1.1")!
    .includes("docker tag registry.zeroshield.ai/cbom/scan-node:1.1 mirror.bank.local/zs/scan-node:1.1"));
  assert.equal(offlineImageSteps("ami", "registry.zeroshield.ai/cbom/scan-node:1.0"), null);
  assert.equal(offlineImageSteps("ova", "registry.zeroshield.ai/cbom/scan-node:1.0"), null);
  // the same steps the scan node README documents, and the make target exists (run from frontend/)
  const readme = readFileSync(join("..", "scan_node", "README.md"), "utf8");
  assert.ok(readme.includes("make node-image") && readme.includes("sha256sum -c scan-node-<version>.tar.gz.sha256")
    && readme.includes("docker load -i scan-node-<version>.tar.gz"));
  assert.ok(/^node-image:/m.test(readFileSync(join("..", "Makefile"), "utf8")));
}

console.log("logic.test.ts: all checks passed");
