// Run: npx --yes tsx components/cbom/sources/logic.test.ts
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { join } from "node:path";

import {
  DEFAULT_NODE_IMAGE,
  DEPLOY_SUPPORT,
  KIT_STEPS,
  ago,
  ansibleSnippet,
  blankSecretError,
  countHours,
  csvFirstColumn,
  defaultWindow,
  downloadKinds,
  downloadLabel,
  EXPOSURE_CHOICES,
  exposureFrom,
  formatDateTime,
  formatDay,
  helmAgentCommand,
  installCommand,
  nodeInstallNames,
  mixedGroupScope,
  nodeImages,
  normalizeGrid,
  notAvailable,
  readTextFile,
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
  assert.ok(one.includes("\ndocker run -d --pull never --name zs-scan-node-dc-mumbai-01 ") && one.includes("-v zs-node-dc-mumbai-01:/var/lib/zs-node"));
  assert.ok(two.includes("\ndocker run -d --pull never --name zs-scan-node-dmz-pune ") && two.includes("-v zs-node-dmz-pune:/var/lib/zs-node"));
  assert.ok(installCommand("docker", { token: "t", apiUrl: "u", image: "reg/x:1", name: "n", pull: true }).startsWith("docker run -d --name zs-scan-node-n "));
  const h1 = installCommand("helm", { token: "t", apiUrl: "u", image: "reg/x:2.0", name: "dc-mumbai-01" });
  const h2 = installCommand("helm", { token: "t", apiUrl: "u", image: "reg/x:2.0", name: "dmz.pune" });
  assert.ok(h1.includes("\nhelm upgrade --install zs-scan-node-dc-mumbai-01 ") && h2.includes("\nhelm upgrade --install zs-scan-node-dmz-pune "));
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
// schedules: the next run in the team's zone, matching "Daily at 19:11 (Asia/Kolkata)" whatever the browser's zone
assert.match(formatDateTime("2026-11-10T13:41:00Z", "Asia/Kolkata"), /07:11|19:11/);
assert.match(formatDateTime("2026-11-10T13:41:00Z", "UTC"), /01:41|13:41/);
assert.equal(formatDateTime("2026-11-10T13:41:00Z", "Not/AZone"), formatDateTime("2026-11-10T13:41:00Z"));
assert.equal(formatDateTime(null, "UTC"), "—");

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

// Local lab round 5 (u1): MySQL 8's auto-generated /var/lib/mysql/ca.pem ends with "\n\0"; uploading it as the MySQL
// source's CA said "ca.pem is a binary file" and the source could not be saved with a password.
const fileChecks = (async () => {
  const pem = "-----BEGIN CERTIFICATE-----\nMIIB\n-----END CERTIFICATE-----\n";
  assert.equal(await readTextFile(new File([pem + "\0"], "ca.pem")), pem);
  assert.equal(await readTextFile(new File([pem + "\0\0"], "ca.pem")), pem);
  await assert.rejects(readTextFile(new File(["-----BEGIN\0CERTIFICATE-----\n"], "x.pem")), /is a binary file/);
  await assert.rejects(readTextFile(new File([new Uint8Array([0xff, 0xfe, 0x41])], "x.pem")), /not UTF-8/);
})();

// Local lab round 5 (u1): one container images source with two images and no cluster read "Kubernetes: 2 clusters"
// on Review & Run (its units are images, planning.py); an HSM counted as a database the same way.
assert.equal(mixedGroupScope("kubernetes", { container_images: 1 }, 2), "2 container images");
assert.equal(mixedGroupScope("kubernetes", { kubernetes: 2, container_images: 1 }, 5), "2 clusters · 3 container images");
assert.equal(mixedGroupScope("kubernetes", { kubernetes: 1 }, 1), "1 cluster");
assert.equal(mixedGroupScope("databases", { database: 2 }, 2), "2 databases");
assert.equal(mixedGroupScope("databases", { database: 2, key_manager: 1 }, 3), "2 databases · 1 HSM or key manager");
assert.equal(mixedGroupScope("databases", { key_manager: 2 }, 2), "2 HSMs or key managers");

// Customers have no repository and no ZeroShield registry (owner, staging 14 Nov): the Docker and Helm commands load
// the image file the server serves (Download scan node image), check it first, and never pull it, unless the server
// names a registry customers can pull from.
{
  const opts = { token: "zsr_T", apiUrl: "https://api.example", name: "dc-1" }
  const loaded = nodeImages(undefined).loaded
  assert.equal(loaded.image, DEFAULT_NODE_IMAGE)
  assert.equal(DEFAULT_NODE_IMAGE, "zeroshield/cbom-scan-node:1.0.0")
  const docker = installCommand("docker", { ...opts, ...loaded })
  const check = docker.indexOf("sha256sum -c scan-node-1.0.0.tar.gz.sha256")
  const load = docker.indexOf("docker load -i scan-node-1.0.0.tar.gz")
  const run = docker.indexOf("docker run -d --pull never --name zs-scan-node-dc-1")
  assert.ok(check >= 0 && load > check && run > load, docker)
  assert.ok(docker.trimEnd().endsWith("  zeroshield/cbom-scan-node:1.0.0"), "runs the name the file loads as")
  // the image the scan_node_image.sh archive is saved under is the one the command runs (SCAN_NODE_IMAGE default)
  const script = readFileSync(join("..", "scripts", "release", "scan_node_image.sh"), "utf8")
  assert.ok(script.includes('IMAGE="${SCAN_NODE_IMAGE:-zeroshield/cbom-scan-node}"'))
  assert.ok(readFileSync(join("..", "scan_node", "zs_scan_node", "__init__.py"), "utf8").includes('VERSION = "1.0.0"'))
  // the server's names win: its file names and the name its file loads as
  const served = nodeImages({
    version: "1.2.0", image_ref: "zeroshield/cbom-scan-node:1.2.0", pull_image_ref: null,
    artifacts: [
      { kind: "image", label: "", available: true, filename: "scan-node-1.2.0.tar.gz", size: 1, sha256: "a".repeat(64), message: null },
      { kind: "helm-chart", label: "", available: true, filename: "cbom-scan-node-1.2.0.tgz", size: 1, sha256: "b".repeat(64), message: null },
    ],
  })
  assert.equal(served.pulled, null, "no registry configured: no pull variant")
  const helm = installCommand("helm", { ...opts, ...served.loaded })
  assert.ok(helm.includes('REGISTRY=registry.example.internal/zeroshield') && helm.includes("docker load -i scan-node-1.2.0.tar.gz"), helm)
  assert.ok(helm.includes('docker tag zeroshield/cbom-scan-node:1.2.0 "$REGISTRY/cbom-scan-node:1.2.0"'), helm)
  assert.ok(helm.includes('docker push "$REGISTRY/cbom-scan-node:1.2.0"'), helm)
  assert.ok(helm.includes("helm upgrade --install zs-scan-node-dc-1 ./cbom-scan-node-1.2.0.tgz \\"), helm)
  assert.ok(helm.includes(`--set image.repository="$REGISTRY/cbom-scan-node" --set image.tag='1.2.0'`), helm)
  assert.ok(!helm.includes("oci://"), "the chart is the downloaded file")
  const agents = helmAgentCommand({ poolToken: "zsp_T", apiUrl: "https://api.example", ...served.loaded })
  assert.ok(agents.includes("helm upgrade --install zs-host-agents ./cbom-scan-node-1.2.0.tgz") && agents.includes('"$REGISTRY/cbom-scan-node"'), agents)
  // a registry the server names (CBOM_NODE_IMAGE_REF): a pull variant for Docker, a one-command Helm install
  const both = nodeImages({ version: "1.2.0", image_ref: "zeroshield/cbom-scan-node:1.2.0", pull_image_ref: "reg.bank.example:5000/zs/scan-node:1.2.0", artifacts: [] })
  assert.ok(both.pulled && both.pulled.pull)
  const pulled = installCommand("docker", { ...opts, ...both.pulled! })
  assert.ok(!pulled.includes("--pull never") && !pulled.includes("docker load") && pulled.trimEnd().endsWith("reg.bank.example:5000/zs/scan-node:1.2.0"), pulled)
  const helmPull = installCommand("helm", { ...opts, ...both.pulled! })
  assert.ok(helmPull.includes("--set image.repository='reg.bank.example:5000/zs/scan-node' --set image.tag='1.2.0'") && !helmPull.includes("REGISTRY="), helmPull)
  // a build's NEXT_PUBLIC_CBOM_NODE_IMAGE counts as a registry only when the server names none
  assert.equal(nodeImages(undefined, "ghcr.io/o/devsecshield-scan-node:dev-1").pulled?.image, "ghcr.io/o/devsecshield-scan-node:dev-1")
  assert.equal(nodeImages(undefined, "").pulled, null)
  // the AMI and the OVA are built with the downloaded kit: their settings still come from the wizard
  assert.ok(installCommand("ami", { ...opts, ...loaded }).includes("AMI build kit"))
  assert.ok(installCommand("ova", { ...opts, ...loaded }).includes("OVA build kit"))
}

// The download buttons say what they are and how big; a file the server does not hold says so.
{
  const image = { kind: "image" as const, label: "Scan node image", available: true, filename: "scan-node-1.0.0.tar.gz",
    size: 66_270_412, sha256: "3f9a1c2b7d4e5f60718293a4b5c6d7e8f90123456789abcdef0123456789abcd", message: null }
  assert.equal(downloadLabel("image", image), "Download scan node image (63.2 MB, sha256 3f9a1c2b7d4e…)")
  assert.equal(downloadLabel("ova-kit", null), "Download OVA build kit")
  assert.equal(downloadLabel("ami-kit", { ...image, kind: "ami-kit", available: false, size: null, sha256: null }), "Download AMI build kit")
  assert.equal(downloadLabel("helm-chart", { ...image, kind: "helm-chart", size: 20_480, sha256: null }), "Download Helm chart (0.0 MB)")
  assert.deepEqual(downloadKinds("docker"), ["image"])
  assert.deepEqual(downloadKinds("helm"), ["helm-chart", "image"])
  assert.deepEqual(downloadKinds("ova"), ["ova-kit", "image"])
  assert.deepEqual(downloadKinds("ami"), ["ami-kit", "image"])
  assert.equal(notAvailable("ova-kit", null), "OVA build kit is not available on this server yet. Contact your administrator.")
  assert.equal(notAvailable("image", { ...image, available: false, message: "Scan node image is not available on this server yet. Contact your administrator." }),
    "Scan node image is not available on this server yet. Contact your administrator.")
  // the server's sentence and the wizard's fallback are the same (backend/routers/cbom_node_artifacts.py NOT_AVAILABLE)
  const router = readFileSync(join("..", "backend", "routers", "cbom_node_artifacts.py"), "utf8")
  assert.ok(router.includes('NOT_AVAILABLE = "{label} is not available on this server yet. Contact your administrator."'))
  assert.equal(KIT_STEPS.ova.length, 3)
  assert.equal(KIT_STEPS.ami.length, 3)
  assert.ok(DEPLOY_SUPPORT.ova.note.includes("build kit") && DEPLOY_SUPPORT.ami.note.includes("build kit"))
}

fileChecks.then(
  () => console.log("logic.test.ts: all checks passed"),
  (err) => {
    console.error(err);
    process.exit(1);
  },
);
