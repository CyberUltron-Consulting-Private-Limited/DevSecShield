// node --test e2e/cbom/flow/  (no browser, no docker: the docker probes are injected)
import assert from "node:assert/strict";
import { test } from "node:test";
import { randomBytes } from "node:crypto";
import { allowedDiff, allowedTokens, sameTokens, splitCommand, tokenDiff } from "./command.mjs";

// a registration token made at test time, so no token-shaped literal sits in the repository
const TOKEN = `zsr_${randomBytes(18).toString("base64url")}`;

const UI = [
  "docker run -d --name zs-scan-node-e2e-node-1 --restart unless-stopped \\",
  "  -e ZS_API_URL='https://api.dss.test' \\",
  `  -e ZS_REGISTRATION_TOKEN='${TOKEN}' \\`,
  "  -v zs-node-e2e-node-1:/var/lib/zs-node \\",
  "  registry.zeroshield.ai/cbom/scan-node:1.0",
].join("\n");

test("splitCommand reads the UI's docker command token for token", () => {
  assert.deepEqual(splitCommand(UI), ["docker", "run", "-d", "--name", "zs-scan-node-e2e-node-1", "--restart",
    "unless-stopped", "-e", "ZS_API_URL=https://api.dss.test", "-e", `ZS_REGISTRATION_TOKEN=${TOKEN}`, "-v",
    "zs-node-e2e-node-1:/var/lib/zs-node", "registry.zeroshield.ai/cbom/scan-node:1.0"]);
  assert.deepEqual(splitCommand(`a "b c" 'd e' f\\ g`), ["a", "b c", "d e", "f g"]);
  assert.throws(() => splitCommand("a 'b"), /unterminated/);
});

test("with CB-03's stack (alias + image) the run is the UI command plus the allowed diff only", () => {
  const plan = allowedDiff(UI, { ca: "/lab-ca.pem", hasAlias: () => true, exists: () => true });
  assert.deepEqual(plan.extra, []);
  assert.deepEqual(plan.removed, []);
  const d = tokenDiff(splitCommand(UI), plan.argv);
  assert.deepEqual(d.removed, []);
  assert.deepEqual(d.added, ["--network", "cbom-e2e-net", "-e", "ZS_CA_FILE=/lab/ca.pem", "-v", "/lab-ca.pem:/lab/ca.pem:ro"]);
  assert.equal(plan.argv.at(-1), "registry.zeroshield.ai/cbom/scan-node:1.0");
  assert.equal(plan.container, "zs-scan-node-e2e-node-1");
  assert.equal(plan.volume, "zs-node-e2e-node-1");
});

test("before CB-03 every extra token is recorded, so G3 fails instead of passing quietly", () => {
  const plan = allowedDiff(UI, { ca: "/lab-ca.pem", image: "cb-01/scan-node:abc", hasAlias: () => false,
    exists: (img) => img === "cb-01/scan-node:abc" });
  assert.equal(plan.extra.length, 2);
  assert.match(plan.extra[0], /--network host/);
  assert.match(plan.extra[1], /cb-01\/scan-node:abc instead of registry/);
  assert.deepEqual(plan.removed, ["registry.zeroshield.ai/cbom/scan-node:1.0"]);
  assert.equal(plan.imageServed, false);
  assert.equal(plan.argv.at(-1), "cb-01/scan-node:abc");
});

test("a command that is not docker run is refused", () => {
  assert.throws(() => allowedDiff("helm upgrade --install x", { hasAlias: () => true, exists: () => true }), /not a docker run/);
});

test("the live G3 check: the executed argv differs from the UI command by exactly the allowed tokens", () => {
  const ui = splitCommand(UI);
  const good = allowedDiff(UI, { ca: "/lab-ca.pem", hasAlias: () => true, exists: () => true });
  const d = tokenDiff(ui, good.argv);
  assert.ok(d.removed.length === 0 && sameTokens(d.added, allowedTokens({ ca: "/lab-ca.pem" })));
  // a planner that slips in a token without reporting it in `extra` is still caught by the real diff
  const sneaky = [...good.argv.slice(0, -1), "--privileged", good.argv.at(-1)];
  const d2 = tokenDiff(ui, sneaky);
  assert.ok(!sameTokens(d2.added, allowedTokens({ ca: "/lab-ca.pem" })));
  // and so is a dropped UI token
  const dropped = good.argv.filter((t) => t !== "unless-stopped");
  assert.deepEqual(tokenDiff(ui, dropped).removed, ["unless-stopped"]);
});
