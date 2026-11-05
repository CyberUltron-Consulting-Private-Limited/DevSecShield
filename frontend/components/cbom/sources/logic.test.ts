// Run: npx --yes tsx components/cbom/sources/logic.test.ts
import assert from "node:assert/strict";

import {
  ago,
  ansibleSnippet,
  countHours,
  csvFirstColumn,
  defaultWindow,
  EXPOSURE_CHOICES,
  exposureFrom,
  formatDay,
  installCommand,
  normalizeGrid,
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

console.log("logic.test.ts: all checks passed");
