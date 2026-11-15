/**
 * Servers form checks (#149 known_hosts, #151 CSV import header and line limit, #156 Windows/AD ports), mirrored from
 * the backend so the form says it before Save.
 * Run: npx --yes tsx components/cbom/sources/sourceFormChecks.test.ts
 */
import assert from "node:assert/strict";
import fs from "node:fs";
import path from "node:path";

import { csvFirstColumn, knownHostsProblem, mergeImportedTargets, TARGET_HEADER_WORDS, windowsPortProblem } from "./logic";

const here = path.dirname(new URL(import.meta.url).pathname);

// #151: one header list on both sides; the imported file's own header is dropped, wherever the box already is
const backend = fs.readFileSync(path.join(here, "../../../../backend/utilities/cbom_sources/targets.py"), "utf8");
const words = /_HEADER_WORDS = \{([^}]*)\}/.exec(backend);
assert.ok(words);
assert.deepEqual(Array.from(words[1].matchAll(/"([a-z]+)"/g)).map((m) => m[1]).sort(), [...TARGET_HEADER_WORDS].sort());
for (const header of ["hosts", "targets", "Addresses", "IP"]) {
  assert.deepEqual(csvFirstColumn(`${header}\n10.20.0.10\n10.20.0.11\n`), ["10.20.0.10", "10.20.0.11"], header);
}
const merged = mergeImportedTargets("10.99.0.1", csvFirstColumn("hosts\n10.20.0.10\n10.99.0.1\n"), 1000);
assert.deepEqual(merged, { text: "10.99.0.1\n10.20.0.10", error: null });
const big = csvFirstColumn("ip\n" + Array.from({ length: 1001 }, (_, i) => `10.1.${i >> 8}.${i & 255}`).join("\n"));
assert.equal(mergeImportedTargets("", big, 1000).error, "1,001 lines; the limit is 1,000 per source");

// #149: known_hosts lines only; a private key is refused before it reaches the box
const ed = "10.20.0.1 ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIE0Bq1hQ0j7lC1n6x3o0b9Z7w2YtqXxw9i6ZQ5mM2kHq";
assert.equal(knownHostsProblem(`# keyscan\n${ed}\n[10.20.0.2]:2222,app ${ed.split(" ").slice(1).join(" ")} c\n`), null);
assert.equal(knownHostsProblem(`@cert-authority *.bank.local ${ed.split(" ").slice(1).join(" ")}`), null);
assert.match(knownHostsProblem("hello world") ?? "", /^Line 1 is not a known_hosts line/);
assert.match(knownHostsProblem(`${ed}\n10.0.0.9 ssh-rsa`) ?? "", /^Line 2/);
assert.match(knownHostsProblem("-----BEGIN OPENSSH PRIVATE KEY-----\nAAAA\n-----END OPENSSH PRIVATE KEY-----") ?? "", /private key/);
assert.match(knownHostsProblem("  \n# only a comment\n") ?? "", /Paste the known_hosts lines/);

// #156: plain-HTTP WinRM ports and non-LDAPS AD ports
assert.match(windowsPortProblem("windows_servers", 80) ?? "", /HTTPS \(5986\)/);
assert.match(windowsPortProblem("windows_servers", 5985) ?? "", /HTTPS \(5986\)/);
assert.equal(windowsPortProblem("windows_servers", 5986), null);
assert.match(windowsPortProblem("active_directory", 389) ?? "", /636/);
assert.equal(windowsPortProblem("active_directory", 3269), null);
assert.equal(windowsPortProblem("linux_servers", 80), null);
// the same port sets as the backend
const kinds = fs.readFileSync(path.join(here, "../../../../backend/utilities/cbom_sources/kinds.py"), "utf8");
const set = (name: string) => Array.from((new RegExp(`${name} = frozenset\\(\\{([^}]*)\\}`).exec(kinds) ?? ["", ""])[1].matchAll(/\d+/g)).map(Number).sort();
for (const p of set("WINRM_HTTP_PORTS")) assert.ok(windowsPortProblem("windows_servers", p), `WinRM ${p}`);
for (const p of set("AD_NOT_LDAPS_PORTS")) assert.ok(windowsPortProblem("active_directory", p), `AD ${p}`);
assert.ok(set("WINRM_HTTP_PORTS").length >= 3 && set("AD_NOT_LDAPS_PORTS").length >= 4);

// wired into the Servers form: validate(), the CSV import and the known_hosts upload
const tab = fs.readFileSync(path.join(here, "ServersTab.tsx"), "utf8");
assert.match(tab, /knownHostsProblem\(form\.knownHosts\)/);
assert.match(tab, /const problem = knownHostsProblem\(text\);/);
assert.match(tab, /mergeImportedTargets\(form\.targets, rows, MAX_TARGET_LINES\)/);
assert.match(tab, /windowsPortProblem\(form\.kind, Number\(form\.port\)\)/);
console.log("sourceFormChecks.test.ts: ok");
