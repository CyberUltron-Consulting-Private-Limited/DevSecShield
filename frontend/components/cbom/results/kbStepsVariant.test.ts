/**
 * KbFindingDetails variant="steps" (the run finding dialog's Issues tab, boards 27-C / 28-B / 29-D / 30-A): every text
 * of every knowledge-base issue is in the DOM (clamped or hidden, never dropped), each step is a button with
 * aria-expanded / aria-controls, CVEs beyond the cap and proof commands beyond the cap stay in the DOM behind
 * "Show all (n)", the Verify block lists each command once with the issues it proves, and "No weakness is flagged"
 * stays. Rendered with renderToStaticMarkup.
 * Run (frontend/): npx --yes tsx@4.23.15 components/cbom/results/kbStepsVariant.test.ts
 */
import assert from "node:assert/strict";
import React from "react";
import { renderToStaticMarkup } from "react-dom/server";

import KbFindingDetails, { CVE_CAP, VERIFY_CAP, verifyCommands } from "@/components/cbom/KbFindingDetails";
import type { KbFindingDetail } from "@/utils/backend_api";

const h = React.createElement;
const unescape = (s: string) => s.replace(/&#x27;/g, "'").replace(/&quot;/g, '"').replace(/&amp;/g, "&").replace(/&lt;/g, "<").replace(/&gt;/g, ">");
const count = (hay: string, needle: string) => hay.split(needle).length - 1;

const shared = { label: "Protocol versions the server accepts", command: "nmap --script ssl-enum-ciphers -p 443 10.232.0.64" };
const cves = Array.from({ length: CVE_CAP + 3 }, (_, i) => ({
  id: `CVE-2020-${1000 + i}`, url: `https://nvd.nist.gov/vuln/detail/CVE-2020-${1000 + i}`,
  cvss: { version: "3.1", score: 5 + (i % 4), vector: null, severity: "MEDIUM" }, matched_on: "finding type", summary: `summary of CVE ${i}`,
}));
const kb = (code: string, extra: Partial<KbFindingDetail> = {}): KbFindingDetail => ({
  code, title: `Title ${code}`, observed: `F5 profile accepts ${code}`, description: `Why ${code} matters, a long explanation that the strip clamps.`,
  attack: `How ${code} is attacked, in full.`, impact: "i", category: "c", pqc: null,
  cwe: [{ id: "CWE-327", name: "Use of a Broken or Risky Cryptographic Algorithm", url: "https://cwe.mitre.org/data/definitions/327.html" }],
  owasp_2021: [{ id: "A02:2021", label: "A02:2021 Cryptographic Failures", basis: "b" }],
  owasp_2025: [{ id: "A04:2025", label: "A04:2025 Cryptographic Failures", basis: "b" }],
  cves: [], standards: ["NIST SP 800-52r2"], compliance: [{ framework: "RBI", id: "para 16", text: "Strong.", source: "https://rbi.org.in", note: null }],
  remediation: { summary: `Fix ${code} now.`, steps: [{ platform: "nginx", how: `ssl_protocols TLSv1.2 TLSv1.3; # ${code}` }, { platform: "Apache httpd", how: "SSLProtocol -all +TLSv1.2 +TLSv1.3" }] },
  verify: [shared, { label: `Handshake for ${code}`, command: `openssl s_client -connect 10.232.0.64:443 -${code.toLowerCase()}` }],
  references: [], ...extra,
} as unknown as KbFindingDetail);

const many = Array.from({ length: VERIFY_CAP + 2 }, (_, i) => ({ label: `extra ${i}`, command: `echo extra-${i}` }));
const details = [
  kb("PROTO_SSLv3", { cves }),
  kb("PROTO_TLS10"),
  kb("WEAK_CIPHER", { observed: null, verify: [shared, ...many] }),
];
const html = renderToStaticMarkup(h(KbFindingDetails, { details, variant: "steps" }));
const text = unescape(html);

// every text of every issue is in the DOM
for (const d of details) {
  for (const t of [d.title, d.code, d.description, d.attack, d.remediation.summary, ...d.remediation.steps.flatMap((s) => [s.platform, s.how]),
    ...d.cwe.map((c) => c.id), ...d.owasp_2021.map((o) => o.label), ...d.owasp_2025.map((o) => o.label)] as string[]) {
    assert.ok(text.includes(t), `${d.code}: "${t}" is in the DOM`);
  }
  if (d.observed) assert.ok(text.includes(d.observed), `${d.code}: observed text`);
  for (const v of d.verify) assert.ok(text.includes(v.command), `${d.code}: proof command ${v.command}`);
  for (const step of ["observed", "why", "attack", "fix", "verify"]) {
    const btn = new RegExp(`<button[^>]*aria-expanded="false"[^>]*aria-controls="[^"]+"[^>]*data-testid="kb-step-${d.code}-${step}"`).exec(html);
    assert.ok(btn, `${d.code}: step ${step} is a button with aria-expanded / aria-controls`);
  }
}
assert.ok(text.includes("Observed") && text.includes("Why it matters") && text.includes("How it is attacked") && text.includes("Verify"));
// every CVE is in the DOM; past the cap they are hidden behind "Show all (n)"
for (const c of cves) {
  assert.ok(text.includes(c.id) && text.includes(c.summary!), `${c.id} in the DOM`);
}
const distinct = verifyCommands(details).length;
assert.equal(count(html, "<li hidden=\"\""), (cves.length - CVE_CAP) + (distinct - VERIFY_CAP), "CVEs and commands past the caps are hidden, not dropped");
assert.ok(text.includes(`Show all (${cves.length})`), "CVE Show all");
assert.match(html, /<button[^>]*aria-expanded="false"[^>]*aria-controls="[^"]+"[^>]*>Show all \(15\)/);
assert.ok(text.includes(`CVEs (${cves.length})`));
// one Verify block: the shared command once, tagged with every issue it proves
assert.equal(count(html, 'data-testid="kb-verify"'), 1, "one Verify block");
assert.equal(count(text, shared.command), 1, "a command shared by three issues is listed once");
const cmds = verifyCommands(details);
assert.deepEqual(cmds[0].issues.map((i) => i.code), ["PROTO_SSLv3", "PROTO_TLS10", "WEAK_CIPHER"]);
assert.equal(cmds.length, 1 + 2 + many.length, "each distinct command once");
assert.ok(text.includes(`Show all (${cmds.length})`), "Verify Show all");
// platform commands: a grid with a Copy button per platform
assert.ok(count(text, "Fix commands by platform") === 3);
assert.ok(count(text, "Copy") >= 6 + cmds.length);
// no per-code standards in the steps variant (the dialog's Standards tab shows them once)
assert.equal(count(text, "Standards and regulations"), 0);
// the empty state is kept
assert.ok(renderToStaticMarkup(h(KbFindingDetails, { details: [], variant: "steps" })).includes("No weakness is flagged on this asset."));
// the cards variant (default) is not touched by the variant (sharedCodeMode.test.ts compares it with the base commit)
assert.ok(!renderToStaticMarkup(h(KbFindingDetails, { details })).includes("kb-step-"));

console.log("KB steps variant tests passed");
