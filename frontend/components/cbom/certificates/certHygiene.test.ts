/**
 * Output 04 "Certificates: orphaned and unmanaged" rendered with react-dom/server: the flag counts as filter buttons
 * (every flag, 0 included), one row per certificate with its flags and expiry, the empty list, and the notes that say
 * why a list may be incomplete. Run (frontend/): npx --yes tsx@4.23.15 components/cbom/certificates/certHygiene.test.ts
 */
import assert from "node:assert/strict";
import React from "react";
import { renderToStaticMarkup } from "react-dom/server";

import { HygieneSummary, HygieneTable, ListBasisNote } from "./CertHygiene";
import { HYGIENE_FLAGS, SHOWN_FLAGS, csvFileName, expiryText, filterParams, stateNote, type HygieneCert } from "./certHygiene";

const h = React.createElement;
const esc = (s: string) => s.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
const attr = (html: string, raw: string, name: string) =>
  new RegExp(`data-testid="${esc(raw)}"[^>]*?${name}="([^"]*)"|${name}="([^"]*)"[^>]*?data-testid="${esc(raw)}"`).exec(html)?.slice(1).find((v) => v != null);

const flags = Object.fromEntries(HYGIENE_FLAGS.map((f) => [f, `${f} text`]));
const counts = { certificates: 4, flagged: 3, by_flag: { unmanaged: 3, prober_only: 1, orphaned: 2, no_owner: 2, expired_served: 1 } };
const summary = renderToStaticMarkup(h(HygieneSummary, { page: { counts, flags }, active: "orphaned" }));
assert.equal(attr(summary, "cert-hygiene-summary", "data-flagged"), "3");
for (const f of SHOWN_FLAGS) {
  assert.equal(attr(summary, `cert-hygiene-flag-${f}`, "data-count"), String((counts.by_flag as Record<string, number>)[f] ?? 0));
}
// review 6039899144 M5: no "Not seen lately" chip (the flag is never set: the list is each source's latest collection)
assert.ok(!summary.includes("cert-hygiene-flag-stale") && !summary.includes("Not seen lately"));
assert.deepEqual([...SHOWN_FLAGS], HYGIENE_FLAGS.filter((f) => f !== "stale"));
const basis = renderToStaticMarkup(h(ListBasisNote));
assert.match(basis, /latest collection, the rule the Certificate Estate Register \(D8\) uses/);
assert.match(basis, /reported by drift/);
assert.ok(!basis.includes("Not seen lately"));
assert.ok(summary.includes('aria-pressed="true"'));

const CERT: HygieneCert = {
  key: "cert:1", label: "CN=old.lab", key_kind: "cross", subject: "CN=old.lab", issuer: "CN=Lab CA", serial: "0b",
  not_after: "2026-11-09T00:00:00Z", days_left: -5, expired: true, flags: ["unmanaged", "prober_only", "expired_served"],
  not_seen_runs: 0, owners: [], applications: ["Web"], sources: ["probe-web"],
  observations: [{ source_name: "probe-web", source_kind: "linux_servers", location: "10.0.0.1:8443#chain[0]", presence: "present",
                   served: true, managing: false, seen_at: null, not_seen_runs: 0 }],
};
const table = renderToStaticMarkup(h(HygieneTable, { items: [CERT], flags }));
assert.equal(attr(table, "cert-hygiene-row", "data-flags"), "unmanaged prober_only expired_served");
assert.ok(table.includes("Expired 5 days ago") && table.includes("Web") && table.includes('data-flag="expired_served"'));
assert.ok(renderToStaticMarkup(h(HygieneTable, { items: [], flags })).includes('data-testid="cert-hygiene-empty"'));

assert.equal(expiryText({ days_left: 1 }), "Expires in 1 day");
assert.equal(expiryText({ days_left: null }), "—");
assert.deepEqual(filterParams({ flag: "stale", q: "  web ", all: true }), { flag: "stale", q: "web", all: "true" });
assert.deepEqual(filterParams({ flag: null, q: "", all: false }), {});
assert.equal(stateNote({ state: "ready", probed: true }), null);
assert.match(stateNote({ state: "ready", probed: false }) ?? "", /No endpoint is probed/);
assert.match(stateNote({ state: "pending", probed: true }) ?? "", /still being written/);
assert.equal(csvFileName(7, new Date("2026-11-14T10:00:00Z")), "certificate-hygiene-team7-2026-11-14.csv");

console.log("certHygiene.test.ts: ok");
