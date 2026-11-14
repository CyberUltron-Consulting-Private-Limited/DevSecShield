/**
 * #268 (results template, code scans and Sources runs): the algorithm-family heat-map and the certificate calendar
 * are stacked full width (heat-map first), the heat-map box sizes to its content (no half-width squeeze, no empty
 * area beside a 3-column "By source" table), and "Next to expire" names host:port so one certificate served on two
 * ports is not shown as an identical duplicate; only true duplicates collapse.
 * #272: the lab-mode banner is a calm note (role="note", 1 px border, only the key phrase bold, spaced from the form,
 * one line plus "Details" on a phone).
 * Run (frontend/): npx --yes tsx@4.23.15 components/cbom/results/insightsLayout.test.ts
 */
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import path from "node:path";
import { test } from "node:test";
import React from "react";
import { renderToStaticMarkup } from "react-dom/server";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";

import CertCalendar from "../CertCalendar";
import CryptoHeatmap from "../CryptoHeatmap";
import { certDedupeKey, certWhere, dedupeCerts } from "../heatmapLogic";
import { RunInsights } from "../sources/ChangesPanel";
import { AWS_LAB_BANNER, LabModeBanner } from "../sources/LabModeBanner";
import { cbomOpsKeys, type CbomRunHeatmap } from "@/utils/api/cbom_ops";

const h = React.createElement;
const read = (p: string) => readFileSync(path.join(__dirname, p), "utf8");

const web4 = (port: number) => ({
  subject: "CN=web4.lab", issuer: "CN=Lab CA", not_after: "2026-12-01T00:00:00Z",
  target: "10.20.0.14", location: `10.20.0.14:${port}#chain[0]`, name: "CN=web4.lab",
});
const NOW = new Date("2026-11-14T00:00:00Z");

test("certWhere: host:port from the endpoint location; other certificates keep their label", () => {
  assert.equal(certWhere(web4(443)), "10.20.0.14:443");
  assert.equal(certWhere(web4(8443)), "10.20.0.14:8443");
  assert.equal(certWhere({ target: "fd00::1", location: "[fd00::1]:636#chain[1]" }), "[fd00::1]:636");
  assert.equal(certWhere({ target: "web4.lab", location: "web4.lab:5432#chain[0]" }), "web4.lab:5432");
  // not an endpoint: the source label as before (ACM ARN, k8s secret, a file in a repository)
  assert.equal(certWhere({ target: "aws-prod", location: "arn:aws:acm:eu-west-1:1:certificate/x" }), "aws-prod");
  assert.equal(certWhere({ target: "cluster-a", location: "default/secret/tls-web" }), "cluster-a");
  assert.equal(certWhere({ location: "src/certs/server.pem" }), "src/certs/server.pem");
  assert.equal(certWhere({}), null);
});

test("dedupeCerts collapses only true duplicates", () => {
  const other = { ...web4(443), issuer: "CN=Other CA" };
  const out = dedupeCerts([web4(443), web4(8443), web4(443), other]);
  assert.equal(out.length, 3, "same certificate on 443 and 8443 stays two entries; the repeated 443 one collapses");
  assert.deepEqual(out.map(certWhere), ["10.20.0.14:443", "10.20.0.14:8443", "10.20.0.14:443"]);
  assert.notEqual(certDedupeKey(web4(443)), certDedupeKey(web4(8443)));
  assert.notEqual(certDedupeKey(web4(443)), certDedupeKey(other));
  assert.equal(certDedupeKey(web4(443)), certDedupeKey({ ...web4(443) }));
});

test("Next to expire shows host:port per entry, no identical duplicate rows", () => {
  const html = renderToStaticMarkup(h(CertCalendar, {
    certs: [web4(443), web4(8443), web4(443), { name: "acm", target: "aws-prod", location: "arn:aws:acm:x", not_after: "2026-12-20T00:00:00Z" }],
    now: NOW, testId: "cal",
  }));
  const list = html.slice(html.indexOf('data-testid="cal-list"'));
  const items = list.match(/<li\b[^>]*>.*?<\/li>/g) ?? [];
  assert.equal(items.length, 3, items.join("\n"));
  assert.ok(items[0].includes("10.20.0.14:443") && items[1].includes("10.20.0.14:8443"), items.join("\n"));
  assert.ok(items[2].includes("aws-prod"));
  assert.equal(new Set(items).size, items.length, "no two rows read the same");
});

test("CertCalendar: calendar and its list side by side from md up, stacked on a phone", () => {
  const html = renderToStaticMarkup(h(CertCalendar, { certs: [web4(443)], now: NOW, testId: "cal" }));
  const body = html.match(/<div class="([^"]*)" data-testid="cal-body"/);
  assert.ok(body, "calendar body found");
  assert.match(body![1], /\bgrid-cols-1\b.*\bmd:grid-cols-\[/);
  assert.ok(html.indexOf('data-testid="cal-body"') < html.indexOf('data-testid="cal-list"'), "the list is inside the body");
});

test("CryptoHeatmap box sizes to its content (w-fit, max-w-full) instead of filling its column", () => {
  const html = renderToStaticMarkup(h(CryptoHeatmap, {
    data: { rows: ["RSA"], columns: ["a", "b", "c"], cells: [{ row: "RSA", column: "a", count: 1, worst: "High", by_impact: { High: 1 } }] },
    testId: "hm",
  }));
  assert.match(html, /<div class="[^"]*overflow-x-auto[^"]*\bw-fit\b[^"]*\bmax-w-full\b/);
});

test("RunInsights stacks heat-map then calendar, both full width (no 50/50 row)", () => {
  const qc = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  const data: CbomRunHeatmap = {
    by: "source", rows: ["RSA"], columns: ["net-a", "net-b", "net-c"],
    cells: [{ row: "RSA", column: "net-a", count: 2, worst: "High", by_impact: { High: 2 } }],
    certificates: [web4(443), web4(8443)],
  } as CbomRunHeatmap;
  qc.setQueryData(cbomOpsKeys.heatmap(1, 12, "source"), data);
  const html = renderToStaticMarkup(h(QueryClientProvider, { client: qc }, h(RunInsights, { teamId: 1, runId: 12, active: false })));
  const box = html.match(/<div class="([^"]*)" data-testid="run-insights"/);
  assert.ok(box, html.slice(0, 400));
  assert.ok(!/grid-cols-2/.test(box![1]), `run-insights must not split into two columns: ${box![1]}`);
  assert.ok(html.indexOf('data-testid="run-heatmap"') < html.indexOf('data-testid="run-cert-calendar"'), "heat-map first");
});

test("code scans use the same stacked layout (CodeHeatmapAndCalendar)", () => {
  const src = read("../CbomCryptoCharts.tsx");
  const body = src.slice(src.indexOf("function CodeHeatmapAndCalendar"));
  const wrap = body.match(/return \(\s*<div className="([^"]*)"/);
  assert.ok(wrap, "wrapper found");
  assert.ok(!/grid-cols-2/.test(wrap![1]), `code heat-map + calendar must stack: ${wrap![1]}`);
  assert.ok(body.indexOf('testId="code-heatmap"') < body.indexOf('testId="code-cert-calendar"'), "heat-map first");
});

test("LabModeBanner is a calm note, not an alert", () => {
  const html = renderToStaticMarkup(h(LabModeBanner, { testId: "lab", detail: "Detail text." }));
  assert.match(html, /role="note"/);
  assert.ok(!/role="alert"/.test(html), "never role=alert");
  const cls = html.match(/<div[^>]*class="([^"]*)"[^>]*data-testid="lab"|<div[^>]*data-testid="lab"[^>]*class="([^"]*)"/);
  const c = (cls?.[1] ?? cls?.[2]) || "";
  assert.ok(c.includes("border ") || / border$/.test(c) || /\bborder\b/.test(c), c);
  assert.ok(!/\bborder-2\b/.test(c), `1 px border: ${c}`);
  assert.ok(!/\bfont-(semibold|bold)\b/.test(c), `body text is normal weight: ${c}`);
  // only the key phrase is bold, and the sentence still matches the backend's lab_mode.LAB_BANNER
  assert.match(html, /<strong[^>]*>Lab mode:<\/strong>/);
  assert.ok(html.replace(/<[^>]+>/g, "").includes(AWS_LAB_BANNER));
  // compact on a phone: detail behind a "Details" disclosure below sm, inline from sm up
  assert.match(html, /<details[^>]*class="[^"]*sm:hidden[^"]*"[^>]*><summary[^>]*>Details<\/summary>/);
  assert.match(html, /class="[^"]*hidden sm:block[^"]*"[^>]*>Detail text\./);
});

test("the AWS form gives the banner the same spacing as other blocks", () => {
  const tab = read("../sources/CloudIdentityTab.tsx");
  const at = tab.indexOf("<LabModeBanner");
  const call = tab.slice(at, tab.indexOf("/>", at));
  assert.match(call, /className="mb-4"/);
});
