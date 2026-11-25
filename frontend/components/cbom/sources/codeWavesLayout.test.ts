/**
 * PR #500 review 6061095673 #3: the code scan's remediation-waves table does not scroll sideways on a 390 px phone.
 * A rendered check, not class names: the real CodeWavesTable markup (react-dom/server) inside the real Card /
 * CardContent, styled by Tailwind compiled from those classes (@tailwindcss/node), in the app font (Geist, the
 * woff2 Next.js ships), measured by headless Chrome at a 390 px viewport after the font has loaded:
 * the scroll wrapper's scrollWidth <= clientWidth and the page has no horizontal overflow.
 * The page around the card is the results page's `container mx-auto p-6`.
 * Headless Chrome opens no window under 500 px, so the phone is a 390 px wide box (no `sm:` rule applies below 640).
 * Skipped (with a note) where no Chrome binary exists; CI's frontend job keeps the markup test codeWavesTable.test.ts.
 * Run (frontend/): npx --yes tsx@4.23.15 --test components/cbom/sources/codeWavesLayout.test.ts
 */
import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import { existsSync, mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { createRequire } from "node:module";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import test from "node:test";
import { pathToFileURL } from "node:url";
import React from "react";
import { renderToStaticMarkup } from "react-dom/server";

import { Card, CardContent } from "@/components/ui/card";
import type { CbomRemediationItem } from "@/utils/api/cbom_ops";

import { CodeWavesTable } from "./WavesControls";

const CHROME = ["/usr/bin/google-chrome", "/usr/bin/chromium", "/usr/bin/chromium-browser"].find((p) => existsSync(p));
const require_ = createRequire(import.meta.url);

const item = (n: number, over: Partial<CbomRemediationItem> = {}): CbomRemediationItem => ({
  asset_key: `k${n}`, scope: "code", label: `src/very/long/path/to/module_${n}/crypto_helpers.py:MD5`, type: "algorithm",
  impact: "High", finding_codes: ["WEAK_ALGORITHM"], quantum_vulnerable: false, exposure: "internal", hndl: false,
  owner_hint: "payments-platform-team", suggested_wave: 2, wave: 2, wave_source: "suggested", assignment: null, ...over,
});

const ITEMS = [
  item(1),
  item(2, { wave: 4, suggested_wave: 4 }),
  item(3, { wave: 1, wave_source: "assigned",
            assignment: { wave: 1, owner: "crypto-guild@example.com", target_date: "2026-12-31", status: "in_progress", note: null } }),
  item(4, { impact: null, owner_hint: null }),
];

function page(): string {
  const h = React.createElement;
  const table = h(CodeWavesTable, { items: ITEMS, selected: new Set<string>(), onToggle: () => undefined });
  const wrapper = h("div", { className: "max-h-96 overflow-y-auto border rounded-md", id: "scroll" }, table);
  const card = h(Card, { className: "border-zinc-200 min-w-0" }, h(CardContent, null, wrapper));
  const shell = h("div", { className: "container mx-auto p-6 space-y-6" }, card);
  // headless Chrome will not open a window narrower than 500 px: the 390 px phone is this box (every `sm:` rule
  // starts at 640 px, so the phone layout applies either way)
  return renderToStaticMarkup(h("div", { id: "phone", style: { width: "390px" } }, shell));
}

async function css(markup: string): Promise<string> {
  const { compile } = await import("@tailwindcss/node");
  const base = dirname(require_.resolve("tailwindcss/package.json"));
  const compiler = await compile('@import "tailwindcss";', { base, onDependency: () => undefined });
  const candidates = [...markup.matchAll(/class="([^"]*)"/g)].flatMap((m) => m[1].split(/\s+/)).filter(Boolean);
  return compiler.build([...new Set(candidates)]);
}

test("the waves table fits a 390 px phone in Geist (rendered)", { skip: CHROME ? false : "no Chrome binary" }, async () => {
  const font = join(dirname(require_.resolve("next/package.json")), "dist/esm/next-devtools/server/font/geist-latin.woff2");
  assert.ok(existsSync(font), font);
  const markup = page();
  const dir = mkdtempSync(join(tmpdir(), "waves-layout-"));
  try {
    const html = `<!doctype html><html><head><meta name="viewport" content="width=device-width, initial-scale=1">
<style>@font-face{font-family:Geist;src:url("${pathToFileURL(font).href}") format("woff2");font-weight:100 900;}
${await css(markup)}
html,body{margin:0;font-family:Geist,sans-serif;}</style></head><body>${markup}
<pre id="out"></pre>
<script>
document.fonts.load("500 12px Geist").then(() => document.fonts.ready).then(() => {
  const s = document.getElementById("scroll");
  document.getElementById("out").textContent = JSON.stringify({
    geist: document.fonts.check("500 12px Geist"),
    scrollWidth: s.scrollWidth, clientWidth: s.clientWidth,
    pageScroll: document.getElementById("phone").scrollWidth, viewport: document.getElementById("phone").clientWidth,
    badge: Math.max(...[...document.querySelectorAll('[data-testid^="wave-k"] [data-slot="badge"], [data-testid^="wave-k"] span')].map((e) => e.getBoundingClientRect().width)),
  });
});
</script></body></html>`;
    const file = join(dir, "page.html");
    writeFileSync(file, html);
    const dom = execFileSync(CHROME as string, [
      "--headless=new", "--no-sandbox", "--disable-gpu", "--allow-file-access-from-files", "--window-size=390,1200",
      "--virtual-time-budget=5000", "--dump-dom", pathToFileURL(file).href,
    ], { encoding: "utf8", timeout: 60_000, stdio: ["ignore", "pipe", "ignore"] });
    const out = /<pre id="out">([^<]*)<\/pre>/.exec(dom);
    assert.ok(out && out[1], "the page reported no measurement");
    const m = JSON.parse(out[1].replace(/&quot;/g, '"'));
    assert.equal(m.geist, true, "Geist loaded");
    assert.equal(m.viewport, 390);
    console.log(`waves layout: ${JSON.stringify(m)}`);
    assert.ok(m.scrollWidth <= m.clientWidth, `the table scrolls sideways: ${JSON.stringify(m)}`);
    assert.ok(m.pageScroll <= m.viewport, `the page overflows: ${JSON.stringify(m)}`);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});
